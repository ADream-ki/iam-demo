use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use cookie::{Cookie, SameSite};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{
    adapters::{
        dto::{
            AuthResponse, HealthResponse, OtpRequestRequest, OtpRequestResponse, OtpVerifyRequest,
            MfaVerifyResponse, OtpMfaVerifyRequest, PasskeyChallengeResponse,
            PasskeyLoginChallengeRequest, PasskeyRegisterVerifyRequest, PasskeyRegistrationResponse,
            PasskeyVerifyRequest, PasswordLoginRequest, RefreshResponse, SessionItemResponse,
            SessionOverviewResponse,
        },
        session_extractor::{SessionContext, refresh_token, require_full_mfa, require_session},
    },
    application::services::{
        AuthResult, OtpMfaVerifyInput, OtpRequestInput, OtpVerifyInput, PasskeyLoginChallengeInput,
        PasskeyLoginVerifyInput, PasskeyRegisterVerifyInput, PasswordLoginInput, RefreshResult,
    },
    error::AppError,
    infrastructure::AppState,
};

use axum::http::header::SET_COOKIE;
const TRUSTED_DEVICE_COOKIE_NAME: &str = "trusted_device_token";
// ---- Router builder ----

/// 组装 API 路由与中间件。
///
/// 按安全边界拆分为公开鉴权路由、刷新路由、登录态路由和强认证路由。
pub fn build_router(state: AppState, config: crate::config::AppConfig) -> Router {
    let trusted_origin = HeaderValue::from_str(&config.trusted_origin)
        .expect("TRUSTED_ORIGIN must be a valid header value");
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(trusted_origin))
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-refresh-token"),
            HeaderName::from_static("x-trusted-device-token"),
        ]);

    let public_auth = Router::new()
        .route("/password/login", post(password_login))
        .route("/otp/request", post(otp_request))
        .route("/otp/verify", post(otp_verify))
        .route("/passkey/challenge", post(passkey_login_challenge))
        .route("/passkey/verify", post(passkey_login_verify))
        .layer(middleware::from_fn_with_state(state.clone(), public_rate_limit));

    let refresh_auth = Router::new()
        .route("/refresh", post(refresh_access))
        .layer(middleware::from_fn_with_state(state.clone(), public_rate_limit));

    let protected_auth = Router::new()
        .route("/session", get(current_session))
        .route("/logout", post(logout))
        .route("/mfa/otp/request", post(mfa_otp_request))
        .route("/mfa/otp/verify", post(mfa_otp_verify))
        .layer(middleware::from_fn_with_state(state.clone(), require_session));

    let passkey_register = Router::new()
        .route("/register/challenge", post(passkey_register_challenge))
        .route("/register/verify", post(passkey_register_verify))
        .layer(middleware::from_fn_with_state(state.clone(), require_full_mfa));

    let sessions = Router::new()
        .route("/", get(list_sessions))
        .route("/revoke-others", post(revoke_other_sessions))
        .route("/{session_id}", post(revoke_session))
        .layer(middleware::from_fn_with_state(state.clone(), require_full_mfa));

    Router::new()
        .route("/health", get(health))
        .nest("/api/auth", public_auth)
        .nest("/api/auth", refresh_auth)
        .nest("/api/auth", protected_auth)
        .nest("/api/auth/passkey", passkey_register)
        .nest("/api/sessions", sessions)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ---- Rate limit middleware ----

/// 公开鉴权接口的统一频控中间件，基于路径、来源 IP 和 UA 做速率限制。
async fn public_rate_limit(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    // 在公开鉴权接口上统一执行频控，降低暴力尝试和接口滥用风险。
    let remote_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let ip = source_ip(request.headers(), remote_addr, state.trust_proxy_headers);
    let agent = user_agent(request.headers());
    state
        .security_service
        .enforce_public_auth_rate_limit(request.uri().path(), ip.as_deref(), agent.as_deref())
        .await?;
    Ok(next.run(request).await)
}
// ---- Handlers ----

/// 健康检查端点，供 Docker 与外部探针确认服务是否可用。
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// 处理密码登录请求，并在成功后把 access/refresh Cookie 写回客户端。
async fn password_login(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordLoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let ip = source_ip(&headers, Some(remote_addr), state.trust_proxy_headers);
    let result = state.auth_service.login_with_password(PasswordLoginInput {
        email: body.email,
        password: body.password,
        role: body.role,
        device_name: body.device_name,
        remember_device: body.remember_device,
        trusted_device_token: trusted_device_token(&headers),
        user_agent: user_agent(&headers),
        ip,
    }).await?;
    Ok(with_auth_cookies(&state, result))
}

/// 请求一阶段登录 OTP；开发环境会带回 demo code 以便联调。
async fn otp_request(
    State(state): State<AppState>,
    Json(body): Json<OtpRequestRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result = state.auth_service.request_otp(OtpRequestInput {
        email: body.email,
        role: body.role,
    }).await?;
    Ok(Json(OtpRequestResponse::from(result)))
}

/// 校验登录 OTP，并在通过后签发正式会话。
async fn otp_verify(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<OtpVerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let ip = source_ip(&headers, Some(remote_addr), state.trust_proxy_headers);
    let result = state.auth_service.verify_otp(OtpVerifyInput {
        email: body.email,
        code: body.code,
        role: body.role,
        device_name: body.device_name,
        remember_device: body.remember_device,
        trusted_device_token: trusted_device_token(&headers),
        user_agent: user_agent(&headers),
        ip,
    }).await?;
    Ok(with_auth_cookies(&state, result))
}

/// 为 Passkey 登录生成 assertion challenge。
async fn passkey_login_challenge(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasskeyLoginChallengeRequest>,
) -> Result<impl IntoResponse, AppError> {
    let ip = source_ip(&headers, Some(remote_addr), state.trust_proxy_headers);
    let result = state.auth_service.begin_passkey_login(PasskeyLoginChallengeInput {
        email: body.email,
        role: body.role,
        user_agent: user_agent(&headers),
        ip,
    }).await?;
    Ok(Json(PasskeyChallengeResponse::from(result)))
}

/// 校验浏览器返回的 Passkey assertion，并在成功后完成登录。
async fn passkey_login_verify(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasskeyVerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let ip = source_ip(&headers, Some(remote_addr), state.trust_proxy_headers);
    let result = state.auth_service.finish_passkey_login(PasskeyLoginVerifyInput {
        challenge_id: body.challenge_id,
        email: body.email,
        role: body.role,
        response: body.response,
        device_name: body.device_name,
        remember_device: body.remember_device,
        trusted_device_token: trusted_device_token(&headers),
        user_agent: user_agent(&headers),
        ip,
    }).await?;
    Ok(with_auth_cookies(&state, result))
}

/// 使用 refresh token 轮换访问令牌，并同步回写新 Cookie。
async fn refresh_access(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let token = refresh_token(&headers, &state.refresh_cookie_name).ok_or(AppError::Unauthorized)?;
    let ip = source_ip(&headers, Some(remote_addr), state.trust_proxy_headers);
    let result = state.auth_service.refresh_access_token(&token, ip, user_agent(&headers))
        .await?.ok_or(AppError::Unauthorized)?;
    Ok(with_refresh_cookies(&state, result))
}
/// 为已完成完整 MFA 的当前会话生成 Passkey 注册 challenge。
async fn passkey_register_challenge(
    State(state): State<AppState>,
    SessionContext(current): SessionContext,
) -> Result<impl IntoResponse, AppError> {
    let result = state.auth_service.begin_passkey_registration(&current).await?;
    Ok(Json(PasskeyChallengeResponse::from(result)))
}

/// 校验 Passkey 注册响应，并把新凭据持久化到后端。
async fn passkey_register_verify(
    State(state): State<AppState>,
    SessionContext(current): SessionContext,
    Json(body): Json<PasskeyRegisterVerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result = state.auth_service.finish_passkey_registration(
        &current,
        PasskeyRegisterVerifyInput { challenge_id: body.challenge_id, response: body.response },
    ).await?;
    Ok(Json(PasskeyRegistrationResponse::from(result)))
}

/// 返回当前登录会话的概览信息。
async fn current_session(
    State(state): State<AppState>,
    SessionContext(current): SessionContext,
) -> Result<impl IntoResponse, AppError> {
    let result = state.auth_service.current_session(&current).await?;
    Ok(Json(SessionOverviewResponse::from(result)))
}

/// 为部分认证会话发送第二因子 OTP。
async fn mfa_otp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    SessionContext(current): SessionContext,
) -> Result<impl IntoResponse, AppError> {
    let result = state
        .auth_service
        .request_mfa_otp(&current, user_agent(&headers))
        .await?;
    Ok(Json(OtpRequestResponse::from(result)))
}

/// 校验第二因子 OTP，并在通过后回写 trusted device Cookie。
async fn mfa_otp_verify(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    SessionContext(current): SessionContext,
    Json(body): Json<OtpMfaVerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let ip = source_ip(&headers, Some(remote_addr), state.trust_proxy_headers);
    let result = state.auth_service.verify_mfa_otp(
        &current,
        OtpMfaVerifyInput { code: body.code, user_agent: user_agent(&headers), ip },
    ).await?;
    let tdt = result.trusted_device_token.clone();
    Ok(with_trusted_device_cookie(
        &state,
        tdt.as_deref(),
        false,
        Json(MfaVerifyResponse::from(result)),
    ))
}

/// 注销当前会话，并让客户端 Cookie 立即过期。
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    SessionContext(current): SessionContext,
) -> Result<impl IntoResponse, AppError> {
    state.auth_service.logout(&current, trusted_device_token(&headers).as_deref()).await?;
    let secure = state.app_env.eq_ignore_ascii_case("production");
    let mut h = HeaderMap::new();
    h.append(SET_COOKIE, expired_cookie(&state.access_cookie_name, secure));
    h.append(SET_COOKIE, expired_cookie(&state.refresh_cookie_name, secure));
    h.append(SET_COOKIE, expired_cookie(TRUSTED_DEVICE_COOKIE_NAME, secure));
    Ok((StatusCode::OK, h, Json(serde_json::json!({ "logged_out": true }))))
}

/// 列出当前主体下的所有活跃会话。
async fn list_sessions(
    State(state): State<AppState>,
    SessionContext(current): SessionContext,
) -> Result<impl IntoResponse, AppError> {
    let result = state.auth_service.list_sessions(&current).await?;
    Ok(Json(
        result
            .into_iter()
            .map(SessionItemResponse::from)
            .collect::<Vec<_>>(),
    ))
}

/// 撤销指定会话；如果撤销的是当前会话，则一并清理本地 Cookie。
async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    SessionContext(current): SessionContext,
    Path(session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let revoked = state.auth_service.revoke_session(
        &current, session_id, trusted_device_token(&headers).as_deref(),
    ).await?;
    if session_id == current.session_id && revoked {
        let secure = state.app_env.eq_ignore_ascii_case("production");
        let mut h = HeaderMap::new();
        h.append(SET_COOKIE, expired_cookie(&state.access_cookie_name, secure));
        h.append(SET_COOKIE, expired_cookie(&state.refresh_cookie_name, secure));
        h.append(SET_COOKIE, expired_cookie(TRUSTED_DEVICE_COOKIE_NAME, secure));
        return Ok((StatusCode::OK, h, Json(serde_json::json!({ "revoked": true }))));
    }
    Ok((StatusCode::OK, HeaderMap::new(), Json(serde_json::json!({ "revoked": revoked }))))
}

/// 撤销除当前会话外的全部其他设备会话。
async fn revoke_other_sessions(
    State(state): State<AppState>,
    SessionContext(current): SessionContext,
) -> Result<impl IntoResponse, AppError> {
    Ok(Json(serde_json::json!({
        "revoked_count": state.auth_service.revoke_other_sessions(&current).await?
    })))
}

// ---- Cookie helpers ----

/// 为登录成功响应拼装 access/refresh Cookie 与业务 JSON 载荷。
fn with_auth_cookies(
    state: &AppState,
    result: AuthResult,
) -> (StatusCode, HeaderMap, Json<AuthResponse>) {
    // 登录成功时一次性写入 access/refresh cookie，减少前端额外握手。
    let secure = state.app_env.eq_ignore_ascii_case("production");
    let mut h = HeaderMap::new();
    h.append(SET_COOKIE, session_cookie(&state.access_cookie_name, &result.access_token, cookie_max_age(result.access_expires_at), secure));
    h.append(SET_COOKIE, session_cookie(&state.refresh_cookie_name, &result.refresh_token, cookie_max_age(result.refresh_expires_at), secure));
    append_trusted_device_cookie(&mut h, secure, result.trusted_device_token.as_deref(), result.clear_trusted_device, state.session_ttl_hours);
    (StatusCode::OK, h, Json(AuthResponse::from(result)))
}

/// 为 refresh 成功响应写回轮换后的 access/refresh Cookie。
fn with_refresh_cookies(
    state: &AppState,
    result: RefreshResult,
) -> (StatusCode, HeaderMap, Json<RefreshResponse>) {
    // 刷新流程仅轮换令牌，不修改业务返回结构。
    let secure = state.app_env.eq_ignore_ascii_case("production");
    let mut h = HeaderMap::new();
    h.append(SET_COOKIE, session_cookie(&state.access_cookie_name, &result.access_token, cookie_max_age(result.access_expires_at), secure));
    h.append(SET_COOKIE, session_cookie(&state.refresh_cookie_name, &result.refresh_token, cookie_max_age(result.refresh_expires_at), secure));
    (StatusCode::OK, h, Json(RefreshResponse::from(result)))
}

/// 为响应附加 trusted device Cookie，既支持写入也支持主动清除。
fn with_trusted_device_cookie<T: serde::Serialize>(
    state: &AppState,
    token: Option<&str>,
    clear: bool,
    body: Json<T>,
) -> (StatusCode, HeaderMap, Json<T>) {
    let secure = state.app_env.eq_ignore_ascii_case("production");
    let mut h = HeaderMap::new();
    append_trusted_device_cookie(&mut h, secure, token, clear, state.session_ttl_hours);
    (StatusCode::OK, h, body)
}

/// 根据绝对过期时间换算 Cookie 的 max-age。
fn cookie_max_age(expires_at: DateTime<Utc>) -> cookie::time::Duration {
    let secs = (expires_at - Utc::now()).num_seconds().max(0);
    cookie::time::Duration::seconds(secs)
}

/// 生成 HttpOnly 会话 Cookie。
fn session_cookie(name: &str, token: &str, max_age: cookie::time::Duration, secure: bool) -> HeaderValue {
    let mut c = Cookie::build((name.to_string(), token.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(max_age);
    if secure { c = c.secure(true); }
    HeaderValue::from_str(&c.build().to_string()).expect("cookie header value must be valid")
}

/// 生成一个立即过期的 Cookie，用于强制客户端清理本地认证状态。
fn expired_cookie(name: &str, secure: bool) -> HeaderValue {
    let mut c = Cookie::build((name.to_string(), String::new()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(0));
    if secure { c = c.secure(true); }
    HeaderValue::from_str(&c.build().to_string()).expect("cookie header value must be valid")
}

/// 依据业务结果向响应头追加 trusted device Cookie。
fn append_trusted_device_cookie(
    headers: &mut HeaderMap,
    secure: bool,
    token: Option<&str>,
    clear: bool,
    session_ttl_hours: i64,
) {
    if let Some(t) = token {
        headers.append(SET_COOKIE, session_cookie(TRUSTED_DEVICE_COOKIE_NAME, t, cookie::time::Duration::hours(session_ttl_hours), secure));
        return;
    }
    if clear {
        headers.append(SET_COOKIE, expired_cookie(TRUSTED_DEVICE_COOKIE_NAME, secure));
    }
}

// ---- Utility functions ----

/// 从请求头提取 user-agent，供风控与审计使用。
fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).map(ToOwned::to_owned)
}

/// 根据配置决定是否信任代理头，并提取审计用来源 IP。
fn source_ip(headers: &HeaderMap, remote_addr: Option<SocketAddr>, trust_proxy: bool) -> Option<String> {
    // 仅在显式配置下信任代理头，避免被伪造来源地址污染风控判断。
    if trust_proxy {
        forwarded_ip(headers).or_else(|| remote_addr.map(|a| a.ip().to_string()))
    } else {
        remote_addr.map(|a| a.ip().to_string())
    }
}

/// 从代理头中提取最左侧的真实来源 IP。
fn forwarded_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(fwd) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let first = fwd.split(',').next()?.trim();
        if !first.is_empty() { return Some(first.to_string()); }
    }
    headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(str::trim).filter(|v| !v.is_empty()).map(ToOwned::to_owned)
}

/// 提取 trusted device token，优先使用 Cookie，再回退显式请求头。
fn trusted_device_token(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, TRUSTED_DEVICE_COOKIE_NAME).or_else(|| {
        headers.get("x-trusted-device-token").and_then(|v| v.to_str().ok()).map(ToOwned::to_owned)
    })
}

/// 从原始 Cookie Header 中读取指定 Cookie 值。
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k == name { return Some(v.to_string()); }
        }
    }
    None
}
