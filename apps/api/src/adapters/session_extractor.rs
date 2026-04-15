use axum::{
    extract::{FromRequestParts, State},
    http::{HeaderMap, Request, request::Parts},
    middleware::Next,
    response::Response,
};

use crate::{
    domain::entities::{CurrentSession, MfaLevel},
    error::AppError,
    infrastructure::AppState,
};

// 这是适配器层暴露给路由的会话上下文包装类型。
// 中间件先把认证后的 CurrentSession 放进 request extensions，
// handler 再通过提取器拿到它，避免在每个接口里重复解析 token。
#[derive(Debug, Clone)]
pub struct SessionContext(pub CurrentSession);

impl<S> FromRequestParts<S> for SessionContext
where
    S: Send + Sync,
{
    type Rejection = AppError;

    /// 从 request extensions 中提取前置中间件已经认证好的会话上下文。
    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        // 这里不做新的认证动作，只读取前置中间件已经确认过的会话结果。
        let result = parts
            .extensions
            .get::<CurrentSession>()
            .cloned()
            .map(SessionContext)
            .ok_or(AppError::Unauthorized);
        async move { result }
    }
}

// require_session 是适配器层的统一登录校验入口。
// 它负责把 HTTP 请求中的 access token 提取出来，
// 然后委托 application service 做真正的会话认证。
pub async fn require_session(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    // 浏览器请求通常从 HttpOnly Cookie 取 token；非浏览器客户端则允许 Authorization Header。
    let token = access_token(request.headers(), &state.access_cookie_name).ok_or(AppError::Unauthorized)?;
    // 适配器层不直接访问 repository，而是统一交给 AuthService 处理。
    let current = state
        .auth_service
        .authenticate_token(&token)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // 认证完成后把领域态 CurrentSession 塞回请求上下文，供后续 handler 使用。
    tracing::info!(
        role = current.subject_role.as_str(),
        session_id = %current.session_id,
        "session authenticated"
    );
    request.extensions_mut().insert(current);
    Ok(next.run(request).await)
}

// require_full_mfa 在 require_session 的基础上再加一层授权约束。
// 它表达的不是“是否登录”，而是“当前会话是否已经完成完整 MFA”。
pub async fn require_full_mfa(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token = access_token(request.headers(), &state.access_cookie_name).ok_or(AppError::Unauthorized)?;
    let current = state
        .auth_service
        .authenticate_token(&token)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // partial session 只允许继续完成二次验证，不能访问需要完整会话的资源。
    if current.mfa_level != MfaLevel::Full {
        return Err(AppError::MfaRequired);
    }

    request.extensions_mut().insert(current);
    Ok(next.run(request).await)
}

/// 提取 access token，优先读取 Cookie，再回退 Bearer Token。
fn access_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    // 对浏览器最友好的默认路径是 Cookie。
    if let Some(cookie) = cookie_token(headers, cookie_name) {
        return Some(cookie);
    }

    // 为了兼容 Postman、脚本和前后端分离调试，也支持 Bearer Token。
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

/// 提取 refresh token，优先读取 Cookie，再回退自定义请求头。
pub fn refresh_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    // refresh token 也优先从 Cookie 读取，保证浏览器端不需要手工传参。
    cookie_token(headers, cookie_name).or_else(|| {
        // 非浏览器联调时允许显式通过自定义 Header 传递。
        headers
            .get("x-refresh-token")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    })
}

/// 从原始 Cookie Header 中解析指定名称的 token 值。
fn cookie_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    // 这里只做最小化 Cookie 解析，避免在中间件层引入更重的依赖和耦合。
    let header = headers.get(axum::http::header::COOKIE)?;
    let raw = header.to_str().ok()?;
    for part in raw.split(';') {
        let trimmed = part.trim();
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        if name == cookie_name {
            return Some(value.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, header::COOKIE};

    use super::cookie_token;

    #[test]
    /// 验证简易 Cookie 解析器会跳过损坏片段并继续找到目标 cookie。
    fn cookie_parser_skips_malformed_segments() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "broken; another=ok; session_token=token123"
                .parse()
                .expect("valid cookie header"),
        );

        let token = cookie_token(&headers, "session_token");
        assert_eq!(token.as_deref(), Some("token123"));
    }
}
