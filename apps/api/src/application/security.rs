use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

use crate::{
    domain::{
        entities::{CredentialType, Email, RiskEvent, RiskEventType, SubjectRole},
        ports::{Clock, RiskEventRepository, SecurityStore},
    },
    error::AppError,
};

// 安全策略编排服务：
// 1) 负责认证入口限流与失败计数；
// 2) 负责把安全事件写入风险审计仓储；
// 3) 只依赖 domain ports，不直接耦合具体 Redis/Postgres 实现。
// SecurityService ä½äºŽ application å±‚ã€‚
// å®ƒä¸ç›´æŽ¥æŒæœ‰ HTTPã€æ•°æ®åº“å®žçŽ°ç»†èŠ‚ï¼Œè€Œæ˜¯é€šè¿‡é¢†åŸŸç«¯å£æŠŠé™æµã€å¤±è´¥è®¡æ•°ã€å®¡è®¡è®°å½•ç¼–æŽ’èµ·æ¥ã€‚
pub struct SecurityService {
    store: Arc<dyn SecurityStore>,
    risk_events: Arc<dyn RiskEventRepository>,
    clock: Arc<dyn Clock>,
    public_rate_limit_max: u64,
    public_rate_limit_window_seconds: u64,
    login_failure_limit: u64,
    login_failure_source_limit: u64,
    login_failure_window_seconds: u64,
    otp_request_limit: u64,
    otp_request_window_seconds: u64,
}

impl SecurityService {
    #[allow(clippy::too_many_arguments)]
    // 构造函数注入所有安全策略阈值与外部依赖。
    // 这些阈值是运行时配置的一部分，便于不同环境做策略差异化。
    pub fn new(
        store: Arc<dyn SecurityStore>,
        risk_events: Arc<dyn RiskEventRepository>,
        clock: Arc<dyn Clock>,
        public_rate_limit_max: u64,
        public_rate_limit_window_seconds: u64,
        login_failure_limit: u64,
        login_failure_source_limit: u64,
        login_failure_window_seconds: u64,
        otp_request_limit: u64,
        otp_request_window_seconds: u64,
    ) -> Self {
        Self {
            store,
            risk_events,
            clock,
            public_rate_limit_max,
            public_rate_limit_window_seconds,
            login_failure_limit,
            login_failure_source_limit,
            login_failure_window_seconds,
            otp_request_limit,
            otp_request_window_seconds,
        }
    }

    // å…¬å¼€è®¤è¯æŽ¥å£åœ¨è¿›å…¥å…·ä½“ç™»å½•é€»è¾‘å‰ï¼Œå…ˆåšä¸€å±‚æŒ‰è·¯å¾„ + IP çš„ç²—ç²’åº¦é™æµã€‚
    // è¿™å±‚ç­–ç•¥ä¸åŒºåˆ†å¯†ç /OTP/Passkeyï¼Œåªè´Ÿè´£æŒ¡ä½æ˜Žæ˜¾çš„æ´ªæ³›æµé‡ã€‚
    /// 对公开认证入口执行路径级频控，优先挡住明显的洪泛流量。
    pub async fn enforce_public_auth_rate_limit(
        &self,
        path: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        let key = format!(
            "ratelimit:public-auth:{}:{}",
            path,
            ip.unwrap_or("anonymous")
        );
        let counter = self
            .store
            .increment_with_ttl(&key, self.public_rate_limit_window_seconds)
            .await?;

        // æœªè¶…è¿‡é˜ˆå€¼ç›´æŽ¥æ”¾è¡Œï¼Œä¸é¢å¤–äº§ç”Ÿå®¡è®¡å™ªéŸ³ã€‚
        if counter.count <= self.public_rate_limit_max {
            return Ok(());
        }

        // è¶…é™åŽä»¥ best effort æ–¹å¼è½ä¸€æ¡é£Žé™©äº‹ä»¶ã€‚
        // å³ä¾¿å®¡è®¡å†™å…¥å¤±è´¥ï¼Œä¹Ÿä¸åº”è¯¥å½±å“çœŸå®žçš„é™æµç»“è®ºã€‚
        self.record_risk_event_best_effort(RiskEventInput {
            event_type: RiskEventType::RateLimitExceeded,
            credential_type: None,
            identity_id: None,
            email: None,
            subject_role: None,
            ip,
            user_agent,
            detail: json!({
                "path": path,
                "count": counter.count,
                "retry_after_seconds": counter.retry_after_seconds,
            }),
        })
        .await;

        Err(AppError::RateLimited(format!(
            "Too many requests, retry in {} seconds",
            counter.retry_after_seconds.max(1)
        )))
    }

    /// 检查指定主体的 OTP 申请频率是否仍在允许范围内。
    pub async fn assert_otp_request_allowed(
        &self,
        email: &Email,
        role: SubjectRole,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        // OTP 申请按“角色 + 邮箱”限流，防止单账号被短信/邮件轰炸。
        let key = format!("auth:otp:request:{}:{}", role.as_str(), email.as_str());
        let counter = self
            .store
            .increment_with_ttl(&key, self.otp_request_window_seconds)
            .await?;

        if counter.count <= self.otp_request_limit {
            return Ok(());
        }

        self.record_risk_event_best_effort(RiskEventInput {
            event_type: RiskEventType::RateLimitExceeded,
            credential_type: Some(CredentialType::Otp),
            identity_id: None,
            email: Some(email.as_str()),
            subject_role: Some(role),
            ip: None,
            user_agent,
            detail: json!({
                "scope": "otp_request",
                "count": counter.count,
                "limit": self.otp_request_limit,
                "retry_after_seconds": counter.retry_after_seconds,
            }),
        })
        .await;

        Err(AppError::RateLimited(format!(
            "Too many OTP requests, retry in {} seconds",
            counter.retry_after_seconds.max(1)
        )))
    }

    // assert_login_allowed ç”¨äºŽæ›´ç»†ç²’åº¦çš„ç™»å½•æ‹¦æˆªã€‚
    // å®ƒåŒæ—¶æ£€æŸ¥è´¦å·ç»´åº¦å’Œæ¥æºç»´åº¦ï¼Œé¿å…å•è´¦å·æš´ç ´ï¼Œä¹Ÿé¿å…åŒä¸€æ¥æºæ’žå¤šä¸ªè´¦å·ã€‚
    /// 在真正执行登录前，按账号维度和来源维度判断是否允许继续尝试。
    pub async fn assert_login_allowed(
        &self,
        credential_type: CredentialType,
        email: &Email,
        role: SubjectRole,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        // è´¦å·ç»´åº¦çš„å¤±è´¥è®¡æ•°ä»¥ credential + role + email ä½œä¸ºä½œç”¨åŸŸã€‚
        let account_key = account_login_failure_key(credential_type, email, role);
        let account_failures = self.store.get_count(&account_key).await?;

        // æ¥æºç»´åº¦çš„å¤±è´¥è®¡æ•°ä»¥ credential + role + ip ä½œä¸ºä½œç”¨åŸŸã€‚
        let source_key = source_login_failure_key(credential_type, role, ip);
        let source_failures = match source_key.as_deref() {
            Some(key) => self.store.get_count(key).await?,
            None => 0,
        };

        let account_blocked = account_failures >= self.login_failure_limit;
        let source_blocked = source_failures >= self.login_failure_source_limit;
        if !account_blocked && !source_blocked {
            return Ok(());
        }

        // å‘½ä¸­æ‹¦æˆªåŽåˆ†åˆ«è¯»å– TTLï¼Œè¿”å›žæœ€å¤§çš„å‰©ä½™ç­‰å¾…æ—¶é—´ç»™è°ƒç”¨æ–¹ã€‚
        let account_retry_after_seconds = if account_blocked {
            self.store
                .get_ttl(&account_key)
                .await?
                .unwrap_or(self.login_failure_window_seconds)
        } else {
            0
        };
        let source_retry_after_seconds = if let Some(key) = source_key.as_deref() {
            if source_blocked {
                self.store
                    .get_ttl(key)
                    .await?
                    .unwrap_or(self.login_failure_window_seconds)
            } else {
                0
            }
        } else {
            0
        };
        let retry_after_seconds = account_retry_after_seconds
            .max(source_retry_after_seconds)
            .max(1);

        self.record_risk_event_best_effort(RiskEventInput {
            event_type: RiskEventType::LoginBlocked,
            credential_type: Some(credential_type),
            identity_id: None,
            email: Some(email.as_str()),
            subject_role: Some(role),
            ip,
            user_agent,
            detail: json!({
                "blocked_by_account": account_blocked,
                "blocked_by_source": source_blocked,
                "account_count": account_failures,
                "account_limit": self.login_failure_limit,
                "account_retry_after_seconds": account_retry_after_seconds,
                "source_count": source_failures,
                "source_limit": self.login_failure_source_limit,
                "source_retry_after_seconds": source_retry_after_seconds,
                "retry_after_seconds": retry_after_seconds,
            }),
        })
        .await;

        Err(AppError::RateLimited(format!(
            "Too many failed login attempts, retry in {} seconds",
            retry_after_seconds
        )))
    }

    // ç™»å½•å¤±è´¥åŽåŒæ—¶ç´¯åŠ è´¦å·ç»´åº¦ä¸Žæ¥æºç»´åº¦çš„è®¡æ•°å™¨ã€‚
    // è¿™ä¸¤ä¸ªè®¡æ•°å™¨éƒ½æ”¾åœ¨ Redis / DB æŠ½è±¡åŽé¢ï¼Œè€Œä¸æ˜¯è¿›ç¨‹å†…å†…å­˜ï¼Œä¾¿äºŽå¤šå®žä¾‹éƒ¨ç½²ã€‚
    /// 记录一次登录失败，并累加账号/来源两个维度的失败计数。
    pub async fn record_login_failure(
        &self,
        credential_type: CredentialType,
        email: &Email,
        role: SubjectRole,
        ip: Option<&str>,
        user_agent: Option<&str>,
        reason: &str,
    ) -> Result<(), AppError> {
        let account_key = account_login_failure_key(credential_type, email, role);
        let account_counter = self
            .store
            .increment_with_ttl(&account_key, self.login_failure_window_seconds)
            .await?;

        let source_counter = match source_login_failure_key(credential_type, role, ip) {
            Some(key) => Some(
                self.store
                    .increment_with_ttl(&key, self.login_failure_window_seconds)
                    .await?,
            ),
            None => None,
        };

        self.record_risk_event_best_effort(RiskEventInput {
            event_type: RiskEventType::LoginFailed,
            credential_type: Some(credential_type),
            identity_id: None,
            email: Some(email.as_str()),
            subject_role: Some(role),
            ip,
            user_agent,
            detail: json!({
                "reason": reason,
                "account_count": account_counter.count,
                "account_limit": self.login_failure_limit,
                "account_retry_after_seconds": account_counter.retry_after_seconds,
                "source_count": source_counter.as_ref().map(|counter| counter.count),
                "source_limit": self.login_failure_source_limit,
                "source_retry_after_seconds": source_counter.as_ref().map(|counter| counter.retry_after_seconds),
            }),
        })
        .await;
        Ok(())
    }

    // æˆåŠŸç™»å½•åŽåªæ¸…ç†è´¦å·ç»´åº¦å¤±è´¥è®¡æ•°ï¼Œä¸æ¸…ç†æ¥æºç»´åº¦è®¡æ•°ã€‚
    // è¿™æ ·å¯ä»¥é˜²æ­¢åŒä¸€ IP å¯¹å¤šä¸ªè´¦å·çš„æ¶æ„å°è¯•è¢«ä¸€æ¬¡æˆåŠŸç™»å½•â€œæ´—ç™½â€ã€‚
    /// 在登录成功后清除账号维度的失败计数。
    pub async fn clear_login_failures(
        &self,
        credential_type: CredentialType,
        email: &Email,
        role: SubjectRole,
    ) -> Result<(), AppError> {
        // 仅在认证成功后清理账号维度失败计数；
        // source 维度失败计数不清理，用于持续抑制恶意来源。
        self.store
            .delete(&account_login_failure_key(credential_type, email, role))
            .await
    }

    /// 检查某个部分认证会话是否还能继续尝试 MFA 校验。
    pub async fn assert_session_mfa_allowed(
        &self,
        session_id: Uuid,
        credential_type: CredentialType,
        role: SubjectRole,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        // 二次验证失败计数绑定到 session_id，避免不同会话间相互污染。
        let session_key = session_mfa_failure_key(session_id, credential_type, role);
        let session_failures = self.store.get_count(&session_key).await?;
        if session_failures < self.login_failure_limit {
            return Ok(());
        }

        let retry_after_seconds = self
            .store
            .get_ttl(&session_key)
            .await?
            .unwrap_or(self.login_failure_window_seconds)
            .max(1);

        self.record_risk_event_best_effort(RiskEventInput {
            event_type: RiskEventType::LoginBlocked,
            credential_type: Some(credential_type),
            identity_id: None,
            email: None,
            subject_role: Some(role),
            ip,
            user_agent,
            detail: json!({
                "scope": "session_mfa",
                "session_id": session_id,
                "session_count": session_failures,
                "session_limit": self.login_failure_limit,
                "retry_after_seconds": retry_after_seconds,
            }),
        })
        .await;

        Err(AppError::RateLimited(format!(
            "Too many failed MFA attempts, retry in {} seconds",
            retry_after_seconds
        )))
    }

    /// 记录某个会话的一次 MFA 失败，并累加该会话的失败计数。
    pub async fn record_session_mfa_failure(
        &self,
        session_id: Uuid,
        credential_type: CredentialType,
        role: SubjectRole,
        ip: Option<&str>,
        user_agent: Option<&str>,
        reason: &str,
    ) -> Result<(), AppError> {
        let session_key = session_mfa_failure_key(session_id, credential_type, role);
        let session_counter = self
            .store
            .increment_with_ttl(&session_key, self.login_failure_window_seconds)
            .await?;

        self.record_risk_event_best_effort(RiskEventInput {
            event_type: RiskEventType::LoginFailed,
            credential_type: Some(credential_type),
            identity_id: None,
            email: None,
            subject_role: Some(role),
            ip,
            user_agent,
            detail: json!({
                "scope": "session_mfa",
                "session_id": session_id,
                "reason": reason,
                "session_count": session_counter.count,
                "session_limit": self.login_failure_limit,
                "session_retry_after_seconds": session_counter.retry_after_seconds,
            }),
        })
        .await;
        Ok(())
    }

    /// 在 MFA 升级成功后清除当前会话的 MFA 失败计数。
    pub async fn clear_session_mfa_failures(
        &self,
        session_id: Uuid,
        credential_type: CredentialType,
        role: SubjectRole,
    ) -> Result<(), AppError> {
        // MFA 升级成功后清理当前会话的 MFA 失败计数，避免误封禁后续正常操作。
        self.store
            .delete(&session_mfa_failure_key(session_id, credential_type, role))
            .await
    }

    // refresh token åŒæ ·æ‹¥æœ‰ç‹¬ç«‹çš„å¤±è´¥è®¡æ•°ä¸Žæ‹¦æˆªç­–ç•¥ã€‚
    // è¿™é‡ŒæŒ‰ refresh token hash å’Œæ¥æº IP åŒç»´åº¦æ²»ç†ï¼Œé¿å… refresh è¢«æš´åŠ›è¯•æŽ¢ã€‚
    /// 在 refresh 之前检查 token 维度与来源维度是否已被风控拦截。
    pub async fn assert_refresh_allowed(
        &self,
        refresh_token_hash: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), AppError> {
        let token_key = refresh_token_failure_key(refresh_token_hash);
        let token_failures = self.store.get_count(&token_key).await?;

        let source_key = refresh_source_failure_key(ip);
        let source_failures = match source_key.as_deref() {
            Some(key) => self.store.get_count(key).await?,
            None => 0,
        };

        let token_blocked = token_failures >= self.login_failure_limit;
        let source_blocked = source_failures >= self.login_failure_source_limit;
        if !token_blocked && !source_blocked {
            return Ok(());
        }

        let token_retry_after_seconds = if token_blocked {
            self.store
                .get_ttl(&token_key)
                .await?
                .unwrap_or(self.login_failure_window_seconds)
        } else {
            0
        };
        let source_retry_after_seconds = if let Some(key) = source_key.as_deref() {
            if source_blocked {
                self.store
                    .get_ttl(key)
                    .await?
                    .unwrap_or(self.login_failure_window_seconds)
            } else {
                0
            }
        } else {
            0
        };
        let retry_after_seconds = token_retry_after_seconds
            .max(source_retry_after_seconds)
            .max(1);

        self.record_risk_event_best_effort(RiskEventInput {
            event_type: RiskEventType::RefreshBlocked,
            credential_type: Some(CredentialType::Refresh),
            identity_id: None,
            email: None,
            subject_role: None,
            ip,
            user_agent,
            detail: json!({
                "blocked_by_token": token_blocked,
                "blocked_by_source": source_blocked,
                "token_count": token_failures,
                "token_limit": self.login_failure_limit,
                "token_retry_after_seconds": token_retry_after_seconds,
                "source_count": source_failures,
                "source_limit": self.login_failure_source_limit,
                "source_retry_after_seconds": source_retry_after_seconds,
                "retry_after_seconds": retry_after_seconds,
            }),
        })
        .await;

        Err(AppError::RateLimited(format!(
            "Too many failed refresh attempts, retry in {} seconds",
            retry_after_seconds
        )))
    }

    // refresh å¤±è´¥æ—¶è¦è½åº“å®¡è®¡ï¼Œå¹¶ç´¯åŠ  token / source åŒç»´åº¦å¤±è´¥è®¡æ•°ã€‚
    /// 记录一次 refresh 失败，并累加 token/source 两个维度的失败计数。
    pub async fn record_refresh_failure(
        &self,
        refresh_token_hash: &str,
        ip: Option<&str>,
        user_agent: Option<&str>,
        reason: &str,
    ) -> Result<(), AppError> {
        let token_key = refresh_token_failure_key(refresh_token_hash);
        let token_counter = self
            .store
            .increment_with_ttl(&token_key, self.login_failure_window_seconds)
            .await?;

        let source_counter = match refresh_source_failure_key(ip) {
            Some(key) => Some(
                self.store
                    .increment_with_ttl(&key, self.login_failure_window_seconds)
                    .await?,
            ),
            None => None,
        };

        self.record_risk_event_best_effort(RiskEventInput {
            event_type: RiskEventType::RefreshFailed,
            credential_type: Some(CredentialType::Refresh),
            identity_id: None,
            email: None,
            subject_role: None,
            ip,
            user_agent,
            detail: json!({
                "reason": reason,
                "token_count": token_counter.count,
                "token_limit": self.login_failure_limit,
                "token_retry_after_seconds": token_counter.retry_after_seconds,
                "source_count": source_counter.as_ref().map(|counter| counter.count),
                "source_limit": self.login_failure_source_limit,
                "source_retry_after_seconds": source_counter.as_ref().map(|counter| counter.retry_after_seconds),
            }),
        })
        .await;
        Ok(())
    }

    // refresh æˆåŠŸåŽåªæ¸…æŽ‰ token è‡ªèº«å¤±è´¥è®¡æ•°ï¼Œæ¥æºç»´åº¦è®¡æ•°ä»ç„¶ä¿ç•™ã€‚
    /// 在 refresh 成功后清除 refresh token 维度的失败计数。
    pub async fn clear_refresh_failures(&self, refresh_token_hash: &str) -> Result<(), AppError> {
        // refresh 成功后只清理 token 维度失败计数，保留 source 维度防护强度。
        self.store
            .delete(&refresh_token_failure_key(refresh_token_hash))
            .await
    }

    // é£Žé™©äº‹ä»¶å±žäºŽè¾…åŠ©è§‚æµ‹èƒ½åŠ›ï¼Œä¸èƒ½åè¿‡æ¥æ‹–åž®ä¸»é“¾è·¯ã€‚
    // å› æ­¤è¿™é‡Œç»Ÿä¸€é‡‡ç”¨ best effort è¯­ä¹‰ã€‚
    /// 以 best-effort 语义记录风险事件，避免审计写入失败影响主链路。
    async fn record_risk_event_best_effort(&self, input: RiskEventInput<'_>) {
        if let Err(error) = self.record_risk_event(input).await {
            tracing::warn!(error = ?error, "risk event persistence failed");
        }
    }

    // çœŸæ­£çš„è½åº“åŠ¨ä½œåœ¨è¿™é‡Œå®Œæˆï¼ŒæŠŠè°ƒç”¨ä¸Šä¸‹æ–‡æ•´ç†æˆ RiskEvent èšåˆè®°å½•ã€‚
    /// 把安全上下文封装成 `RiskEvent` 并持久化到风险审计仓储。
    async fn record_risk_event(&self, input: RiskEventInput<'_>) -> Result<(), AppError> {
        // detail 统一序列化为 JSON 字符串，保证数据库字段稳定且易于后续检索回放。
        let detail = serde_json::to_string(&input.detail)
            .map_err(|_| AppError::Infrastructure("risk event serialization failed".to_string()))?;
        let event = RiskEvent {
            id: Uuid::new_v4(),
            event_type: input.event_type,
            credential_type: input.credential_type,
            identity_id: input.identity_id,
            email: input.email.map(ToOwned::to_owned),
            subject_role: input.subject_role,
            ip: input.ip.map(ToOwned::to_owned),
            user_agent: input.user_agent.map(ToOwned::to_owned),
            detail,
            created_at: self.clock.now(),
        };
        self.risk_events.create_risk_event(&event).await
    }
}

// RiskEventInput æ˜¯ application å±‚å†…éƒ¨ DTOã€‚
// å®ƒåªç”¨äºŽåœ¨ service å†…éƒ¨ä¼ é€’å®¡è®¡ä¸Šä¸‹æ–‡ï¼Œä¸è¿›å…¥ domain entity å¯¹å¤–æŽ¥å£ã€‚
struct RiskEventInput<'a> {
    event_type: RiskEventType,
    credential_type: Option<CredentialType>,
    identity_id: Option<Uuid>,
    email: Option<&'a str>,
    subject_role: Option<SubjectRole>,
    ip: Option<&'a str>,
    user_agent: Option<&'a str>,
    detail: serde_json::Value,
}

/// 构造账号维度的登录失败计数 key。
fn account_login_failure_key(
    credential_type: CredentialType,
    email: &Email,
    role: SubjectRole,
) -> String {
    // è´¦å·å¤±è´¥è®¡æ•°å™¨ key å¿…é¡»æ˜Žç¡®åˆ°å‡­è¯ç±»åž‹ä¸Žä¸»ä½“è§’è‰²ï¼Œé¿å…ä¸åŒç™»å½•é“¾è·¯äº’ç›¸æ±¡æŸ“ã€‚
    format!(
        "auth:failures:account:{}:{}:{}",
        credential_type.as_str(),
        role.as_str(),
        email.as_str()
    )
}

/// 构造来源维度的登录失败计数 key；无来源 IP 时返回空。
fn source_login_failure_key(
    credential_type: CredentialType,
    role: SubjectRole,
    ip: Option<&str>,
) -> Option<String> {
    // æ²¡æœ‰å¯è¯†åˆ«æ¥æºæ—¶ä¸æž„å»º source çº§åˆ« keyï¼Œåªä¿ç•™ account ç»´åº¦æ²»ç†ã€‚
    let source = ip.map(str::trim).filter(|value| !value.is_empty())?;
    Some(format!(
        "auth:failures:source:{}:{}:{}",
        credential_type.as_str(),
        role.as_str(),
        source
    ))
}

/// 构造会话维度的 MFA 失败计数 key。
fn session_mfa_failure_key(
    session_id: Uuid,
    credential_type: CredentialType,
    role: SubjectRole,
) -> String {
    format!(
        "auth:failures:session:{}:{}:{}",
        credential_type.as_str(),
        role.as_str(),
        session_id
    )
}

/// 构造 refresh token 维度的失败计数 key。
fn refresh_token_failure_key(refresh_token_hash: &str) -> String {
    format!("auth:failures:refresh:token:{refresh_token_hash}")
}

/// 构造 refresh 来源维度的失败计数 key；无来源 IP 时返回空。
fn refresh_source_failure_key(ip: Option<&str>) -> Option<String> {
    let source = ip.map(str::trim).filter(|value| !value.is_empty())?;
    Some(format!("auth:failures:refresh:source:{source}"))
}

