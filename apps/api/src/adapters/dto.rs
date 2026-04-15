use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    application::services::{
        AuthResult, OtpRequestResult, PasskeyChallengeResult, PasskeyRegistrationResult,
        MfaVerifyResult, RefreshResult, SessionItem, SessionOverview,
    },
    domain::entities::{MfaLevel, SubjectRole},
};

#[derive(Debug, Deserialize)]
pub struct PasswordLoginRequest {
    pub email: String,
    pub password: String,
    pub role: SubjectRole,
    pub device_name: String,
    pub remember_device: bool,
}

#[derive(Debug, Deserialize)]
pub struct OtpRequestRequest {
    pub email: String,
    pub role: SubjectRole,
}

#[derive(Debug, Deserialize)]
pub struct OtpVerifyRequest {
    pub email: String,
    pub code: String,
    pub role: SubjectRole,
    pub device_name: String,
    pub remember_device: bool,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginChallengeRequest {
    pub email: String,
    pub role: SubjectRole,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyVerifyRequest {
    pub challenge_id: String,
    pub email: String,
    pub role: SubjectRole,
    pub response: serde_json::Value,
    pub device_name: String,
    pub remember_device: bool,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterVerifyRequest {
    pub challenge_id: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct OtpMfaVerifyRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SessionOverviewResponse {
    pub session_id: Uuid,
    pub subject_role: SubjectRole,
    pub display_name: String,
    pub email: String,
    pub mfa_level: MfaLevel,
    pub device_name: String,
    pub expires_at: DateTime<Utc>,
    pub current: bool,
}

impl From<SessionOverview> for SessionOverviewResponse {
    /// 把应用层会话概览转换为 API 返回结构。
    fn from(value: SessionOverview) -> Self {
        Self {
            session_id: value.session_id,
            subject_role: value.subject_role,
            display_name: value.display_name,
            email: value.email,
            mfa_level: value.mfa_level,
            device_name: value.device_name,
            expires_at: value.expires_at,
            current: value.current,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionItemResponse {
    pub id: Uuid,
    pub device_name: String,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub mfa_level: MfaLevel,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub current: bool,
}

impl From<SessionItem> for SessionItemResponse {
    /// 把应用层会话列表项转换为 API 返回结构。
    fn from(value: SessionItem) -> Self {
        Self {
            id: value.id,
            device_name: value.device_name,
            user_agent: value.user_agent,
            ip: value.ip,
            mfa_level: value.mfa_level,
            expires_at: value.expires_at,
            last_seen_at: value.last_seen_at,
            current: value.current,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OtpRequestResponse {
    pub sent: bool,
    pub demo_code: Option<String>,
    pub auto_registered: bool,
    pub expires_in_seconds: u64,
    pub retry_after_seconds: u64,
}

impl From<OtpRequestResult> for OtpRequestResponse {
    /// 把 OTP 请求结果转换为统一响应体。
    fn from(value: OtpRequestResult) -> Self {
        Self {
            sent: value.sent,
            demo_code: value.demo_code,
            auto_registered: value.auto_registered,
            expires_in_seconds: value.expires_in_seconds,
            retry_after_seconds: value.retry_after_seconds,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PasskeyChallengeResponse {
    pub challenge_id: String,
    pub public_key: serde_json::Value,
}

impl From<PasskeyChallengeResult> for PasskeyChallengeResponse {
    /// 把 Passkey challenge 结果转换为浏览器可消费的响应结构。
    fn from(value: PasskeyChallengeResult) -> Self {
        Self {
            challenge_id: value.challenge_id,
            public_key: value.public_key,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PasskeyRegistrationResponse {
    pub external_id: String,
    pub label: String,
}

impl From<PasskeyRegistrationResult> for PasskeyRegistrationResponse {
    /// 把 Passkey 注册结果转换为 API 返回结构。
    fn from(value: PasskeyRegistrationResult) -> Self {
        Self {
            external_id: value.external_id,
            label: value.label,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MfaVerifyResponse {
    pub session: SessionOverviewResponse,
    pub trusted_device_token: Option<String>,
}

impl From<MfaVerifyResult> for MfaVerifyResponse {
    /// 把 MFA 校验结果转换为 API 返回结构。
    fn from(value: MfaVerifyResult) -> Self {
        Self {
            session: value.session.into(),
            trusted_device_token: value.trusted_device_token,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

impl From<RefreshResult> for RefreshResponse {
    /// 把 refresh 结果转换为 API 返回结构。
    fn from(value: RefreshResult) -> Self {
        Self {
            access_token: value.access_token,
            refresh_token: value.refresh_token,
            access_expires_at: value.access_expires_at,
            refresh_expires_at: value.refresh_expires_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub session: SessionOverviewResponse,
    pub dashboard_path: String,
    pub requires_mfa: bool,
    pub trusted_device_token: Option<String>,
    pub clear_trusted_device: bool,
}

impl From<AuthResult> for AuthResponse {
    /// 把统一认证结果转换为前端登录流所需的完整响应体。
    fn from(value: AuthResult) -> Self {
        let dashboard_path = match value.session.subject_role {
            SubjectRole::Member => "/dashboard/member",
            SubjectRole::CommunityStaff => "/dashboard/community",
            SubjectRole::PlatformStaff => "/dashboard/platform",
        };
        Self {
            access_token: value.access_token,
            refresh_token: value.refresh_token,
            access_expires_at: value.access_expires_at,
            refresh_expires_at: value.refresh_expires_at,
            session: value.session.into(),
            dashboard_path: dashboard_path.to_string(),
            requires_mfa: value.requires_mfa,
            trusted_device_token: value.trusted_device_token,
            clear_trusted_device: value.clear_trusted_device,
        }
    }
}
