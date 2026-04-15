use axum::http::StatusCode;
use thiserror::Error;

use crate::domain::errors::DomainError;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("mfa required")]
    MfaRequired,
    #[error("resource not found")]
    NotFound,
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    RateLimited(String),
    #[error("infrastructure error")]
    Infrastructure(String),
}

impl AppError {
    /// 把领域/应用错误映射为 HTTP 状态码。
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::MfaRequired => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Infrastructure(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 生成返回给客户端的脱敏错误文案，避免泄露内部实现细节。
    pub(crate) fn public_message(&self) -> String {
        match self {
            Self::Validation(message) | Self::Conflict(message) | Self::RateLimited(message) => {
                message.clone()
            }
            Self::Unauthorized => "Authentication required".to_string(),
            Self::Forbidden => "Forbidden".to_string(),
            Self::MfaRequired => "Multi-factor authentication required".to_string(),
            Self::NotFound => "Not found".to_string(),
            Self::Infrastructure(_) => "Internal server error".to_string(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    /// 将数据库错误统一降级为基础设施错误，并把细节保留在日志中。
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database operation failed");
        Self::Infrastructure("database operation failed".to_string())
    }
}

impl From<redis::RedisError> for AppError {
    /// 将 Redis 错误统一降级为基础设施错误，并把细节保留在日志中。
    fn from(e: redis::RedisError) -> Self {
        tracing::error!(error = %e, "redis operation failed");
        Self::Infrastructure("redis operation failed".to_string())
    }
}

impl From<argon2::password_hash::Error> for AppError {
    /// 将密码哈希/校验错误统一映射为基础设施错误。
    fn from(e: argon2::password_hash::Error) -> Self {
        tracing::error!(error = %e, "password operation failed");
        Self::Infrastructure("password operation failed".to_string())
    }
}

impl From<totp_rs::SecretParseError> for AppError {
    /// 将 TOTP Secret 解析错误统一映射为基础设施错误。
    fn from(e: totp_rs::SecretParseError) -> Self {
        tracing::error!(error = %e, "totp secret parse failed");
        Self::Infrastructure("totp secret parse failed".to_string())
    }
}

impl From<totp_rs::TotpUrlError> for AppError {
    /// 将 TOTP 配置错误统一映射为基础设施错误。
    fn from(e: totp_rs::TotpUrlError) -> Self {
        tracing::error!(error = %e, "totp configuration failed");
        Self::Infrastructure("totp configuration failed".to_string())
    }
}

impl From<DomainError> for AppError {
    /// 将领域错误转换为更贴近接口语义的应用错误。
    fn from(e: DomainError) -> Self {
        match e {
            DomainError::InvalidEmailFormat => Self::Validation("Invalid email format".to_string()),
            DomainError::PasswordHashMustUseArgon2 => {
                Self::Validation("Password hash must use Argon2".to_string())
            }
            DomainError::SessionTokenEntropyInsufficient => {
                Self::Validation("Session token does not meet entropy requirements".to_string())
            }
            DomainError::UnsupportedSubjectRole => {
                Self::Validation("Unsupported subject role".to_string())
            }
            DomainError::UnsupportedCredentialType => {
                Self::Validation("Unsupported credential type".to_string())
            }
            DomainError::UnsupportedRiskEventType => {
                Self::Validation("Unsupported risk event type".to_string())
            }
            DomainError::EmptySubjectDisplayName => {
                Self::Validation("Subject display name cannot be empty".to_string())
            }
            DomainError::EmptyDeviceName => {
                Self::Validation("Device name cannot be empty".to_string())
            }
            DomainError::InvalidSessionTimeRange => {
                Self::Validation("Session time range is invalid".to_string())
            }
            DomainError::InvalidTrustedDeviceTimeRange => {
                Self::Validation("Trusted device time range is invalid".to_string())
            }
        }
    }
}
