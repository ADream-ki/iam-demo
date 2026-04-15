use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tracing::info;

use crate::{
    domain::{
        entities::{Email, SubjectRole},
        ports::OtpDelivery,
    },
    error::AppError,
};

pub struct LoggingOtpDelivery;

#[async_trait]
impl OtpDelivery for LoggingOtpDelivery {
    /// 以日志形式模拟发送登录 OTP，供开发与测试环境联调。
    async fn send_login_code(
        &self,
        email: &Email,
        role: SubjectRole,
        code: &str,
        expires_at: DateTime<Utc>,
        auto_registered: bool,
    ) -> Result<(), AppError> {
        info!(
            email = %email.as_str(),
            role = %role.as_str(),
            code = %code,
            expires_at = %expires_at,
            auto_registered,
            "otp email delivery"
        );
        Ok(())
    }

    /// 以日志形式模拟发送 MFA OTP，供开发与测试环境联调。
    async fn send_mfa_code(
        &self,
        email: &Email,
        role: SubjectRole,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        info!(
            email = %email.as_str(),
            role = %role.as_str(),
            code = %code,
            expires_at = %expires_at,
            "mfa otp email delivery"
        );
        Ok(())
    }
}
