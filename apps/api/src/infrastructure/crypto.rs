use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::{Rng, distr::Alphanumeric};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{
    domain::ports::{Clock, PasswordHasher, TotpService},
    error::AppError,
};

pub struct ArgonPasswordHasher;

impl PasswordHasher for ArgonPasswordHasher {
    /// 使用 Argon2 生成密码哈希。
    fn hash(&self, password: &str) -> Result<String, AppError> {
        let salt = SaltString::generate(&mut OsRng);
        Ok(Argon2::default()
            .hash_password(password.as_bytes(), &salt)?
            .to_string())
    }

    /// 校验输入密码是否与给定 Argon2 哈希匹配。
    fn verify(&self, password: &str, hash: &str) -> Result<bool, AppError> {
        let parsed = PasswordHash::new(hash)?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    /// 对 token 做 SHA-256 摘要，用于数据库与缓存中的不可逆存储。
    fn hash_token(&self, token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        format!("{:x}", digest)
    }

    /// 生成高熵随机 token，用于 access / refresh / trusted device 场景。
    fn random_token(&self) -> Result<String, AppError> {
        Ok(rand::rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect())
    }

    /// 生成指定长度的纯数字验证码。
    fn random_numeric_code(&self, length: usize) -> String {
        let mut rng = rand::rng();
        (0..length)
            .map(|_| char::from(b'0' + rng.random_range(0..10) as u8))
            .collect()
    }
}

pub struct TotpRsService;

impl TotpService for TotpRsService {
    /// 校验 TOTP 验证码，并容忍一个时间步长的时钟偏差。
    fn verify_code(&self, secret: &str, code: &str) -> Result<bool, AppError> {
        let bytes = Secret::Encoded(secret.to_string()).to_bytes()?;
        let now = Utc::now().timestamp();

        // Accept the current window plus one adjacent step to tolerate small clock drift.
        Ok((-1_i64..=1).any(|offset| generate_totp_code(&bytes, now + (offset * 30)) == code))
    }

    /// 生成 TOTP provisioning URI，供认证器扫码导入。
    fn provisioning_uri(&self, email: &str, issuer: &str, secret: &str) -> Result<String, AppError> {
        let bytes = Secret::Encoded(secret.to_string()).to_bytes()?;
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            bytes,
            Some(issuer.to_string()),
            email.to_string(),
        )?;
        Ok(totp.get_url())
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    /// 返回当前 UTC 时间。
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// 构造共享的密码哈希服务实例。
pub fn shared_hasher() -> Arc<dyn PasswordHasher> {
    Arc::new(ArgonPasswordHasher)
}

/// 构造共享的 TOTP 服务实例。
pub fn shared_totp() -> Arc<dyn TotpService> {
    Arc::new(TotpRsService)
}

/// 构造共享的系统时钟实例。
pub fn shared_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// 按 RFC 6238 的动态截断规则生成一个 6 位 TOTP 验证码。
fn generate_totp_code(secret: &[u8], timestamp: i64) -> String {
    let step = (timestamp.div_euclid(30)) as u64;
    let counter = step.to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac accepts arbitrary key length");
    mac.update(&counter);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let truncated = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    format!("{:06}", truncated % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::{TotpRsService, generate_totp_code};
    use crate::domain::ports::TotpService;
    use totp_rs::Secret;

    #[test]
    /// 验证固定 demo secret 生成的验证码可以被当前 TOTP 服务接受。
    fn verifies_seeded_demo_secret() {
        let secret = "JBSWY3DPEHPK3PXP";
        let bytes = Secret::Encoded(secret.to_string())
            .to_bytes()
            .expect("demo secret must parse");
        let code = generate_totp_code(&bytes, chrono::Utc::now().timestamp());

        assert!(TotpRsService.verify_code(secret, &code).expect("verification should succeed"));
    }
}
