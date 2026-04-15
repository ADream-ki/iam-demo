use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::AsyncCommands;

use crate::{
    domain::{
        entities::{Email, SubjectRole},
        ports::{
            ChallengeStore, CounterState, OtpDispatch, OtpStore, OtpStoreSaveResult, OtpVerifyResult,
            SecurityStore,
        },
    },
    error::AppError,
};

pub struct RedisOtpStore {
    client: redis::Client,
}

impl RedisOtpStore {
    /// 构造 OTP 存储实现，底层使用 Redis 维护短期验证码状态。
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }
}

pub struct RedisChallengeStore {
    client: redis::Client,
}

impl RedisChallengeStore {
    /// 构造 Passkey challenge 存储实现。
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }
}

pub struct RedisSecurityStore {
    client: redis::Client,
}

impl RedisSecurityStore {
    /// 构造安全计数器存储实现。
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OtpStore for RedisOtpStore {
    /// 保存登录 OTP，并用 Lua 脚本保证冷却时间与覆盖写入判断的原子性。
    async fn store_login_code(
        &self,
        email: &Email,
        role: SubjectRole,
        dispatch: &OtpDispatch,
    ) -> Result<OtpStoreSaveResult, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = login_otp_key(email, role);
        let now = dispatch.issued_at.timestamp();
        let resend_available_at = dispatch.resend_available_at.timestamp();
        let expires_at = dispatch.expires_at.timestamp();
        let ttl_seconds = (dispatch.expires_at - dispatch.issued_at).num_seconds().max(1) as u64;
        let script = redis::Script::new(
            r#"
            local now = tonumber(ARGV[1])
            local resend_at = tonumber(redis.call('HGET', KEYS[1], 'resend_available_at') or '0')
            if redis.call('EXISTS', KEYS[1]) == 1 and resend_at > now then
                return {0, resend_at - now}
            end

            redis.call('HSET', KEYS[1],
                'code_hash', ARGV[2],
                'expires_at', ARGV[3],
                'attempts_remaining', ARGV[4],
                'resend_available_at', ARGV[5]
            )
            redis.call('EXPIRE', KEYS[1], ARGV[6])
            return {1, 0}
            "#,
        );
        let (stored, retry_after_seconds): (i64, i64) = script
            .key(&key)
            .arg(now)
            .arg(&dispatch.code_hash)
            .arg(expires_at)
            .arg(dispatch.max_attempts)
            .arg(resend_available_at)
            .arg(ttl_seconds)
            .invoke_async(&mut conn)
            .await?;

        Ok(OtpStoreSaveResult {
            stored: stored == 1,
            retry_after_seconds: retry_after_seconds.max(0) as u64,
        })
    }

    /// 校验登录 OTP，并根据脚本结果返回验证状态。
    async fn verify_login_code(
        &self,
        email: &Email,
        role: SubjectRole,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<OtpVerifyResult, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = login_otp_key(email, role);
        verify_otp_code(&mut conn, &key, code_hash, now).await
    }

    /// 保存 MFA OTP，并用 Lua 脚本保证冷却时间与覆盖写入判断的原子性。
    async fn store_mfa_code(
        &self,
        session_id: uuid::Uuid,
        role: SubjectRole,
        dispatch: &OtpDispatch,
    ) -> Result<OtpStoreSaveResult, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = mfa_otp_key(session_id, role);
        let now = dispatch.issued_at.timestamp();
        let resend_available_at = dispatch.resend_available_at.timestamp();
        let expires_at = dispatch.expires_at.timestamp();
        let ttl_seconds = (dispatch.expires_at - dispatch.issued_at).num_seconds().max(1) as u64;
        let script = redis::Script::new(
            r#"
            local now = tonumber(ARGV[1])
            local resend_at = tonumber(redis.call('HGET', KEYS[1], 'resend_available_at') or '0')
            if redis.call('EXISTS', KEYS[1]) == 1 and resend_at > now then
                return {0, resend_at - now}
            end

            redis.call('HSET', KEYS[1],
                'code_hash', ARGV[2],
                'expires_at', ARGV[3],
                'attempts_remaining', ARGV[4],
                'resend_available_at', ARGV[5]
            )
            redis.call('EXPIRE', KEYS[1], ARGV[6])
            return {1, 0}
            "#,
        );
        let (stored, retry_after_seconds): (i64, i64) = script
            .key(&key)
            .arg(now)
            .arg(&dispatch.code_hash)
            .arg(expires_at)
            .arg(dispatch.max_attempts)
            .arg(resend_available_at)
            .arg(ttl_seconds)
            .invoke_async(&mut conn)
            .await?;

        Ok(OtpStoreSaveResult {
            stored: stored == 1,
            retry_after_seconds: retry_after_seconds.max(0) as u64,
        })
    }

    /// 校验 MFA OTP，并根据脚本结果返回验证状态。
    async fn verify_mfa_code(
        &self,
        session_id: uuid::Uuid,
        role: SubjectRole,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<OtpVerifyResult, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = mfa_otp_key(session_id, role);
        verify_otp_code(&mut conn, &key, code_hash, now).await
    }
}

/// 复用一套 Lua 校验逻辑完成 OTP 的原子验证、失效删除与失败计数扣减。
async fn verify_otp_code(
    conn: &mut redis::aio::MultiplexedConnection,
    key: &str,
    code_hash: &str,
    now: DateTime<Utc>,
) -> Result<OtpVerifyResult, AppError> {
        let script = redis::Script::new(
            r#"
            if redis.call('EXISTS', KEYS[1]) == 0 then
                return {'not_found', 0}
            end

            local now = tonumber(ARGV[1])
            local expires_at = tonumber(redis.call('HGET', KEYS[1], 'expires_at') or '0')
            if expires_at > 0 and expires_at <= now then
                redis.call('DEL', KEYS[1])
                return {'expired', 0}
            end

            local stored_hash = redis.call('HGET', KEYS[1], 'code_hash')
            if stored_hash == ARGV[2] then
                redis.call('DEL', KEYS[1])
                return {'verified', 0}
            end

            local attempts_remaining = tonumber(redis.call('HINCRBY', KEYS[1], 'attempts_remaining', -1))
            if attempts_remaining <= 0 then
                redis.call('DEL', KEYS[1])
                return {'exhausted', 0}
            end

            return {'invalid', attempts_remaining}
            "#,
        );
        let (status, attempts_remaining): (String, i64) = script
            .key(key)
            .arg(now.timestamp())
            .arg(code_hash)
            .invoke_async(conn)
            .await?;

        let result = match status.as_str() {
            "verified" => OtpVerifyResult::Verified,
            "invalid" => OtpVerifyResult::Invalid {
                attempts_remaining: attempts_remaining.max(0) as u8,
            },
            "exhausted" => OtpVerifyResult::Exhausted,
            "expired" => OtpVerifyResult::Expired,
            _ => OtpVerifyResult::NotFound,
        };
        Ok(result)
}

/// 构造登录 OTP 的 Redis key。
fn login_otp_key(email: &Email, role: SubjectRole) -> String {
    format!("otp:login:{}:{}", role.as_str(), email.as_str())
}

/// 构造 MFA OTP 的 Redis key。
fn mfa_otp_key(session_id: uuid::Uuid, role: SubjectRole) -> String {
    format!("otp:mfa:{}:{}", role.as_str(), session_id)
}

#[async_trait]
impl ChallengeStore for RedisChallengeStore {
    /// 保存 Passkey challenge，并设置一次性消费所需的 TTL。
    async fn save_passkey_challenge(
        &self,
        challenge_id: &str,
        payload: serde_json::Value,
        ttl_seconds: u64,
    ) -> Result<(), AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("webauthn:challenge:{challenge_id}");
        let raw = serde_json::to_string(&payload)
            .map_err(|_| AppError::Infrastructure("challenge serialization failed".to_string()))?;
        conn.set_ex::<_, _, ()>(key, raw, ttl_seconds).await?;
        Ok(())
    }

    /// 以 GETDEL 语义消费 Passkey challenge，防止重放。
    async fn consume_passkey_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<serde_json::Value>, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("webauthn:challenge:{challenge_id}");
        let stored: Option<String> = redis::cmd("GETDEL").arg(&key).query_async(&mut conn).await?;
        stored
            .map(|raw| {
                serde_json::from_str(&raw)
                    .map_err(|_| AppError::Infrastructure("challenge parse failed".to_string()))
            })
            .transpose()
    }
}

#[async_trait]
impl SecurityStore for RedisSecurityStore {
    /// 对计数器做自增并补齐 TTL，用于限流与失败计数场景。
    async fn increment_with_ttl(&self, key: &str, ttl_seconds: u64) -> Result<CounterState, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let script = redis::Script::new(
            r#"
            local current = redis.call('INCR', KEYS[1])
            local ttl = redis.call('TTL', KEYS[1])
            if ttl < 0 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
                ttl = tonumber(ARGV[1])
            end
            return { current, ttl }
            "#,
        );
        let (count, retry_after_seconds): (u64, i64) = script
            .key(key)
            .arg(ttl_seconds)
            .invoke_async(&mut conn)
            .await?;

        Ok(CounterState {
            count,
            retry_after_seconds: retry_after_seconds.max(1) as u64,
        })
    }

    /// 读取当前计数器值，不存在时返回 0。
    async fn get_count(&self, key: &str) -> Result<u64, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let value: Option<u64> = conn.get(key).await?;
        Ok(value.unwrap_or(0))
    }

    /// 读取计数器剩余 TTL；不存在或无 TTL 时返回空。
    async fn get_ttl(&self, key: &str) -> Result<Option<u64>, AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let ttl: i64 = conn.ttl(key).await?;
        match ttl {
            value if value > 0 => Ok(Some(value as u64)),
            _ => Ok(None),
        }
    }

    /// 删除指定安全计数器 key。
    async fn delete(&self, key: &str) -> Result<(), AppError> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        conn.del::<_, ()>(key).await?;
        Ok(())
    }
}
