//! Mock implementations for security, OTP stores, and OTP delivery.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use iam_api::domain::entities::{Email, SubjectRole};
use iam_api::domain::ports::{
    ChallengeStore, CounterState, OtpDelivery, OtpDispatch, OtpStore, OtpStoreSaveResult,
    OtpVerifyResult, PasswordHasher, SecurityStore,
};
use iam_api::error::AppError;

#[derive(Debug, Default)]
pub struct MockSecurityStore {
    counters: Arc<Mutex<HashMap<String, (u64, Option<u64>)>>>,
}

impl MockSecurityStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_count_internal(&self, key: &str, count: u64, ttl: Option<u64>) {
        let mut counters = self.counters.lock().unwrap();
        counters.insert(key.to_string(), (count, ttl));
    }

    pub fn get_count_internal(&self, key: &str) -> Option<u64> {
        let counters = self.counters.lock().unwrap();
        counters.get(key).map(|(c, _)| *c)
    }
}

#[async_trait]
impl SecurityStore for MockSecurityStore {
    async fn increment_with_ttl(
        &self,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<CounterState, AppError> {
        let mut counters = self.counters.lock().unwrap();
        let (count, _) = counters
            .entry(key.to_string())
            .or_insert((0, Some(ttl_seconds)));
        *count += 1;
        Ok(CounterState {
            count: *count,
            retry_after_seconds: ttl_seconds,
        })
    }

    async fn get_count(&self, key: &str) -> Result<u64, AppError> {
        let counters = self.counters.lock().unwrap();
        Ok(counters.get(key).map(|(c, _)| *c).unwrap_or(0))
    }

    async fn get_ttl(&self, key: &str) -> Result<Option<u64>, AppError> {
        let counters = self.counters.lock().unwrap();
        Ok(counters.get(key).and_then(|(_, ttl)| *ttl))
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        let mut counters = self.counters.lock().unwrap();
        counters.remove(key);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct StoredOtp {
    code_hash: String,
    expires_at: DateTime<Utc>,
    resend_available_at: DateTime<Utc>,
    attempts_remaining: u8,
}

#[derive(Debug, Default)]
pub struct MockOtpStore {
    codes: Arc<Mutex<HashMap<String, StoredOtp>>>,
}

impl MockOtpStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed_code_hash(
        &self,
        email: &Email,
        role: SubjectRole,
        code_hash: &str,
        now: DateTime<Utc>,
        ttl_seconds: i64,
        attempts_remaining: u8,
    ) {
        let key = format!("otp:{}:{}", role.as_str(), email.as_str());
        let mut codes = self.codes.lock().unwrap();
        codes.insert(
            key,
            StoredOtp {
                code_hash: code_hash.to_string(),
                expires_at: now + chrono::Duration::seconds(ttl_seconds),
                resend_available_at: now,
                attempts_remaining,
            },
        );
    }

    pub fn seed_mfa_code_hash(
        &self,
        session_id: Uuid,
        role: SubjectRole,
        code_hash: &str,
        now: DateTime<Utc>,
        ttl_seconds: i64,
        attempts_remaining: u8,
    ) {
        let key = format!("otp:mfa:{}:{}", role.as_str(), session_id);
        let mut codes = self.codes.lock().unwrap();
        codes.insert(
            key,
            StoredOtp {
                code_hash: code_hash.to_string(),
                expires_at: now + chrono::Duration::seconds(ttl_seconds),
                resend_available_at: now,
                attempts_remaining,
            },
        );
    }
}

#[async_trait]
impl OtpStore for MockOtpStore {
    async fn store_login_code(
        &self,
        email: &Email,
        role: SubjectRole,
        dispatch: &OtpDispatch,
    ) -> Result<OtpStoreSaveResult, AppError> {
        let key = format!("otp:{}:{}", role.as_str(), email.as_str());
        let mut codes = self.codes.lock().unwrap();
        if let Some(existing) = codes.get(&key) {
            if existing.resend_available_at > dispatch.issued_at {
                return Ok(OtpStoreSaveResult {
                    stored: false,
                    retry_after_seconds: (existing.resend_available_at - dispatch.issued_at)
                        .num_seconds()
                        .max(1) as u64,
                });
            }
        }
        codes.insert(
            key,
            StoredOtp {
                code_hash: dispatch.code_hash.clone(),
                expires_at: dispatch.expires_at,
                resend_available_at: dispatch.resend_available_at,
                attempts_remaining: dispatch.max_attempts,
            },
        );
        Ok(OtpStoreSaveResult {
            stored: true,
            retry_after_seconds: 0,
        })
    }

    async fn verify_login_code(
        &self,
        email: &Email,
        role: SubjectRole,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<OtpVerifyResult, AppError> {
        let key = format!("otp:{}:{}", role.as_str(), email.as_str());
        let mut codes = self.codes.lock().unwrap();
        let Some(stored) = codes.get_mut(&key) else {
            return Ok(OtpVerifyResult::NotFound);
        };
        if stored.expires_at <= now {
            codes.remove(&key);
            return Ok(OtpVerifyResult::Expired);
        }
        if stored.code_hash == code_hash {
            codes.remove(&key);
            return Ok(OtpVerifyResult::Verified);
        }
        stored.attempts_remaining = stored.attempts_remaining.saturating_sub(1);
        let attempts_remaining = stored.attempts_remaining;
        if attempts_remaining == 0 {
            codes.remove(&key);
            return Ok(OtpVerifyResult::Exhausted);
        }
        Ok(OtpVerifyResult::Invalid { attempts_remaining })
    }

    async fn store_mfa_code(
        &self,
        session_id: Uuid,
        role: SubjectRole,
        dispatch: &OtpDispatch,
    ) -> Result<OtpStoreSaveResult, AppError> {
        let key = format!("otp:mfa:{}:{}", role.as_str(), session_id);
        let mut codes = self.codes.lock().unwrap();
        if let Some(existing) = codes.get(&key) {
            if existing.resend_available_at > dispatch.issued_at {
                return Ok(OtpStoreSaveResult {
                    stored: false,
                    retry_after_seconds: (existing.resend_available_at - dispatch.issued_at)
                        .num_seconds()
                        .max(1) as u64,
                });
            }
        }
        codes.insert(
            key,
            StoredOtp {
                code_hash: dispatch.code_hash.clone(),
                expires_at: dispatch.expires_at,
                resend_available_at: dispatch.resend_available_at,
                attempts_remaining: dispatch.max_attempts,
            },
        );
        Ok(OtpStoreSaveResult {
            stored: true,
            retry_after_seconds: 0,
        })
    }

    async fn verify_mfa_code(
        &self,
        session_id: Uuid,
        role: SubjectRole,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<OtpVerifyResult, AppError> {
        let key = format!("otp:mfa:{}:{}", role.as_str(), session_id);
        let mut codes = self.codes.lock().unwrap();
        let Some(stored) = codes.get_mut(&key) else {
            return Ok(OtpVerifyResult::NotFound);
        };
        if stored.expires_at <= now {
            codes.remove(&key);
            return Ok(OtpVerifyResult::Expired);
        }
        if stored.code_hash == code_hash {
            codes.remove(&key);
            return Ok(OtpVerifyResult::Verified);
        }
        stored.attempts_remaining = stored.attempts_remaining.saturating_sub(1);
        let attempts_remaining = stored.attempts_remaining;
        if attempts_remaining == 0 {
            codes.remove(&key);
            return Ok(OtpVerifyResult::Exhausted);
        }
        Ok(OtpVerifyResult::Invalid { attempts_remaining })
    }
}

#[derive(Debug, Default)]
pub struct MockOtpDelivery {
    sent_codes: Arc<Mutex<Vec<String>>>,
}

impl MockOtpDelivery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sent_codes(&self) -> Vec<String> {
        self.sent_codes.lock().unwrap().clone()
    }
}

#[async_trait]
impl OtpDelivery for MockOtpDelivery {
    async fn send_login_code(
        &self,
        _email: &Email,
        _role: SubjectRole,
        code: &str,
        _expires_at: DateTime<Utc>,
        _auto_registered: bool,
    ) -> Result<(), AppError> {
        self.sent_codes.lock().unwrap().push(code.to_string());
        Ok(())
    }

    async fn send_mfa_code(
        &self,
        _email: &Email,
        _role: SubjectRole,
        code: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<(), AppError> {
        self.sent_codes.lock().unwrap().push(code.to_string());
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MockChallengeStore {
    challenges: Arc<Mutex<HashMap<String, (serde_json::Value, Option<std::time::Instant>)>>>,
}

impl MockChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChallengeStore for MockChallengeStore {
    async fn save_passkey_challenge(
        &self,
        challenge_id: &str,
        payload: serde_json::Value,
        _ttl_seconds: u64,
    ) -> Result<(), AppError> {
        let mut challenges = self.challenges.lock().unwrap();
        challenges.insert(challenge_id.to_string(), (payload, None));
        Ok(())
    }

    async fn consume_passkey_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<serde_json::Value>, AppError> {
        let mut challenges = self.challenges.lock().unwrap();
        Ok(challenges.remove(challenge_id).map(|(payload, _)| payload))
    }
}

#[derive(Debug, Default)]
pub struct MockPasswordHasher;

impl MockPasswordHasher {
    pub fn new() -> Self {
        Self
    }
}

impl PasswordHasher for MockPasswordHasher {
    fn hash(&self, password: &str) -> Result<String, AppError> {
        Ok(format!(
            "$argon2id$v=19$m=19456,t=2,p=1${}$test",
            Self::encode_password(password)
        ))
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, AppError> {
        Ok(self.hash(password)? == hash)
    }

    fn hash_token(&self, token: &str) -> String {
        format!("token_hash_{}", token)
    }

    fn random_token(&self) -> Result<String, AppError> {
        Ok(format!("mock_token_{}", uuid::Uuid::new_v4()))
    }

    fn random_numeric_code(&self, length: usize) -> String {
        "0".repeat(length)
    }
}

impl MockPasswordHasher {
    fn encode_password(password: &str) -> String {
        password
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
