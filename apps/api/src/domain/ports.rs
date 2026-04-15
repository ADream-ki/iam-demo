use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    domain::entities::{
        Email, Identity, PasskeyCredential, PasswordCredential, RiskEvent, Session, Subject,
        SubjectRole, TrustedDevice,
    },
    error::AppError,
};

#[derive(Debug, Clone, Copy)]
pub struct CounterState {
    pub count: u64,
    pub retry_after_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct OtpDispatch {
    pub code_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub resend_available_at: DateTime<Utc>,
    pub max_attempts: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct OtpStoreSaveResult {
    pub stored: bool,
    pub retry_after_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpVerifyResult {
    Verified,
    /// Code was wrong; `attempts_remaining` is how many tries are left (> 0).
    Invalid { attempts_remaining: u8 },
    /// All attempts used up; the slot has been deleted from the store.
    Exhausted,
    NotFound,
    Expired,
}

#[async_trait]
pub trait IdentityRepository: Send + Sync {
    async fn find_identity_by_email(&self, email: &Email) -> Result<Option<Identity>, AppError>;
    async fn find_identity_by_id(&self, identity_id: Uuid) -> Result<Option<Identity>, AppError>;
    async fn mark_identity_email_verified(
        &self,
        identity_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
    async fn find_subject_by_id(&self, subject_id: Uuid) -> Result<Option<Subject>, AppError>;
    async fn find_subject_by_identity_and_role(
        &self,
        identity_id: Uuid,
        role: SubjectRole,
    ) -> Result<Option<Subject>, AppError>;
    async fn find_subject_by_email_and_role(
        &self,
        email: &Email,
        role: SubjectRole,
    ) -> Result<Option<(Identity, Subject)>, AppError>;
    async fn find_password_credential(
        &self,
        identity_id: Uuid,
    ) -> Result<Option<PasswordCredential>, AppError>;
    async fn list_passkeys_for_subject(
        &self,
        subject_id: Uuid,
    ) -> Result<Vec<PasskeyCredential>, AppError>;
    async fn insert_passkey(
        &self,
        subject_id: Uuid,
        external_id: &str,
        label: &str,
        verifier_data: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyCredential, AppError>;
    async fn update_passkey_verifier_data(
        &self,
        passkey_id: Uuid,
        current_verifier_data: &str,
        next_verifier_data: &str,
    ) -> Result<bool, AppError>;
    async fn ensure_subject_with_default_password(
        &self,
        email: &Email,
        role: SubjectRole,
        default_password: &str,
        now: DateTime<Utc>,
    ) -> Result<(Identity, Subject), AppError>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create_session(&self, session: &Session) -> Result<(), AppError>;
    async fn find_session_by_access_token_hash(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AppError>;
    async fn find_session_by_refresh_token_hash(
        &self,
        refresh_token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AppError>;
    async fn list_sessions_for_subject(
        &self,
        subject_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Vec<Session>, AppError>;
    async fn revoke_session(
        &self,
        session_id: Uuid,
        subject_id: Uuid,
    ) -> Result<bool, AppError>;
    async fn revoke_other_sessions(
        &self,
        current_session_id: Uuid,
        subject_id: Uuid,
    ) -> Result<u64, AppError>;
    async fn upgrade_mfa(&self, session_id: Uuid, now: DateTime<Utc>) -> Result<bool, AppError>;
    async fn touch_session(
        &self,
        session_id: Uuid,
        access_token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
    async fn rotate_session_tokens(
        &self,
        session_id: Uuid,
        current_refresh_token_hash: &str,
        next_access_token_hash: &str,
        next_refresh_token_hash: &str,
        access_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
}

#[async_trait]
pub trait TrustedDeviceRepository: Send + Sync {
    async fn find_trusted_device_by_token_hash(
        &self,
        subject_id: Uuid,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<TrustedDevice>, AppError>;
    async fn create_trusted_device(&self, device: &TrustedDevice) -> Result<(), AppError>;
    async fn touch_trusted_device(
        &self,
        trusted_device_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
    async fn revoke_trusted_device_by_token_hash(
        &self,
        subject_id: Uuid,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError>;
    async fn revoke_trusted_devices_by_device(
        &self,
        subject_id: Uuid,
        device_name: &str,
        user_agent: Option<&str>,
        ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<u64, AppError>;
}

#[async_trait]
pub trait OtpStore: Send + Sync {
    async fn store_login_code(
        &self,
        email: &Email,
        role: SubjectRole,
        dispatch: &OtpDispatch,
    ) -> Result<OtpStoreSaveResult, AppError>;
    async fn verify_login_code(
        &self,
        email: &Email,
        role: SubjectRole,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<OtpVerifyResult, AppError>;
    async fn store_mfa_code(
        &self,
        session_id: Uuid,
        role: SubjectRole,
        dispatch: &OtpDispatch,
    ) -> Result<OtpStoreSaveResult, AppError>;
    async fn verify_mfa_code(
        &self,
        session_id: Uuid,
        role: SubjectRole,
        code_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<OtpVerifyResult, AppError>;
}

#[async_trait]
pub trait OtpDelivery: Send + Sync {
    async fn send_login_code(
        &self,
        email: &Email,
        role: SubjectRole,
        code: &str,
        expires_at: DateTime<Utc>,
        auto_registered: bool,
    ) -> Result<(), AppError>;
    async fn send_mfa_code(
        &self,
        email: &Email,
        role: SubjectRole,
        code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AppError>;
}

#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn save_passkey_challenge(
        &self,
        challenge_id: &str,
        payload: serde_json::Value,
        ttl_seconds: u64,
    ) -> Result<(), AppError>;
    async fn consume_passkey_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<serde_json::Value>, AppError>;
}

#[async_trait]
pub trait SecurityStore: Send + Sync {
    async fn increment_with_ttl(
        &self,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<CounterState, AppError>;
    async fn get_count(&self, key: &str) -> Result<u64, AppError>;
    async fn get_ttl(&self, key: &str) -> Result<Option<u64>, AppError>;
    async fn delete(&self, key: &str) -> Result<(), AppError>;
}

#[async_trait]
pub trait RiskEventRepository: Send + Sync {
    async fn create_risk_event(&self, event: &RiskEvent) -> Result<(), AppError>;
}

pub trait PasswordHasher: Send + Sync {
    fn hash(&self, password: &str) -> Result<String, AppError>;
    fn verify(&self, password: &str, hash: &str) -> Result<bool, AppError>;
    fn hash_token(&self, token: &str) -> String;
    fn random_token(&self) -> Result<String, AppError>;
    fn random_numeric_code(&self, length: usize) -> String;
}

pub trait TotpService: Send + Sync {
    fn verify_code(&self, secret: &str, code: &str) -> Result<bool, AppError>;
    fn provisioning_uri(&self, email: &str, issuer: &str, secret: &str)
        -> Result<String, AppError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub trait PasskeyVerifier: Send + Sync {
    fn issue_registration_challenge(
        &self,
        subject_id: Uuid,
        email: &str,
        display_name: &str,
        registered: &[PasskeyCredential],
    ) -> Result<(String, serde_json::Value), AppError>;
    fn issue_authentication_challenge(
        &self,
        registered: &[PasskeyCredential],
    ) -> Result<(String, serde_json::Value), AppError>;
    fn verify_registration(
        &self,
        challenge_state: &str,
        response: serde_json::Value,
    ) -> Result<(String, String, String), AppError>;
    fn verify_authentication(
        &self,
        challenge_state: &str,
        response: serde_json::Value,
        registered: &[PasskeyCredential],
    ) -> Result<Option<(Uuid, String)>, AppError>;
}
