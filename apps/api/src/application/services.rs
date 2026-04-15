use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::SecurityService;
use crate::{
    domain::{
        entities::{
            CredentialType, CurrentSession, Email, MfaLevel, Session, SessionToken, Subject, SubjectRole,
            TrustedDevice,
        },
        ports::{
            ChallengeStore, Clock, IdentityRepository, OtpDelivery, OtpDispatch, OtpStore,
            OtpVerifyResult as StoreOtpVerifyResult, PasswordHasher, PasskeyVerifier,
            SessionRepository, TrustedDeviceRepository,
        },
    },
    error::AppError,
};

// AUTO_PROVISION_PASSWORD is only used during OTP-triggered account provisioning.
// It is never accepted as a valid login credential — password login requires
// email_verified to be true AND the password to differ from this sentinel value.
// In production the sentinel is still stored as an Argon2 hash, but the
// login_with_password path explicitly rejects it, forcing users through OTP first.
const AUTO_PROVISION_PASSWORD: &str = "__otp_provisioned_no_password_login__";

#[derive(Debug, Clone)]
pub struct PasswordLoginInput {
    pub email: String,
    pub password: String,
    pub role: SubjectRole,
    pub device_name: String,
    pub remember_device: bool,
    pub trusted_device_token: Option<String>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OtpRequestInput {
    pub email: String,
    pub role: SubjectRole,
}

#[derive(Debug, Clone)]
pub struct OtpVerifyInput {
    pub email: String,
    pub code: String,
    pub role: SubjectRole,
    pub device_name: String,
    pub remember_device: bool,
    pub trusted_device_token: Option<String>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OtpMfaVerifyInput {
    pub code: String,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PasskeyLoginChallengeInput {
    pub email: String,
    pub role: SubjectRole,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PasskeyLoginVerifyInput {
    pub challenge_id: String,
    pub email: String,
    pub role: SubjectRole,
    pub response: serde_json::Value,
    pub device_name: String,
    pub remember_device: bool,
    pub trusted_device_token: Option<String>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PasskeyRegisterVerifyInput {
    pub challenge_id: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct PasskeyChallengeResult {
    pub challenge_id: String,
    pub public_key: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct PasskeyRegistrationResult {
    pub external_id: String,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct OtpRequestResult {
    pub sent: bool,
    pub demo_code: Option<String>,
    pub auto_registered: bool,
    pub expires_in_seconds: u64,
    pub retry_after_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct MfaVerifyResult {
    pub session: SessionOverview,
    pub trusted_device_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionOverview {
    pub session_id: Uuid,
    pub subject_role: SubjectRole,
    pub display_name: String,
    pub email: String,
    pub mfa_level: MfaLevel,
    pub device_name: String,
    pub expires_at: DateTime<Utc>,
    pub current: bool,
}

#[derive(Debug, Clone)]
pub struct SessionItem {
    pub id: Uuid,
    pub device_name: String,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub mfa_level: MfaLevel,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub current: bool,
}

#[derive(Debug, Clone)]
pub struct RefreshResult {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub session: SessionOverview,
    pub requires_mfa: bool,
    pub trusted_device_token: Option<String>,
    pub clear_trusted_device: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum StoredPasskeyChallenge {
    Registration {
        subject_id: Uuid,
        state: String,
    },
    Authentication {
        subject_id: Uuid,
        email: String,
        subject_role: SubjectRole,
        state: String,
    },
}

#[derive(Debug, Clone, Default)]
struct TrustedDeviceDecision {
    authenticated: bool,
    clear_cookie: bool,
}

pub struct AuthService {
    identities: Arc<dyn IdentityRepository>,
    sessions: Arc<dyn SessionRepository>,
    trusted_devices: Arc<dyn TrustedDeviceRepository>,
    otp_store: Arc<dyn OtpStore>,
    otp_delivery: Arc<dyn OtpDelivery>,
    challenge_store: Arc<dyn ChallengeStore>,
    password_hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
    passkey_verifier: Arc<dyn PasskeyVerifier>,
    security_service: Arc<SecurityService>,
    access_token_ttl_minutes: i64,
    session_ttl_hours: i64,
    otp_code_ttl_seconds: u64,
    otp_max_attempts: u8,
    otp_resend_cooldown_seconds: u64,
    otp_code_pepper: String,
    is_production: bool,
}

#[allow(clippy::too_many_arguments)]
impl AuthService {
    #[allow(clippy::too_many_arguments)]
    /// 构造认证服务并注入全部依赖端口。
    ///
    /// 服务自身不持久化状态，所有鉴权状态都委托给仓储与缓存实现。
    pub fn new(
        identities: Arc<dyn IdentityRepository>,
        sessions: Arc<dyn SessionRepository>,
        trusted_devices: Arc<dyn TrustedDeviceRepository>,
        otp_store: Arc<dyn OtpStore>,
        otp_delivery: Arc<dyn OtpDelivery>,
        challenge_store: Arc<dyn ChallengeStore>,
        password_hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
        passkey_verifier: Arc<dyn PasskeyVerifier>,
        security_service: Arc<SecurityService>,
        access_token_ttl_minutes: i64,
        session_ttl_hours: i64,
        otp_code_ttl_seconds: u64,
        otp_max_attempts: u8,
        otp_resend_cooldown_seconds: u64,
        otp_code_pepper: String,
        is_production: bool,
    ) -> Self {
        Self {
            identities,
            sessions,
            trusted_devices,
            otp_store,
            otp_delivery,
            challenge_store,
            password_hasher,
            clock,
            passkey_verifier,
            security_service,
            access_token_ttl_minutes,
            session_ttl_hours,
            otp_code_ttl_seconds,
            otp_max_attempts,
            otp_resend_cooldown_seconds,
            otp_code_pepper,
            is_production,
        }
    }
    /// 密码登录主流程：限流校验 -> 身份校验 -> 会话签发。
    ///
    /// 若账户要求多因子且设备不可信，则先返回部分认证态，等待后续 MFA 验证。
    pub async fn login_with_password(
        &self,
        input: PasswordLoginInput,
    ) -> Result<AuthResult, AppError> {
        let email = Email::new(input.email)?;
        self.security_service
            .assert_login_allowed(
                CredentialType::Password,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
            )
            .await?;

        let Some((identity, subject)) = self
            .identities
            .find_subject_by_email_and_role(&email, input.role)
            .await?
        else {
            // Account does not exist yet. Record failure without leaking existence,
            // and return a generic Unauthorized to avoid user enumeration.
            self.record_login_failure(
                CredentialType::Password,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
                "subject_not_found",
            )
            .await?;
            return Err(AppError::Unauthorized);
        };
        if !identity.email_verified() {
            return Err(AppError::Validation(
                "Email verification required. Request OTP and complete verification before password login."
                    .to_string(),
            ));
        }
        let Some(credential) = self
            .identities
            .find_password_credential(identity.id)
            .await?
        else {
            self.record_login_failure(
                CredentialType::Password,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
                "password_credential_missing",
            )
            .await?;
            return Err(AppError::Unauthorized);
        };
        // Reject the OTP-provisioning sentinel password even if the hash matches.
        // Accounts auto-created via OTP flow must complete email verification and
        // set a real password before they can use the password login path.
        if input.password == AUTO_PROVISION_PASSWORD {
            self.record_login_failure(
                CredentialType::Password,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
                "sentinel_password_rejected",
            )
            .await?;
            return Err(AppError::Unauthorized);
        }
        if !self.password_hasher.verify(
            &input.password,
            credential.password_hash.expose().expose_secret(),
        )? {
            self.record_login_failure(
                CredentialType::Password,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
                "invalid_password",
            )
            .await?;
            return Err(AppError::Unauthorized);
        }
        let trusted_device = self
            .evaluate_trusted_device(subject.id(), input.trusted_device_token.as_deref())
            .await?;

        let result = self
            .issue_session(
                identity.id,
                &email,
                &subject,
                input.device_name,
                input.user_agent,
                input.ip,
                input.remember_device,
                trusted_device,
            )
            .await?;
        self.clear_login_failures(CredentialType::Password, &email, input.role)
            .await?;
        Ok(result)
    }
    /// 请求 OTP 登录码，并写入短时存储。
    ///
    /// 该流程会触发安全频控，避免验证码接口被滥用。
    pub async fn request_otp(&self, input: OtpRequestInput) -> Result<OtpRequestResult, AppError> {
        let email = Email::new(input.email)?;
        self.security_service
            .assert_otp_request_allowed(&email, input.role, None)
            .await?;
        let now = self.clock.now();
        let (_identity, _subject, auto_registered) =
            self.resolve_or_provision_subject(&email, input.role).await?;
        let code = self.password_hasher.random_numeric_code(6);
        let dispatch = OtpDispatch {
            code_hash: self.hash_otp_code(&email, input.role, &code),
            issued_at: now,
            expires_at: now + Duration::seconds(self.otp_code_ttl_seconds as i64),
            resend_available_at: now + Duration::seconds(self.otp_resend_cooldown_seconds as i64),
            max_attempts: self.otp_max_attempts,
        };
        let save_result = self
            .otp_store
            .store_login_code(&email, input.role, &dispatch)
            .await?;
        if !save_result.stored {
            return Err(AppError::RateLimited(format!(
                "OTP already sent recently. Retry in {} seconds.",
                save_result.retry_after_seconds.max(1)
            )));
        }
        self.otp_delivery
            .send_login_code(&email, input.role, &code, dispatch.expires_at, auto_registered)
            .await?;
        Ok(OtpRequestResult {
            sent: true,
            demo_code: (!self.is_production).then_some(code),
            auto_registered,
            expires_in_seconds: self.otp_code_ttl_seconds,
            retry_after_seconds: 0,
        })
    }
    /// 校验 OTP 并完成登录态签发。
    ///
    /// 根据“记住设备”决策决定是否签发 trusted device token。
    pub async fn verify_otp(&self, input: OtpVerifyInput) -> Result<AuthResult, AppError> {
        let email = Email::new(input.email)?;
        self.security_service
            .assert_login_allowed(
                CredentialType::Otp,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
            )
            .await?;
        // During OTP verify the subject must exist — it is provisioned by request_otp.
        // If it is missing here it means verify was called without a prior request,
        // or the account was deleted between steps. Either way the OTP store will
        // have no active code, so fall through to the normal NotFound path below
        // rather than leaking subject existence via a distinct error.
        let (identity, subject) = match self
            .identities
            .find_subject_by_email_and_role(&email, input.role)
            .await?
        {
            Some(pair) => pair,
            None => {
                self.record_login_failure(
                    CredentialType::Otp,
                    &email,
                    input.role,
                    input.ip.as_deref(),
                    input.user_agent.as_deref(),
                    "otp_subject_not_found",
                )
                .await?;
                return Err(AppError::Validation(
                    "No active OTP code found. Request a new code and try again.".to_string(),
                ));
            }
        };
        match self
            .otp_store
            .verify_login_code(
                &email,
                input.role,
                &self.hash_otp_code(&email, input.role, &input.code),
                self.clock.now(),
            )
            .await?
        {
            StoreOtpVerifyResult::Verified => {}
            StoreOtpVerifyResult::Invalid { attempts_remaining } => {
                self.record_login_failure(
                    CredentialType::Otp,
                    &email,
                    input.role,
                    input.ip.as_deref(),
                    input.user_agent.as_deref(),
                    "invalid_otp",
                )
                .await?;
                if attempts_remaining == 0 {
                    return Err(AppError::Validation(
                        "Invalid OTP code. No attempts remaining — request a new code."
                            .to_string(),
                    ));
                }
                return Err(AppError::Validation(format!(
                    "Invalid OTP code. {} attempt(s) remaining.",
                    attempts_remaining
                )));
            }
            StoreOtpVerifyResult::Exhausted => {
                return Err(AppError::Validation(
                    "Too many incorrect attempts. Request a new OTP code and try again."
                        .to_string(),
                ));
            }
            StoreOtpVerifyResult::Expired => {
                return Err(AppError::Validation(
                    "OTP code expired. Request a new code and try again.".to_string(),
                ));
            }
            StoreOtpVerifyResult::NotFound => {
                return Err(AppError::Validation(
                    "No active OTP code found. Request a new code and try again.".to_string(),
                ));
            }
        }
        if !identity.email_verified()
            && !self
                .identities
                .mark_identity_email_verified(identity.id, self.clock.now())
                .await?
        {
            return Err(AppError::Unauthorized);
        }
        let trusted_device = self
            .evaluate_trusted_device(subject.id(), input.trusted_device_token.as_deref())
            .await?;
        let result = self
            .issue_session(
                identity.id,
                &email,
                &subject,
                input.device_name,
                input.user_agent,
                input.ip,
                input.remember_device,
                trusted_device,
            )
            .await?;
        self.clear_login_failures(CredentialType::Otp, &email, input.role)
            .await?;
        Ok(result)
    }
    /// 为已完成一因子的部分认证态发送 OTP，用于完成第二因子校验。
    pub async fn request_mfa_otp(
        &self,
        current: &CurrentSession,
        user_agent: Option<String>,
    ) -> Result<OtpRequestResult, AppError> {
        if current.mfa_level != MfaLevel::Partial {
            return Err(AppError::Forbidden);
        }

        let subject = self
            .identities
            .find_subject_by_id(current.subject_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let identity = self
            .identities
            .find_identity_by_id(current.identity_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        self.security_service
            .assert_otp_request_allowed(&identity.email, subject.role(), user_agent.as_deref())
            .await?;

        let now = self.clock.now();
        let code = self.password_hasher.random_numeric_code(6);
        let dispatch = OtpDispatch {
            code_hash: self.hash_otp_code(&identity.email, subject.role(), &code),
            issued_at: now,
            expires_at: now + Duration::seconds(self.otp_code_ttl_seconds as i64),
            resend_available_at: now + Duration::seconds(self.otp_resend_cooldown_seconds as i64),
            max_attempts: self.otp_max_attempts,
        };
        let save_result = self
            .otp_store
            .store_mfa_code(current.session_id, subject.role(), &dispatch)
            .await?;
        if !save_result.stored {
            return Err(AppError::RateLimited(format!(
                "OTP already sent recently. Retry in {} seconds.",
                save_result.retry_after_seconds.max(1)
            )));
        }
        self.otp_delivery
            .send_mfa_code(&identity.email, subject.role(), &code, dispatch.expires_at)
            .await?;

        Ok(OtpRequestResult {
            sent: true,
            demo_code: (!self.is_production).then_some(code),
            auto_registered: false,
            expires_in_seconds: self.otp_code_ttl_seconds,
            retry_after_seconds: 0,
        })
    }

    /// 对部分认证态执行 OTP 二次验证并提升 MFA 等级。
    ///
    /// 成功后会刷新访问令牌，使新令牌携带完整认证等级。
    pub async fn verify_mfa_otp(
        &self,
        current: &CurrentSession,
        input: OtpMfaVerifyInput,
    ) -> Result<MfaVerifyResult, AppError> {
        if current.mfa_level != MfaLevel::Partial {
            return Err(AppError::Forbidden);
        }

        let subject = self
            .identities
            .find_subject_by_id(current.subject_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let identity = self
            .identities
            .find_identity_by_id(current.identity_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        self.security_service
            .assert_session_mfa_allowed(
                current.session_id,
                CredentialType::Otp,
                current.subject_role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
            )
            .await?;

        match self
            .otp_store
            .verify_mfa_code(
                current.session_id,
                current.subject_role,
                &self.hash_otp_code(&identity.email, current.subject_role, &input.code),
                self.clock.now(),
            )
            .await?
        {
            StoreOtpVerifyResult::Verified => {}
            StoreOtpVerifyResult::Invalid { attempts_remaining } => {
                self.security_service
                    .record_session_mfa_failure(
                        current.session_id,
                        CredentialType::Otp,
                        current.subject_role,
                        input.ip.as_deref(),
                        input.user_agent.as_deref(),
                        "invalid_otp",
                    )
                    .await?;
                if attempts_remaining == 0 {
                    return Err(AppError::Validation(
                        "Invalid OTP code. No attempts remaining — request a new code."
                            .to_string(),
                    ));
                }
                return Err(AppError::Validation(format!(
                    "Invalid OTP code. {} attempt(s) remaining.",
                    attempts_remaining
                )));
            }
            StoreOtpVerifyResult::Exhausted => {
                return Err(AppError::Validation(
                    "Too many incorrect attempts. Request a new OTP code and try again."
                        .to_string(),
                ));
            }
            StoreOtpVerifyResult::Expired => {
                return Err(AppError::Validation(
                    "OTP code expired. Request a new code and try again.".to_string(),
                ));
            }
            StoreOtpVerifyResult::NotFound => {
                return Err(AppError::Validation(
                    "No active OTP code found. Request a new code and try again.".to_string(),
                ));
            }
        }

        let now = self.clock.now();
        if !self.sessions.upgrade_mfa(current.session_id, now).await? {
            return Err(AppError::Unauthorized);
        }
        self.security_service
            .clear_session_mfa_failures(
                current.session_id,
                CredentialType::Otp,
                current.subject_role,
            )
            .await?;

        let session = self
            .sessions
            .list_sessions_for_subject(current.subject_id, now)
            .await?
            .into_iter()
            .find(|session| session.id() == current.session_id)
            .ok_or(AppError::Unauthorized)?;
        let trusted_device_token = if session.remember_device() && subject.requires_step_up_mfa() {
            Some(self.issue_trusted_device(&session, now).await?)
        } else {
            None
        };

        Ok(MfaVerifyResult {
            session: SessionOverview {
                session_id: session.id(),
                subject_role: current.subject_role,
                display_name: subject.display_name().to_string(),
                email: identity.email.as_str().to_string(),
                mfa_level: MfaLevel::Full,
                device_name: session.device_name().to_string(),
                expires_at: session.expires_at(),
                current: true,
            },
            trusted_device_token,
        })
    }
    /// 发起通行密钥注册挑战。
    ///
    /// 返回 challenge_id 与 public_key 选项，供前端调用 WebAuthn API。
    pub async fn begin_passkey_registration(
        &self,
        current: &CurrentSession,
    ) -> Result<PasskeyChallengeResult, AppError> {
        if current.mfa_level != MfaLevel::Full {
            return Err(AppError::Forbidden);
        }
        let subject = self
            .identities
            .find_subject_by_id(current.subject_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let identity = self
            .identities
            .find_identity_by_id(subject.identity_id())
            .await?
            .ok_or(AppError::Unauthorized)?;
        let registered = self
            .identities
            .list_passkeys_for_subject(subject.id())
            .await?;
        let (challenge_id, options) = self.passkey_verifier.issue_registration_challenge(
            subject.id(),
            identity.email.as_str(),
            subject.display_name(),
            &registered,
        )?;

        // Store the entire options value so the state field is not assumed to be
        // a plain string — webauthn-rs state is a JSON object.
        let state = options
            .get("state")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                AppError::Infrastructure("passkey registration state missing".to_string())
            })?;
        let stored = serde_json::to_value(StoredPasskeyChallenge::Registration {
            subject_id: subject.id(),
            state: state.to_string(),
        })
        .map_err(|_| AppError::Infrastructure("passkey challenge serialization failed".to_string()))?;

        // 180 s gives enough time for platform authenticators on slow mobile devices.
        self.challenge_store
            .save_passkey_challenge(&challenge_id, stored, 180)
            .await?;

        Ok(PasskeyChallengeResult {
            challenge_id,
            public_key: options["public_key"].clone(),
        })
    }
    /// 完成通行密钥注册。
    ///
    /// 仅在挑战消费成功且验签通过后写库，避免注册重放。
    pub async fn finish_passkey_registration(
        &self,
        current: &CurrentSession,
        input: PasskeyRegisterVerifyInput,
    ) -> Result<PasskeyRegistrationResult, AppError> {
        if current.mfa_level != MfaLevel::Full {
            return Err(AppError::Forbidden);
        }
        let payload = self
            .challenge_store
            .consume_passkey_challenge(&input.challenge_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let payload: StoredPasskeyChallenge =
            serde_json::from_value(payload).map_err(|_| AppError::Unauthorized)?;
        let state = match payload {
            StoredPasskeyChallenge::Registration { subject_id, state }
                if subject_id == current.subject_id =>
            {
                state
            }
            _ => return Err(AppError::Unauthorized),
        };

        let subject = self
            .identities
            .find_subject_by_id(current.subject_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let (external_id, label, verifier_data) = self
            .passkey_verifier
            .verify_registration(&state, input.response)?;
        self.identities
            .insert_passkey(subject.id(), &external_id, &label, &verifier_data, self.clock.now())
            .await?;

        Ok(PasskeyRegistrationResult { external_id, label })
    }
    /// 发起通行密钥登录挑战。
    ///
    /// 先按邮箱与角色定位主体，再生成 assertion challenge。
    pub async fn begin_passkey_login(
        &self,
        input: PasskeyLoginChallengeInput,
    ) -> Result<PasskeyChallengeResult, AppError> {
        let email = Email::new(input.email)?;
        self.security_service
            .assert_login_allowed(
                CredentialType::Passkey,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
            )
            .await?;

        // Return Unauthorized for both "account not found" and "no passkeys registered"
        // to avoid leaking account existence via distinct error messages.
        let Some((_identity, subject)) = self
            .identities
            .find_subject_by_email_and_role(&email, input.role)
            .await?
        else {
            self.record_login_failure(
                CredentialType::Passkey,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
                "subject_not_found",
            )
            .await?;
            return Err(AppError::Unauthorized);
        };
        let passkeys = self
            .identities
            .list_passkeys_for_subject(subject.id())
            .await?;
        if passkeys.is_empty() {
            self.record_login_failure(
                CredentialType::Passkey,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
                "passkey_not_registered",
            )
            .await?;
            return Err(AppError::Unauthorized);
        }
        let (challenge_id, options) = self
            .passkey_verifier
            .issue_authentication_challenge(&passkeys)?;
        let state = options
            .get("state")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                AppError::Infrastructure("passkey authentication state missing".to_string())
            })?;
        let stored = serde_json::to_value(StoredPasskeyChallenge::Authentication {
            subject_id: subject.id(),
            email: email.as_str().to_string(),
            subject_role: subject.role(),
            state: state.to_string(),
        })
        .map_err(|_| AppError::Infrastructure("passkey challenge serialization failed".to_string()))?;
        // 300 s matches the WebAuthn spec recommendation for assertion challenges.
        self.challenge_store
            .save_passkey_challenge(&challenge_id, stored, 300)
            .await?;

        Ok(PasskeyChallengeResult {
            challenge_id,
            public_key: options["public_key"].clone(),
        })
    }
    /// 验证通行密钥登录响应并签发会话。
    ///
    /// 会话签发与设备信任策略与密码/OTP 登录保持一致。
    pub async fn finish_passkey_login(
        &self,
        input: PasskeyLoginVerifyInput,
    ) -> Result<AuthResult, AppError> {
        let email = Email::new(input.email)?;
        // Do NOT call assert_login_allowed here — the challenge was already
        // consumed atomically in consume_passkey_challenge, so replay is
        // impossible. A second rate-limit check here would double-count
        // legitimate attempts and could lock out valid users.

        let Some((identity, subject)) = self
            .identities
            .find_subject_by_email_and_role(&email, input.role)
            .await?
        else {
            self.record_login_failure(
                CredentialType::Passkey,
                &email,
                input.role,
                input.ip.as_deref(),
                input.user_agent.as_deref(),
                "subject_not_found",
            )
            .await?;
            return Err(AppError::Unauthorized);
        };

        let payload: StoredPasskeyChallenge = self
            .challenge_store
            .consume_passkey_challenge(&input.challenge_id)
            .await?
            .ok_or(AppError::Unauthorized)
            .and_then(|payload| serde_json::from_value(payload).map_err(|_| AppError::Unauthorized))?;
        let passkeys = self
            .identities
            .list_passkeys_for_subject(subject.id())
            .await?;
        let state = match payload {
            StoredPasskeyChallenge::Authentication { subject_id, email: challenge_email, subject_role, state }
                if subject_id == subject.id() && challenge_email == email.as_str() && subject_role == input.role => state,
            _ => return Err(AppError::Unauthorized),
        };
        let verification =
            self.passkey_verifier
                .verify_authentication(&state, input.response, &passkeys);
        let maybe_updated_passkey = match verification {
            Ok(result) => result,
            Err(AppError::Unauthorized) => {
                self.record_login_failure(
                    CredentialType::Passkey,
                    &email,
                    input.role,
                    input.ip.as_deref(),
                    input.user_agent.as_deref(),
                    "invalid_passkey",
                )
                .await?;
                return Err(AppError::Unauthorized);
            }
            Err(AppError::Validation(message)) => {
                self.record_login_failure(
                    CredentialType::Passkey,
                    &email,
                    input.role,
                    input.ip.as_deref(),
                    input.user_agent.as_deref(),
                    "invalid_passkey_payload",
                )
                .await?;
                return Err(AppError::Validation(message));
            }
            Err(error) => return Err(error),
        };
        if let Some((passkey_id, verifier_data)) = maybe_updated_passkey {
            let current_verifier_data = passkeys
                .iter()
                .find(|passkey| passkey.id == passkey_id)
                .map(|passkey| passkey.verifier_data.as_str())
                .ok_or(AppError::Unauthorized)?;
            if !self
                .identities
                .update_passkey_verifier_data(passkey_id, current_verifier_data, &verifier_data)
                .await?
            {
                return Err(AppError::Unauthorized);
            }
        }
        let trusted_device = self
            .evaluate_trusted_device(subject.id(), input.trusted_device_token.as_deref())
            .await?;

        let result = self
            .issue_session(
                identity.id,
                &email,
                &subject,
                input.device_name,
                input.user_agent,
                input.ip,
                input.remember_device,
                trusted_device,
            )
            .await?;
        self.clear_login_failures(CredentialType::Passkey, &email, input.role)
            .await?;
        Ok(result)
    }
    /// 查询当前会话视图。
    ///
    /// 此接口只读，不做令牌轮换。
    pub async fn current_session(
        &self,
        current: &CurrentSession,
    ) -> Result<SessionOverview, AppError> {
        let subject = self
            .identities
            .find_subject_by_id(current.subject_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let identity = self
            .identities
            .find_identity_by_id(current.identity_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let now = self.clock.now();
        let session = self
            .sessions
            .list_sessions_for_subject(current.subject_id, now)
            .await?
            .into_iter()
            .find(|session| session.id() == current.session_id)
            .ok_or(AppError::Unauthorized)?;

        Ok(SessionOverview {
            session_id: session.id(),
            subject_role: current.subject_role,
            display_name: subject.display_name().to_string(),
            email: identity.email.as_str().to_string(),
            mfa_level: session.mfa_level(),
            device_name: session.device_name().to_string(),
            expires_at: session.expires_at(),
            current: true,
        })
    }
    /// 列出当前主体的活跃会话列表。
    ///
    /// 返回 `current` 标记，便于前端区分本机会话与其他设备会话。
    pub async fn list_sessions(
        &self,
        current: &CurrentSession,
    ) -> Result<Vec<SessionItem>, AppError> {
        let now = self.clock.now();
        let sessions = self
            .sessions
            .list_sessions_for_subject(current.subject_id, now)
            .await?;

        Ok(sessions
            .into_iter()
            .map(|session| SessionItem {
                id: session.id(),
                device_name: session.device_name().to_string(),
                user_agent: session.user_agent().map(ToString::to_string),
                ip: session.ip().map(ToString::to_string),
                mfa_level: session.mfa_level(),
                expires_at: session.expires_at(),
                last_seen_at: session.last_seen_at(),
                current: session.id() == current.session_id,
            })
            .collect())
    }
    /// 撤销指定会话。
    ///
    /// 如果会话不属于当前主体，返回未授权错误，防止越权操作。
    pub async fn revoke_session(
        &self,
        current: &CurrentSession,
        session_id: Uuid,
        trusted_device_token: Option<&str>,
    ) -> Result<bool, AppError> {
        let now = self.clock.now();
        let target_session = self
            .sessions
            .list_sessions_for_subject(current.subject_id, now)
            .await?
            .into_iter()
            .find(|session| session.id() == session_id);
        let revoked = self
            .sessions
            .revoke_session(session_id, current.subject_id)
            .await?;
        if !revoked {
            return Ok(false);
        }

        if let Some(session) = target_session.as_ref() {
            self.revoke_trusted_devices_for_session(session, now)
            .await?;
        }
        if session_id == current.session_id {
            self.revoke_trusted_device_token(current.subject_id, trusted_device_token, now)
            .await?;
        }

        Ok(true)
    }
    /// 撤销除当前会话外的所有会话。
    ///
    /// 常用于凭证重置后的风险收敛，返回实际撤销数量。
    pub async fn revoke_other_sessions(&self, current: &CurrentSession) -> Result<u64, AppError> {
        let now = self.clock.now();
        let other_sessions = self
            .sessions
             .list_sessions_for_subject(current.subject_id, now)
            .await?
            .into_iter()
            .filter(|session| session.id() != current.session_id)
            .collect::<Vec<_>>();
        let revoked_count = self
            .sessions
            .revoke_other_sessions(current.session_id, current.subject_id)
            .await?;

        for session in &other_sessions {
            self.revoke_trusted_devices_for_session(session, now)
            .await?;
        }

        Ok(revoked_count)
    }
    /// 注销当前会话并清理关联状态。
    ///
    /// 与路由层配合后，客户端应同时清除会话与信任设备 Cookie。
    pub async fn logout(
        &self,
        current: &CurrentSession,
        trusted_device_token: Option<&str>,
    ) -> Result<bool, AppError> {
        let now = self.clock.now();
        let current_session = self
            .sessions
            .list_sessions_for_subject(current.subject_id, now)
            .await?
            .into_iter()
            .find(|session| session.id() == current.session_id);
        let revoked = self
            .sessions
            .revoke_session(current.session_id, current.subject_id)
            .await?;
        if !revoked {
            return Ok(false);
        }

        if let Some(session) = current_session.as_ref() {
            self.revoke_trusted_devices_for_session(session, now)
            .await?;
        }
        self.revoke_trusted_device_token(current.subject_id, trusted_device_token, now)
        .await?;

        Ok(true)
    }
    /// 解析并鉴权访问令牌。
    ///
    /// 验证通过后返回 `CurrentSession`，供上层路由做授权判断。
    pub async fn authenticate_token(
        &self,
        token: &str,
    ) -> Result<Option<CurrentSession>, AppError> {
        let token = match SessionToken::new(token.to_string()) {
            Ok(token) => token,
            Err(_) => return Ok(None),
        };
        let access_token_hash = self
            .password_hasher
            .hash_token(token.expose().expose_secret());
        let now = self.clock.now();
        let Some(session) = self
            .sessions
            .find_session_by_access_token_hash(&access_token_hash, now)
            .await?
        else {
            return Ok(None);
        };
        if !self
            .sessions
            .touch_session(session.id(), &access_token_hash, now)
            .await?
        {
            return Ok(None);
        }
        Ok(Some(CurrentSession {
            session_id: session.id(),
            identity_id: session.identity_id(),
            subject_id: session.subject_id(),
            subject_role: session.subject_role(),
            mfa_level: session.mfa_level(),
        }))
    }
    /// 使用 refresh token 轮换访问令牌。
    ///
    /// 轮换前会校验会话状态，确保已撤销会话无法继续刷新。
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Option<RefreshResult>, AppError> {
        let refresh_token_hash = self.password_hasher.hash_token(refresh_token);
        self.security_service
            .assert_refresh_allowed(&refresh_token_hash, ip.as_deref(), user_agent.as_deref())
            .await?;

        let refresh_token = match SessionToken::new(refresh_token.to_string()) {
            Ok(token) => token,
            Err(_) => {
                self.security_service
                    .record_refresh_failure(
                        &refresh_token_hash,
                        ip.as_deref(),
                        user_agent.as_deref(),
                        "invalid_refresh_token_format",
                    )
                    .await?;
                return Ok(None);
            }
        };
        let refresh_token_hash = self
            .password_hasher
            .hash_token(refresh_token.expose().expose_secret());
        let now = self.clock.now();
        let Some(session) = self
            .sessions
            .find_session_by_refresh_token_hash(&refresh_token_hash, now)
            .await?
        else {
            self.security_service
                .record_refresh_failure(
                    &refresh_token_hash,
                    ip.as_deref(),
                    user_agent.as_deref(),
                    "refresh_session_not_found",
                )
                .await?;
            return Ok(None);
        };

        if session.mfa_level() == MfaLevel::Partial {
            self.security_service
                .record_refresh_failure(
                    &refresh_token_hash,
                    ip.as_deref(),
                    user_agent.as_deref(),
                    "partial_session_refresh_denied",
                )
                .await?;
            return Ok(None);
        }

        let raw_access_token = self.password_hasher.random_token()?;
        let raw_refresh_token = self.password_hasher.random_token()?;
        let access_token_hash = self.password_hasher.hash_token(&raw_access_token);
        let next_refresh_token_hash = self.password_hasher.hash_token(&raw_refresh_token);
        let access_expires_at = self.access_expires_at(now);
        let rotated = self
            .sessions
            .rotate_session_tokens(
                session.id(),
                session.refresh_token_hash(),
                &access_token_hash,
                &next_refresh_token_hash,
                access_expires_at,
                now,
            )
            .await?;
        if !rotated {
            self.security_service
                .record_refresh_failure(
                    &refresh_token_hash,
                    ip.as_deref(),
                    user_agent.as_deref(),
                    "refresh_session_update_missed",
                )
                .await?;
            return Ok(None);
        }
        self.security_service
            .clear_refresh_failures(&refresh_token_hash)
            .await?;

        Ok(Some(RefreshResult {
            access_token: raw_access_token,
            refresh_token: raw_refresh_token,
            access_expires_at,
            refresh_expires_at: session.expires_at(),
        }))
    }
    /// 统一签发登录成功后的会话与令牌，并根据 trusted device 判定初始 MFA 等级。
    async fn issue_session(
        &self,
        identity_id: Uuid,
        email: &Email,
        subject: &Subject,
        device_name: String,
        user_agent: Option<String>,
        ip: Option<String>,
        remember_device: bool,
        trusted_device: TrustedDeviceDecision,
    ) -> Result<AuthResult, AppError> {
        let now = self.clock.now();
        let raw_access_token = self.password_hasher.random_token()?;
        let raw_refresh_token = self.password_hasher.random_token()?;
        let access_token_hash = self.password_hasher.hash_token(&raw_access_token);
        let refresh_token_hash = self.password_hasher.hash_token(&raw_refresh_token);
        let requires_step_up = subject.requires_step_up_mfa();
        let mfa_level = if requires_step_up && !trusted_device.authenticated {
            MfaLevel::Partial
        } else {
            MfaLevel::Full
        };
        let session = Session::new(
            Uuid::new_v4(),
            identity_id,
            subject.id(),
            subject.role(),
            access_token_hash,
            refresh_token_hash,
            device_name.clone(),
            user_agent,
            ip,
            mfa_level,
            remember_device || trusted_device.authenticated,
            self.access_expires_at(now),
            self.refresh_expires_at(now),
            now,
            now,
            None,
        )?;
        self.sessions.create_session(&session).await?;

        Ok(AuthResult {
            access_token: raw_access_token,
            refresh_token: raw_refresh_token,
            access_expires_at: session.access_expires_at(),
            refresh_expires_at: session.expires_at(),
            session: SessionOverview {
                session_id: session.id(),
                subject_role: subject.role(),
                display_name: subject.display_name().to_string(),
                email: email.as_str().to_string(),
                mfa_level,
                device_name,
                expires_at: session.expires_at(),
                current: true,
            },
            requires_mfa: mfa_level != MfaLevel::Full,
            trusted_device_token: None,
            clear_trusted_device: trusted_device.clear_cookie,
        })
    }
    /// 校验客户端携带的 trusted device token 是否仍然有效，并给出是否应清理 Cookie 的决策。
    async fn evaluate_trusted_device(
        &self,
        subject_id: Uuid,
        token: Option<&str>,
    ) -> Result<TrustedDeviceDecision, AppError> {
        let Some(token) = token.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(TrustedDeviceDecision {
                authenticated: false,
                clear_cookie: false,
            });
        };
        if token.len() < 32 {
            return Ok(TrustedDeviceDecision {
                authenticated: false,
                clear_cookie: true,
            });
        }

        let now = self.clock.now();
        let token_hash = self.password_hasher.hash_token(token);
        let Some(device) = self
            .trusted_devices
            .find_trusted_device_by_token_hash(subject_id, &token_hash, now)
            .await?
        else {
            return Ok(TrustedDeviceDecision {
                authenticated: false,
                clear_cookie: true,
            });
        };
        if !self
            .trusted_devices
            .touch_trusted_device(device.id(), now)
            .await?
        {
            return Ok(TrustedDeviceDecision {
                authenticated: false,
                clear_cookie: true,
            });
        }
        Ok(TrustedDeviceDecision {
            authenticated: true,
            clear_cookie: false,
        })
    }
    /// 为“记住此设备”的完整认证会话签发新的 trusted device token。
    async fn issue_trusted_device(
        &self,
        session: &Session,
        now: DateTime<Utc>,
    ) -> Result<String, AppError> {
        let raw_token = self.password_hasher.random_token()?;
        let token_hash = self.password_hasher.hash_token(&raw_token);
        let trusted_device = TrustedDevice::new(
            Uuid::new_v4(),
            session.identity_id(),
            session.subject_id(),
            session.subject_role(),
            token_hash,
            session.device_name().to_string(),
            session.user_agent().map(ToString::to_string),
            session.ip().map(ToString::to_string),
            now + Duration::hours(self.session_ttl_hours),
            now,
            now,
            None,
        )?;
        self.trusted_devices
            .create_trusted_device(&trusted_device)
            .await?;
        Ok(raw_token)
    }
    /// 按 token 撤销单个 trusted device 凭据，常用于主动登出当前设备。
    async fn revoke_trusted_device_token(
        &self,
        subject_id: Uuid,
        token: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let Some(token) = token.map(str::trim).filter(|value| value.len() >= 32) else {
            return Ok(());
        };

        let token_hash = self.password_hasher.hash_token(token);
        self.trusted_devices
            .revoke_trusted_device_by_token_hash(subject_id, &token_hash, now)
            .await?;
        Ok(())
    }

    /// 根据会话的设备指纹批量撤销关联 trusted device，避免会话撤销后设备仍被视为可信。
    async fn revoke_trusted_devices_for_session(
        &self,
        session: &Session,
        now: DateTime<Utc>,
    ) -> Result<u64, AppError> {
        self.trusted_devices
            .revoke_trusted_devices_by_device(
                session.subject_id(),
                session.device_name(),
                session.user_agent(),
                session.ip(),
                now,
            )
            .await
    }

    /// 将登录失败事件统一委托给安全服务，便于复用限流与风险记录策略。
    async fn record_login_failure(
        &self,
        credential_type: CredentialType,
        email: &Email,
        role: SubjectRole,
        ip: Option<&str>,
        user_agent: Option<&str>,
        reason: &str,
    ) -> Result<(), AppError> {
        self.security_service
            .record_login_failure(credential_type, email, role, ip, user_agent, reason)
            .await
    }

    /// 在登录成功后清除该凭证类型对应的失败计数，避免误触后续风控。
    async fn clear_login_failures(
        &self,
        credential_type: CredentialType,
        email: &Email,
        role: SubjectRole,
    ) -> Result<(), AppError> {
        self.security_service
            .clear_login_failures(credential_type, email, role)
            .await
    }

    /// 解析目标主体；若不存在则按 OTP 自助注册语义自动补齐 identity 与 subject。
    async fn resolve_or_provision_subject(
        &self,
        email: &Email,
        role: SubjectRole,
    ) -> Result<(crate::domain::entities::Identity, Subject, bool), AppError> {
        if let Some((identity, subject)) = self
            .identities
            .find_subject_by_email_and_role(email, role)
            .await?
        {
            return Ok((identity, subject, false));
        }

        let now = self.clock.now();
        let (identity, subject) = self
            .identities
            .ensure_subject_with_default_password(email, role, AUTO_PROVISION_PASSWORD, now)
            .await?;
        Ok((identity, subject, true))
    }

    /// 对 OTP 进行带 pepper 的上下文化哈希，避免明文验证码进入存储层。
    fn hash_otp_code(&self, email: &Email, role: SubjectRole, code: &str) -> String {
        self.password_hasher.hash_token(&format!(
            "{}:{}:{}:{}",
            self.otp_code_pepper,
            role.as_str(),
            email.as_str(),
            code.trim()
        ))
    }

    /// 计算 access token 的绝对过期时间。
    fn access_expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now + Duration::minutes(self.access_token_ttl_minutes)
    }
    /// 计算 refresh token / session 的绝对过期时间。
    fn refresh_expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now + Duration::hours(self.session_ttl_hours)
    }
}


