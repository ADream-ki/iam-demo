//! Authentication flow tests

use std::sync::Arc;

use uuid::Uuid;

use iam_api::{
    application::services::{
        AuthService, OtpMfaVerifyInput, OtpRequestInput, OtpVerifyInput,
        PasskeyLoginChallengeInput, PasskeyLoginVerifyInput, PasskeyRegisterVerifyInput,
        PasswordLoginInput,
    },
    domain::entities::{CurrentSession, Email, MfaLevel, SubjectRole},
    domain::ports::{
        ChallengeStore, Clock, IdentityRepository, OtpDelivery, OtpStore, PasskeyVerifier,
        PasswordHasher, RiskEventRepository, SecurityStore, SessionRepository,
        TrustedDeviceRepository,
    },
    error::AppError,
};

mod mocks;
use mocks::{
    MockChallengeStore, MockClock, MockIdentityRepository, MockOtpDelivery, MockOtpStore,
    MockPasswordHasher, MockRiskEventRepository, MockSecurityStore, MockSessionRepository,
    MockTrustedDeviceRepository,
};

fn create_auth_service() -> (
    AuthService,
    Arc<MockIdentityRepository>,
    Arc<MockSessionRepository>,
    Arc<MockOtpStore>,
    Arc<MockOtpDelivery>,
    Arc<MockPasswordHasher>,
    Arc<MockClock>,
) {
    let identities = Arc::new(MockIdentityRepository::new());
    let sessions = Arc::new(MockSessionRepository::new());
    let trusted_devices = Arc::new(MockTrustedDeviceRepository::new());
    let otp_store = Arc::new(MockOtpStore::new());
    let otp_delivery = Arc::new(MockOtpDelivery::new());
    let challenge_store = Arc::new(MockChallengeStore::new());
    let security_store = Arc::new(MockSecurityStore::new());
    let risk_events = Arc::new(MockRiskEventRepository::new());
    let clock = Arc::new(MockClock::new());
    let password_hasher = Arc::new(MockPasswordHasher::new());
    let passkey_verifier = Arc::new(MockPasskeyVerifier::new());

    let security_service = Arc::new(iam_api::application::security::SecurityService::new(
        Arc::clone(&security_store) as Arc<dyn SecurityStore>,
        Arc::clone(&risk_events) as Arc<dyn RiskEventRepository>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        5,
        60,
        5,
        20,
        900,
        5,
        300,
    ));

    let service = AuthService::new(
        Arc::clone(&identities) as Arc<dyn IdentityRepository>,
        Arc::clone(&sessions) as Arc<dyn SessionRepository>,
        Arc::clone(&trusted_devices) as Arc<dyn TrustedDeviceRepository>,
        Arc::clone(&otp_store) as Arc<dyn OtpStore>,
        Arc::clone(&otp_delivery) as Arc<dyn OtpDelivery>,
        Arc::clone(&challenge_store) as Arc<dyn ChallengeStore>,
        Arc::clone(&password_hasher) as Arc<dyn PasswordHasher>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        Arc::clone(&passkey_verifier) as Arc<dyn PasskeyVerifier>,
        Arc::clone(&security_service),
        15,
        168,
        600,
        5,
        60,
        "test-otp-pepper".to_string(),
        false,
    );

    (
        service,
        identities,
        sessions,
        otp_store,
        otp_delivery,
        password_hasher,
        clock,
    )
}

struct MockPasskeyVerifier;

impl MockPasskeyVerifier {
    fn new() -> Self {
        Self
    }
}

impl PasskeyVerifier for MockPasskeyVerifier {
    fn issue_registration_challenge(
        &self,
        subject_id: Uuid,
        _email: &str,
        _display_name: &str,
        _registered: &[iam_api::domain::entities::PasskeyCredential],
    ) -> Result<(String, serde_json::Value), AppError> {
        Ok((
            format!("challenge-{}", subject_id),
            serde_json::json!({"challenge": "test", "state": "state"}),
        ))
    }

    fn issue_authentication_challenge(
        &self,
        _registered: &[iam_api::domain::entities::PasskeyCredential],
    ) -> Result<(String, serde_json::Value), AppError> {
        Ok((
            "auth-challenge".to_string(),
            serde_json::json!({"challenge": "auth", "state": "state"}),
        ))
    }

    fn verify_registration(
        &self,
        _state: &str,
        _response: serde_json::Value,
    ) -> Result<(String, String, String), AppError> {
        Ok((
            "credential-id".to_string(),
            "test-label".to_string(),
            "verifier-data".to_string(),
        ))
    }

    fn verify_authentication(
        &self,
        _state: &str,
        _response: serde_json::Value,
        registered: &[iam_api::domain::entities::PasskeyCredential],
    ) -> Result<Option<(Uuid, String)>, AppError> {
        let Some(passkey) = registered.first() else {
            return Err(AppError::Unauthorized);
        };
        Ok(Some((passkey.id, "updated-verifier-data".to_string())))
    }
}

#[tokio::test]
async fn fails_with_nonexistent_user() {
    let (service, _, _, _, _, _, _) = create_auth_service();

    let result: Result<_, AppError> = service
        .login_with_password(PasswordLoginInput {
            email: "nonexistent@example.com".to_string(),
            password: "password123".to_string(),
            role: SubjectRole::Member,
            device_name: "Test Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;

    assert!(matches!(result, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn unknown_email_password_login_returns_unauthorized_without_leaking_existence() {
    let (service, identities, _, _, otp_delivery, _, _) = create_auth_service();

    // Unknown account: must return generic Unauthorized (no enumeration).
    let password_result = service
        .login_with_password(PasswordLoginInput {
            email: "new-user@example.com".to_string(),
            password: "any-password".to_string(),
            role: SubjectRole::Member,
            device_name: "Test Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;

    assert!(matches!(password_result, Err(AppError::Unauthorized)));
    // Account must NOT have been created by the failed password attempt.
    assert!(
        identities
            .find_subject_by_email_and_role(
                &Email::new("new-user@example.com").unwrap(),
                SubjectRole::Member
            )
            .await
            .unwrap()
            .is_none()
    );

    // Correct path: use OTP to register.
    let otp_result = service
        .request_otp(OtpRequestInput {
            email: "new-user@example.com".to_string(),
            role: SubjectRole::Member,
        })
        .await
        .unwrap();

    assert!(otp_result.auto_registered);
    assert_eq!(otp_delivery.sent_codes().len(), 1);
}

#[tokio::test]
async fn otp_auto_register_verify_succeeds_and_blocks_sentinel_password() {
    let (service, _, _, _, _, _, _) = create_auth_service();

    // Step 1: request OTP for a new account — auto-provisions the subject.
    let otp_result = service
        .request_otp(OtpRequestInput {
            email: "new-user@example.com".to_string(),
            role: SubjectRole::Member,
        })
        .await
        .unwrap();
    assert!(otp_result.auto_registered);
    assert_eq!(otp_result.demo_code.as_deref(), Some("000000"));

    // Step 2: verify OTP — marks email as verified and issues a session.
    let verify_result = service
        .verify_otp(OtpVerifyInput {
            email: "new-user@example.com".to_string(),
            code: "000000".to_string(),
            role: SubjectRole::Member,
            device_name: "Test Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;
    assert!(verify_result.is_ok(), "OTP verify must succeed: {:?}", verify_result);

    // Step 3: the auto-provisioned sentinel password must never allow login.
    // Users must set a real password through the profile/change-password flow.
    let sentinel_login = service
        .login_with_password(PasswordLoginInput {
            email: "new-user@example.com".to_string(),
            password: "__otp_provisioned_no_password_login__".to_string(),
            role: SubjectRole::Member,
            device_name: "Test Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;
    assert!(
        matches!(sentinel_login, Err(AppError::Unauthorized)),
        "Sentinel password must be rejected: {:?}",
        sentinel_login
    );

    // Step 4: OTP login continues to work for the now-verified account.
    let otp_result2 = service
        .request_otp(OtpRequestInput {
            email: "new-user@example.com".to_string(),
            role: SubjectRole::Member,
        })
        .await
        .unwrap();
    assert!(!otp_result2.auto_registered, "Second OTP must not auto-register again");
    let login2 = service
        .verify_otp(OtpVerifyInput {
            email: "new-user@example.com".to_string(),
            code: "000000".to_string(),
            role: SubjectRole::Member,
            device_name: "Test Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;
    assert!(login2.is_ok(), "Second OTP verify must succeed: {:?}", login2);
}

#[tokio::test]
async fn succeeds_with_valid_credentials() {
    let (service, identities, _, _, _, hasher, _) = create_auth_service();

    let (identity, _) = identities.add_test_identity("valid@example.com", SubjectRole::Member);
    let password_hash = hasher.hash("correct_password").unwrap();
    identities.set_password(identity.id, &password_hash);

    let result = service
        .login_with_password(PasswordLoginInput {
            email: "valid@example.com".to_string(),
            password: "correct_password".to_string(),
            role: SubjectRole::Member,
            device_name: "Test Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;

    assert!(result.is_ok());
    let auth_result = result.unwrap();
    assert!(!auth_result.requires_mfa);
    assert_eq!(auth_result.session.subject_role, SubjectRole::Member);
}

#[tokio::test]
async fn otp_wrong_code_decrements_attempts_without_immediate_consumption() {
    let (service, _, _, _, _, _, _) = create_auth_service();

    service
        .request_otp(OtpRequestInput {
            email: "otpuser@example.com".to_string(),
            role: SubjectRole::Member,
        })
        .await
        .unwrap();

    let wrong = service
        .verify_otp(OtpVerifyInput {
            email: "otpuser@example.com".to_string(),
            code: "123456".to_string(),
            role: SubjectRole::Member,
            device_name: "Test Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;
    assert!(matches!(wrong, Err(AppError::Validation(_))));

    let right = service
        .verify_otp(OtpVerifyInput {
            email: "otpuser@example.com".to_string(),
            code: "000000".to_string(),
            role: SubjectRole::Member,
            device_name: "Test Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;
    assert!(right.is_ok());
}

#[tokio::test]
async fn otp_request_returns_demo_code_in_dev() {
    let (service, _, _, _, _, _, _) = create_auth_service();

    let result = service
        .request_otp(OtpRequestInput {
            email: "test@example.com".to_string(),
            role: SubjectRole::Member,
        })
        .await
        .unwrap();

    assert!(result.sent);
    assert!(result.demo_code.is_some());
    assert_eq!(result.expires_in_seconds, 600);
}

#[tokio::test]
async fn platform_staff_requires_mfa() {
    let (service, identities, _, _, _, hasher, _) = create_auth_service();

    let (identity, _) =
        identities.add_test_identity("platform@example.com", SubjectRole::PlatformStaff);
    let password_hash = hasher.hash("password123").unwrap();
    identities.set_password(identity.id, &password_hash);

    let result = service
        .login_with_password(PasswordLoginInput {
            email: "platform@example.com".to_string(),
            password: "password123".to_string(),
            role: SubjectRole::PlatformStaff,
            device_name: "Admin Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap().requires_mfa);
}

#[tokio::test]
async fn platform_staff_completes_mfa_with_otp() {
    let (service, identities, _, _, otp_delivery, hasher, _) = create_auth_service();

    let (identity, subject) =
        identities.add_test_identity("platform-otp@example.com", SubjectRole::PlatformStaff);
    let password_hash = hasher.hash("password123").unwrap();
    identities.set_password(identity.id, &password_hash);

    let login = service
        .login_with_password(PasswordLoginInput {
            email: "platform-otp@example.com".to_string(),
            password: "password123".to_string(),
            role: SubjectRole::PlatformStaff,
            device_name: "Admin Device".to_string(),
            remember_device: true,
            trusted_device_token: None,
            user_agent: Some("test-agent".to_string()),
            ip: Some("127.0.0.1".to_string()),
        })
        .await
        .unwrap();

    assert!(login.requires_mfa);
    assert_eq!(login.session.mfa_level, MfaLevel::Partial);

    let current = CurrentSession {
        session_id: login.session.session_id,
        identity_id: identity.id,
        subject_id: subject.id(),
        subject_role: SubjectRole::PlatformStaff,
        mfa_level: MfaLevel::Partial,
    };

    let request = service
        .request_mfa_otp(&current, Some("test-agent".to_string()))
        .await
        .unwrap();
    assert!(request.sent);
    assert_eq!(request.demo_code.as_deref(), Some("000000"));
    assert_eq!(otp_delivery.sent_codes().last().map(String::as_str), Some("000000"));

    let verified = service
        .verify_mfa_otp(
            &current,
            OtpMfaVerifyInput {
                code: "000000".to_string(),
                user_agent: Some("test-agent".to_string()),
                ip: Some("127.0.0.1".to_string()),
            },
        )
        .await
        .unwrap();

    assert_eq!(verified.session.mfa_level, MfaLevel::Full);
    assert!(verified.trusted_device_token.is_some());
}

#[tokio::test]
async fn same_email_different_roles_creates_separate_sessions() {
    let (service, identities, _, _, _, hasher, _) = create_auth_service();

    let (identity1, _) = identities.add_test_identity("multi@example.com", SubjectRole::Member);
    let subject_id2 = uuid::Uuid::new_v4();
    identities.add_subject_for_identity(identity1.id, SubjectRole::CommunityStaff, subject_id2);

    let password_hash = hasher.hash("password").unwrap();
    identities.set_password(identity1.id, &password_hash);

    let member_result = service
        .login_with_password(PasswordLoginInput {
            email: "multi@example.com".to_string(),
            password: "password".to_string(),
            role: SubjectRole::Member,
            device_name: "Member Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await
        .unwrap();

    let staff_result = service
        .login_with_password(PasswordLoginInput {
            email: "multi@example.com".to_string(),
            password: "password".to_string(),
            role: SubjectRole::CommunityStaff,
            device_name: "Staff Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await
        .unwrap();

    assert_eq!(member_result.session.subject_role, SubjectRole::Member);
    assert_eq!(
        staff_result.session.subject_role,
        SubjectRole::CommunityStaff
    );
    assert_ne!(
        member_result.session.session_id,
        staff_result.session.session_id
    );
}

#[tokio::test]
async fn passkey_registration_enables_subsequent_login() {
    let (service, identities, _, _, _, _, _) = create_auth_service();
    let (identity, subject) = identities.add_test_identity("passkey@example.com", SubjectRole::Member);
    let current = CurrentSession {
        session_id: Uuid::new_v4(),
        identity_id: identity.id,
        subject_id: subject.id(),
        subject_role: SubjectRole::Member,
        mfa_level: MfaLevel::Full,
    };

    let challenge = service.begin_passkey_registration(&current).await.unwrap();
    assert!(!challenge.challenge_id.is_empty());

    let registered = service
        .finish_passkey_registration(
            &current,
            PasskeyRegisterVerifyInput {
                challenge_id: challenge.challenge_id,
                response: serde_json::json!({ "id": "credential-id-1" }),
            },
        )
        .await
        .unwrap();
    assert_eq!(registered.external_id, "credential-id");
    assert_eq!(identities.count_passkeys_for_subject(subject.id()), 1);

    let login_challenge = service
        .begin_passkey_login(PasskeyLoginChallengeInput {
            email: "passkey@example.com".to_string(),
            role: SubjectRole::Member,
            user_agent: None,
            ip: None,
        })
        .await
        .unwrap();

    let auth = service
        .finish_passkey_login(PasskeyLoginVerifyInput {
            challenge_id: login_challenge.challenge_id,
            email: "passkey@example.com".to_string(),
            role: SubjectRole::Member,
            response: serde_json::json!({ "id": "credential-id-1" }),
            device_name: "Passkey Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await
        .unwrap();

    assert_eq!(auth.session.subject_role, SubjectRole::Member);
    assert!(!auth.requires_mfa);
}

#[tokio::test]
async fn passkey_challenge_is_bound_to_subject_role() {
    let (service, identities, _, _, _, _, _) = create_auth_service();
    let (identity, member_subject) =
        identities.add_test_identity("role-bound@example.com", SubjectRole::Member);
    let community_subject_id = Uuid::new_v4();
    identities.add_subject_for_identity(
        identity.id,
        SubjectRole::CommunityStaff,
        community_subject_id,
    );

    let member_current = CurrentSession {
        session_id: Uuid::new_v4(),
        identity_id: identity.id,
        subject_id: member_subject.id(),
        subject_role: SubjectRole::Member,
        mfa_level: MfaLevel::Full,
    };

    service
        .finish_passkey_registration(
            &member_current,
            PasskeyRegisterVerifyInput {
                challenge_id: service
                    .begin_passkey_registration(&member_current)
                    .await
                    .unwrap()
                    .challenge_id,
                response: serde_json::json!({ "id": "credential-id-2" }),
            },
        )
        .await
        .unwrap();

    let challenge = service
        .begin_passkey_login(PasskeyLoginChallengeInput {
            email: "role-bound@example.com".to_string(),
            role: SubjectRole::Member,
            user_agent: None,
            ip: None,
        })
        .await
        .unwrap();

    let wrong_role = service
        .finish_passkey_login(PasskeyLoginVerifyInput {
            challenge_id: challenge.challenge_id,
            email: "role-bound@example.com".to_string(),
            role: SubjectRole::CommunityStaff,
            response: serde_json::json!({ "id": "credential-id-2" }),
            device_name: "Wrong Role Device".to_string(),
            remember_device: false,
            trusted_device_token: None,
            user_agent: None,
            ip: None,
        })
        .await;

    assert!(matches!(wrong_role, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn passkey_registration_requires_full_mfa_even_inside_service_layer() {
    let (service, identities, _, _, _, _, _) = create_auth_service();
    let (identity, subject) =
        identities.add_test_identity("stepup@example.com", SubjectRole::PlatformStaff);
    let partial = CurrentSession {
        session_id: Uuid::new_v4(),
        identity_id: identity.id,
        subject_id: subject.id(),
        subject_role: SubjectRole::PlatformStaff,
        mfa_level: MfaLevel::Partial,
    };

    let begin = service.begin_passkey_registration(&partial).await;
    assert!(matches!(begin, Err(AppError::Forbidden)));
}
