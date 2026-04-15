//! Security service tests

use std::sync::Arc;

use iam_api::{
    application::security::SecurityService,
    domain::entities::{CredentialType, Email, SubjectRole},
    domain::ports::{Clock, RiskEventRepository, SecurityStore},
    error::AppError,
};

mod mocks;
use mocks::{MockClock, MockRiskEventRepository, MockSecurityStore};

/// Extension trait for MockSecurityStore to allow setting counts directly
trait MockSecurityStoreExt {
    fn set_count(&self, key: &str, count: u64, ttl: Option<u64>);
    fn get_raw_count(&self, key: &str) -> Option<u64>;
}

impl MockSecurityStoreExt for MockSecurityStore {
    fn set_count(&self, key: &str, count: u64, ttl: Option<u64>) {
        self.set_count_internal(key, count, ttl);
    }

    fn get_raw_count(&self, key: &str) -> Option<u64> {
        self.get_count_internal(key)
    }
}

fn create_security_service() -> (
    SecurityService,
    Arc<MockSecurityStore>,
    Arc<MockRiskEventRepository>,
    Arc<MockClock>,
) {
    let store = Arc::new(MockSecurityStore::new());
    let risk_events = Arc::new(MockRiskEventRepository::new());
    let clock = Arc::new(MockClock::new());

    let service = SecurityService::new(
        Arc::clone(&store) as Arc<dyn SecurityStore>,
        Arc::clone(&risk_events) as Arc<dyn RiskEventRepository>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        5,   // public_rate_limit_max
        60,  // public_rate_limit_window_seconds
        5,   // login_failure_limit
        20,  // login_failure_source_limit
        900, // login_failure_window_seconds
        5,   // otp_request_limit
        300, // otp_request_window_seconds
    );

    (service, store, risk_events, clock)
}

#[tokio::test]
async fn allows_requests_under_limit() {
    let (service, _, _, _) = create_security_service();

    for _ in 0..5 {
        let result: Result<(), AppError> = service
            .enforce_public_auth_rate_limit("/api/auth/password/login", Some("192.168.1.1"), None)
            .await;
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn blocks_requests_over_limit() {
    let (service, _, risk_events, _) = create_security_service();

    // First 5 requests should pass
    for _ in 0..5 {
        let _: Result<(), AppError> = service
            .enforce_public_auth_rate_limit("/api/auth/password/login", Some("192.168.1.2"), None)
            .await;
    }

    // 6th request should be blocked
    let result: Result<(), AppError> = service
        .enforce_public_auth_rate_limit("/api/auth/password/login", Some("192.168.1.2"), None)
        .await;
    assert!(matches!(result, Err(AppError::RateLimited(_))));

    // Risk event should be recorded
    assert_eq!(risk_events.count_events(), 1);
}

#[tokio::test]
async fn tracks_different_ips_separately() {
    let (service, _, _, _) = create_security_service();

    // 5 requests from IP 1
    for _ in 0..5 {
        let _: Result<(), AppError> = service
            .enforce_public_auth_rate_limit("/api/auth/password/login", Some("10.0.0.1"), None)
            .await;
    }

    // IP 2 should still be allowed
    let result: Result<(), AppError> = service
        .enforce_public_auth_rate_limit("/api/auth/password/login", Some("10.0.0.2"), None)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn allows_login_under_failure_limit() {
    let (service, store, _, _) = create_security_service();
    let email = Email::new("test@example.com").unwrap();

    // Pre-populate with 4 failures (under limit of 5)
    let key = format!("auth:failures:account:password:member:test@example.com");
    store.set_count(&key, 4, Some(900));

    let result: Result<(), AppError> = service
        .assert_login_allowed(
            CredentialType::Password,
            &email,
            SubjectRole::Member,
            Some("192.168.1.1"),
            None,
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn blocks_login_at_failure_limit() {
    let (service, store, risk_events, _) = create_security_service();
    let email = Email::new("blocked@example.com").unwrap();

    // Pre-populate with 5 failures (at limit)
    let key = format!("auth:failures:account:password:member:blocked@example.com");
    store.set_count(&key, 5, Some(900));

    let result: Result<(), AppError> = service
        .assert_login_allowed(
            CredentialType::Password,
            &email,
            SubjectRole::Member,
            Some("192.168.1.1"),
            None,
        )
        .await;

    assert!(matches!(result, Err(AppError::RateLimited(_))));
    assert_eq!(risk_events.count_events(), 1);
}

#[tokio::test]
async fn records_login_failure() {
    let (service, store, risk_events, _) = create_security_service();
    let email = Email::new("fail@example.com").unwrap();

    let result: Result<(), AppError> = service
        .record_login_failure(
            CredentialType::Password,
            &email,
            SubjectRole::Member,
            Some("192.168.1.1"),
            None,
            "invalid_password",
        )
        .await;

    assert!(result.is_ok());

    let key = format!("auth:failures:account:password:member:fail@example.com");
    assert_eq!(store.get_raw_count(&key), Some(1));
    assert_eq!(risk_events.count_events(), 1);
}

#[tokio::test]
async fn clears_failures_on_success() {
    let (service, store, _, _) = create_security_service();
    let email = Email::new("clear@example.com").unwrap();

    // Set up some failures
    let key = format!("auth:failures:account:password:member:clear@example.com");
    store.set_count(&key, 3, Some(900));

    let result: Result<(), AppError> = service
        .clear_login_failures(CredentialType::Password, &email, SubjectRole::Member)
        .await;
    assert!(result.is_ok());

    assert_eq!(store.get_raw_count(&key), None);
}

#[tokio::test]
async fn blocks_by_source_after_too_many_failures() {
    let (service, store, risk_events, _) = create_security_service();

    // Set source failures to limit
    let source_key = "auth:failures:source:password:member:192.168.1.100";
    store.set_count(source_key, 20, Some(900));

    let email = Email::new("victim@example.com").unwrap();
    let result: Result<(), AppError> = service
        .assert_login_allowed(
            CredentialType::Password,
            &email,
            SubjectRole::Member,
            Some("192.168.1.100"),
            None,
        )
        .await;

    assert!(matches!(result, Err(AppError::RateLimited(_))));
    assert_eq!(risk_events.count_events(), 1);
}

#[tokio::test]
async fn allows_otp_requests_under_limit() {
    let (service, _, _, _) = create_security_service();
    let email = Email::new("otp@example.com").unwrap();

    for _ in 0..5 {
        let result: Result<(), AppError> = service
            .assert_otp_request_allowed(&email, SubjectRole::Member, None)
            .await;
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn blocks_otp_requests_over_limit() {
    let (service, _, risk_events, _) = create_security_service();
    let email = Email::new("spam@example.com").unwrap();

    // Use up the limit
    for _ in 0..5 {
        let _: Result<(), AppError> = service
            .assert_otp_request_allowed(&email, SubjectRole::Member, None)
            .await;
    }

    // 6th should be blocked
    let result: Result<(), AppError> = service
        .assert_otp_request_allowed(&email, SubjectRole::Member, None)
        .await;
    assert!(matches!(result, Err(AppError::RateLimited(_))));
    assert_eq!(risk_events.count_events(), 1);
}
