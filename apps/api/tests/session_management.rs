//! Session management tests

use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use iam_api::{
    domain::entities::{MfaLevel, Session, SubjectRole},
    domain::ports::SessionRepository,
};

mod mocks;
use mocks::MockSessionRepository;

fn create_test_session(subject_id: Uuid, mfa_level: MfaLevel) -> Session {
    let now = Utc::now();
    Session::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        subject_id,
        SubjectRole::Member,
        format!("access_{}", Uuid::new_v4()),
        format!("refresh_{}", Uuid::new_v4()),
        "Test Device".to_string(),
        Some("Test Agent".to_string()),
        Some("192.168.1.1".to_string()),
        mfa_level,
        false,
        now + Duration::minutes(15),
        now + Duration::hours(168),
        now,
        now,
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn session_has_correct_mfa_level() {
    let session = create_test_session(Uuid::new_v4(), MfaLevel::None);
    assert_eq!(session.mfa_level(), MfaLevel::None);
    assert!(session.expires_at() > Utc::now());
    assert!(session.access_expires_at() > Utc::now());
}

#[tokio::test]
async fn create_and_find_session() {
    let repo = MockSessionRepository::new();
    let session = create_test_session(Uuid::new_v4(), MfaLevel::None);

    <MockSessionRepository as SessionRepository>::create_session(&repo, &session)
        .await
        .unwrap();

    let found = repo
        .find_session_by_access_token_hash(session.access_token_hash(), Utc::now())
        .await
        .unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id(), session.id());
}

#[tokio::test]
async fn find_by_refresh_token_hash() {
    let repo = MockSessionRepository::new();
    let session = create_test_session(Uuid::new_v4(), MfaLevel::None);

    <MockSessionRepository as SessionRepository>::create_session(&repo, &session)
        .await
        .unwrap();

    let found = repo
        .find_session_by_refresh_token_hash(session.refresh_token_hash(), Utc::now())
        .await
        .unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id(), session.id());
}

#[tokio::test]
async fn revoke_session() {
    let repo = MockSessionRepository::new();
    let session = create_test_session(Uuid::new_v4(), MfaLevel::None);

    <MockSessionRepository as SessionRepository>::create_session(&repo, &session)
        .await
        .unwrap();

    let revoked = repo
        .revoke_session(session.id(), session.subject_id())
        .await
        .unwrap();
    assert!(revoked);

    // Should not find after revocation
    let found = repo
        .find_session_by_access_token_hash(session.access_token_hash(), Utc::now())
        .await
        .unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn revoke_other_sessions() {
    let repo = MockSessionRepository::new();
    let subject_id = Uuid::new_v4();

    // Create multiple sessions for the same subject
    let current = create_test_session(subject_id, MfaLevel::None);
    let other1 = create_test_session(subject_id, MfaLevel::None);
    let other2 = create_test_session(subject_id, MfaLevel::None);

    <MockSessionRepository as SessionRepository>::create_session(&repo, &current)
        .await
        .unwrap();
    <MockSessionRepository as SessionRepository>::create_session(&repo, &other1)
        .await
        .unwrap();
    <MockSessionRepository as SessionRepository>::create_session(&repo, &other2)
        .await
        .unwrap();

    let count = repo
        .revoke_other_sessions(current.id(), subject_id)
        .await
        .unwrap();
    assert_eq!(count, 2);

    // Current session should still exist
    let found_current = repo.get_session(current.id());
    assert!(found_current.is_some());
    assert!(found_current.unwrap().revoked_at().is_none());
}

#[tokio::test]
async fn upgrade_mfa_level() {
    let repo = MockSessionRepository::new();
    let session = create_test_session(Uuid::new_v4(), MfaLevel::Partial);

    <MockSessionRepository as SessionRepository>::create_session(&repo, &session)
        .await
        .unwrap();

    repo.upgrade_mfa(session.id(), Utc::now()).await.unwrap();

    let found = repo.get_session(session.id()).unwrap();
    assert_eq!(found.mfa_level(), MfaLevel::Full);
}

#[tokio::test]
async fn list_sessions_for_subject() {
    let repo = MockSessionRepository::new();
    let subject_id = Uuid::new_v4();

    // Create sessions for subject
    let s1 = create_test_session(subject_id, MfaLevel::None);
    let s2 = create_test_session(subject_id, MfaLevel::None);
    let s3 = create_test_session(Uuid::new_v4(), MfaLevel::None); // Different subject

    <MockSessionRepository as SessionRepository>::create_session(&repo, &s1)
        .await
        .unwrap();
    <MockSessionRepository as SessionRepository>::create_session(&repo, &s2)
        .await
        .unwrap();
    <MockSessionRepository as SessionRepository>::create_session(&repo, &s3)
        .await
        .unwrap();

    let sessions = repo
        .list_sessions_for_subject(subject_id, Utc::now())
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn rotate_tokens_updates_both_hashes() {
    let repo = MockSessionRepository::new();
    let session = create_test_session(Uuid::new_v4(), MfaLevel::None);

    <MockSessionRepository as SessionRepository>::create_session(&repo, &session)
        .await
        .unwrap();

    let new_access = "new_access_hash";
    let new_refresh = "new_refresh_hash";

    let success = repo
        .rotate_session_tokens(
            session.id(),
            session.refresh_token_hash(),
            new_access,
            new_refresh,
            Utc::now() + Duration::minutes(15),
            Utc::now(),
        )
        .await
        .unwrap();

    assert!(success);

    let found = repo.get_session(session.id()).unwrap();
    assert_eq!(found.access_token_hash(), new_access);
    assert_eq!(found.refresh_token_hash(), new_refresh);
}
