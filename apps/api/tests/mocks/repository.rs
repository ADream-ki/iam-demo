//! Mock implementations for repositories

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use iam_api::domain::{
    entities::{
        Email, HashedPassword, Identity, PasskeyCredential, PasswordCredential, RiskEvent, Session,
        Subject, SubjectRole, TrustedDevice,
    },
    ports::{IdentityRepository, RiskEventRepository, SessionRepository, TrustedDeviceRepository},
};
use iam_api::error::AppError;

/// Mock identity repository
#[derive(Debug, Default)]
pub struct MockIdentityRepository {
    identities: Arc<Mutex<HashMap<Uuid, Identity>>>,
    subjects: Arc<Mutex<HashMap<Uuid, Subject>>>,
    passwords: Arc<Mutex<HashMap<Uuid, PasswordCredential>>>,
    passkeys: Arc<Mutex<HashMap<Uuid, PasskeyCredential>>>,
    email_to_identity: Arc<Mutex<HashMap<String, Uuid>>>,
}

impl MockIdentityRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_test_identity(&self, email: &str, role: SubjectRole) -> (Identity, Subject) {
        let now = Utc::now();
        let identity_id = Uuid::new_v4();
        let subject_id = Uuid::new_v4();

        let identity = Identity {
            id: identity_id,
            email: Email::new(email).unwrap(),
            email_verified_at: Some(now),
            created_at: now,
            updated_at: now,
        };

        let subject = Subject::new(
            subject_id,
            identity_id,
            role,
            "Test User".to_string(),
            None,
            false,
            now,
        )
        .unwrap();

        let mut identities = self.identities.lock().unwrap();
        let mut subjects = self.subjects.lock().unwrap();
        let mut email_map = self.email_to_identity.lock().unwrap();

        identities.insert(identity_id, identity.clone());
        subjects.insert(subject_id, subject.clone());
        email_map.insert(email.to_lowercase(), identity_id);

        (identity, subject)
    }

    pub fn set_password(&self, identity_id: Uuid, password_hash: &str) {
        let mut passwords = self.passwords.lock().unwrap();
        // Use a valid Argon2 hash format for testing
        let hash = if password_hash.starts_with("$argon2") {
            password_hash.to_string()
        } else {
            "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g".to_string()
        };
        passwords.insert(
            identity_id,
            PasswordCredential {
                identity_id,
                password_hash: HashedPassword::new(hash).unwrap(),
            },
        );
    }

    /// Store a password credential whose hash encodes the raw password string,
    /// matching the `MockPasswordHasher` format so verify() works correctly.
    pub fn set_password_raw(&self, identity_id: Uuid, password: &str) {
        // MockPasswordHasher::hash(p) = "$argon2id$v=19$m=19456,t=2,p=1$<hex>$test"
        let hex: String = password
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let hash = format!("$argon2id$v=19$m=19456,t=2,p=1${}$test", hex);
        let mut passwords = self.passwords.lock().unwrap();
        passwords.insert(
            identity_id,
            PasswordCredential {
                identity_id,
                password_hash: HashedPassword::new(hash).unwrap(),
            },
        );
    }

    /// Add a subject for an existing identity (for multi-role testing)
    pub fn add_subject_for_identity(
        &self,
        identity_id: Uuid,
        role: SubjectRole,
        subject_id: Uuid,
    ) -> Subject {
        let now = Utc::now();
        let subject = Subject::new(
            subject_id,
            identity_id,
            role,
            "Test User".to_string(),
            None,
            false,
            now,
        )
        .unwrap();

        let mut subjects = self.subjects.lock().unwrap();
        subjects.insert(subject_id, subject.clone());
        subject
    }

    pub fn count_passkeys_for_subject(&self, subject_id: Uuid) -> usize {
        let passkeys = self.passkeys.lock().unwrap();
        passkeys
            .values()
            .filter(|passkey| passkey.subject_id == subject_id)
            .count()
    }
}

#[async_trait]
impl IdentityRepository for MockIdentityRepository {
    async fn find_identity_by_email(&self, email: &Email) -> Result<Option<Identity>, AppError> {
        let email_map = self.email_to_identity.lock().unwrap();
        let identities = self.identities.lock().unwrap();

        if let Some(id) = email_map.get(email.as_str()) {
            Ok(identities.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn find_identity_by_id(&self, identity_id: Uuid) -> Result<Option<Identity>, AppError> {
        let identities = self.identities.lock().unwrap();
        Ok(identities.get(&identity_id).cloned())
    }

    async fn mark_identity_email_verified(
        &self,
        identity_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let mut identities = self.identities.lock().unwrap();
        if let Some(identity) = identities.get_mut(&identity_id) {
            identity.email_verified_at = Some(now);
            identity.updated_at = now;
            return Ok(true);
        }
        Ok(false)
    }
    async fn find_subject_by_id(&self, subject_id: Uuid) -> Result<Option<Subject>, AppError> {
        let subjects = self.subjects.lock().unwrap();
        Ok(subjects.get(&subject_id).cloned())
    }

    async fn find_subject_by_identity_and_role(
        &self,
        identity_id: Uuid,
        role: SubjectRole,
    ) -> Result<Option<Subject>, AppError> {
        let subjects = self.subjects.lock().unwrap();
        Ok(subjects
            .values()
            .find(|s| s.identity_id() == identity_id && s.role() == role)
            .cloned())
    }

    async fn find_subject_by_email_and_role(
        &self,
        email: &Email,
        role: SubjectRole,
    ) -> Result<Option<(Identity, Subject)>, AppError> {
        let email_map = self.email_to_identity.lock().unwrap();
        let identities = self.identities.lock().unwrap();
        let subjects = self.subjects.lock().unwrap();

        if let Some(identity_id) = email_map.get(email.as_str()) {
            if let Some(identity) = identities.get(identity_id) {
                if let Some(subject) = subjects
                    .values()
                    .find(|s| s.identity_id() == *identity_id && s.role() == role)
                {
                    return Ok(Some((identity.clone(), subject.clone())));
                }
            }
        }
        Ok(None)
    }

    async fn find_password_credential(
        &self,
        identity_id: Uuid,
    ) -> Result<Option<PasswordCredential>, AppError> {
        let passwords = self.passwords.lock().unwrap();
        Ok(passwords.get(&identity_id).cloned())
    }

    async fn list_passkeys_for_subject(
        &self,
        subject_id: Uuid,
    ) -> Result<Vec<PasskeyCredential>, AppError> {
        let passkeys = self.passkeys.lock().unwrap();
        Ok(passkeys
            .values()
            .filter(|passkey| passkey.subject_id == subject_id)
            .cloned()
            .collect())
    }

    async fn insert_passkey(
        &self,
        subject_id: Uuid,
        external_id: &str,
        label: &str,
        verifier_data: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyCredential, AppError> {
        let passkey = PasskeyCredential {
            id: Uuid::new_v4(),
            subject_id,
            external_id: external_id.to_string(),
            label: label.to_string(),
            verifier_data: verifier_data.to_string(),
            created_at: now,
        };
        let mut passkeys = self.passkeys.lock().unwrap();
        passkeys.insert(passkey.id, passkey.clone());
        Ok(passkey)
    }

    async fn update_passkey_verifier_data(
        &self,
        passkey_id: Uuid,
        current: &str,
        next: &str,
    ) -> Result<bool, AppError> {
        let mut passkeys = self.passkeys.lock().unwrap();
        let Some(passkey) = passkeys.get_mut(&passkey_id) else {
            return Ok(false);
        };
        if passkey.verifier_data != current {
            return Ok(false);
        }
        passkey.verifier_data = next.to_string();
        Ok(true)
    }

    async fn ensure_subject_with_default_password(
        &self,
        email: &Email,
        role: SubjectRole,
        default_password: &str,
        _now: DateTime<Utc>,
    ) -> Result<(Identity, Subject), AppError> {
        if let Some(existing) = self.find_subject_by_email_and_role(email, role).await? {
            return Ok(existing);
        }
        let (identity, subject) = self.add_test_identity(email.as_str(), role);
        // Mark email as unverified — OTP verify must complete before any login.
        {
            let mut identities = self.identities.lock().unwrap();
            if let Some(stored) = identities.get_mut(&identity.id) {
                stored.email_verified_at = None;
            }
        }
        // Store the sentinel password so password-login tests can exercise the
        // rejection path without hitting 'password_credential_missing'.
        self.set_password_raw(identity.id, default_password);
        Ok((identity, subject))
    }
}

/// Mock session repository
#[derive(Debug, Default)]
pub struct MockSessionRepository {
    sessions: Arc<Mutex<HashMap<Uuid, Session>>>,
}

impl MockSessionRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_session(&self, session: &Session) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session.id(), session.clone());
    }

    pub fn get_session(&self, id: Uuid) -> Option<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(&id).cloned()
    }
}

#[async_trait]
impl SessionRepository for MockSessionRepository {
    async fn create_session(&self, session: &Session) -> Result<(), AppError> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session.id(), session.clone());
        Ok(())
    }

    async fn find_session_by_access_token_hash(
        &self,
        token_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<Session>, AppError> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions
            .values()
            .find(|s| s.access_token_hash() == token_hash && s.revoked_at().is_none())
            .cloned())
    }

    async fn find_session_by_refresh_token_hash(
        &self,
        refresh_token_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<Session>, AppError> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions
            .values()
            .find(|s| s.refresh_token_hash() == refresh_token_hash && s.revoked_at().is_none())
            .cloned())
    }

    async fn list_sessions_for_subject(
        &self,
        subject_id: Uuid,
        _now: DateTime<Utc>,
    ) -> Result<Vec<Session>, AppError> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions
            .values()
            .filter(|s| s.subject_id() == subject_id && s.revoked_at().is_none())
            .cloned()
            .collect())
    }

    async fn revoke_session(&self, session_id: Uuid, _subject_id: Uuid) -> Result<bool, AppError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&session_id) {
            session.revoke(Utc::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn revoke_other_sessions(
        &self,
        current_session_id: Uuid,
        subject_id: Uuid,
    ) -> Result<u64, AppError> {
        let mut sessions = self.sessions.lock().unwrap();
        let mut count = 0;
        for session in sessions.values_mut() {
            if session.subject_id() == subject_id
                && session.id() != current_session_id
                && session.revoked_at().is_none()
            {
                session.revoke(Utc::now());
                count += 1;
            }
        }
        Ok(count)
    }

    async fn upgrade_mfa(&self, session_id: Uuid, _now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&session_id) {
            session.upgrade_mfa();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn touch_session(
        &self,
        session_id: Uuid,
        access_token_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&session_id) {
            session.touch(access_token_hash.to_string(), Utc::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn rotate_session_tokens(
        &self,
        session_id: Uuid,
        _current_refresh_hash: &str,
        next_access_hash: &str,
        next_refresh_hash: &str,
        access_expires: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(&session_id) {
            session.rotate_tokens(
                next_access_hash.to_string(),
                next_refresh_hash.to_string(),
                access_expires,
                now,
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Mock trusted device repository
#[derive(Debug, Default)]
pub struct MockTrustedDeviceRepository {
    devices: Arc<Mutex<HashMap<Uuid, TrustedDevice>>>,
}

impl MockTrustedDeviceRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TrustedDeviceRepository for MockTrustedDeviceRepository {
    async fn find_trusted_device_by_token_hash(
        &self,
        subject_id: Uuid,
        token_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<TrustedDevice>, AppError> {
        let devices = self.devices.lock().unwrap();
        Ok(devices
            .values()
            .find(|d| {
                d.subject_id() == subject_id
                    && d.token_hash() == token_hash
                    && d.revoked_at().is_none()
            })
            .cloned())
    }

    async fn create_trusted_device(&self, device: &TrustedDevice) -> Result<(), AppError> {
        let mut devices = self.devices.lock().unwrap();
        devices.insert(device.id(), device.clone());
        Ok(())
    }

    async fn touch_trusted_device(
        &self,
        device_id: Uuid,
        _now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let mut devices = self.devices.lock().unwrap();
        if let Some(device) = devices.get_mut(&device_id) {
            device.touch(Utc::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn revoke_trusted_device_by_token_hash(
        &self,
        subject_id: Uuid,
        token_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let mut devices = self.devices.lock().unwrap();
        if let Some(device) = devices
            .values_mut()
            .find(|d| d.subject_id() == subject_id && d.token_hash() == token_hash)
        {
            device.revoke(Utc::now());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn revoke_trusted_devices_by_device(
        &self,
        subject_id: Uuid,
        device_name: &str,
        _user_agent: Option<&str>,
        _ip: Option<&str>,
        _now: DateTime<Utc>,
    ) -> Result<u64, AppError> {
        let mut devices = self.devices.lock().unwrap();
        let mut count = 0;
        for device in devices.values_mut() {
            if device.subject_id() == subject_id
                && device.device_name() == device_name
                && device.revoked_at().is_none()
            {
                device.revoke(Utc::now());
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Mock risk event repository
#[derive(Debug, Default)]
pub struct MockRiskEventRepository {
    events: Arc<Mutex<Vec<RiskEvent>>>,
}

impl MockRiskEventRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_events(&self) -> Vec<RiskEvent> {
        let events = self.events.lock().unwrap();
        events.clone()
    }

    pub fn count_events(&self) -> usize {
        let events = self.events.lock().unwrap();
        events.len()
    }
}

#[async_trait]
impl RiskEventRepository for MockRiskEventRepository {
    async fn create_risk_event(&self, event: &RiskEvent) -> Result<(), AppError> {
        let mut events = self.events.lock().unwrap();
        events.push(event.clone());
        Ok(())
    }
}
