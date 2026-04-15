use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Invalid email format")]
    InvalidEmailFormat,
    #[error("Password hash must use Argon2")]
    PasswordHashMustUseArgon2,
    #[error("Session token does not meet entropy requirements")]
    SessionTokenEntropyInsufficient,
    #[error("Unsupported subject role")]
    UnsupportedSubjectRole,
    #[error("Unsupported credential type")]
    UnsupportedCredentialType,
    #[error("Unsupported risk event type")]
    UnsupportedRiskEventType,
    #[error("Subject display name cannot be empty")]
    EmptySubjectDisplayName,
    #[error("Device name cannot be empty")]
    EmptyDeviceName,
    #[error("Session time range is invalid")]
    InvalidSessionTimeRange,
    #[error("Trusted device time range is invalid")]
    InvalidTrustedDeviceTimeRange,
}
