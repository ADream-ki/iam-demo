use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::errors::DomainError;

/// 邮箱值对象：
/// - 统一做 `trim + lower-case` 标准化，避免同一邮箱多形态存储；
/// - 在构造时做基础格式校验，防止脏数据进入领域模型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Email(String);

impl Email {
    /// 构造并标准化邮箱值对象。
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainError> {
        let value = raw.into().trim().to_ascii_lowercase();
        if value.len() < 5 || !value.contains('@') || value.starts_with('@') || value.ends_with('@') {
            return Err(DomainError::InvalidEmailFormat);
        }

        Ok(Self(value))
    }

    /// 以只读字符串形式暴露标准化后的邮箱地址。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 密码哈希值对象：
/// - 仅接受 Argon2 格式；
/// - 使用 `SecretString` 减少日志/调试过程中的明文泄漏风险。
#[derive(Debug, Clone)]
pub struct HashedPassword(SecretString);

impl HashedPassword {
    /// 构造密码哈希值对象，并确保其符合 Argon2 格式约束。
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainError> {
        let value = raw.into();
        if !value.starts_with("$argon2") {
            return Err(DomainError::PasswordHashMustUseArgon2);
        }

        Ok(Self(SecretString::new(value.into())))
    }

    /// 暴露底层 `SecretString`，供哈希校验逻辑使用。
    pub fn expose(&self) -> &SecretString {
        &self.0
    }
}

/// 会话令牌值对象（access/refresh/trusted-device 均可复用）：
/// - 只描述“令牌本身”的最低熵要求，不承载业务语义；
/// - 业务语义由上层 `CredentialType` 与调用场景决定。
#[derive(Debug, Clone)]
pub struct SessionToken(SecretString);

impl SessionToken {
    /// 构造会话令牌值对象，并校验最小熵要求。
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainError> {
        let value = raw.into();
        if value.len() < 32 {
            return Err(DomainError::SessionTokenEntropyInsufficient);
        }

        Ok(Self(SecretString::new(value.into())))
    }

    /// 暴露底层 `SecretString`，供哈希与签发流程使用。
    pub fn expose(&self) -> &SecretString {
        &self.0
    }
}

/// 业务主体角色：
/// - 同一个 identity 可以绑定多个 subject（多角色）；
/// - role 是授权和会话隔离的核心维度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRole {
    Member,
    CommunityStaff,
    PlatformStaff,
}

impl SubjectRole {
    /// 返回角色在存储与接口层使用的稳定字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::CommunityStaff => "community_staff",
            Self::PlatformStaff => "platform_staff",
        }
    }

    /// 判断该角色默认是否要求 MFA。
    pub fn requires_mfa(&self) -> bool {
        matches!(self, Self::PlatformStaff)
    }
}

impl TryFrom<&str> for SubjectRole {
    type Error = DomainError;

    /// 将外部字符串安全地解析为领域角色枚举。
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "member" | "MEMBER" => Ok(Self::Member),
            "community_staff" | "community" | "STAFF" => Ok(Self::CommunityStaff),
            "platform_staff" | "platform" | "ADMIN" => Ok(Self::PlatformStaff),
            _ => Err(DomainError::UnsupportedSubjectRole),
        }
    }
}

/// 会话 MFA 等级：
/// - `None`：无需二次认证；
/// - `Partial`：已通过一因子，等待升级；
/// - `Full`：已完成完整认证，可访问高敏资源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaLevel {
    None,
    Partial,
    Full,
}

/// 凭证类型枚举：
/// 用于风控统计、审计归因和策略分流。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    Password,
    Otp,
    Passkey,
    Totp,
    Refresh,
}

impl CredentialType {
    /// 返回凭证类型在存储与审计中使用的稳定字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Otp => "otp",
            Self::Passkey => "passkey",
            Self::Totp => "totp",
            Self::Refresh => "refresh",
        }
    }
}

impl TryFrom<&str> for CredentialType {
    type Error = DomainError;

    /// 将外部字符串安全地解析为凭证类型枚举。
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "password" => Ok(Self::Password),
            "otp" => Ok(Self::Otp),
            "passkey" => Ok(Self::Passkey),
            "totp" => Ok(Self::Totp),
            "refresh" => Ok(Self::Refresh),
            _ => Err(DomainError::UnsupportedCredentialType),
        }
    }
}

/// 风险事件类型：
/// - 与登录/刷新等链路的限流与失败判定对应；
/// - 事件语义应保持稳定，便于审计报表和告警规则长期复用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskEventType {
    RateLimitExceeded,
    LoginFailed,
    LoginBlocked,
    RefreshFailed,
    RefreshBlocked,
}

impl RiskEventType {
    /// 返回风险事件类型在存储与审计中使用的稳定字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::LoginFailed => "login_failed",
            Self::LoginBlocked => "login_blocked",
            Self::RefreshFailed => "refresh_failed",
            Self::RefreshBlocked => "refresh_blocked",
        }
    }
}

impl TryFrom<&str> for RiskEventType {
    type Error = DomainError;

    /// 将外部字符串安全地解析为风险事件类型枚举。
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "rate_limit_exceeded" => Ok(Self::RateLimitExceeded),
            "login_failed" => Ok(Self::LoginFailed),
            "login_blocked" => Ok(Self::LoginBlocked),
            "refresh_failed" => Ok(Self::RefreshFailed),
            "refresh_blocked" => Ok(Self::RefreshBlocked),
            _ => Err(DomainError::UnsupportedRiskEventType),
        }
    }
}

pub trait Credential: Send + Sync {
    /// 返回该凭证实例对应的领域凭证类型。
    fn credential_type(&self) -> CredentialType;
}

/// 全局身份聚合根（Identity）：
/// - 表示“自然人/账号”；
/// - 不直接表示具体业务权限，权限由 Subject 承载。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: Uuid,
    pub email: Email,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Identity {
    /// 判断 identity 的邮箱是否已经完成验证。
    pub fn email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }
}

/// 业务主体（Subject）：
/// - 挂在 Identity 下，代表某个业务域中的角色身份；
/// - 会话、可信设备等均以 subject 维度隔离。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    id: Uuid,
    identity_id: Uuid,
    role: SubjectRole,
    display_name: String,
    totp_secret: Option<String>,
    passkey_enabled: bool,
    created_at: DateTime<Utc>,
}

impl Subject {
    #[allow(clippy::too_many_arguments)]
    /// 构造 Subject，并校验展示名等基础领域约束。
    pub fn new(
        id: Uuid,
        identity_id: Uuid,
        role: SubjectRole,
        display_name: String,
        totp_secret: Option<String>,
        passkey_enabled: bool,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if display_name.trim().is_empty() {
            return Err(DomainError::EmptySubjectDisplayName);
        }

        Ok(Self {
            id,
            identity_id,
            role,
            display_name,
            totp_secret,
            passkey_enabled,
            created_at,
        })
    }

    /// 返回 Subject 主键。
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// 返回所属 Identity 主键。
    pub fn identity_id(&self) -> Uuid {
        self.identity_id
    }

    /// 返回该 Subject 的角色。
    pub fn role(&self) -> SubjectRole {
        self.role
    }

    /// 返回业务展示名。
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// 返回关联的 TOTP secret（如果存在）。
    pub fn totp_secret(&self) -> Option<&str> {
        self.totp_secret.as_deref()
    }

    /// 判断该 Subject 是否已启用 Passkey。
    pub fn passkey_enabled(&self) -> bool {
        self.passkey_enabled
    }

    /// 返回 Subject 创建时间。
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// 判断该 Subject 是否配置了 TOTP。
    pub fn has_totp(&self) -> bool {
        self.totp_secret.is_some()
    }

    /// 判断该 Subject 在当前策略下是否需要 step-up MFA。
    pub fn requires_step_up_mfa(&self) -> bool {
        self.role.requires_mfa() || self.has_totp()
    }
}

/// 密码凭证：
/// - 绑定 Identity（不是 Subject），表示“同一身份的口令因子”；
/// - 登录时再结合 role 解析到具体 Subject。
#[derive(Debug, Clone)]
pub struct PasswordCredential {
    pub identity_id: Uuid,
    pub password_hash: HashedPassword,
}

impl Credential for PasswordCredential {
    /// 返回该凭证实例的类型标识。
    fn credential_type(&self) -> CredentialType {
        CredentialType::Password
    }
}

/// 会话实体：
/// - 同时保存 access/refresh 的哈希值；
/// - `access_expires_at` 与 `expires_at` 分别表达短期访问和长期会话生命周期；
/// - `revoked_at` 为软撤销标记，支持审计与并发会话管理。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    id: Uuid,
    identity_id: Uuid,
    subject_id: Uuid,
    subject_role: SubjectRole,
    access_token_hash: String,
    refresh_token_hash: String,
    device_name: String,
    user_agent: Option<String>,
    ip: Option<String>,
    mfa_level: MfaLevel,
    remember_device: bool,
    access_expires_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    /// 构造会话实体，并校验时间范围与设备名称等领域约束。
    pub fn new(
        id: Uuid,
        identity_id: Uuid,
        subject_id: Uuid,
        subject_role: SubjectRole,
        access_token_hash: String,
        refresh_token_hash: String,
        device_name: String,
        user_agent: Option<String>,
        ip: Option<String>,
        mfa_level: MfaLevel,
        remember_device: bool,
        access_expires_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        last_seen_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
    ) -> Result<Self, DomainError> {
        if device_name.trim().is_empty() {
            return Err(DomainError::EmptyDeviceName);
        }
        if access_expires_at > expires_at || last_seen_at < created_at {
            return Err(DomainError::InvalidSessionTimeRange);
        }
        if let Some(revoked_at) = revoked_at {
            if revoked_at < created_at {
                return Err(DomainError::InvalidSessionTimeRange);
            }
        }

        Ok(Self {
            id,
            identity_id,
            subject_id,
            subject_role,
            access_token_hash,
            refresh_token_hash,
            device_name,
            user_agent,
            ip,
            mfa_level,
            remember_device,
            access_expires_at,
            expires_at,
            last_seen_at,
            created_at,
            revoked_at,
        })
    }

    /// 返回会话主键。
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// 返回所属 Identity 主键。
    pub fn identity_id(&self) -> Uuid {
        self.identity_id
    }

    /// 返回所属 Subject 主键。
    pub fn subject_id(&self) -> Uuid {
        self.subject_id
    }

    /// 返回会话绑定的 Subject 角色。
    pub fn subject_role(&self) -> SubjectRole {
        self.subject_role
    }

    /// 返回 access token 的哈希值。
    pub fn access_token_hash(&self) -> &str {
        &self.access_token_hash
    }

    /// 返回 refresh token 的哈希值。
    pub fn refresh_token_hash(&self) -> &str {
        &self.refresh_token_hash
    }

    /// 返回设备名称。
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// 返回记录的 User-Agent。
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// 返回记录的来源 IP。
    pub fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }

    /// 返回当前会话的 MFA 等级。
    pub fn mfa_level(&self) -> MfaLevel {
        self.mfa_level
    }

    /// 返回该会话是否请求“记住此设备”。
    pub fn remember_device(&self) -> bool {
        self.remember_device
    }

    /// 返回 access token 的绝对过期时间。
    pub fn access_expires_at(&self) -> DateTime<Utc> {
        self.access_expires_at
    }

    /// 返回 refresh/session 的绝对过期时间。
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// 返回最后活跃时间。
    pub fn last_seen_at(&self) -> DateTime<Utc> {
        self.last_seen_at
    }

    /// 返回会话创建时间。
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// 返回撤销时间；未撤销则为空。
    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    /// 软撤销当前会话。
    pub fn revoke(&mut self, now: DateTime<Utc>) {
        self.revoked_at = Some(now);
    }

    /// 将会话 MFA 等级提升为完整认证。
    pub fn upgrade_mfa(&mut self) {
        self.mfa_level = MfaLevel::Full;
    }

    /// 更新 access token 哈希与最后活跃时间。
    pub fn touch(&mut self, access_token_hash: String, now: DateTime<Utc>) {
        self.access_token_hash = access_token_hash;
        self.last_seen_at = now;
    }

    /// 轮换 access/refresh token，并刷新访问过期时间与活跃时间。
    pub fn rotate_tokens(
        &mut self,
        access_token_hash: String,
        refresh_token_hash: String,
        access_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) {
        self.access_token_hash = access_token_hash;
        self.refresh_token_hash = refresh_token_hash;
        self.access_expires_at = access_expires_at;
        self.last_seen_at = now;
    }

    /// 判断 access token 在给定时刻是否仍可用于访问。
    pub fn is_access_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.access_expires_at > now && self.expires_at > now
    }

    /// 判断会话在给定时刻是否整体仍然有效。
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }

    /// 判断会话是否属于指定 Subject。
    pub fn belongs_to_subject(&self, subject_id: Uuid) -> bool {
        self.subject_id == subject_id
    }
}

/// 可信设备实体：
/// - 与 Subject 绑定，防止跨角色复用；
/// - 通过 token hash 标识设备信任状态，支持过期与撤销。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    id: Uuid,
    identity_id: Uuid,
    subject_id: Uuid,
    subject_role: SubjectRole,
    token_hash: String,
    device_name: String,
    user_agent: Option<String>,
    ip: Option<String>,
    expires_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TrustedDevice {
    #[allow(clippy::too_many_arguments)]
    /// 构造可信设备实体，并校验时间范围与设备名称等领域约束。
    pub fn new(
        id: Uuid,
        identity_id: Uuid,
        subject_id: Uuid,
        subject_role: SubjectRole,
        token_hash: String,
        device_name: String,
        user_agent: Option<String>,
        ip: Option<String>,
        expires_at: DateTime<Utc>,
        last_seen_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
    ) -> Result<Self, DomainError> {
        if device_name.trim().is_empty() {
            return Err(DomainError::EmptyDeviceName);
        }
        if expires_at <= created_at || last_seen_at < created_at {
            return Err(DomainError::InvalidTrustedDeviceTimeRange);
        }
        if let Some(revoked_at) = revoked_at {
            if revoked_at < created_at {
                return Err(DomainError::InvalidTrustedDeviceTimeRange);
            }
        }

        Ok(Self {
            id,
            identity_id,
            subject_id,
            subject_role,
            token_hash,
            device_name,
            user_agent,
            ip,
            expires_at,
            last_seen_at,
            created_at,
            revoked_at,
        })
    }

    /// 返回可信设备主键。
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// 返回所属 Identity 主键。
    pub fn identity_id(&self) -> Uuid {
        self.identity_id
    }

    /// 返回所属 Subject 主键。
    pub fn subject_id(&self) -> Uuid {
        self.subject_id
    }

    /// 返回设备绑定的 Subject 角色。
    pub fn subject_role(&self) -> SubjectRole {
        self.subject_role
    }

    /// 返回可信设备 token 的哈希值。
    pub fn token_hash(&self) -> &str {
        &self.token_hash
    }

    /// 返回设备名称。
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// 返回记录的 User-Agent。
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// 返回记录的来源 IP。
    pub fn ip(&self) -> Option<&str> {
        self.ip.as_deref()
    }

    /// 返回可信设备绝对过期时间。
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// 返回最后活跃时间。
    pub fn last_seen_at(&self) -> DateTime<Utc> {
        self.last_seen_at
    }

    /// 返回创建时间。
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// 返回撤销时间；未撤销则为空。
    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    /// 更新可信设备最后活跃时间。
    pub fn touch(&mut self, now: DateTime<Utc>) {
        self.last_seen_at = now;
    }

    /// 软撤销可信设备。
    pub fn revoke(&mut self, now: DateTime<Utc>) {
        self.revoked_at = Some(now);
    }

    /// 判断可信设备在给定时刻是否仍然有效。
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// Passkey 凭证实体：
/// - 绑定 Subject；
/// - `external_id` 用于跨系统唯一定位凭证；
/// - `verifier_data` 保存后续认证所需验证材料（由具体实现解释）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: Uuid,
    pub subject_id: Uuid,
    pub external_id: String,
    pub label: String,
    pub verifier_data: String,
    pub created_at: DateTime<Utc>,
}

impl Credential for PasskeyCredential {
    /// 返回该凭证实例的类型标识。
    fn credential_type(&self) -> CredentialType {
        CredentialType::Passkey
    }
}

/// 当前会话快照：
/// - 用于在 HTTP 适配层和应用层之间传递“已认证主体上下文”；
/// - 字段最小化，避免泄露不必要内部状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentSession {
    pub session_id: Uuid,
    pub identity_id: Uuid,
    pub subject_id: Uuid,
    pub subject_role: SubjectRole,
    pub mfa_level: MfaLevel,
}

/// 风险事件实体：
/// - 作为审计日志入库模型；
/// - 允许部分字段为空（例如匿名限流事件），以兼容不同链路的证据可得性。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvent {
    pub id: Uuid,
    pub event_type: RiskEventType,
    pub credential_type: Option<CredentialType>,
    pub identity_id: Option<Uuid>,
    pub email: Option<String>,
    pub subject_role: Option<SubjectRole>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub detail: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::{CredentialType, Email, HashedPassword, RiskEventType, SessionToken};

    #[test]
    /// 验证邮箱值对象会拒绝明显非法格式。
    fn email_validates_format() {
        assert!(Email::new("valid@example.com").is_ok());
        assert!(Email::new("invalid").is_err());
    }

    #[test]
    /// 验证密码哈希值对象只接受 Argon2 格式。
    fn password_hash_must_be_argon2() {
        assert!(HashedPassword::new("$argon2id$v=19$m=19456,t=2,p=1$abc$def").is_ok());
        assert!(HashedPassword::new("plain").is_err());
    }

    #[test]
    /// 验证会话令牌值对象要求最小熵长度。
    fn session_token_requires_entropy() {
        assert!(SessionToken::new("1234").is_err());
        assert!(SessionToken::new("abcdefghijklmnopqrstuvwxyz0123456789").is_ok());
    }

    #[test]
    /// 验证凭证类型字符串与枚举之间可正确往返。
    fn credential_type_supports_otp() {
        assert_eq!(CredentialType::try_from("otp").unwrap().as_str(), "otp");
        assert_eq!(CredentialType::try_from("refresh").unwrap().as_str(), "refresh");
    }

    #[test]
    /// 验证风险事件类型字符串与枚举之间可正确往返。
    fn risk_event_type_round_trips() {
        assert_eq!(RiskEventType::try_from("login_failed").unwrap().as_str(), "login_failed");
        assert_eq!(RiskEventType::try_from("refresh_failed").unwrap().as_str(), "refresh_failed");
    }
}
