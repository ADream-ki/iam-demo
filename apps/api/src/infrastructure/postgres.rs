use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    domain::{
        entities::{
            Email, HashedPassword, Identity, MfaLevel, PasskeyCredential, PasswordCredential,
            RiskEvent, Session, Subject, SubjectRole, TrustedDevice,
        },
        ports::{
            IdentityRepository, PasswordHasher, RiskEventRepository, SessionRepository,
            TrustedDeviceRepository,
        },
    },
    error::AppError,
};

/// èº«ä»½ä¸Žä¸»ä½“èšåˆçš„ PostgreSQL ä»“å‚¨å®žçŽ°ã€‚
///
/// è¯¥ä»“å‚¨è´Ÿè´£ identity/subject/credential ç­‰è¯»å†™ï¼Œå¹¶ä¿æŒé¢†åŸŸæ¨¡åž‹çº¦æŸã€‚
pub struct PostgresIdentityRepository {
    pool: PgPool,
    hasher: Arc<dyn PasswordHasher>,
}

impl PostgresIdentityRepository {
    /// 构造 Identity 仓储实现。
    pub fn new(pool: PgPool, hasher: Arc<dyn PasswordHasher>) -> Self {
        Self { pool, hasher }
    }
}

/// ä¼šè¯èšåˆçš„ PostgreSQL ä»“å‚¨å®žçŽ°ã€‚
pub struct PostgresSessionRepository {
    pool: PgPool,
}

impl PostgresSessionRepository {
    /// 构造 Session 仓储实现。
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// ä¿¡ä»»è®¾å¤‡èšåˆçš„ PostgreSQL ä»“å‚¨å®žçŽ°ã€‚
pub struct PostgresTrustedDeviceRepository {
    pool: PgPool,
}

impl PostgresTrustedDeviceRepository {
    /// 构造 Trusted Device 仓储实现。
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// é£Žé™©äº‹ä»¶ä»“å‚¨å®žçŽ°ï¼Œç”¨äºŽç™»å½•å¤±è´¥ã€é™æµè§¦å‘ç­‰å®‰å…¨å®¡è®¡ã€‚
pub struct PostgresRiskEventRepository {
    pool: PgPool,
}

impl PostgresRiskEventRepository {
    /// 构造风险事件仓储实现。
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// å°†æ•°æ®åº“ä¸­çš„è§’è‰²å­—ç¬¦ä¸²æ˜ å°„ä¸ºé¢†åŸŸè§’è‰²æžšä¸¾ã€‚
fn parse_role(raw: &str) -> Result<SubjectRole, AppError> {
    Ok(SubjectRole::try_from(raw)?)
}

/// å°†æ•°æ®åº“ä¸­çš„ mfa_level å­—æ®µæ˜ å°„ä¸ºé¢†åŸŸæžšä¸¾ã€‚
fn parse_mfa(raw: &str) -> Result<MfaLevel, AppError> {
    match raw {
        "none" => Ok(MfaLevel::None),
        "partial" => Ok(MfaLevel::Partial),
        "full" => Ok(MfaLevel::Full),
        _ => Err(AppError::Infrastructure(
            "invalid mfa level in database".to_string(),
        )),
    }
}

/// è¡Œæ•°æ® -> `Identity` é¢†åŸŸå¯¹è±¡æ˜ å°„ã€‚
fn map_identity(row: &sqlx::postgres::PgRow) -> Result<Identity, AppError> {
    Ok(Identity {
        id: row.try_get("id")?,
        email: Email::new(row.try_get::<String, _>("email")?)?,
        email_verified_at: row.try_get("email_verified_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// è¡Œæ•°æ® -> `Subject` é¢†åŸŸå¯¹è±¡æ˜ å°„ã€‚
///
/// `passkey_count > 0` è¢«æŠ˜å ä¸º `passkey_enabled`ï¼Œä½œä¸ºç™»å½•å†³ç­–è¾“å…¥ã€‚
fn map_subject(row: &sqlx::postgres::PgRow) -> Result<Subject, AppError> {
    Subject::new(
        row.try_get("subject_id")?,
        row.try_get("identity_id")?,
        parse_role(&row.try_get::<String, _>("role")?)?,
        row.try_get("display_name")?,
        row.try_get("totp_secret")?,
        row.try_get::<i64, _>("passkey_count")? > 0,
        row.try_get("subject_created_at")?,
    )
    .map_err(Into::into)
}

/// è¡Œæ•°æ® -> `Session` é¢†åŸŸå¯¹è±¡æ˜ å°„ã€‚
fn map_session(row: sqlx::postgres::PgRow) -> Result<Session, AppError> {
    Session::new(
        row.try_get("id")?,
        row.try_get("identity_id")?,
        row.try_get("subject_id")?,
        parse_role(&row.try_get::<String, _>("subject_role")?)?,
        row.try_get("token_hash")?,
        row.try_get("refresh_token_hash")?,
        row.try_get("device_name")?,
        row.try_get("user_agent")?,
        row.try_get("ip")?,
        parse_mfa(&row.try_get::<String, _>("mfa_level")?)?,
        row.try_get("remember_device")?,
        row.try_get("access_expires_at")?,
        row.try_get("expires_at")?,
        row.try_get("last_seen_at")?,
        row.try_get("created_at")?,
        row.try_get("revoked_at")?,
    )
    .map_err(Into::into)
}

/// è¡Œæ•°æ® -> `TrustedDevice` é¢†åŸŸå¯¹è±¡æ˜ å°„ã€‚
fn map_trusted_device(row: sqlx::postgres::PgRow) -> Result<TrustedDevice, AppError> {
    TrustedDevice::new(
        row.try_get("id")?,
        row.try_get("identity_id")?,
        row.try_get("subject_id")?,
        parse_role(&row.try_get::<String, _>("subject_role")?)?,
        row.try_get("token_hash")?,
        row.try_get("device_name")?,
        row.try_get("user_agent")?,
        row.try_get("ip")?,
        row.try_get("expires_at")?,
        row.try_get("last_seen_at")?,
        row.try_get("created_at")?,
        row.try_get("revoked_at")?,
    )
    .map_err(Into::into)
}

#[async_trait]
impl IdentityRepository for PostgresIdentityRepository {
    /// 按邮箱查找 Identity。
    async fn find_identity_by_email(&self, email: &Email) -> Result<Option<Identity>, AppError> {
        let row = sqlx::query(
            r#"
            select id, email, email_verified_at, created_at, updated_at
            from identities
            where email = $1
            "#,
        )
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(map_identity).transpose()
    }

    /// 按主键查找 Identity。
    async fn find_identity_by_id(&self, identity_id: Uuid) -> Result<Option<Identity>, AppError> {
        let row = sqlx::query(
            r#"
            select id, email, email_verified_at, created_at, updated_at
            from identities
            where id = $1
            "#,
        )
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(map_identity).transpose()
    }

    /// 标记邮箱已验证；若已验证则保持幂等。
    async fn mark_identity_email_verified(
        &self,
        identity_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            update identities
            set email_verified_at = coalesce(email_verified_at, $2),
                updated_at = $2
            where id = $1
            "#,
        )
        .bind(identity_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 按 Subject 主键查找主体聚合。
    async fn find_subject_by_id(&self, subject_id: Uuid) -> Result<Option<Subject>, AppError> {
        let row = sqlx::query(
            r#"
            select s.id as subject_id, s.identity_id, s.role, s.display_name, s.totp_secret,
                   s.created_at as subject_created_at, count(p.id) as passkey_count
            from subjects s
            left join passkey_credentials p on p.subject_id = s.id
            where s.id = $1
            group by s.id
            "#,
        )
        .bind(subject_id)
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(map_subject).transpose()
    }

    /// 按 identity + role 查找对应 Subject。
    async fn find_subject_by_identity_and_role(
        &self,
        identity_id: Uuid,
        role: SubjectRole,
    ) -> Result<Option<Subject>, AppError> {
        let row = sqlx::query(
            r#"
            select s.id as subject_id, s.identity_id, s.role, s.display_name, s.totp_secret,
                   s.created_at as subject_created_at, count(p.id) as passkey_count
            from subjects s
            left join passkey_credentials p on p.subject_id = s.id
            where s.identity_id = $1 and s.role = $2
            group by s.id
            "#,
        )
        .bind(identity_id)
        .bind(role.as_str())
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(map_subject).transpose()
    }

    /// 按邮箱 + role 联表查找 Identity 与 Subject。
    async fn find_subject_by_email_and_role(
        &self,
        email: &Email,
        role: SubjectRole,
    ) -> Result<Option<(Identity, Subject)>, AppError> {
        let row = sqlx::query(
            r#"
            select i.id, i.email, i.email_verified_at, i.created_at, i.updated_at,
                   s.id as subject_id, s.identity_id, s.role, s.display_name, s.totp_secret,
                   s.created_at as subject_created_at, count(p.id) as passkey_count
            from identities i
            join subjects s on s.identity_id = i.id
            left join passkey_credentials p on p.subject_id = s.id
            where i.email = $1 and s.role = $2
            group by i.id, s.id
            "#,
        )
        .bind(email.as_str())
        .bind(role.as_str())
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref()
            .map(|row| Ok((map_identity(row)?, map_subject(row)?)))
            .transpose()
    }

    /// 查找某个 Identity 绑定的密码凭证。
    async fn find_password_credential(
        &self,
        identity_id: Uuid,
    ) -> Result<Option<PasswordCredential>, AppError> {
        let row = sqlx::query(
            r#"
            select identity_id, password_hash
            from password_credentials
            where identity_id = $1
            limit 1
            "#,
        )
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            Ok(PasswordCredential {
                identity_id: row.try_get("identity_id")?,
                password_hash: HashedPassword::new(row.try_get::<String, _>("password_hash")?)?,
            })
        })
        .transpose()
    }

    /// 列出某个 Subject 下已注册的全部 Passkey。
    async fn list_passkeys_for_subject(
        &self,
        subject_id: Uuid,
    ) -> Result<Vec<PasskeyCredential>, AppError> {
        let rows = sqlx::query(
            r#"
            select id, subject_id, external_id, label, verifier_data, created_at
            from passkey_credentials
            where subject_id = $1
            order by created_at asc
            "#,
        )
        .bind(subject_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(PasskeyCredential {
                    id: row.try_get("id")?,
                    subject_id: row.try_get("subject_id")?,
                    external_id: row.try_get("external_id")?,
                    label: row.try_get("label")?,
                    verifier_data: row.try_get("verifier_data")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    /// 为 Subject 插入一条新的 Passkey 凭证记录。
    async fn insert_passkey(
        &self,
        subject_id: Uuid,
        external_id: &str,
        label: &str,
        verifier_data: &str,
        now: DateTime<Utc>,
    ) -> Result<PasskeyCredential, AppError> {
        let row = sqlx::query(
            r#"
            insert into passkey_credentials (id, subject_id, external_id, label, verifier_data, created_at)
            values ($1, $2, $3, $4, $5, $6)
            returning id, subject_id, external_id, label, verifier_data, created_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(subject_id)
        .bind(external_id)
        .bind(label)
        .bind(verifier_data)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(PasskeyCredential {
            id: row.try_get("id")?,
            subject_id: row.try_get("subject_id")?,
            external_id: row.try_get("external_id")?,
            label: row.try_get("label")?,
            verifier_data: row.try_get("verifier_data")?,
            created_at: row.try_get("created_at")?,
        })
    }

    /// 以乐观并发方式更新 Passkey verifier_data。
    async fn update_passkey_verifier_data(
        &self,
        passkey_id: Uuid,
        current_verifier_data: &str,
        next_verifier_data: &str,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            update passkey_credentials
            set verifier_data = $3
            where id = $1 and verifier_data = $2
            "#,
        )
        .bind(passkey_id)
        .bind(current_verifier_data)
        .bind(next_verifier_data)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 在 OTP 自助注册场景下确保 identity、password credential 与 subject 存在。
    async fn ensure_subject_with_default_password(
        &self,
        email: &Email,
        role: SubjectRole,
        default_password: &str,
        now: DateTime<Utc>,
    ) -> Result<(Identity, Subject), AppError> {
        let mut tx = self.pool.begin().await?;
        let identity = if let Some(row) = sqlx::query(
            r#"
            select id, email, email_verified_at, created_at, updated_at
            from identities
            where email = $1
            "#,
        )
        .bind(email.as_str())
        .fetch_optional(&mut *tx)
        .await?
        {
            map_identity(&row)?
        } else {
            let row = sqlx::query(
                r#"
                insert into identities (id, email, email_verified_at, created_at, updated_at)
                values ($1, $2, null, $3, $4)
                returning id, email, email_verified_at, created_at, updated_at
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(email.as_str())
            .bind(now)
            .bind(now)
            .fetch_one(&mut *tx)
            .await?;
            map_identity(&row)?
        };

        let password_hash = self.hasher.hash(default_password)?;
        sqlx::query(
            r#"
            insert into password_credentials (id, identity_id, password_hash, created_at)
            values ($1, $2, $3, $4)
            on conflict (identity_id) do nothing
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(identity.id)
        .bind(password_hash)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        let default_display_name = email
            .as_str()
            .split('@')
            .next()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("New User")
            .to_string();

        sqlx::query(
            r#"
            insert into subjects (id, identity_id, role, display_name, totp_secret, created_at)
            values ($1, $2, $3, $4, null, $5)
            on conflict (identity_id, role) do nothing
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(identity.id)
        .bind(role.as_str())
        .bind(default_display_name)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        let subject_row = sqlx::query(
            r#"
            select s.id as subject_id, s.identity_id, s.role, s.display_name, s.totp_secret,
                   s.created_at as subject_created_at, count(p.id) as passkey_count
            from subjects s
            left join passkey_credentials p on p.subject_id = s.id
            where s.identity_id = $1 and s.role = $2
            group by s.id
            "#,
        )
        .bind(identity.id)
        .bind(role.as_str())
        .fetch_one(&mut *tx)
        .await?;
        let subject = map_subject(&subject_row)?;

        tx.commit().await?;
        Ok((identity, subject))
    }

}

impl PostgresIdentityRepository {
    /// 初始化本地演示账号与主体数据，便于开发和手工联调。
    pub async fn ensure_demo_seed(&self, now: DateTime<Utc>) -> Result<(), AppError> {
        let identities = vec![
            (
                Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                "alex@example.com",
                "Passw0rd!",
                vec![
                    (
                        Uuid::parse_str("21111111-1111-1111-1111-111111111111").unwrap(),
                        "member",
                        "Alex Member",
                        None,
                    ),
                    (
                        Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
                        "community_staff",
                        "Alex Community",
                        None,
                    ),
                ],
            ),
            (
                Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
                "platform@example.com",
                "Platf0rm!",
                vec![(
                    Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap(),
                    "platform_staff",
                    "Taylor Platform",
                    Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
                )],
            ),
        ];

        for (identity_id, email, password, subjects) in identities {
            sqlx::query(
                r#"
                insert into identities (id, email, email_verified_at, created_at, updated_at)
                values ($1, $2, $3, $4, $5)
                on conflict (email) do nothing
                "#,
            )
            .bind(identity_id)
            .bind(email)
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(&self.pool)
            .await?;

            let password_hash = self.hasher.hash(password)?;
            sqlx::query(
                r#"
                insert into password_credentials (id, identity_id, password_hash, created_at)
                values ($1, $2, $3, $4)
                on conflict (identity_id) do nothing
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(identity_id)
            .bind(password_hash)
            .bind(now)
            .execute(&self.pool)
            .await?;

            for (subject_id, role, display_name, totp_secret) in subjects {
                sqlx::query(
                    r#"
                    insert into subjects (id, identity_id, role, display_name, totp_secret, created_at)
                    values ($1, $2, $3, $4, $5, $6)
                    on conflict (identity_id, role) do update
                    set display_name = excluded.display_name,
                        totp_secret = excluded.totp_secret
                    "#,
                )
                .bind(subject_id)
                .bind(identity_id)
                .bind(role)
                .bind(display_name)
                .bind(totp_secret)
                .bind(now)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    /// 持久化新创建的会话记录。
    async fn create_session(&self, session: &Session) -> Result<(), AppError> {
        sqlx::query(
            r#"
            insert into sessions (
                id, identity_id, subject_id, subject_role, token_hash, refresh_token_hash, device_name, user_agent, ip,
                mfa_level, remember_device, access_expires_at, expires_at, last_seen_at, created_at, revoked_at
            )
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            "#,
        )
        .bind(session.id())
        .bind(session.identity_id())
        .bind(session.subject_id())
        .bind(session.subject_role().as_str())
        .bind(session.access_token_hash())
        .bind(session.refresh_token_hash())
        .bind(session.device_name())
        .bind(session.user_agent())
        .bind(session.ip())
        .bind(match session.mfa_level() {
            MfaLevel::None => "none",
            MfaLevel::Partial => "partial",
            MfaLevel::Full => "full",
        })
        .bind(session.remember_device())
        .bind(session.access_expires_at())
        .bind(session.expires_at())
        .bind(session.last_seen_at())
        .bind(session.created_at())
        .bind(session.revoked_at())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 依据 access token 哈希查找当前仍可访问的会话。
    async fn find_session_by_access_token_hash(
        &self,
        access_token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AppError> {
        let row = sqlx::query(
            r#"
            select *
            from sessions
            where token_hash = $1
              and revoked_at is null
              and access_expires_at > $2
              and expires_at > $2
            limit 1
            "#,
        )
        .bind(access_token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        row.map(map_session).transpose()
    }

    /// 依据 refresh token 哈希查找当前仍可续签的会话。
    async fn find_session_by_refresh_token_hash(
        &self,
        refresh_token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Session>, AppError> {
        let row = sqlx::query(
            r#"
            select *
            from sessions
            where refresh_token_hash = $1
              and revoked_at is null
              and expires_at > $2
            limit 1
            "#,
        )
        .bind(refresh_token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        row.map(map_session).transpose()
    }

    /// 轮换会话的 access/refresh token，并刷新访问过期时间。
    async fn rotate_session_tokens(
        &self,
        session_id: Uuid,
        current_refresh_token_hash: &str,
        next_access_token_hash: &str,
        next_refresh_token_hash: &str,
        access_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            update sessions
            set token_hash = $3,
                refresh_token_hash = $4,
                access_expires_at = $5,
                last_seen_at = $6
            where id = $1
              and refresh_token_hash = $2
              and revoked_at is null
              and expires_at > $6
            "#,
        )
        .bind(session_id)
        .bind(current_refresh_token_hash)
        .bind(next_access_token_hash)
        .bind(next_refresh_token_hash)
        .bind(access_expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 列出某个 Subject 当前全部未过期且未撤销的会话。
    async fn list_sessions_for_subject(
        &self,
        subject_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Vec<Session>, AppError> {
        let rows = sqlx::query(
            r#"
            select *
            from sessions
            where subject_id = $1
              and revoked_at is null
              and expires_at > $2
            order by created_at desc
            "#,
        )
        .bind(subject_id)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(map_session).collect()
    }

    /// 撤销指定 Subject 下的某个会话。
    async fn revoke_session(
        &self,
        session_id: Uuid,
        subject_id: Uuid,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            update sessions
            set revoked_at = now()
            where id = $1 and subject_id = $2 and revoked_at is null
            "#,
        )
        .bind(session_id)
        .bind(subject_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 撤销指定 Subject 下除当前会话外的全部其他会话。
    async fn revoke_other_sessions(
        &self,
        current_session_id: Uuid,
        subject_id: Uuid,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            r#"
            update sessions
            set revoked_at = now()
            where id <> $1 and subject_id = $2 and revoked_at is null
            "#,
        )
        .bind(current_session_id)
        .bind(subject_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// 将部分认证会话升级为完整 MFA 会话。
    async fn upgrade_mfa(&self, session_id: Uuid, now: DateTime<Utc>) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            update sessions
            set mfa_level = 'full'
            where id = $1
              and mfa_level = 'partial'
              and revoked_at is null
              and expires_at > $2
            "#,
        )
        .bind(session_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 刷新会话最后活跃时间，维持在线状态。
    async fn touch_session(
        &self,
        session_id: Uuid,
        access_token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            update sessions
            set last_seen_at = $3
            where id = $1
              and token_hash = $2
              and revoked_at is null
              and access_expires_at > $3
              and expires_at > $3
            "#,
        )
        .bind(session_id)
        .bind(access_token_hash)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl TrustedDeviceRepository for PostgresTrustedDeviceRepository {
    /// 依据 token 哈希查找仍有效的可信设备。
    async fn find_trusted_device_by_token_hash(
        &self,
        subject_id: Uuid,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<TrustedDevice>, AppError> {
        let row = sqlx::query(
            r#"
            select *
            from trusted_devices
            where subject_id = $1
              and token_hash = $2
              and revoked_at is null
              and expires_at > $3
            limit 1
            "#,
        )
        .bind(subject_id)
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        row.map(map_trusted_device).transpose()
    }

    /// 持久化一条新的可信设备记录。
    async fn create_trusted_device(&self, device: &TrustedDevice) -> Result<(), AppError> {
        sqlx::query(
            r#"
            insert into trusted_devices (
                id, identity_id, subject_id, subject_role, token_hash, device_name, user_agent, ip,
                expires_at, last_seen_at, created_at, revoked_at
            )
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(device.id())
        .bind(device.identity_id())
        .bind(device.subject_id())
        .bind(device.subject_role().as_str())
        .bind(device.token_hash())
        .bind(device.device_name())
        .bind(device.user_agent())
        .bind(device.ip())
        .bind(device.expires_at())
        .bind(device.last_seen_at())
        .bind(device.created_at())
        .bind(device.revoked_at())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// 刷新可信设备最后活跃时间。
    async fn touch_trusted_device(
        &self,
        trusted_device_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            update trusted_devices
            set last_seen_at = $2
            where id = $1
              and revoked_at is null
              and expires_at > $2
            "#,
        )
        .bind(trusted_device_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 按 token 哈希撤销单个可信设备。
    async fn revoke_trusted_device_by_token_hash(
        &self,
        subject_id: Uuid,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let result = sqlx::query(
            r#"
            update trusted_devices
            set revoked_at = $3
            where subject_id = $1
              and token_hash = $2
              and revoked_at is null
              and expires_at > $3
            "#,
        )
        .bind(subject_id)
        .bind(token_hash)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// 按设备指纹批量撤销可信设备记录。
    async fn revoke_trusted_devices_by_device(
        &self,
        subject_id: Uuid,
        device_name: &str,
        user_agent: Option<&str>,
        ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<u64, AppError> {
        let result = sqlx::query(
            r#"
            update trusted_devices
            set revoked_at = $5
            where subject_id = $1
              and device_name = $2
              and user_agent is not distinct from $3
              and ip is not distinct from $4
              and revoked_at is null
              and expires_at > $5
            "#,
        )
        .bind(subject_id)
        .bind(device_name)
        .bind(user_agent)
        .bind(ip)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
#[async_trait]
impl RiskEventRepository for PostgresRiskEventRepository {
    /// 持久化一条风险事件审计记录。
    async fn create_risk_event(&self, event: &RiskEvent) -> Result<(), AppError> {
        sqlx::query(
            r#"
            insert into risk_events (
                id, event_type, credential_type, identity_id, email, subject_role, ip, user_agent, detail, created_at
            )
            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(event.id)
        .bind(event.event_type.as_str())
        .bind(event.credential_type.map(|value| value.as_str().to_string()))
        .bind(event.identity_id)
        .bind(&event.email)
        .bind(event.subject_role.map(|value| value.as_str().to_string()))
        .bind(&event.ip)
        .bind(&event.user_agent)
        .bind(&event.detail)
        .bind(event.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}



