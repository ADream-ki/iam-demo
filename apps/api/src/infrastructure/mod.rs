pub mod crypto;
pub mod email;
pub mod passkey;
pub mod postgres;
pub mod redis_store;

use std::sync::Arc;

use anyhow::{Context, anyhow};
use sqlx::PgPool;
use sqlx::migrate::{MigrateError, Migrator};

use crate::{
    application::{AuthService, SecurityService},
    config::AppConfig,
    domain::ports::Clock,
};

use self::{
    crypto::{shared_clock, shared_hasher},
    email::LoggingOtpDelivery,
    passkey::WebauthnPasskeyVerifier,
    postgres::{
        PostgresIdentityRepository, PostgresRiskEventRepository, PostgresSessionRepository,
        PostgresTrustedDeviceRepository,
    },
    redis_store::{RedisChallengeStore, RedisOtpStore, RedisSecurityStore},
};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const LEGACY_0007_CHECKSUM_HEX: &str =
    "14ba14b1f0a4117e147d5fadf966ed3ad9394339480fa7c5e9450ac37afc3a53607d5c905c48ec78fd0555d04fdb9773";

#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<AuthService>,
    pub security_service: Arc<SecurityService>,
    pub access_cookie_name: String,
    pub refresh_cookie_name: String,
    pub access_token_ttl_minutes: i64,
    pub session_ttl_hours: i64,
    pub app_env: String,
    pub trust_proxy_headers: bool,
}

/// 组装基础设施实现并生成应用启动所需的共享状态。
pub async fn build_state(config: AppConfig) -> anyhow::Result<AppState> {
    let pool = PgPool::connect(&config.database_url).await?;
    run_migrations(&pool, &config).await?;

    let hasher = shared_hasher();
    let clock = shared_clock();
    let redis = redis::Client::open(config.redis_url.clone())?;

    let identities = Arc::new(PostgresIdentityRepository::new(pool.clone(), hasher.clone()));
    identities.ensure_demo_seed(Clock::now(clock.as_ref())).await?;

    let sessions = Arc::new(PostgresSessionRepository::new(pool.clone()));
    let trusted_devices = Arc::new(PostgresTrustedDeviceRepository::new(pool.clone()));
    let risk_events = Arc::new(PostgresRiskEventRepository::new(pool));
    let otp_store = Arc::new(RedisOtpStore::new(redis.clone()));
    let challenge_store = Arc::new(RedisChallengeStore::new(redis.clone()));
    let security_store = Arc::new(RedisSecurityStore::new(redis));
    let passkey_verifier = Arc::new(WebauthnPasskeyVerifier::new(&config.trusted_origin)?);
    let otp_delivery = Arc::new(LoggingOtpDelivery);

    let security_service = Arc::new(SecurityService::new(
        security_store,
        risk_events,
        clock.clone(),
        config.public_rate_limit_max,
        config.public_rate_limit_window_seconds,
        config.login_failure_limit,
        config.login_failure_source_limit,
        config.login_failure_window_seconds,
        config.otp_request_limit,
        config.otp_request_window_seconds,
    ));

    let is_production = config.is_production();
    let auth_service = Arc::new(AuthService::new(
        identities,
        sessions,
        trusted_devices,
        otp_store,
        otp_delivery,
        challenge_store,
        hasher,
        clock,
        passkey_verifier,
        security_service.clone(),
        config.access_token_ttl_minutes,
        config.session_ttl_hours,
        config.otp_code_ttl_seconds,
        config.otp_max_attempts,
        config.otp_resend_cooldown_seconds,
        config.otp_code_pepper,
        is_production,
    ));

    Ok(AppState {
        auth_service,
        security_service,
        access_cookie_name: config.session_cookie_name,
        refresh_cookie_name: config.refresh_cookie_name,
        access_token_ttl_minutes: config.access_token_ttl_minutes,
        session_ttl_hours: config.session_ttl_hours,
        app_env: config.app_env,
        trust_proxy_headers: config.trust_proxy_headers,
    })
}

/// 启动时执行数据库迁移；开发环境下会兼容一次已知的旧 checksum 偏差。
async fn run_migrations(pool: &PgPool, config: &AppConfig) -> anyhow::Result<()> {
    match MIGRATOR.run(pool).await {
        Ok(()) => Ok(()),
        Err(MigrateError::VersionMismatch(7)) if !config.is_production() => {
            if !repair_legacy_migration_0007(pool).await? {
                return Err(anyhow!(
                    "migration 7 checksum mismatch does not match the known local legacy variant; manual repair required"
                ));
            }

            MIGRATOR.run(pool).await?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// 修复本地历史上遗留的 0007 migration checksum 漂移，避免开发库无法继续迁移。
async fn repair_legacy_migration_0007(pool: &PgPool) -> anyhow::Result<bool> {
    let applied_checksum_hex: Option<String> =
        sqlx::query_scalar("select encode(checksum, 'hex') from _sqlx_migrations where version = 7")
            .fetch_optional(pool)
            .await?;

    if applied_checksum_hex.as_deref() != Some(LEGACY_0007_CHECKSUM_HEX) {
        return Ok(false);
    }

    let expected_checksum = MIGRATOR
        .iter()
        .find(|migration| migration.version == 7)
        .map(|migration| migration.checksum.as_ref().to_vec())
        .context("embedded migration 0007 not found")?;

    sqlx::query("update _sqlx_migrations set checksum = $2 where version = $1")
        .bind(7_i64)
        .bind(expected_checksum)
        .execute(pool)
        .await?;

    tracing::warn!(
        "repaired legacy migration 0007 checksum in development; follow-up migration 0009 will finalize the schema"
    );

    Ok(true)
}
