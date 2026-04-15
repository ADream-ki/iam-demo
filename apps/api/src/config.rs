use std::env;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub app_env: String,
    pub database_url: String,
    pub redis_url: String,
    pub bind_addr: String,
    pub session_cookie_name: String,
    pub refresh_cookie_name: String,
    pub access_token_ttl_minutes: i64,
    pub session_ttl_hours: i64,
    pub public_rate_limit_max: u64,
    pub public_rate_limit_window_seconds: u64,
    pub login_failure_limit: u64,
    pub login_failure_source_limit: u64,
    pub login_failure_window_seconds: u64,
    pub otp_request_limit: u64,
    pub otp_request_window_seconds: u64,
    pub otp_code_ttl_seconds: u64,
    pub otp_max_attempts: u8,
    pub otp_resend_cooldown_seconds: u64,
    pub otp_code_pepper: String,
    pub trust_proxy_headers: bool,
    pub trusted_origin: String,
}

impl AppConfig {
    /// 从环境变量加载应用配置，并对开发环境提供可运行的默认值。
    pub fn from_env() -> Self {
        Self {
            app_env: env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/iam".to_string()),
            redis_url: env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            session_cookie_name: env::var("SESSION_COOKIE_NAME")
                .unwrap_or_else(|_| "session_token".to_string()),
            refresh_cookie_name: env::var("REFRESH_COOKIE_NAME")
                .unwrap_or_else(|_| "refresh_token".to_string()),
            access_token_ttl_minutes: env::var("ACCESS_TOKEN_TTL_MINUTES")
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(15),
            session_ttl_hours: env::var("SESSION_TTL_HOURS")
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(24 * 7),
            public_rate_limit_max: env::var("PUBLIC_RATE_LIMIT_MAX")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(5),
            public_rate_limit_window_seconds: env::var("PUBLIC_RATE_LIMIT_WINDOW_SECONDS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60),
            login_failure_limit: env::var("LOGIN_FAILURE_LIMIT")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(5),
            login_failure_source_limit: env::var("LOGIN_FAILURE_SOURCE_LIMIT")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(20),
            login_failure_window_seconds: env::var("LOGIN_FAILURE_WINDOW_SECONDS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(15 * 60),
            otp_request_limit: env::var("OTP_REQUEST_LIMIT")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(5),
            otp_request_window_seconds: env::var("OTP_REQUEST_WINDOW_SECONDS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60 * 5),
            otp_code_ttl_seconds: env::var("OTP_CODE_TTL_SECONDS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60 * 10),
            otp_max_attempts: env::var("OTP_MAX_ATTEMPTS")
                .ok()
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or(5),
            otp_resend_cooldown_seconds: env::var("OTP_RESEND_COOLDOWN_SECONDS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60),
            otp_code_pepper: env::var("OTP_CODE_PEPPER")
                .unwrap_or_else(|_| "dev-otp-pepper-change-me".to_string()),
            trust_proxy_headers: env::var("TRUST_PROXY_HEADERS")
                .ok()
                .map(|value| {
                    matches!(
                        value.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
                .unwrap_or(false),
            trusted_origin: env::var("TRUSTED_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
        }
    }

    /// 判断当前运行环境是否为 production。
    pub fn is_production(&self) -> bool {
        self.app_env.eq_ignore_ascii_case("production")
    }
}
