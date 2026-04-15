use iam_api::{adapters::router::build_router, config::AppConfig, infrastructure::build_state};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
/// 进程入口：加载配置、组装状态、挂载路由并启动 HTTP 服务。
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env();
    let state = build_state(config.clone()).await?;
    let app = build_router(state, config.clone());

    tracing::info!(
        bind_addr = %config.bind_addr,
        trust_proxy_headers = config.trust_proxy_headers,
        "iam-api listening"
    );
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
