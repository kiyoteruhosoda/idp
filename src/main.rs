mod application;
mod config;
mod domain;
mod infrastructure;
mod presentation;
mod telemetry;

use anyhow::Context;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 開発時は .env を読み込む（存在しなくてもよい）。
    let _ = dotenvy::dotenv();

    let config = config::Config::from_env().context("failed to load configuration")?;

    telemetry::init(&config);

    let pool = infrastructure::db::connect(&config)
        .await
        .context("failed to connect to database")?;

    // スキーマ整合性の fail-fast チェック（DB が期待 version 以上か）。
    infrastructure::db::verify_schema_version(&pool)
        .await
        .context("database schema version check failed")?;

    let app = presentation::router::build(pool);

    let addr: SocketAddr = config
        .bind_addr()
        .parse()
        .with_context(|| format!("invalid bind address: {}", config.bind_addr()))?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    tracing::info!(%addr, issuer = config.issuer(), "IdP server started");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("shutdown signal received");
    }
}
