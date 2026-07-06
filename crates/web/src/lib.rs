//! OIDC IdP の Web（`idp-web`）。
//!
//! ADR-0007（API/Web サービス分割）の web サービス。HTML 画面（ログイン画面・管理コンソール）を
//! 描画し、データ取得/操作は api へ HTTP 越しに行う。**DB（sqlx）/ infrastructure には依存しない**
//! （crate 境界で強制）。
//!
//! P3 のステージ 1（本コミット）では、設定・ログ・API クライアント・ヘルスチェックの土台を用意する。
//! ログイン画面・管理コンソールの移設（application 層直接呼び出しの API クライアント化）と i18n の移設は
//! 後続ステージで行う。

pub mod api_client;
pub mod config;
pub mod handlers;
pub mod router;
pub mod state;
pub mod telemetry;

use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;

/// web サービスを起動する（設定読み込み → ログ初期化 → API クライアント組立 → HTTP サーバ起動）。
pub async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let config = config::Config::from_env().context("failed to load web configuration")?;
    telemetry::init(&config);

    if config.internal_service_token_is_dev() {
        tracing::warn!(
            "using the built-in development INTERNAL_SERVICE_TOKEN; set INTERNAL_SERVICE_TOKEN (shared with api) in production"
        );
    }

    let addr: SocketAddr = config
        .bind_addr()
        .parse()
        .with_context(|| format!("invalid bind address: {}", config.bind_addr()))?;
    let api_base_url = config.api_base_url().to_string();

    let state = state::WebState::build(Arc::new(config));
    let app = router::build(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    tracing::info!(%addr, api_base_url, "IdP web server started");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("web server error")?;

    Ok(())
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("shutdown signal received");
    }
}
