//! OIDC IdP の API（`idp-api`）。
//!
//! axum の presentation 層（OIDC protocol・JSON 管理 API・管理コンソール HTML）とバイナリ起動を担う。
//! Domain / Application / Infrastructure・設定・ログ基盤は `idp-core` にある。
//!
//! ADR-0007（API/Web サービス分割）の P1 として単一 crate を分割した。ここでは core の各モジュールを
//! 再エクスポートし、presentation 内の `crate::domain` 等の参照と統合テストの参照経路を維持する
//! （all-in-one を保ったまま crate 境界だけを作る段階）。web crate 化は P3 で行う。
pub use idp_core::{application, config, domain, infrastructure, telemetry};

pub mod presentation;

use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;

/// アプリを起動する（設定読み込み → ログ初期化 → DB 接続 → スキーマ照合 → 署名鍵ブートストラップ
/// → HTTP サーバ起動）。
pub async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let config = config::Config::from_env().context("failed to load configuration")?;

    telemetry::init(&config);

    if config.key_encryption_key_is_dev() {
        tracing::warn!(
            "using the built-in development KEY_ENCRYPTION_KEY; set KEY_ENCRYPTION_KEY in production"
        );
    }
    if config.internal_service_token_is_dev() {
        tracing::warn!(
            "using the built-in development INTERNAL_SERVICE_TOKEN; set INTERNAL_SERVICE_TOKEN in production"
        );
    }

    let pool = infrastructure::db::connect(&config)
        .await
        .context("failed to connect to database")?;

    infrastructure::db::verify_schema_version(&pool)
        .await
        .context("database schema version check failed")?;

    let clock: Arc<dyn domain::clock::Clock> = Arc::new(infrastructure::clock::SystemClock);

    // ユースケースの組み立て（依存注入は AppState::build に集約）。
    let state = presentation::state::AppState::build(pool.clone(), Arc::new(config.clone()), clock);

    // 署名鍵ブートストラップ: ACTIVE 鍵が無ければ生成して永続化する。
    state
        .keys
        .ensure_active_key()
        .await
        .context("failed to ensure an active signing key")?;

    // 署名鍵自動ローテーション（K2）: バックグラウンドタスクで定期チェック。
    {
        let keys = state.keys.clone();
        let lead_days = config.key_rotation_lead_days();
        tokio::spawn(async move {
            // 起動直後は 1 分待ってから最初のチェック（DB 起動完了を待つ余裕を持たせる）。
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            loop {
                if let Err(e) = keys.rotate_if_needed(lead_days).await {
                    tracing::error!(error = %e, "signing key rotation check failed");
                }
                tokio::time::sleep(std::time::Duration::from_secs(3_600)).await;
            }
        });
    }

    let app = presentation::router::build(state);

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
