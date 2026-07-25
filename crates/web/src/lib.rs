//! OIDC IdP の Web（`idp-web`）。
//!
//! ADR-0007（API/Web サービス分割）の web サービス。HTML 画面（ログイン画面・管理コンソール）を
//! 描画し、データ取得/操作は api へ HTTP 越しに行う。**DB（sqlx）/ infrastructure には依存しない**
//! （crate 境界で強制）。
//!
//! ログイン画面（`/login`）と i18n は web へ移設済み（P3-2）。管理コンソール（`/admin/console/*`）の
//! 移設は後続ステージで行う。

pub mod admin_dto;
pub mod api_client;
pub mod config;
pub mod cookies;
pub mod correlation;
pub mod csrf;
pub mod dto;
pub mod error_pages;
pub mod handlers;
pub mod i18n;
pub mod router;
pub mod security_headers;
pub mod state;
pub mod telemetry;
pub mod templates;
pub mod tenant;

use anyhow::Context;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// web サービスを起動する（bootstrap 設定読み込み → ログ初期化 → api から共有ランタイム設定を取得
/// → 設定の再解決 → API クライアント組立 → HTTP サーバ起動）。
pub async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    // 1 段目: ENV だけで組み立てる。api へ問い合わせるための `API_BASE_URL` と
    // `INTERNAL_SERVICE_TOKEN` がここで確定する。
    let bootstrap = config::Config::from_env().context("failed to load web configuration")?;
    telemetry::init(&bootstrap);

    if bootstrap.internal_service_token_is_dev() {
        tracing::warn!(
            "using the built-in development INTERNAL_SERVICE_TOKEN; set INTERNAL_SERVICE_TOKEN (shared with api) in production"
        );
    }

    // 2 段目: api と共有する DB 管理設定（COOKIE_SECURE 等）を取得して設定を解決し直す
    // （MT26 / ADR-0013）。api が唯一の DB 所有者なので、web はここでしか DB 値を知り得ない。
    let shared = fetch_shared_runtime_settings(&bootstrap).await?;
    let config = config::Config::from_env_and_shared_settings(&shared)
        .context("failed to resolve web configuration from api/env/defaults")?;
    if !config.shared_settings_from_api().is_empty() {
        tracing::info!(
            keys = ?config.shared_settings_from_api(),
            "applied DB-managed runtime settings from api"
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

/// api から共有ランタイム設定（DB 上書き値）を取得する。一過性の失敗は指数バックオフで再試行し、
/// 全試行が失敗したら**起動を失敗させる**（MT26 / ADR-0013）。
///
/// fail-soft（ENV だけで起動）にしない理由: 共有キーは値がずれると壊れるものばかりで、しかも
/// 壊れ方が静かである。`COOKIE_SECURE` がずれれば api の発行した Cookie を web が上書きで
/// 非 Secure にし得るし、`AUTH_SESSION_TTL_SECS` がずれれば Cookie だけ先に切れてログインが
/// 進まなくなる。設定を取り違えたまま動く web より、起動しない web の方が原因に辿り着ける
/// （Compose では `depends_on: api(service_healthy)` と `restart` で回復する）。
async fn fetch_shared_runtime_settings(
    config: &config::Config,
) -> anyhow::Result<HashMap<String, String>> {
    const ATTEMPTS: u32 = 5;
    const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

    let api = api_client::ApiClient::new(config.api_base_url(), config.internal_service_token());
    let mut backoff = INITIAL_BACKOFF;
    let mut last_error = None;
    for attempt in 1..=ATTEMPTS {
        match api.fetch_shared_runtime_settings().await {
            Ok(settings) => return Ok(settings),
            Err(e) => {
                if attempt < ATTEMPTS {
                    tracing::warn!(
                        error = %e,
                        attempt,
                        max_attempts = ATTEMPTS,
                        backoff_ms = backoff.as_millis(),
                        "failed to fetch shared runtime settings from api; retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                last_error = Some(e);
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("shared runtime settings fetch did not run"))
        .context(format!(
            "could not read DB-managed runtime settings from api ({}) after {ATTEMPTS} attempts; \
             refusing to start with possibly divergent COOKIE_SECURE / HSTS_MAX_AGE / \
             AUTH_SESSION_TTL_SECS",
            config.api_base_url()
        )))
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("shutdown signal received");
    }
}
