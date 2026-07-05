//! OIDC IdP のライブラリクレート。
//!
//! バイナリ（`main.rs`）と統合テスト（`tests/`）の双方から各モジュールを参照できるよう、
//! アプリのロジックはライブラリ側に置く。

pub mod application;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod presentation;
pub mod telemetry;

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

    let pool = infrastructure::db::connect(&config)
        .await
        .context("failed to connect to database")?;

    infrastructure::db::verify_schema_version(&pool)
        .await
        .context("database schema version check failed")?;

    let clock: Arc<dyn domain::clock::Clock> = Arc::new(infrastructure::clock::SystemClock);

    // 署名鍵ブートストラップ: ACTIVE 鍵が無ければ生成して永続化する。
    let signing_keys = Arc::new(
        infrastructure::repositories::signing_key::SqlxSigningKeyRepository::new(pool.clone()),
    );
    let key_service = application::key_service::KeyService::new(
        signing_keys,
        clock.clone(),
        *config.key_encryption_key(),
    );
    key_service
        .ensure_active_key()
        .await
        .context("failed to ensure an active signing key")?;

    // ユースケースの組み立てと共有状態。
    let users = Arc::new(infrastructure::repositories::user::SqlxUserRepository::new(
        pool.clone(),
    ));
    let password_hasher = Arc::new(infrastructure::password::Argon2PasswordHasher::new());
    let register = Arc::new(application::register::RegisterService::new(
        users,
        password_hasher,
        clock.clone(),
    ));

    let state = presentation::state::AppState {
        pool: pool.clone(),
        register,
    };
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
