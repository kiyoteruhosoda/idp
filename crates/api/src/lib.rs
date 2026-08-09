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
pub mod service_restart;

use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;

/// アプリを起動する（設定読み込み → ログ初期化 → DB 接続 → スキーマ照合 → 署名鍵ブートストラップ
/// → HTTP サーバ起動）。
pub async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let config = config::Config::from_env().context("failed to load configuration")?;

    // ログ初期化は DB 接続より前に要る。受信端だけ受け取っておき、プールができてから
    // `log` テーブルへの書き込みタスクを起こす（CLAUDE.md「ログ」）。
    let log_receiver = telemetry::init(&config);

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

    let db_settings = load_db_managed_settings(&pool)
        .await
        .context("failed to load DB-managed settings")?;
    let config = config::Config::from_env_and_db_settings(&db_settings)
        .context("failed to resolve configuration from env/DB/defaults")?;

    let clock: Arc<dyn domain::clock::Clock> = Arc::new(infrastructure::clock::SystemClock);

    // seed 済み root テナントの存在確認（fail-fast。マイグレーション/seed 漏れの検出）。
    // root UUID は固定値だが、識別は `parent_tenant_id IS NULL` の構造で行いログへ記録する（ADR-0011）。
    {
        use domain::repositories::TenantRepository as _;
        let tenants = infrastructure::repositories::tenant::SqlxTenantRepository::new(pool.clone());
        let root = tenants
            .find_root()
            .await
            .context("failed to resolve the root tenant")?
            .context("root tenant not found; run migrations/seed first")?;
        tracing::info!(root_tenant_id = %root.id, "root tenant resolved");
    }

    // ユースケースの組み立て（依存注入は AppState::build に集約）。
    let state = presentation::state::AppState::build(pool.clone(), Arc::new(config.clone()), clock);

    // 署名鍵ブートストラップ: ACTIVE 鍵が無ければ生成して永続化する。
    ensure_active_signing_key(&state.keys)
        .await
        .context("failed to ensure an active signing key")?;

    // エラー・警告ログの DB 書き込み（CLAUDE.md「ログ」）。取り込み層 → チャネル → ここ。
    spawn_application_log_writer(state.application_logs.clone(), log_receiver);
    spawn_application_log_purge(
        state.application_logs.clone(),
        config.app_log_retention_days(),
    );

    // 期限切れレコードの一括 GC（G2）。認可セッション・authorization code・refresh token・
    // SSO セッション・失効 jti・パスキーチャレンジ・各種一時トークンを 1 本のタスクで掃除する。
    // 表ごとにループを生やすと追加のたびに掃除漏れが生まれるため、対象は
    // `infrastructure::repositories::expired_records` に単一定義してある。
    if let Some(interval) = config.expired_record_purge_interval() {
        let purge = state.expired_records.clone();
        tracing::info!(
            tables = ?purge.table_names(),
            interval_secs = interval.as_secs(),
            "expired record purge enabled"
        );
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                purge.purge_once().await;
            }
        });
    } else {
        tracing::warn!(
            "expired record purge is disabled (EXPIRED_RECORD_PURGE_INTERVAL_SECS=0); \
             flow-state and one-time token tables will grow without bound"
        );
    }

    // Back-channel logout の送信ワーカー（G5）。ログアウトのハンドラは通知要求をキューへ積むだけで
    // 終わり、実際の HTTP 送信と再試行はここが担う。プロセスが落ちても未送信分は行として残るため、
    // 再起動後にこのループが拾い直す。
    {
        let deliveries = state.backchannel_logout.clone();
        let interval = config.backchannel_logout_poll_interval();
        let retention_days = config.backchannel_logout_retention_days();
        tokio::spawn(async move {
            // 決着済み行の掃除は毎回やる必要がないため、一定回数に 1 度だけ走らせる。
            let purge_every = (3_600 / interval.as_secs().max(1)).max(1);
            let mut tick: u64 = 0;
            loop {
                match deliveries.deliver_due().await {
                    Ok(handled) if handled > 0 => {
                        tracing::debug!(handled, "processed back-channel logout deliveries");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(error = %e, "back-channel logout delivery run failed");
                    }
                }
                if retention_days > 0 && tick.is_multiple_of(purge_every) {
                    let retention = chrono::Duration::days(retention_days as i64);
                    if let Err(e) = deliveries.purge_settled(retention).await {
                        tracing::error!(error = %e, "back-channel logout queue purge failed");
                    }
                }
                tick = tick.wrapping_add(1);
                tokio::time::sleep(interval).await;
            }
        });
    }

    // 署名鍵自動ローテーション（K2）: バックグラウンドタスクで定期チェック。
    // 排他制御は無い。**api を単一インスタンスで動かす前提**（README「スケール前提」・G9）。
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

    // 設定画面からの再起動要求（ADR-0017）。ハンドラは `AppState` 越しに同じ値を持つ。
    let restart = state.restart.clone();
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
        .with_graceful_shutdown(shutdown_signal(restart.clone()))
        .await
        .context("server error")?;

    if restart.was_requested() {
        // 新しいプロセスを起こすのは配置側の再起動ポリシー（ADR-0017）。終了コードは 0 なので
        // `restart: unless-stopped` / `always` 系でのみ再起動される。
        tracing::info!("exiting to be restarted by the process manager");
    }

    Ok(())
}

/// 1 回の INSERT でまとめる最大件数（バースト時に 1 文が巨大にならないように区切る）。
const APP_LOG_BATCH_SIZE: usize = 128;
/// 保持期間の適用間隔。日単位の保持なので 1 時間ごとで十分。
const APP_LOG_PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3_600);

/// `tracing` が拾った WARN / ERROR を `log` テーブルへ書き続けるタスクを起こす。
///
/// **このタスクは自分の失敗をログに出さない**。ログ書き込みの失敗ログがまた書き込みを誘発して
/// 止まらなくなるため、失敗は捨てる（stdout の構造化ログには元のイベントが出ているので、
/// 情報そのものは失われない。DB への保存は best-effort）。
fn spawn_application_log_writer(
    logs: Arc<application::application_log::ApplicationLogService>,
    mut receiver: infrastructure::log_capture::ApplicationLogReceiver,
) {
    tokio::spawn(async move {
        while let Some(mut batch) = receiver.recv_batch(APP_LOG_BATCH_SIZE).await {
            // 溢れて捨てた件数は、捨てたこと自体をログに出す代わりに 1 行の記録として残す
            // （`tracing` へ出すと取り込み層が拾って再帰する）。
            let dropped = receiver.take_dropped();
            // `recv_batch` は 1 件以上たまってから返すので、batch は必ず非空。
            if let (true, Some(occurred_at)) = (
                dropped > 0,
                batch.first().map(|first| first.occurred_at.clone()),
            ) {
                batch.push(dropped_notice(dropped, occurred_at));
            }
            let _ = logs.ingest(&batch).await;
        }
    });
}

/// 溢れて捨てた件数を伝える 1 件を組み立てる。
fn dropped_notice(
    dropped: u64,
    occurred_at: String,
) -> idp_contracts::application_log::ApplicationLogPayload {
    idp_contracts::application_log::ApplicationLogPayload {
        occurred_at,
        level: "WARN".to_string(),
        service: idp_contracts::application_log::SERVICE_API.to_string(),
        target: "idp_api::log_writer".to_string(),
        message: format!(
            "dropped {dropped} application log record(s); the DB write queue was full"
        ),
        correlation_id: None,
        tenant_id: None,
        traceback: None,
    }
}

/// 保持期間を過ぎたエラー・警告ログを定期的に削除するタスクを起こす。
/// `retention_days = 0` は「削除しない」（設定で明示的に選んだ場合のみ）。
fn spawn_application_log_purge(
    logs: Arc<application::application_log::ApplicationLogService>,
    retention_days: u32,
) {
    if retention_days == 0 {
        tracing::info!("application log retention is disabled (APP_LOG_RETENTION_DAYS=0)");
        return;
    }
    tokio::spawn(async move {
        loop {
            // 削除の成否はログに出さない（取り込み層が拾って自己増殖するため）。
            let _ = logs.purge_expired(retention_days).await;
            tokio::time::sleep(APP_LOG_PURGE_INTERVAL).await;
        }
    });
}

/// `system_settings` から DB 管理設定（非 secret）を読み出す。[`config::Config`] の解決に渡す
/// 起動時スナップショットであり、**起動後に読み直さない**。
///
/// `/internal/runtime-settings`（MT26 / ADR-0013）はこのスナップショット由来の値を web へ配る。
/// 「実行中の api が使っている値」と「web が受け取る値」を同じものに保つための境界がここにある。
pub async fn load_db_managed_settings(
    pool: &sqlx::MySqlPool,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    use domain::repositories::SystemSettingsRepository as _;
    let repo = infrastructure::repositories::system_setting::SqlxSystemSettingsRepository::new(
        pool.clone(),
    );
    Ok(repo
        .load_all()
        .await?
        .into_iter()
        .filter(|setting| !setting.is_secret)
        .map(|setting| (setting.key, setting.value))
        .collect())
}

/// 署名鍵ブートストラップを、一過性の失敗に対して指数バックオフで再試行する。
///
/// `ensure_active_key` は冪等（ACTIVE 鍵があれば何もしない・挿入は advisory lock で排他）なので
/// 再試行は安全。ここで失敗する典型は「他インスタンスと同時起動して排他ロック待ちがタイムアウトした」
/// 「DB 接続が一過性に切れた」であり、いずれも次の試行で解消する。全試行が失敗したときだけ
/// 起動を失敗させる（鍵が無ければトークン発行ができないため fail-fast は維持する）。
async fn ensure_active_signing_key(
    keys: &application::key_service::KeyService,
) -> anyhow::Result<()> {
    const ATTEMPTS: u32 = 5;
    const INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

    let mut backoff = INITIAL_BACKOFF;
    let mut last_error = None;
    for attempt in 1..=ATTEMPTS {
        match keys.ensure_active_key().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt < ATTEMPTS {
                    tracing::warn!(
                        error = %e,
                        attempt,
                        max_attempts = ATTEMPTS,
                        backoff_ms = backoff.as_millis(),
                        "signing key bootstrap failed; retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                last_error = Some(e);
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("signing key bootstrap did not run"))
        .context(format!("giving up after {ATTEMPTS} attempts")))
}

/// graceful shutdown のきっかけ: OS のシグナルか、設定画面からの再起動要求（ADR-0017）。
async fn shutdown_signal(restart: service_restart::ServiceRestart) {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if result.is_ok() {
                tracing::info!("shutdown signal received");
            }
        }
        _ = restart.requested() => {
            tracing::info!("restart requested from the admin console; draining in-flight requests");
        }
    }
}
