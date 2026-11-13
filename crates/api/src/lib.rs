//! The OIDC IdP API (`assay-api`).
//!
//! Provides the axum presentation layer (OIDC protocol, JSON admin API, admin console HTML) and binary startup.
//! Domain / Application / Infrastructure, settings and logging infrastructure live in `assay-core`.
//!
//! The single crate was split as P1 of ADR-0007 (API/Web service split). Here each core module is
//! re-exported, keeping references like `crate::domain` inside presentation and integration test paths working
//! (the stage of creating only the crate boundary while staying all-in-one). The web crate is done in P3.
pub use assay_core::{application, config, domain, infrastructure, telemetry};

pub mod presentation;
pub mod service_restart;

use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;

/// Starts the app (load settings -> init logging -> connect DB -> check schema -> bootstrap signing key
/// -> start HTTP server).
pub async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let config = config::Config::from_env().context("failed to load configuration")?;

    // Logging init is needed before connecting to the DB. Keep just the receiver, and once the pool exists
    // start the task writing to the `log` table (CLAUDE.md "ログ").
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

    // Check that the seeded root tenant exists (fail-fast; detects missing migrations/seeds).
    // The root UUID is fixed, but it is identified by the structure `parent_tenant_id IS NULL` and logged (ADR-0011).
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

    // Assemble the use cases (dependency injection is consolidated in AppState::build).
    let state = presentation::state::AppState::build(pool.clone(), Arc::new(config.clone()), clock);

    // Signing key bootstrap: if there is no ACTIVE key, generate and persist one.
    ensure_active_signing_key(&state.keys)
        .await
        .context("failed to ensure an active signing key")?;

    // Observe the DB connection pool (G6). Exhaustion is a value we want to see precisely "while nothing is happening",
    // so it is observed periodically rather than on use.
    presentation::metrics::spawn_db_pool_metrics(pool.clone());

    // Write error/warning logs to the DB (CLAUDE.md "ログ"). Ingestion layer -> channel -> here.
    spawn_application_log_writer(state.application_logs.clone(), log_receiver);
    spawn_application_log_purge(
        state.application_logs.clone(),
        config.app_log_retention_days(),
    );

    // Audit log retention (G8). Default 0 (never delete); runs only when a number of days is set explicitly.
    spawn_audit_log_purge(state.audit.clone(), config.audit_log_retention_days());

    // Delete device registrations unused for 180 days (task #872). Each deletion is audited and active orgs are notified,
    // so this is a separate loop from the table cleanup (`expired_records`). Once a day is enough.
    // ⚠ The first run is 5 minutes after startup. With "wait 24 hours before the first run", as long as we redeploy
    //   at least once a day (restarting each time), it would never run.
    {
        let devices = state.device_registry.clone();
        tokio::spawn(async move {
            let mut wait = std::time::Duration::from_secs(5 * 60);
            loop {
                tokio::time::sleep(wait).await;
                wait = std::time::Duration::from_secs(24 * 60 * 60);
                match devices.purge_unused().await {
                    Ok(0) => {}
                    Ok(count) => tracing::info!(count, "expired unused devices"),
                    Err(e) => tracing::error!(error = %e, "device expiry run failed"),
                }
            }
        });
    }

    // Bulk GC of expired records (G2). One task cleans auth sessions, authorization codes, refresh tokens,
    // SSO sessions, revoked jtis, passkey challenges and the various temporary tokens.
    // A loop per table would cause missed cleanups every time one is added, so the targets are
    // defined once in `infrastructure::repositories::expired_records`.
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

    // Back-channel logout sender worker (G5). Logout handlers only queue notification requests
    // and finish; the actual HTTP sending and retries happen here. Unsent items remain as rows even if the process dies,
    // so this loop picks them up again after a restart.
    {
        let deliveries = state.backchannel_logout.clone();
        let interval = config.backchannel_logout_poll_interval();
        let retention_days = config.backchannel_logout_retention_days();
        tokio::spawn(async move {
            // Cleaning up settled rows need not happen every time, so it runs only once every N iterations.
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

    // Automatic signing key rotation (K2): periodic check in a background task.
    // No mutual exclusion. **Assumes the api runs as a single instance** (README "スケール前提", G9).
    {
        let keys = state.keys.clone();
        let lead_days = config.key_rotation_lead_days();
        let publish_lead_hours = config.key_rotation_publish_lead_hours();
        tokio::spawn(async move {
            // Right after startup, wait 1 minute before the first check (leaving room for the DB to finish starting).
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            loop {
                if let Err(e) = keys.rotate_if_needed(lead_days, publish_lead_hours).await {
                    tracing::error!(error = %e, "signing key rotation check failed");
                }
                tokio::time::sleep(std::time::Duration::from_secs(3_600)).await;
            }
        });
    }

    // Restart request from the settings screen (ADR-0017). Handlers hold the same value via `AppState`.
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
        // Starting a new process is the deployment's restart policy (ADR-0017). The exit code is 0, so
        // it is restarted only with `restart: unless-stopped` / `always`-style policies.
        tracing::info!("exiting to be restarted by the process manager");
    }

    Ok(())
}

/// Max entries combined into one INSERT (split so a single statement doesn't get huge during bursts).
const APP_LOG_BATCH_SIZE: usize = 128;
/// Interval for applying retention. Retention is in days, so hourly is plenty.
const APP_LOG_PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3_600);
/// Interval for applying audit log retention (G8). Also in days, so hourly is enough.
const AUDIT_LOG_PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3_600);
/// Wait before the next batch when retention deletion couldn't finish in one cycle (G8).
/// When first enabled, millions of rows may be targeted, so deletion continues without waiting for the cycle. But
/// running back to back would squeeze the authorization flow's INSERTs, so a short gap is kept between batches.
const AUDIT_LOG_PURGE_BATCH_PAUSE: std::time::Duration = std::time::Duration::from_secs(1);

/// Spawns a task that keeps writing WARN / ERROR captured by `tracing` into the `log` table.
///
/// **This task never logs its own failures**. A log about a failed log write would trigger another write and
/// never stop, so failures are dropped (the original event is in the structured stdout log, so
/// the information itself is not lost; saving to the DB is best-effort).
fn spawn_application_log_writer(
    logs: Arc<application::application_log::ApplicationLogService>,
    mut receiver: infrastructure::log_capture::ApplicationLogReceiver,
) {
    tokio::spawn(async move {
        while let Some(mut batch) = receiver.recv_batch(APP_LOG_BATCH_SIZE).await {
            // The number of overflowed-and-dropped entries is kept as one record instead of logging the drop itself
            // (emitting to `tracing` would be picked up by the ingestion layer and recurse).
            let dropped = receiver.take_dropped();
            // `recv_batch` returns only after at least one entry has accumulated, so the batch is never empty.
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

/// Builds the one entry reporting the number of overflowed-and-dropped entries.
fn dropped_notice(
    dropped: u64,
    occurred_at: String,
) -> assay_contracts::application_log::ApplicationLogPayload {
    assay_contracts::application_log::ApplicationLogPayload {
        occurred_at,
        level: "WARN".to_string(),
        service: assay_contracts::application_log::SERVICE_API.to_string(),
        target: "assay_api::log_writer".to_string(),
        message: format!(
            "dropped {dropped} application log record(s); the DB write queue was full"
        ),
        correlation_id: None,
        tenant_id: None,
        traceback: None,
    }
}

/// Spawns a task that periodically deletes error/warning logs past retention.
/// `retention_days = 0` means "never delete" (only when explicitly chosen in settings).
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
            // Deletion success/failure is not logged (the ingestion layer would pick it up and self-amplify).
            let _ = logs.purge_expired(retention_days).await;
            tokio::time::sleep(APP_LOG_PURGE_INTERVAL).await;
        }
    });
}

/// Spawns a task that periodically deletes audit events past retention (G8).
/// `retention_days = 0` (default) means "never delete".
///
/// If one cycle couldn't delete everything, it moves on to the next batch without waiting for the cycle. In environments
/// where retention is enabled later, millions of rows may be targeted at once, and one batch an hour couldn't keep up.
fn spawn_audit_log_purge(audit: Arc<application::audit::AuditService>, retention_days: u32) {
    if retention_days == 0 {
        tracing::info!("audit log retention is disabled (AUDIT_LOG_RETENTION_DAYS=0)");
        return;
    }
    tracing::info!(retention_days, "audit log retention enabled");
    tokio::spawn(async move {
        loop {
            match audit.purge_expired(retention_days).await {
                // Deleted everything (nothing targeted this time). Wait until the next cycle.
                Ok(0) => tokio::time::sleep(AUDIT_LOG_PURGE_INTERVAL).await,
                Ok(deleted) => {
                    tracing::info!(deleted, "purged expired audit log rows");
                    tokio::time::sleep(AUDIT_LOG_PURGE_BATCH_PAUSE).await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "audit log retention purge failed");
                    tokio::time::sleep(AUDIT_LOG_PURGE_INTERVAL).await;
                }
            }
        }
    });
}

/// Reads DB-managed settings (non-secret) from `system_settings`. A startup snapshot passed to
/// [`config::Config`] resolution, **not re-read after startup**.
///
/// `/internal/runtime-settings` (MT26 / ADR-0013) hands values from this snapshot to web.
/// This is the boundary that keeps "values the running api uses" and "values web receives" the same.
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

/// Retries the signing key bootstrap with exponential backoff against transient failures.
///
/// `ensure_active_key` is idempotent (does nothing if an ACTIVE key exists; inserts are serialized by an advisory lock), so
/// retrying is safe. Typical failures here are "started together with another instance and the lock wait timed out" and
/// "the DB connection dropped transiently", both resolved by the next attempt. Startup fails only when all attempts
/// fail (without a key no tokens can be issued, so fail-fast is kept).
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

/// Trigger for graceful shutdown: an OS signal or a restart request from the settings screen (ADR-0017).
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
