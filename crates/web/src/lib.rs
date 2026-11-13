//! Web of the OIDC IdP (`assay-web`).
//!
//! The web service of ADR-0007 (API/Web service split). Renders HTML screens (login screen, admin console)
//! and fetches/operates on data via HTTP to the api. **Does not depend on the DB (sqlx) / infrastructure**
//! (enforced by the crate boundary).
//!
//! The login screen (`/login`) and i18n have been moved to web (P3-2). Moving the admin console (`/admin/console/*`)
//! happens in a later stage.

pub mod admin_dto;
pub mod api_client;
pub mod application_denied;
pub mod authentication_policy_form;
pub mod authorization_response;
pub mod client_country;
pub mod client_ip;
pub mod config;
pub mod cookies;
pub mod correlation;
pub mod csrf;
pub mod device_observation;
pub mod display_preferences;
pub mod dto;
pub mod error_pages;
pub mod handlers;
pub mod i18n;
mod internal_auth;
pub mod login_context;
pub mod pagination;
pub mod router;
pub mod security_headers;
pub mod service_restart;
pub mod session_key;
pub mod settings_filter;
pub mod state;
pub mod telemetry;
pub mod templates;
pub mod tenant;
pub mod theme;

use anyhow::Context;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Starts the web service (load bootstrap settings → init logging → fetch shared runtime settings from the api
/// → re-resolve settings → build the API client → start the HTTP server).
pub async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    // Stage 1: read only the minimal settings needed to query the api (`API_BASE_URL`,
    // `INTERNAL_SERVICE_TOKEN`, `LOG_FORMAT`). Shared keys are **not parsed** here — so that even if ENV
    // has an invalid value, it can be recovered via a DB override (which takes priority over ENV).
    let bootstrap = config::Bootstrap::from_env().context("failed to load web configuration")?;
    // Logging must be initialized before querying the api. Only take the receiving end for forwarding now,
    // and start the forwarding task once the `ApiClient` is built (CLAUDE.md "Logging").
    let log_forwarder = telemetry::init(bootstrap.log_format());

    if bootstrap.internal_service_token_is_dev() {
        tracing::warn!(
            "using the built-in development INTERNAL_SERVICE_TOKEN; set INTERNAL_SERVICE_TOKEN (shared with api) in production"
        );
    }

    // Stage 2: fetch the DB-managed settings shared with the api (COOKIE_SECURE etc.) and re-resolve settings
    // (MT26 / ADR-0013). The api is the sole DB owner, so this is the only place web can learn DB values.
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
    // Ship web's WARN / ERROR to the api's `log` table (web has no DB).
    telemetry::spawn_forwarder(state.api.clone(), log_forwarder);
    // Restart request from the settings screen (ADR-0017). Handlers hold the same value via `WebState`.
    let restart = state.restart.clone();
    let app = router::build(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    tracing::info!(%addr, api_base_url, "IdP web server started");

    // Enable `ConnectInfo` (SEC1). When `TRUST_FORWARDED_HEADERS` is false,
    // the `client_ip` middleware uses the TCP peer address provided here.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(restart.clone()))
    .await
    .context("web server error")?;

    if restart.was_requested() {
        tracing::info!("exiting to be restarted by the process manager");
    }

    Ok(())
}

/// Fetches the shared runtime settings (DB override values) from the api. Transient failures are retried with
/// exponential backoff, and if every attempt fails, **startup fails** (MT26 / ADR-0013).
///
/// Why not fail-soft (start with ENV only): shared keys all break when values diverge, and they
/// break silently. If `COOKIE_SECURE` diverges, web may overwrite a cookie issued by the api as
/// non-Secure; if `AUTH_SESSION_TTL_SECS` diverges, only the cookie expires early and login stops
/// progressing. A web that refuses to start leads to the cause more easily than one running on mixed-up settings
/// (with Compose, `depends_on: api(service_healthy)` and `restart` recover it).
async fn fetch_shared_runtime_settings(
    bootstrap: &config::Bootstrap,
) -> anyhow::Result<HashMap<String, String>> {
    const ATTEMPTS: u32 = 5;
    const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

    let api =
        api_client::ApiClient::new(bootstrap.api_base_url(), bootstrap.internal_service_token());
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
            bootstrap.api_base_url()
        )))
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
