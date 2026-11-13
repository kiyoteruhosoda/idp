//! Collecting and serving Prometheus metrics (G6).
//!
//! Observability was only JSON logs and the `log` / `audit_log` tables, so the values needed for SLOs such as login success rate,
//! token issuance rate, per-endpoint latency and DB pool exhaustion
//! could not be obtained. This installs a `metrics` facade recorder and serves it in Prometheus text format.
//!
//! # Exposure
//!
//! Placed at `/internal/metrics`. `/internal/*` is the surface **assumed to be blocked from outside by the reverse proxy**
//! (ADR-0007 §5), and as defense in depth the service auth token (`X-Internal-Auth-Token`) is also required.
//! Metrics aggregate "which user failed when and how many times", which is not for the public surface.
//! Prometheus fetches with the header set in its scrape config (see `docs/OPERATIONS.md`).
//!
//! # What is measured
//!
//! - **Audit events** (login success/failure, token issuance, key rotation, etc.): recorded in one place,
//!   `AuditService` (`assay_core::metrics::AUDIT_EVENTS`). Instruments are not scattered across
//!   use cases.
//! - **HTTP duration**: this module's middleware.
//! - **DB pool connections**: a periodic task (`spawn_db_pool_metrics`).
//!
//! The policy of keeping label cardinality finite is written in `assay_core::metrics`.

use crate::infrastructure::db::Db;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// `service` label value for this service. Set so it can be told apart if web also emits metrics with the same name
/// (currently only the api has `/metrics`).
const SERVICE: &str = "api";

/// Bucket boundaries (seconds) of the duration histogram.
///
/// IdP responses range from "a few milliseconds (cached discovery)" to "hundreds of milliseconds (token
/// issuance with Argon2)". The default buckets squash this band into 1-2 buckets, making
/// p95 unreadable, so 5ms-10s is divided logarithmically.
const DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Interval for observing DB pool connections. Exhaustion only matters after lasting tens of seconds, so 10 seconds is enough.
const DB_POOL_SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Installs the recorder **only once per process** and returns the handle for rendering.
///
/// The `metrics` recorder is process-global and cannot be installed twice. Integration tests build `AppState`
/// many times in one process, so from the second time on the first handle is returned (not a failure).
pub fn handle() -> Option<PrometheusHandle> {
    static HANDLE: std::sync::OnceLock<Option<PrometheusHandle>> = std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| {
            let builder = PrometheusBuilder::new()
                .add_global_label("service", SERVICE)
                .set_buckets_for_metric(
                    metrics_exporter_prometheus::Matcher::Full(
                        assay_core::metrics::HTTP_REQUEST_DURATION.to_string(),
                    ),
                    DURATION_BUCKETS,
                )
                .expect("duration buckets are a non-empty compile-time constant");
            match builder.install_recorder() {
                Ok(handle) => Some(handle),
                Err(e) => {
                    // Missing metrics is not an availability problem. Startup continues.
                    tracing::warn!(error = %e, "failed to install the metrics recorder; /internal/metrics will be empty");
                    None
                }
            }
        })
        .clone()
}

/// `GET /internal/metrics`: returns current values in Prometheus text format.
///
/// Returns 503 if installing the recorder failed (an empty 200 would be indistinguishable, for monitoring, from
/// "no events have happened at all").
pub async fn metrics_endpoint(
    State(state): State<crate::presentation::state::AppState>,
) -> Response {
    match state.metrics.as_ref() {
        Some(handle) => (
            StatusCode::OK,
            [
                // Prometheus text format (version 0.0.4).
                (
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                ),
                (header::CACHE_CONTROL, "no-store"),
            ],
            handle.render(),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics recorder is not installed\n",
        )
            .into_response(),
    }
}

/// Middleware recording HTTP request duration.
///
/// The `route` label uses **the matched route template**. Using the real URL would turn tenant IDs and user IDs
/// into label values and grow time series without bound. Requests without a template (404) are grouped as
/// `unmatched` -- time series must not grow just because nonexistent paths are hit.
pub async fn track_http_metrics(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());

    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let elapsed = started.elapsed();

    metrics::histogram!(
        assay_core::metrics::HTTP_REQUEST_DURATION,
        "method" => method.as_str().to_string(),
        "route" => route,
        "status" => response.status().as_u16().to_string(),
    )
    .record(elapsed.as_secs_f64());

    response
}

/// Spawns a task that periodically observes the sqlx connection pool's connection count.
///
/// The gauge is not "written on each use" because pool exhaustion is a value we want to see precisely
/// **while nothing is happening** (when exhausted and requests are waiting, the recorder is waiting too).
pub fn spawn_db_pool_metrics(pool: Db) {
    tokio::spawn(async move {
        loop {
            metrics::gauge!(
                assay_core::metrics::DB_POOL_CONNECTIONS,
                "state" => assay_core::metrics::DB_POOL_STATE_TOTAL,
            )
            .set(pool.size() as f64);
            metrics::gauge!(
                assay_core::metrics::DB_POOL_CONNECTIONS,
                "state" => assay_core::metrics::DB_POOL_STATE_IDLE,
            )
            .set(pool.num_idle() as f64);
            tokio::time::sleep(DB_POOL_SAMPLE_INTERVAL).await;
        }
    });
}
