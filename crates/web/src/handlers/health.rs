//! Health checks (ADR-0007 §8, ADR-0031).
//!
//! `/healthz` is liveness (ignores dependencies). `/readyz` checks reachability of the api
//! (web has no DB, so readiness is judged by the api's availability). Both are **unauthenticated**.
//!
//! Details (version, uptime, server time) are in `/internal/health`, readable only behind the
//! internal token (ADR-0031 decision 1).

use crate::state::WebState;
use assay_contracts::health::{service, HealthCheck, LivenessResponse, ServiceHealth};
use assay_contracts::version::{BuildTimeVersionInfoProvider, VersionInfoProvider};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

// The version screen shows, besides web's build info, the DB schema migration state fetched from the api.

/// liveness: 200 if the process is alive. Dependencies are not checked.
///
/// The body carries `service` because, since domain-split (ADR-0019) put web (`idp.*`) and api (`identity.*`)
/// on separate hosts, a mix-up where "a different service answers than the one you meant to hit" can happen.
/// The body used to be empty, so even on 200 **you could not tell which one answered**.
pub async fn liveness() -> (StatusCode, Json<LivenessResponse>) {
    (StatusCode::OK, Json(LivenessResponse::ok(service::WEB)))
}

/// Detailed internal health (`/internal/health`). The router places it inside `require_service_token`.
///
/// web depends only on the api, so that is the only check. `server_time` is returned because it is needed
/// to diagnose clock skew (`private_key_jwt` assertions are judged with `exp` 5 minutes and 60 s tolerance,
/// so skew shows up as an "unexplained `invalid_client`"; ADR-0030).
pub async fn internal_health(State(state): State<WebState>) -> Json<ServiceHealth> {
    let checks = vec![if state.api.is_api_reachable().await {
        HealthCheck::pass("api")
    } else {
        HealthCheck::fail("api", "api unreachable")
    }];

    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    Json(ServiceHealth::new(
        service::WEB,
        provider.version_info(),
        state.started_at,
        chrono::Utc::now(),
        checks,
    ))
}

/// readiness: 200 if the api is reachable, otherwise 503.
pub async fn readiness(State(state): State<WebState>) -> StatusCode {
    if state.api.is_api_reachable().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
