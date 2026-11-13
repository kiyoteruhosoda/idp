//! liveness / readiness health checks.
//!
//! - `GET /healthz`: whether the process is alive (dependencies not checked). **Unauthenticated**.
//! - `GET /readyz`: checks that the DB is reachable. **Unauthenticated**.
//! - `GET /internal/health`: version, uptime and dependency check results. **Behind the internal token** (ADR-0031).
//!
//! The public surface (`/healthz`, `/readyz`) carries only "which service answered"; anything more goes in
//! `/internal/health`, because anything added to the public surface is readable worldwide without auth (ADR-0031 decision 1).

use crate::infrastructure::db::{self, Db};
use crate::presentation::state::AppState;
use assay_contracts::health::{service, HealthCheck, LivenessResponse, ServiceHealth};
use assay_contracts::version::{
    BuildTimeVersionInfoProvider, SchemaVersionInfo, VersionInfo, VersionInfoProvider,
};
use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

/// liveness: 200 if the process is alive. Dependencies are not checked.
///
/// `service` is in the body because, with domain-split (ADR-0019) putting web and api on separate hosts,
/// "a different service answered than the one I meant to hit" mix-ups can happen. Unless written in the response
/// itself rather than the host name, such a mix-up survives until the very end of troubleshooting.
pub async fn liveness() -> (StatusCode, Json<LivenessResponse>) {
    (StatusCode::OK, Json(LivenessResponse::ok(service::API)))
}

/// Detailed internal health (`/internal/health`). The router places it behind `require_service_token`.
///
/// It checks what the api actually depends on -- DB reachability and schema version consistency.
/// The overall `status` derives from the check results, so monitoring only needs to watch this one value.
pub async fn internal_health(State(state): State<AppState>) -> Json<ServiceHealth> {
    let mut checks = Vec::new();

    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => checks.push(HealthCheck::pass("database")),
        Err(e) => {
            tracing::error!(error = %e, "health check: database unreachable");
            // The raw error text is not included but sent to the log (the response stays a status summary).
            checks.push(HealthCheck::fail("database", "database unreachable"));
        }
    }

    checks.push(schema_check(&state.pool).await);

    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    Json(ServiceHealth::new(
        service::API,
        provider.version_info(),
        state.started_at,
        state.clock.now(),
        checks,
    ))
}

/// Schema version consistency (same decision as the fail-fast in `CLAUDE.md` "schema-version").
///
/// "DB is behind" and "DB cannot be read" are different failures, so `detail` distinguishes them.
async fn schema_check(pool: &Db) -> HealthCheck {
    let expected = db::embedded_schema_version();
    match db::applied_schema_version(pool).await {
        Ok(applied) => {
            if applied >= expected {
                HealthCheck::pass("schema").with_detail(format!(
                    "applied={} expected={}",
                    fmt_version(applied),
                    fmt_version(expected)
                ))
            } else {
                HealthCheck::fail(
                    "schema",
                    format!(
                        "database schema is behind (applied={} expected={})",
                        fmt_version(applied),
                        fmt_version(expected)
                    ),
                )
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "health check: schema version unreadable");
            HealthCheck::fail("schema", "_sqlx_migrations is unreadable")
        }
    }
}

fn fmt_version(v: Option<i64>) -> String {
    v.map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string())
}

pub async fn readiness(State(pool): State<Db>) -> (StatusCode, Json<Value>) {
    match sqlx::query("SELECT 1").execute(&pool).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(e) => {
            tracing::error!(error = %e, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
        }
    }
}

/// version: returns the Cargo / Git version info embedded at build time.
pub async fn version() -> Json<VersionInfo> {
    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    Json(provider.version_info())
}

/// schema version: returns the applied state of the DB schema (migrations). Lets operators check the "applied version"
/// and the "version the app expects" even without direct DB access (web uses it for display).
///
/// If the DB cannot be read, it is distinguished as `db_readable = false` (`applied = null`). **To avoid confusing
/// "DB is behind" with "DB cannot be read (operational failure)"**, the error is not swallowed but logged too. The endpoint
/// itself is a status report, so even on DB read failure it returns 200 with the state (unreadable) (fail-soft).
pub async fn schema_version(State(pool): State<Db>) -> Json<SchemaVersionInfo> {
    let (db_readable, applied) = match db::applied_schema_version(&pool).await {
        Ok(applied) => (true, applied),
        Err(e) => {
            tracing::warn!(error = %e, "failed to read applied schema version for /version/schema");
            (false, None)
        }
    };
    Json(SchemaVersionInfo {
        expected: db::embedded_schema_version(),
        db_readable,
        applied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-0031 decision 1: the body names which service answered.
    #[tokio::test]
    async fn liveness_names_the_api_service() {
        let (status, Json(body)) = liveness().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ok");
        assert_eq!(body.service, service::API);
    }

    #[test]
    fn schema_versions_are_rendered_for_humans() {
        assert_eq!(fmt_version(Some(43)), "43");
        assert_eq!(fmt_version(None), "none");
    }
}
