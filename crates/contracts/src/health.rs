//! Health information DTOs and where to draw the line on what may be exposed (ADR-0031).
//!
//! `/healthz` (liveness) returns, without auth, only **which service answered**. Anything more (build version,
//! uptime, dependency check results) lives in `/internal/health`, readable only behind the internal token.
//!
//! api and web build it the same way, so the types both use are defined once here. If only one side's
//! shape changed, the operational view (monitoring, triage procedures) would split per service.

use crate::version::VersionInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Service identifier. Put on the `/healthz` response so it is obvious at a glance which service answered.
///
/// With domain-split (ADR-0016, ADR-0019), web and api are on separate hosts, but a misconfigured front proxy
/// or a wrong DNS target can make "a different service than the one you meant to hit" answer. Unless it is on
/// **the response itself** rather than the host name, that mix-up survives until the very end of triage.
pub mod service {
    pub const API: &str = "api";
    pub const WEB: &str = "web";
}

/// The `/healthz` (liveness) response. **Readable by the whole world without auth**, so only things that are
/// "not secret and of no use to an attacker" may be added here (decision 1 of ADR-0031).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivenessResponse {
    /// Always `"ok"` (if this response comes back, the process is alive).
    pub status: String,
    /// One of [`service`].
    pub service: String,
}

impl LivenessResponse {
    pub fn ok(service: &str) -> Self {
        Self {
            status: "ok".to_string(),
            service: service.to_string(),
        }
    }
}

/// Check result for one dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Name of the checked target (`"database"`, `"api"` etc.).
    pub name: String,
    /// `"pass"` / `"fail"`.
    pub status: String,
    /// Human-readable detail (failure reason, related values). **No raw internal error text**
    /// (this response is behind the internal token, but it stays a summary to avoid duplicating the operational log).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl HealthCheck {
    pub fn pass(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: "pass".to_string(),
            detail: None,
        }
    }

    pub fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: "fail".to_string(),
            detail: Some(detail.into()),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn is_pass(&self) -> bool {
        self.status == "pass"
    }
}

/// The `/internal/health` response (behind the internal token).
///
/// Lets an operator get "which service, which version, running since when, and how dependencies are" in one
/// request. The aim is to avoid hitting several endpoints on every triage.
///
/// Send-only (no `Deserialize`). The embedded [`VersionInfo`] borrows static build-time strings,
/// and readers treat it as JSON anyway (there is no route where web receives this type either).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceHealth {
    /// One of [`service`].
    pub service: String,
    /// `"pass"` if all `checks` pass, `"fail"` if even one fails.
    pub status: String,
    /// Build information of the running binary.
    pub version: VersionInfo,
    /// Process start time (UTC).
    pub started_at: DateTime<Utc>,
    /// Seconds since startup. Kept to tell at a glance whether a restart happened
    /// (so readers need not compute the difference from `started_at`).
    pub uptime_seconds: i64,
    /// Server time at response (UTC). Used to triage clock skew with clients:
    /// `private_key_jwt` assertions are judged with `exp` of 5 minutes and 60 seconds tolerance (ADR-0030),
    /// so clock skew shows up as "an `invalid_client` with no obvious reason".
    pub server_time: DateTime<Utc>,
    /// Dependency check results. Empty for services without dependencies.
    pub checks: Vec<HealthCheck>,
}

impl ServiceHealth {
    /// Builds it, deciding the overall `status` from `checks`.
    pub fn new(
        service: &str,
        version: VersionInfo,
        started_at: DateTime<Utc>,
        server_time: DateTime<Utc>,
        checks: Vec<HealthCheck>,
    ) -> Self {
        let status = if checks.iter().all(HealthCheck::is_pass) {
            "pass"
        } else {
            "fail"
        };
        Self {
            service: service.to_string(),
            status: status.to_string(),
            version,
            started_at,
            uptime_seconds: (server_time - started_at).num_seconds().max(0),
            server_time,
            checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn version() -> VersionInfo {
        VersionInfo {
            package_version: "0.1.0",
            git_version: "abc1234",
            build_number: "312",
        }
    }

    #[test]
    fn liveness_names_the_service_that_answered() {
        let body = serde_json::to_value(LivenessResponse::ok(service::WEB)).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "web");
    }

    #[test]
    fn the_overall_status_follows_the_checks() {
        let healthy = ServiceHealth::new(
            service::API,
            version(),
            at(1000),
            at(1060),
            vec![HealthCheck::pass("database")],
        );
        assert_eq!(healthy.status, "pass");
        assert_eq!(healthy.uptime_seconds, 60);

        let broken = ServiceHealth::new(
            service::API,
            version(),
            at(1000),
            at(1060),
            vec![
                HealthCheck::pass("database"),
                HealthCheck::fail("schema", "DB has not reached the expected version"),
            ],
        );
        assert_eq!(broken.status, "fail");
    }

    /// A service without checks is pass (so "no dependencies" does not read as "broken").
    #[test]
    fn a_service_without_dependencies_is_pass() {
        let health = ServiceHealth::new(service::WEB, version(), at(1000), at(1000), vec![]);
        assert_eq!(health.status, "pass");
        assert_eq!(health.uptime_seconds, 0);
    }

    /// Uptime never goes negative even if the clock goes back (NTP correction can make `server_time < started_at`).
    #[test]
    fn uptime_never_goes_negative() {
        let health = ServiceHealth::new(service::API, version(), at(1000), at(900), vec![]);
        assert_eq!(health.uptime_seconds, 0);
    }
}
