//! **Names and labels of metrics** (G6).
//!
//! Installing the collector (Prometheus recorder) and serving `/internal/metrics` belong to the api
//! (`crate::presentation::metrics`). Only "what is counted under which name" lives here; like
//! `tracing`, it is a layer that **only records to the facade**. If no collector is installed,
//! records are discarded (callers need not branch even when metrics are disabled).
//!
//! # Label cardinality
//!
//! Prometheus creates a time series per combination of label values. Labels whose values keep growing
//! (`tenant_id`, `user_id`, `client_id`, `correlation_id`, URL path variables) make the
//! monitoring side's memory grow with the number of users. **Labels used here are limited to finite enums**.
//! "Which tenant failed" is tracked in the audit log (`audit_log`) -- metrics are
//! aggregates for seeing "how many happen overall".

/// Number of audit events (`event_type` x `result`).
///
/// Login success rate, token issuance rate and key rotation success all come from this one series.
/// Separate instruments are not scattered because audit events are already the domain vocabulary of "what happened",
/// and defining things twice lets one side grow alone and silently drift. Both labels are finite enums.
pub const AUDIT_EVENTS: &str = "idp_audit_events_total";

/// HTTP request duration (seconds). Labels are `service`, `method`, `route`, `status`.
///
/// `route` is **the matched route template** (`/{tenant_id}/admin/users/{user_id}`), not the real URL.
/// Using the real URL would add time series per tenant and user.
pub const HTTP_REQUEST_DURATION: &str = "idp_http_request_duration_seconds";

/// Number of connections in the sqlx connection pool. Label `state` is `total` (established) and `idle` (available).
///
/// Exhaustion shows as "`total` stuck at the limit with `idle` staying 0". Worsening latency alone can't
/// tell whether the DB is slow or we are waiting for the pool, so both are watched.
pub const DB_POOL_CONNECTIONS: &str = "idp_db_pool_connections";

/// `state` label values of `DB_POOL_CONNECTIONS`.
pub const DB_POOL_STATE_TOTAL: &str = "total";
pub const DB_POOL_STATE_IDLE: &str = "idle";
