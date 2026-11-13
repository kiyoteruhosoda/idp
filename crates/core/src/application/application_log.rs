//! Use cases for ingesting, viewing and cleaning up the application log (`log`) (CLAUDE.md "Logging").
//!
//! There are two sources. Both arrive as the same [`ApplicationLogPayload`] and pass the single conversion here.
//!
//! - api itself: `tracing` ingestion layer -> channel -> writer task
//! - web: `tracing` ingestion layer -> `POST /internal/logs` (web has no DB, so api writes for it)
//!
//! Viewed from the admin console's error/warning log screen. Being cross-tenant operational data,
//! viewing is limited to `idp.system.admin` (root) (enforced by the caller, the Presentation extractor).

use crate::domain::application_log::{
    ApplicationLogEntry, ApplicationLogFilter, ApplicationLogRecord, LogLevel, LogService,
};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::repositories::{ApplicationLogQuery, ApplicationLogSink};
use assay_contracts::application_log::ApplicationLogPayload;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// Default number of rows per page.
pub const DEFAULT_LIMIT: i64 = 50;
/// Maximum rows per page (prevents oversized fetches).
pub const MAX_LIMIT: i64 = 200;

/// Search parameters (raw values from Presentation; `limit`/`offset` are not clamped).
#[derive(Debug, Clone, Default)]
pub struct ApplicationLogQueryParams {
    pub level: Option<String>,
    pub service: Option<String>,
    pub target: Option<String>,
    pub correlation_id: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub struct ApplicationLogService {
    sink: Arc<dyn ApplicationLogSink>,
    logs: Arc<dyn ApplicationLogQuery>,
    clock: Arc<dyn Clock>,
}

impl ApplicationLogService {
    pub fn new(
        sink: Arc<dyn ApplicationLogSink>,
        logs: Arc<dyn ApplicationLogQuery>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self { sink, logs, clock }
    }

    /// Ingestion. Rows that cannot be interpreted (unknown level, service or timestamp) are dropped and the rest written.
    /// Returns the number of rows written.
    ///
    /// **Failures are not logged here.** A log of a log-write failure would trigger another write,
    /// so the callers (the writer task and the `/internal/logs` handler) handle them.
    pub async fn ingest(&self, payloads: &[ApplicationLogPayload]) -> Result<usize, DomainError> {
        let records: Vec<ApplicationLogRecord> = payloads
            .iter()
            .filter_map(to_record)
            .map(|r| r.truncated())
            .collect();
        if records.is_empty() {
            return Ok(0);
        }
        self.sink.record_batch(&records).await?;
        Ok(records.len())
    }

    /// Search (newest first).
    pub async fn search(
        &self,
        params: ApplicationLogQueryParams,
    ) -> Result<Vec<ApplicationLogEntry>, DomainError> {
        let filter = ApplicationLogFilter {
            level: normalize(params.level).and_then(|v| LogLevel::parse(&v)),
            service: normalize(params.service).and_then(|v| LogService::parse(&v)),
            target_prefix: normalize(params.target),
            correlation_id: normalize(params.correlation_id),
            from: params.from,
            to: params.to,
            limit: clamp_limit(params.limit),
            offset: params.offset.unwrap_or(0).max(0),
        };
        self.logs.search(&filter).await
    }

    /// Deletes rows past the retention period and returns the count. Disabled (no-op) when `retention_days` is 0.
    pub async fn purge_expired(&self, retention_days: u32) -> Result<u64, DomainError> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = self.clock.now() - chrono::Duration::days(i64::from(retention_days));
        self.sink.purge_older_than(cutoff).await
    }
}

/// Converts one received record into the stored form. `None` if a required field cannot be parsed (only that row is dropped).
fn to_record(payload: &ApplicationLogPayload) -> Option<ApplicationLogRecord> {
    Some(ApplicationLogRecord {
        occurred_at: DateTime::parse_from_rfc3339(&payload.occurred_at)
            .ok()?
            .with_timezone(&Utc),
        level: LogLevel::parse(&payload.level)?,
        service: LogService::parse(&payload.service)?,
        target: payload.target.clone(),
        message: payload.message.clone(),
        correlation_id: normalize(payload.correlation_id.clone()),
        tenant_id: payload
            .tenant_id
            .as_deref()
            .and_then(|v| Uuid::parse_str(v.trim()).ok()),
        traceback: normalize(payload.traceback.clone()),
    })
}

/// Clamps `limit` to 1..=MAX_LIMIT. Missing or non-positive values use the default.
fn clamp_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(l) if l > 0 => l.min(MAX_LIMIT),
        _ => DEFAULT_LIMIT,
    }
}

/// Normalizes an empty string to `None` (to ignore a bare `?level=` in the query).
fn normalize(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(level: &str, service: &str, occurred_at: &str) -> ApplicationLogPayload {
        ApplicationLogPayload {
            occurred_at: occurred_at.to_string(),
            level: level.to_string(),
            service: service.to_string(),
            target: "assay_api::token".to_string(),
            message: "boom".to_string(),
            correlation_id: Some("  ".to_string()),
            tenant_id: Some("0192f0c0-0000-7000-8000-000000000001".to_string()),
            traceback: None,
        }
    }

    #[test]
    fn converts_valid_payload() {
        let record = to_record(&payload("error", "web", "2026-07-27T01:02:03Z")).expect("record");
        assert_eq!(record.level, LogLevel::Error);
        assert_eq!(record.service, LogService::Web);
        assert_eq!(record.occurred_at.to_rfc3339(), "2026-07-27T01:02:03+00:00");
        // A whitespace-only correlation_id is treated as unspecified.
        assert_eq!(record.correlation_id, None);
        assert!(record.tenant_id.is_some());
    }

    #[test]
    fn rejects_unparseable_payloads() {
        assert!(to_record(&payload("info", "api", "2026-07-27T00:00:00Z")).is_none());
        assert!(to_record(&payload("error", "worker", "2026-07-27T00:00:00Z")).is_none());
        assert!(to_record(&payload("error", "api", "not-a-timestamp")).is_none());
    }

    #[test]
    fn clamps_limit_to_bounds_and_defaults() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(MAX_LIMIT + 100)), MAX_LIMIT);
    }

    #[test]
    fn normalizes_blank_to_none() {
        assert_eq!(normalize(Some(" ".to_string())), None);
        assert_eq!(
            normalize(Some(" WARN ".to_string())),
            Some("WARN".to_string())
        );
    }
}
