//! Audit log lookup use case (status screen A3, design spec §7).
//!
//! Filters `audit_log` by `event_type` / `result` (mainly to narrow to errors such as `failure`) / period /
//! `client_id` / `correlation_id` and returns newest first. `correlation_id` lets you
//! trace "request -> processing -> audit event" end to end.

use crate::domain::audit::{AuditLogEntry, AuditLogFilter};
use crate::domain::error::DomainError;
use crate::domain::repositories::AuditLogQuery;
use crate::domain::tenant_context::TenantContext;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// Default number of items per page.
pub const DEFAULT_LIMIT: i64 = 50;
/// Maximum number of items per page (prevents oversized fetches).
pub const MAX_LIMIT: i64 = 200;

/// Search parameters (raw values from Presentation; `limit`/`offset` not yet clamped).
#[derive(Debug, Clone, Default)]
pub struct AuditQueryParams {
    pub event_type: Option<String>,
    pub result: Option<String>,
    pub client_id: Option<String>,
    pub correlation_id: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub struct AuditQueryService {
    logs: Arc<dyn AuditLogQuery>,
}

impl AuditQueryService {
    pub fn new(logs: Arc<dyn AuditLogQuery>) -> Self {
        Self { logs }
    }

    pub async fn search(
        &self,
        tenant: TenantContext,
        params: AuditQueryParams,
    ) -> Result<Vec<AuditLogEntry>, DomainError> {
        let filter = AuditLogFilter {
            // Always included in the filter to prevent cross-tenant viewing (ADR-0009 §8).
            tenant_id: Some(tenant.tenant_id().as_uuid()),
            event_type: normalize(params.event_type),
            result: normalize(params.result),
            client_id: normalize(params.client_id),
            correlation_id: normalize(params.correlation_id),
            from: params.from,
            to: params.to,
            limit: clamp_limit(params.limit),
            offset: params.offset.unwrap_or(0).max(0),
        };
        self.logs.search(&filter).await
    }
}

/// Clamps `limit` into 1..=MAX_LIMIT. Missing or non-positive values become the default.
fn clamp_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(l) if l > 0 => l.min(MAX_LIMIT),
        _ => DEFAULT_LIMIT,
    }
}

/// Normalizes an empty string to `None` (so an unset query like `?event_type=` is ignored).
fn normalize(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_limit_to_bounds_and_defaults() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(-5)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(MAX_LIMIT + 100)), MAX_LIMIT);
    }

    #[test]
    fn normalizes_blank_to_none() {
        assert_eq!(normalize(Some("  ".to_string())), None);
        assert_eq!(
            normalize(Some(" failure ".to_string())),
            Some("failure".to_string())
        );
        assert_eq!(normalize(None), None);
    }
}
