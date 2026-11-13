//! Audit log use case (design spec §7).
//!
//! Writes every audit event to the structured log (`tracing`, JSON) and also to the `audit_log`
//! table. A DB write failure does not fail the original operation (only an error log is left).

use crate::domain::audit::{AuditEvent, AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::repositories::AuditLogSink;
use crate::domain::tenant::TenantId;
use std::sync::Arc;
use uuid::Uuid;

/// Audit context derived from the request (trace key and client connection info).
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub correlation_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub struct AuditService {
    sink: Arc<dyn AuditLogSink>,
    clock: Arc<dyn Clock>,
}

impl AuditService {
    pub fn new(sink: Arc<dyn AuditLogSink>, clock: Arc<dyn Clock>) -> Self {
        Self { sink, clock }
    }

    /// Records one audit event. Pass no PII (users are identified only by internal UUID).
    /// `tenant_id` is the tenant the event belongs to (per-tenant tracing; ADR-0009 §8).
    #[allow(clippy::too_many_arguments)]
    pub async fn record(
        &self,
        event_type: AuditEventType,
        result: AuditResult,
        tenant_id: Option<TenantId>,
        user_id: Option<Uuid>,
        client_id: Option<&str>,
        reason: Option<&str>,
        ctx: &RequestContext,
    ) {
        let event = AuditEvent {
            event_type,
            occurred_at: self.clock.now(),
            tenant_id,
            user_id,
            client_id: client_id.map(str::to_string),
            ip_address: ctx.ip_address.clone(),
            user_agent: ctx.user_agent.clone(),
            result,
            reason: reason.map(str::to_string),
            correlation_id: ctx.correlation_id.clone(),
        };

        // Audit events are the domain vocabulary of "what happened", so metrics are emitted
        // from here too (G6). Login success rate, token issuance rate and key rotation outcomes
        // all derive from this one counter. Scattering meters across use cases lets one drift silently.
        //
        // Labels are only finite enums (`event_type` / `result`). Adding `tenant_id`, `user_id` or
        // `client_id` grows the time series with the number of users (see `crate::metrics`).
        metrics::counter!(
            crate::metrics::AUDIT_EVENTS,
            "event_type" => event.event_type.as_str(),
            "result" => event.result.as_str(),
        )
        .increment(1);

        tracing::info!(
            target: "audit",
            event_type = event.event_type.as_str(),
            result = event.result.as_str(),
            tenant_id = event.tenant_id.map(|t| t.to_string()),
            user_id = event.user_id.map(|u| u.to_string()),
            client_id = event.client_id.as_deref(),
            reason = event.reason.as_deref(),
            correlation_id = %event.correlation_id,
            "audit event"
        );

        if let Err(e) = self.sink.record(&event).await {
            tracing::error!(
                error = %e,
                event_type = event.event_type.as_str(),
                "failed to persist audit event"
            );
        }
    }

    /// Deletes one batch of audit events past the retention period and returns the count (G8).
    /// Does nothing when `retention_days` is 0 (i.e. never delete; the default).
    ///
    /// One call does not necessarily delete everything (the implementation caps the batch). Callers
    /// decide completion by "until the deleted count reaches 0".
    pub async fn purge_expired(&self, retention_days: u32) -> Result<u64, DomainError> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = self.clock.now() - chrono::Duration::days(i64::from(retention_days));
        self.sink.purge_older_than(cutoff).await
    }
}
