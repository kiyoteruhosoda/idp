//! Service restart use case (ADR-0017).
//!
//! A restart is the only way to apply DB overrides of runtime settings, so it can be triggered from the settings screen.
//! Authorization (`idp.system.admin`) is handled by `RequirePerms` in Presentation; this service treats itself
//! as already authorized when called (same policy as the other admin use cases).

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::error::Result;
use crate::domain::service_lifecycle::ServiceRestarter;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use std::time::Duration;

/// Grace period between returning "accepted" and stopping.
///
/// Stopping first would cut this very request along with its connection, making it look like "I pressed it and nothing happened".
/// A short time, just enough to finish writing the response, is sufficient.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

pub struct ServiceRestartService {
    restarter: Arc<dyn ServiceRestarter>,
    audit: Arc<AuditService>,
}

impl ServiceRestartService {
    pub fn new(restarter: Arc<dyn ServiceRestarter>, audit: Arc<AuditService>) -> Self {
        Self { restarter, audit }
    }

    /// Requests a restart. Records to the audit log, then requests a stop after the grace period.
    ///
    /// The audit is written **before** stopping. It cannot be written after the stop, and an operation that aborts
    /// all in-flight requests cannot be traced later unless who did it and when is recorded.
    pub async fn request(
        &self,
        tenant: TenantContext,
        actor: &AdminActor,
        service: &str,
        ctx: &RequestContext,
    ) -> Result<()> {
        self.audit
            .record(
                AuditEventType::ServiceRestartRequested,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(service),
                ctx,
            )
            .await;

        let restarter = self.restarter.clone();
        tokio::spawn(async move {
            tokio::time::sleep(SHUTDOWN_GRACE).await;
            restarter.request_restart();
        });
        Ok(())
    }
}
