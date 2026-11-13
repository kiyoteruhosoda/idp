//! Granting, revoking and listing admin permissions for system clients (ADR-0037).
//!
//! It is a separate service from granting to users (`permission_management`) because **the set of grantable
//! codes differs**. Clients are never granted blanket admin permissions (`idp.system.admin` / `idp.tenant.admin`).
//! Routing both through one service would bury this difference in an `if` branch.
//!
//! Decisions are made in this Application layer; Presentation only gets the result (CLAUDE.md "Permission management").

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::message::MessageKey;
use crate::domain::permission::{self, PermissionCode};
use crate::domain::repositories::{ClientPermissionRepository, ClientRepository};
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum ClientPermissionError {
    /// The target client does not exist in the requested tenant (including deleted ones).
    NotFound,
    /// Invalid permission code (empty, unknown, or a code that cannot be granted to clients).
    Invalid(MessageKey),
    Internal(String),
}

pub struct ClientPermissionManagementService {
    clients: Arc<dyn ClientRepository>,
    client_permissions: Arc<dyn ClientPermissionRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl ClientPermissionManagementService {
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        client_permissions: Arc<dyn ClientPermissionRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            clients,
            client_permissions,
            audit,
            clock,
        }
    }

    /// Lists the permission codes held by the target client (ascending).
    pub async fn list(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<Vec<String>, ClientPermissionError> {
        let client = self.load_client(tenant, client_id).await?;
        let mut codes = self
            .client_permissions
            .list_codes_for_client(client.id)
            .await
            .map_err(map_repo_error)?;
        codes.sort();
        Ok(codes)
    }

    /// Grants a permission code (idempotent). Returns the held codes after granting.
    ///
    /// `tenant_is_root` is **whether the requested tenant is root**. Needed so codes that can only exist
    /// in root cannot be handed out from inside a tenant (`permission::is_grantable_in_tenant`).
    /// Taken as a bool because this layer does not look up the tenants table (doing so adds a boundary).
    pub async fn grant(
        &self,
        tenant: TenantContext,
        tenant_is_root: bool,
        client_id: &str,
        raw_code: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, ClientPermissionError> {
        let code = parse_code(raw_code)?;
        let client = self.load_client(tenant, client_id).await?;

        // Blanket admin permissions are not granted to clients (defense in depth with the DB CHECK constraint).
        // Rejecting here also translates the DB constraint violation into user-facing wording.
        if !permission::is_grantable_to_client(code.as_str()) {
            return Err(ClientPermissionError::Invalid(MessageKey::new(
                "api-client-permission-not-grantable",
            )));
        }

        // Codes that can only exist in root are not handed out from inside a tenant (ADR-0009 §4).
        // ⚠ **This is a different axis from `is_grantable_to_client`.** That one checks "is the granularity OK for a machine";
        //   this one checks "can a permission of that scope exist in that tenant".
        if !permission::is_grantable_in_tenant(code.as_str(), tenant_is_root) {
            return Err(ClientPermissionError::Invalid(MessageKey::new(
                "api-client-permission-not-grantable",
            )));
        }

        self.client_permissions
            .grant(client.id, code.as_str(), self.clock.now())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ClientPermissionGranted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                // The `client_id` column is the client being operated on. When the actor is a machine, it goes in the reason field.
                Some(&client.client_id),
                Some(&audit_reason(code.as_str(), actor)),
                ctx,
            )
            .await;
        self.list(tenant, client_id).await
    }

    /// Revokes a permission code (no error if not held). Returns the held codes after revoking.
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        client_id: &str,
        raw_code: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, ClientPermissionError> {
        let code = parse_code(raw_code)?;
        let client = self.load_client(tenant, client_id).await?;

        self.client_permissions
            .revoke(client.id, code.as_str())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ClientPermissionRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                Some(&client.client_id),
                Some(&audit_reason(code.as_str(), actor)),
                ctx,
            )
            .await;
        self.list(tenant, client_id).await
    }

    /// Resolves an active client in the requested tenant. Another tenant's `client_id` is not resolved.
    async fn load_client(
        &self,
        tenant: TenantContext,
        client_id: &str,
    ) -> Result<crate::domain::client::Client, ClientPermissionError> {
        match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
            // Logically deleted ones (ADR-0035) are treated as "absent". If only permissions were reassigned,
            // a supposedly deleted client would come back holding permissions nobody knew about.
            Ok(Some(client)) if !client.is_deleted() => Ok(client),
            Ok(_) => Err(ClientPermissionError::NotFound),
            Err(e) => Err(ClientPermissionError::Internal(e.to_string())),
        }
    }
}

fn parse_code(raw: &str) -> Result<PermissionCode, ClientPermissionError> {
    PermissionCode::parse(raw.trim()).map_err(|_| {
        ClientPermissionError::Invalid(MessageKey::new("api-permission-code-required"))
    })
}

/// `reason` for the audit log (no PII: the permission codes and, when a machine performed it, its `client_id`).
fn audit_reason(code: &str, actor: &AdminActor) -> String {
    match actor.audit_note() {
        Some(note) => format!("permission={code} {note}"),
        None => format!("permission={code}"),
    }
}

fn map_repo_error(e: DomainError) -> ClientPermissionError {
    match e {
        // An unknown permission code (FK violation) or a CHECK violation is an input error either way.
        DomainError::InvalidValue(_) => {
            ClientPermissionError::Invalid(MessageKey::new("api-client-permission-not-grantable"))
        }
        other => ClientPermissionError::Internal(other.to_string()),
    }
}
