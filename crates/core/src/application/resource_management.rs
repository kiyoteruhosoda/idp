//! Registering, disabling and deleting protected resources (the audience placed in `aud`) (ADR-0042).
//!
//! "Which service account may obtain tokens for this audience" is not held here. The audience is bound as
//! an app's identity, and service accounts are assigned to that app (ADR-0059 decision 6).
//!
//! It is a separate service from permission-code grants (`client_permission_management`) because **the inputs
//! to the decision differ**. That one can statically decide "may this code be granted to a client", whereas this
//! one has to ask the repository "is that audience registered in the requested tenant".
//!
//! Decisions are made in this Application layer, and only the result is passed to Presentation (CLAUDE.md "Permissions").

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::repositories::ProtectedResourceRepository;
use crate::domain::resource::{validate_display_name, validate_resource_uri, ProtectedResource};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::ResourceStatus;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum ResourceManagementError {
    /// The audience does not exist in the requested tenant.
    NotFound,
    /// Invalid input (empty, not an absolute URI, has a fragment, or a reserved audience).
    Invalid(MessageKey),
    /// The same audience is already registered.
    Conflict(MessageKey),
    Internal(String),
}

pub struct ResourceManagementService {
    resources: Arc<dyn ProtectedResourceRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    /// The issuer before the tenant prefix is added. Used to detect reserved audiences (`/userinfo`, `/admin`).
    base_issuer: String,
}

impl ResourceManagementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resources: Arc<dyn ProtectedResourceRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        base_issuer: String,
    ) -> Self {
        Self {
            resources,
            audit,
            clock,
            ids,
            base_issuer,
        }
    }

    /// Lists audiences (ascending `resource_uri`).
    pub async fn list(
        &self,
        tenant: TenantContext,
    ) -> Result<Vec<ProtectedResource>, ResourceManagementError> {
        self.resources
            .list(tenant.tenant_id())
            .await
            .map_err(map_repo_error)
    }

    /// Registers an audience.
    pub async fn register(
        &self,
        tenant: TenantContext,
        raw_uri: &str,
        raw_display_name: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ProtectedResource, ResourceManagementError> {
        let resource_uri =
            validate_resource_uri(raw_uri).map_err(ResourceManagementError::Invalid)?;
        let display_name =
            validate_display_name(raw_display_name).map_err(ResourceManagementError::Invalid)?;
        self.ensure_not_reserved(tenant, &resource_uri)?;

        let now = self.clock.now();
        let resource = ProtectedResource {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            resource_uri,
            display_name,
            status: ResourceStatus::Active,
            created_at: now,
            updated_at: now,
        };
        self.resources
            .create(&resource)
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ResourceRegistered,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                None,
                Some(&audit_reason(&resource.resource_uri, actor)),
                ctx,
            )
            .await;
        Ok(resource)
    }

    /// Changes an audience's status (`DISABLED` makes it unusable as the target of new tokens).
    pub async fn set_status(
        &self,
        tenant: TenantContext,
        id: Uuid,
        status: ResourceStatus,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ProtectedResource, ResourceManagementError> {
        let resource = self.load(tenant, id).await?;
        // The returned bool is not used to detect "missing". MySQL's `rows_affected` counts **rows whose values changed**,
        // so updating a row already in the same state with the same `updated_at` gives 0, turning an existing row
        // into a 404. Existence is checked by the preceding `load`, and disappearance by the trailing `load`.
        self.resources
            .set_status(tenant.tenant_id(), id, status, self.clock.now())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::ResourceUpdated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                None,
                Some(&format!(
                    "{} status={}",
                    audit_reason(&resource.resource_uri, actor),
                    status.as_str()
                )),
                ctx,
            )
            .await;
        self.load(tenant, id).await
    }

    /// Deletes an audience. The app identity (`application_bindings`) is deleted with it.
    ///
    /// **Already issued tokens are not revoked.** `aud` is a signed claim and stays valid from the resource
    /// server's point of view until its lifetime runs out. To stop it quickly, dropping that `client_id` on the
    /// receiving side is faster.
    pub async fn delete(
        &self,
        tenant: TenantContext,
        id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), ResourceManagementError> {
        let resource = self.load(tenant, id).await?;
        let deleted = self
            .resources
            .delete(tenant.tenant_id(), id)
            .await
            .map_err(map_repo_error)?;
        if !deleted {
            return Err(ResourceManagementError::NotFound);
        }

        self.audit
            .record(
                AuditEventType::ResourceDeleted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                None,
                Some(&audit_reason(&resource.resource_uri, actor)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// **This authorization server's own namespace (under the issuer) is not lent out.**
    ///
    /// The `aud` values assay itself uses now are `{issuer}/userinfo` and `{issuer}/admin`, but
    /// rejecting only exact matches would allow **confusing names** like `{issuer}/admin/` (trailing slash) to be registered.
    /// Every new endpoint would force rethinking "was it OK to lend that name", so the whole
    /// prefix is reserved.
    ///
    /// ⚠ **This is defense in depth, not something without which permissions would leak.**
    /// Even if `{issuer}/admin` could be registered, (1) token issuance hits the admin API arm first, so
    /// this table is not read, and (2) even if it were, a token without `perms` passes none of the admin API's
    /// `RequirePerms` (held codes are read from the `perms` claim).
    /// What is protected is **the implicit assumption of branch order on the issuing side**, the kind of thing that
    /// breaks the moment it is reordered, so it is also blocked on the registration side.
    fn ensure_not_reserved(
        &self,
        _tenant: TenantContext,
        resource_uri: &str,
    ) -> Result<(), ResourceManagementError> {
        // Look at the base issuer without the tenant prefix. This also blocks registrations impersonating another
        // tenant's name, like `{base}/{other tenant}/admin`.
        //
        // The comparison **ignores case**. RFC 3986 §3.1 and §3.2.2 define URI scheme and host as
        // case-insensitive, so `HTTPS://…/admin`, differing only in case, would slip through.
        // The error is in the direction of reserving more, so over-rejecting does no harm.
        let base = self.base_issuer.trim_end_matches('/').to_ascii_lowercase();
        let candidate = resource_uri.to_ascii_lowercase();
        let inside_our_namespace = candidate == base || candidate.starts_with(&format!("{base}/"));
        if inside_our_namespace {
            return Err(ResourceManagementError::Invalid(MessageKey::new(
                "api-resource-uri-reserved",
            )));
        }
        Ok(())
    }

    async fn load(
        &self,
        tenant: TenantContext,
        id: Uuid,
    ) -> Result<ProtectedResource, ResourceManagementError> {
        match self.resources.find_by_id(tenant.tenant_id(), id).await {
            Ok(Some(resource)) => Ok(resource),
            Ok(None) => Err(ResourceManagementError::NotFound),
            Err(e) => Err(ResourceManagementError::Internal(e.to_string())),
        }
    }
}

/// The audit log `reason` (no PII. The audience and, if a machine performed it, its `client_id`).
fn audit_reason(resource_uri: &str, actor: &AdminActor) -> String {
    match actor.audit_note() {
        Some(note) => format!("resource={resource_uri} {note}"),
        None => format!("resource={resource_uri}"),
    }
}

fn map_repo_error(e: DomainError) -> ResourceManagementError {
    match e {
        DomainError::Conflict(_) => {
            ResourceManagementError::Conflict(MessageKey::new("api-resource-uri-conflict"))
        }
        DomainError::InvalidValue(_) => {
            ResourceManagementError::Invalid(MessageKey::new("api-resource-uri-invalid"))
        }
        DomainError::NotFound => ResourceManagementError::NotFound,
        other => ResourceManagementError::Internal(other.to_string()),
    }
}
