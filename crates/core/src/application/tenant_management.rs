//! Tenant creation and management use cases (ADR-0009 §4, §5, §6).
//!
//! Tenant creation is uniformly treated as "creating a child tenant under some tenant". It requires `idp.system.admin` (scope =
//! exists only on root), so **in practice only root can create tenants** (§4. The check is done by
//! Presentation's `RequirePerms<IdpSystemAdmin>`).
//!
//! On creation, **the creator themselves** is registered as the new tenant's bootstrap admin (an ACTIVE GUEST
//! membership + `idp.tenant.admin` scoped to the new tenant). The creator enters the new tenant's admin console with their own
//! SSO session, registers the real admin (a HOME user belonging to the new tenant), grants
//! `idp.tenant.admin`, and finally removes their own guest membership to leave (on removal, permission rows scoped to that
//! tenant are also cleaned up. §3). No initial password is handed over, so no plaintext password is returned.
//!
//! The tenant row, the creator's bootstrap membership and the permission grant are persisted by
//! [`TenantProvisioningRepository`] in a **single transaction** (unit of work. REF2).
//! A mid-way failure never leaves behind "a tenant without an admin".
//!
//! Getting, updating and deleting tenants targets **only direct children of the tenant** (`parent_tenant_id` match.
//! Children of other tenants are treated as nonexistent). The root tenant cannot be deleted, enforced in the app layer (§1).

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::paging::{PageRequest, PagedResult};
use crate::domain::repositories::{
    TenantDomainRepository, TenantProvisioningRepository, TenantRepository,
};
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_domain::{validate_domain, TenantDomain};
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::values::TenantStatus;
use std::sync::Arc;
use uuid::Uuid;

/// Permission granted to the creator (bootstrap admin) (scope = the new tenant. ADR-0009 §4).
const TENANT_ADMIN_PERMISSION: &str = "idp.tenant.admin";
/// Default number of items per page of the child tenant list (G7).
pub const DEFAULT_PAGE_LIMIT: i64 = 50;
/// Max number of items per page of the child tenant list (prevents oversized fetches).
pub const MAX_PAGE_LIMIT: i64 = 200;

#[derive(Debug, Clone)]
pub struct CreateTenantCommand {
    pub name: String,
}

/// Partial update command. Fields that are `None` are not changed.
#[derive(Debug, Clone, Default)]
pub struct UpdateTenantCommand {
    pub name: Option<String>,
    pub status: Option<TenantStatus>,
}

#[derive(Debug, thiserror::Error)]
pub enum TenantManagementError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(MessageKey),
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct TenantManagementService {
    tenants: Arc<dyn TenantRepository>,
    /// Domains assigned to tenants (ADR-0029). The admin side touches the same table as sign-in resolution.
    tenant_domains: Arc<dyn TenantDomainRepository>,
    provisioning: Arc<dyn TenantProvisioningRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl TenantManagementService {
    pub fn new(
        tenants: Arc<dyn TenantRepository>,
        tenant_domains: Arc<dyn TenantDomainRepository>,
        provisioning: Arc<dyn TenantProvisioningRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            tenants,
            tenant_domains,
            provisioning,
            audit,
            clock,
            ids,
        }
    }

    /// Creates a child tenant under the `requesting` tenant and registers **the creator themselves** (`actor`) as the new tenant's
    /// bootstrap admin (an ACTIVE GUEST membership + `idp.tenant.admin` scoped to the new tenant).
    /// The 3 rows (tenant, membership, permission) are persisted in a single transaction
    /// (unit of work. REF2). The creator then registers and grants the real admin, and removes themselves (§3, §4).
    pub async fn create_tenant(
        &self,
        requesting: TenantContext,
        cmd: CreateTenantCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Tenant, TenantManagementError> {
        let name = validate_name(cmd.name)?;

        // The creator becomes the new tenant's bootstrap admin (below). A client principal cannot hold
        // a membership or `idp.tenant.admin`, so the moment it is created **a tenant with no
        // admin** would exist. Refuse before that happens.
        // (`idp.system.admin` cannot be granted to clients, so this is not actually reached, but
        //  "not writing it because it is unreachable" would break silently if this assumption changes in the future.)
        let Some(bootstrap_admin) = actor.user_id() else {
            return Err(TenantManagementError::Forbidden(MessageKey::new(
                "api-tenant-create-requires-user-actor",
            )));
        };

        let now = self.clock.now();
        let tenant = Tenant {
            id: TenantId::from(self.ids.new_id()),
            parent_tenant_id: Some(requesting.tenant_id()),
            name,
            status: TenantStatus::Active,
            // Self-registration is disabled by default (fail-closed. SEC6. Tenant admins enable it from the settings screen).
            self_registration_enabled: false,
            // Sign-in by email is disabled by default (fail-closed. ADR-0050 decision 3).
            email_login_enabled: false,
            created_at: now,
            updated_at: now,
        };

        // Make the creator the new tenant's bootstrap admin (ACTIVE GUEST. Their home tenant stays the parent tenant).
        let membership = TenantMembership::new_active_guest(tenant.id, bootstrap_admin, now);

        // Atomically persist the tenant, the creator's membership, and the idp.tenant.admin grant (§4).
        // The permission grant does not go through the cached repository, but the tenant ID was just generated,
        // so the decision cache can never hold that key (no stale deny occurs).
        self.provisioning
            .provision(&tenant, &membership, TENANT_ADMIN_PERMISSION, now)
            .await
            .map_err(|e| match e {
                // The tenant's only unique key is the single-root sentinel column (display names are not unique). Reached only on a race.
                DomainError::Conflict(_) => {
                    TenantManagementError::Conflict(MessageKey::new("api-tenant-create-conflict"))
                }
                other => TenantManagementError::Internal(other.to_string()),
            })?;

        // Only internal IDs are recorded in the audit.
        self.audit
            .record(
                AuditEventType::TenantCreated,
                AuditResult::Success,
                Some(tenant.id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!(
                    "tenant={} bootstrap_admin={}",
                    tenant.id, bootstrap_admin
                )),
                ctx,
            )
            .await;

        Ok(tenant)
    }

    /// Lists the direct child tenants of the `requesting` tenant (§6).
    pub async fn list_children(
        &self,
        requesting: TenantContext,
    ) -> Result<Vec<Tenant>, TenantManagementError> {
        self.tenants
            .list_children(requesting.tenant_id())
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))
    }

    /// Returns one page of direct child tenants (G7). `limit` / `offset` take unvalidated request values,
    /// clamp them into the allowed range, and attach the **applied values** to the result.
    pub async fn list_children_page(
        &self,
        requesting: TenantContext,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<PagedResult<Tenant>, TenantManagementError> {
        let request = PageRequest::clamped(limit, offset, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT);
        let page = self
            .tenants
            .list_children_page(requesting.tenant_id(), request)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;
        Ok(PagedResult::new(page, request))
    }

    /// Gets one direct child tenant of the `requesting` tenant. Children of other tenants and missing ones are `NotFound`.
    pub async fn get_child(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
    ) -> Result<Tenant, TenantManagementError> {
        self.load_child(requesting, child_id).await
    }

    /// Updates a child tenant's display name and status (`parent_tenant_id` is not changed. §1).
    pub async fn update_tenant(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
        cmd: UpdateTenantCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Tenant, TenantManagementError> {
        let mut tenant = self.load_child(requesting, child_id).await?;
        if let Some(name) = cmd.name {
            tenant.name = validate_name(name)?;
        }
        if let Some(status) = cmd.status {
            tenant.status = status;
        }
        self.tenants
            .update(&tenant)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::TenantUpdated,
                AuditResult::Success,
                Some(tenant.id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("tenant={}", tenant.id)),
                ctx,
            )
            .await;
        Ok(tenant)
    }

    /// Gets the current (requested) tenant itself (the tenant settings section of the settings screen. MT14). Unlike
    /// `update_tenant`, which is limited to child tenants, this is used by tenant admins (`idp.tenant.admin`) to view their own tenant.
    pub async fn get_current(
        &self,
        current: TenantContext,
    ) -> Result<Tenant, TenantManagementError> {
        self.tenants
            .find_by_id(current.tenant_id())
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
            .ok_or(TenantManagementError::NotFound)
    }

    /// Updates the settings of the current (requested) tenant itself (the tenant settings section of the settings screen. MT14, SEC6).
    /// Targets the display name and two toggles (`self_registration_enabled`, `email_login_enabled`. `None` keeps
    /// the current value); authorization is handled by Presentation's `RequirePerms<IdpAdmin>`
    /// (`idp.tenant.admin`). `parent_tenant_id` and `status` are not changed.
    pub async fn update_current_settings(
        &self,
        current: TenantContext,
        name: String,
        self_registration_enabled: Option<bool>,
        email_login_enabled: Option<bool>,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Tenant, TenantManagementError> {
        let mut tenant = self.get_current(current).await?;
        tenant.name = validate_name(name)?;
        if let Some(enabled) = self_registration_enabled {
            tenant.self_registration_enabled = enabled;
        }
        if let Some(enabled) = email_login_enabled {
            tenant.email_login_enabled = enabled;
        }
        self.tenants
            .update(&tenant)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;
        self.audit
            .record(
                AuditEventType::TenantUpdated,
                AuditResult::Success,
                Some(tenant.id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("tenant={} (self settings)", tenant.id)),
                ctx,
            )
            .await;
        Ok(tenant)
    }

    /// Deletes a child tenant. Root cannot be deleted (§1). `Conflict` if it has children. If the tenant itself
    /// still has users/clients, the DB's `ON DELETE RESTRICT` makes it `Conflict` (§1).
    pub async fn delete_tenant(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), TenantManagementError> {
        let tenant = self.load_child(requesting, child_id).await?;
        // Root is structurally nobody's child (already rejected by load_child), but it is explicitly forbidden as a second line of defense.
        if tenant.is_root() {
            return Err(TenantManagementError::Forbidden(MessageKey::new(
                "api-tenant-root-cannot-delete",
            )));
        }
        // There must be no child tenants underneath (app-layer pre-validation. §1).
        let grandchildren = self
            .tenants
            .list_children(tenant.id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?;
        if !grandchildren.is_empty() {
            return Err(TenantManagementError::Conflict(MessageKey::new(
                "api-tenant-has-children",
            )));
        }

        // Remaining users/clients are turned into Conflict by the DB FK (ON DELETE RESTRICT) (§1).
        self.tenants.delete(tenant.id).await.map_err(|e| match e {
            // Refusal by FK (ON DELETE RESTRICT) = users or clients remain underneath (§1).
            DomainError::Conflict(_) => {
                TenantManagementError::Conflict(MessageKey::new("api-tenant-has-dependents"))
            }
            other => TenantManagementError::Internal(other.to_string()),
        })?;

        self.audit
            .record(
                AuditEventType::TenantDeleted,
                AuditResult::Success,
                Some(tenant.id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("tenant={}", tenant.id)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Gets `child_id` after checking it is a direct child tenant of `requesting` (children of other tenants
    /// and missing ones become `NotFound`, without leaking existence. §6).
    async fn load_child(
        &self,
        requesting: TenantContext,
        child_id: TenantId,
    ) -> Result<Tenant, TenantManagementError> {
        match self
            .tenants
            .find_by_id(child_id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
        {
            Some(tenant) if tenant.parent_tenant_id == Some(requesting.tenant_id()) => Ok(tenant),
            _ => Err(TenantManagementError::NotFound),
        }
    }

    // ── Domain assignments (ADR-0029) ─────────────────────────────────────────

    /// The target of domain operations is **the own tenant or a direct child**.
    ///
    /// It is not limited to children because root itself also needs domains (root's users enter the tenants
    /// they created as guests, so it is pointless if they cannot enter with domain qualification). Root is nobody's
    /// child, so it cannot be reached by `load_child`.
    async fn load_self_or_child(
        &self,
        requesting: TenantContext,
        target_id: TenantId,
    ) -> Result<Tenant, TenantManagementError> {
        if target_id == requesting.tenant_id() {
            return match self
                .tenants
                .find_by_id(target_id)
                .await
                .map_err(|e| TenantManagementError::Internal(e.to_string()))?
            {
                Some(tenant) => Ok(tenant),
                None => Err(TenantManagementError::NotFound),
            };
        }
        self.load_child(requesting, target_id).await
    }

    /// Lists assigned domains.
    pub async fn list_domains(
        &self,
        requesting: TenantContext,
        target_id: TenantId,
    ) -> Result<Vec<TenantDomain>, TenantManagementError> {
        let tenant = self.load_self_or_child(requesting, target_id).await?;
        self.tenant_domains
            .list_for_tenant(tenant.id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))
    }

    /// Assigns a domain.
    ///
    /// Uniqueness is **global**, so it is `Conflict` even if another tenant holds it. Which tenant
    /// holds it is not returned: other tenants' configuration must not be discoverable by brute-forcing domains.
    pub async fn add_domain(
        &self,
        requesting: TenantContext,
        target_id: TenantId,
        raw_domain: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<TenantDomain, TenantManagementError> {
        let tenant = self.load_self_or_child(requesting, target_id).await?;
        let domain = validate_domain(raw_domain).map_err(TenantManagementError::Validation)?;
        let now = self.clock.now();
        let record = TenantDomain {
            id: self.ids.new_id(),
            tenant_id: tenant.id,
            domain,
            created_at: now,
            updated_at: now,
        };
        self.tenant_domains
            .create(&record)
            .await
            .map_err(|e| match e {
                DomainError::Conflict(_) => {
                    TenantManagementError::Conflict(MessageKey::new("api-tenant-domain-conflict"))
                }
                other => TenantManagementError::Internal(other.to_string()),
            })?;
        // The domain is kept in the audit (not PII, but the tenant's configuration itself). It is an operation that decides
        // which tenant sign-ins go to, and must be traceable with the same weight as permission grants.
        self.record_domain_event(
            AuditEventType::TenantDomainAdded,
            tenant.id,
            actor,
            &record.domain,
            ctx,
        )
        .await;
        Ok(record)
    }

    /// Removes an assignment.
    pub async fn remove_domain(
        &self,
        requesting: TenantContext,
        target_id: TenantId,
        domain_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), TenantManagementError> {
        let tenant = self.load_self_or_child(requesting, target_id).await?;
        // Read before deleting, for the value kept in the audit (after deletion we cannot tell what was removed).
        let removed = self
            .tenant_domains
            .list_for_tenant(tenant.id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
            .into_iter()
            .find(|d| d.id == domain_id)
            .ok_or(TenantManagementError::NotFound)?;
        if !self
            .tenant_domains
            .delete(tenant.id, domain_id)
            .await
            .map_err(|e| TenantManagementError::Internal(e.to_string()))?
        {
            return Err(TenantManagementError::NotFound);
        }
        self.record_domain_event(
            AuditEventType::TenantDomainRemoved,
            tenant.id,
            actor,
            &removed.domain,
            ctx,
        )
        .await;
        Ok(())
    }

    async fn record_domain_event(
        &self,
        event: AuditEventType,
        tenant_id: TenantId,
        actor: &AdminActor,
        domain: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                event,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("domain={domain}")),
                ctx,
            )
            .await;
    }
}

fn validate_name(name: String) -> Result<String, TenantManagementError> {
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err(TenantManagementError::Validation(MessageKey::new(
            "api-tenant-name-empty",
        )));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::values::{MembershipStatus, MembershipType};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 11, 12, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    struct SeqIds(Mutex<u128>);
    impl IdGenerator for SeqIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &AuditEvent) -> DomainResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeTenants {
        rows: Mutex<Vec<Tenant>>,
    }
    #[async_trait]
    impl TenantRepository for FakeTenants {
        async fn create(&self, t: &Tenant) -> DomainResult<()> {
            self.rows.lock().unwrap().push(t.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: TenantId) -> DomainResult<Option<Tenant>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.id == id)
                .cloned())
        }
        async fn find_root(&self) -> DomainResult<Option<Tenant>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.is_root())
                .cloned())
        }
        async fn list_children(&self, parent: TenantId) -> DomainResult<Vec<Tenant>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|t| t.parent_tenant_id == Some(parent))
                .cloned()
                .collect())
        }
        async fn update(&self, t: &Tenant) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|r| r.id == t.id) {
                *row = t.clone();
            }
            Ok(())
        }
        async fn delete(&self, id: TenantId) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|t| t.id != id);
            Ok(())
        }
    }

    /// Fake of the tenant provisioning unit of work. On success records all rows "together" (mimicking atomicity);
    /// with `fail = true` it fails without writing anything (equivalent to a mid-way failure = full rollback).
    /// A tenant without domains (default implementation as is). Existing tests do not go through the domain path.
    struct NoTenantDomains;

    #[async_trait]
    impl crate::domain::repositories::TenantDomainRepository for NoTenantDomains {}

    struct FakeProvisioning {
        tenants: Arc<FakeTenants>,
        memberships: Mutex<Vec<TenantMembership>>,
        granted: Mutex<Vec<(TenantId, Uuid, String)>>,
        fail: bool,
    }
    #[async_trait]
    impl TenantProvisioningRepository for FakeProvisioning {
        async fn provision(
            &self,
            tenant: &Tenant,
            admin_membership: &TenantMembership,
            admin_permission_code: &str,
            _granted_at: DateTime<Utc>,
        ) -> DomainResult<()> {
            if self.fail {
                return Err(DomainError::Repository(
                    "simulated provisioning failure".to_string(),
                ));
            }
            self.tenants.rows.lock().unwrap().push(tenant.clone());
            self.memberships
                .lock()
                .unwrap()
                .push(admin_membership.clone());
            self.granted.lock().unwrap().push((
                admin_membership.tenant_id,
                admin_membership.user_id,
                admin_permission_code.to_string(),
            ));
            Ok(())
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    struct Harness {
        svc: TenantManagementService,
        tenants: Arc<FakeTenants>,
        provisioning: Arc<FakeProvisioning>,
        sink: Arc<CapturingSink>,
    }

    fn harness() -> Harness {
        harness_with(false)
    }

    fn harness_with(fail_provision: bool) -> Harness {
        let sink = Arc::new(CapturingSink::default());
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock(now()))));
        let tenants = Arc::new(FakeTenants::default());
        let provisioning = Arc::new(FakeProvisioning {
            tenants: tenants.clone(),
            memberships: Mutex::new(Vec::new()),
            granted: Mutex::new(Vec::new()),
            fail: fail_provision,
        });
        let svc = TenantManagementService::new(
            tenants.clone(),
            Arc::new(NoTenantDomains),
            provisioning.clone(),
            audit,
            Arc::new(FixedClock(now())),
            Arc::new(SeqIds(Mutex::new(0))),
        );
        Harness {
            svc,
            tenants,
            provisioning,
            sink,
        }
    }

    fn root() -> TenantContext {
        // Represents the creating tenant as root (not used for the parent match).
        TenantContext::new(TenantId::from(Uuid::from_u128(0xAAAA)))
    }

    #[tokio::test]
    async fn create_tenant_adds_creator_as_bootstrap_guest_admin() {
        let h = harness();
        let actor = Uuid::new_v4();
        let tenant = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "  Acme  ".to_string(),
                },
                &AdminActor::User(actor),
                &ctx(),
            )
            .await
            .expect("created");

        assert_eq!(tenant.name, "Acme");
        assert_eq!(tenant.parent_tenant_id, Some(root().tenant_id()));
        // idp.tenant.admin scoped to the new tenant is granted to the creator.
        let granted = h.provisioning.granted.lock().unwrap().clone();
        assert_eq!(
            granted,
            vec![(tenant.id, actor, "idp.tenant.admin".to_string())]
        );
        // The creator's ACTIVE GUEST membership is included in the same unit of work.
        let memberships = h.provisioning.memberships.lock().unwrap();
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].membership_type, MembershipType::Guest);
        assert_eq!(memberships[0].status, MembershipStatus::Active);
        assert_eq!(memberships[0].tenant_id, tenant.id);
        assert_eq!(memberships[0].user_id, actor);
        // tenant.created is recorded in the audit, and no initial admin user is created (no user.created).
        let events = h.sink.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| e.event_type == AuditEventType::TenantCreated));
        assert!(events
            .iter()
            .all(|e| e.event_type != AuditEventType::UserCreated));
    }

    #[tokio::test]
    async fn provision_failure_leaves_no_tenant_and_no_success_audit() {
        let h = harness_with(true);
        let result = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "Acme".to_string(),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await;
        assert!(matches!(result, Err(TenantManagementError::Internal(_))));
        // If the unit of work fails, no tenant, membership or permission remains.
        assert!(h.tenants.rows.lock().unwrap().is_empty());
        assert!(h.provisioning.memberships.lock().unwrap().is_empty());
        assert!(h.provisioning.granted.lock().unwrap().is_empty());
        // The success audit (tenant.created) is not recorded either.
        assert!(h.sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_tenant_rejects_empty_name() {
        let h = harness();
        assert!(matches!(
            h.svc
                .create_tenant(
                    root(),
                    CreateTenantCommand {
                        name: "   ".to_string(),
                    },
                    &AdminActor::User(Uuid::new_v4()),
                    &ctx()
                )
                .await,
            Err(TenantManagementError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn get_update_delete_scope_to_direct_children() {
        let h = harness();
        let created = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "Child".to_string(),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();
        let child_id = created.id;

        // Not visible from another tenant (NotFound).
        let other = TenantContext::new(TenantId::from(Uuid::from_u128(0xBBBB)));
        assert!(matches!(
            h.svc.get_child(other, child_id).await,
            Err(TenantManagementError::NotFound)
        ));

        // A direct child can be fetched.
        assert_eq!(
            h.svc.get_child(root(), child_id).await.unwrap().id,
            child_id
        );

        // Update (display name, status).
        let updated = h
            .svc
            .update_tenant(
                root(),
                child_id,
                UpdateTenantCommand {
                    name: Some("Renamed".to_string()),
                    status: Some(TenantStatus::Disabled),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "Renamed");
        assert_eq!(updated.status, TenantStatus::Disabled);

        // Can be deleted (the fake does not check children/users, but list_children is empty).
        h.svc
            .delete_tenant(root(), child_id, &AdminActor::User(Uuid::new_v4()), &ctx())
            .await
            .expect("deleted");
        assert!(h
            .tenants
            .rows
            .lock()
            .unwrap()
            .iter()
            .all(|t| t.id != child_id));
    }

    #[tokio::test]
    async fn delete_rejects_tenant_with_children() {
        let h = harness();
        let parent = h
            .svc
            .create_tenant(
                root(),
                CreateTenantCommand {
                    name: "Parent".to_string(),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();
        // Create a grandchild under parent (with parent as requesting).
        h.svc
            .create_tenant(
                TenantContext::new(parent.id),
                CreateTenantCommand {
                    name: "Grandchild".to_string(),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .unwrap();

        assert!(matches!(
            h.svc
                .delete_tenant(root(), parent.id, &AdminActor::User(Uuid::new_v4()), &ctx())
                .await,
            Err(TenantManagementError::Conflict(_))
        ));
    }
}
