//! Use case for granting and revoking user permissions (permission codes) (ADR-0006, Progress A2).
//!
//! Only tenant admins (`idp.tenant.admin`; `idp.system.admin` accepted as an alternative) run it. Decisions and validation are completed in this Application layer and only
//! the result is returned to Presentation (CLAUDE.md "Permission management"). Every grant and revocation is recorded in `audit_log`
//! (`user_permission.granted` / `.revoked`, design spec §7).
//!
//! **Reading** permissions (protection checks) is the job of [`crate::application::admin_access::AdminAccessService`].
//! This service has the separate responsibility of "managing (changing) permissions" (SRP), the same role as `ClientManagementService`.

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::message::MessageKey;
use crate::domain::permission::{self, PermissionCode};
use crate::domain::repositories::{
    TenantMembershipRepository, TenantRepository, UserPermissionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum PermissionManagementError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Granting and revoking `idp.system.admin` can only be done by holders of it (ADR-0009 §4).
pub struct PermissionManagementService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    /// Used to resolve the root tenant. `idp.system.admin` can only exist in the root scope, so the actor's
    /// holding must be looked up **in the root scope, not the requested tenant** (ADR-0009 §4).
    tenants: Arc<dyn TenantRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl PermissionManagementService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        tenants: Arc<dyn TenantRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            memberships,
            permissions,
            tenants,
            audit,
            clock,
        }
    }

    /// Returns the list of grantable permission codes (the `permissions` master). Used to present the choices in
    /// the admin console's (A2) grant form.
    pub async fn available_codes(&self) -> Result<Vec<String>, PermissionManagementError> {
        self.permissions
            .list_available_codes()
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// Gets the target user by internal ID (for display in the admin console). Missing, or a home tenant other than
    /// the requested tenant (cross-tenant lookup, including guests), is equivalent to 404 (ADR-0009 §3:
    /// host tenant admins can't reach a guest's `users` record).
    pub async fn get_user(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<User, PermissionManagementError> {
        match self.find_user_by_id(target).await? {
            Some(user) if user.tenant_id == tenant.tenant_id() => Ok(user),
            _ => Err(PermissionManagementError::NotFound),
        }
    }

    /// Finds a user by identifier (email address or user name) (for the admin console's search).
    /// Resolved as an email if it contains `@`, otherwise as a user name. An empty string returns None.
    pub async fn find_user_by_identifier(
        &self,
        tenant: TenantContext,
        identifier: &str,
    ) -> Result<Option<User>, PermissionManagementError> {
        let identifier = identifier.trim();
        if identifier.is_empty() {
            return Ok(None);
        }
        let tenant_id = tenant.tenant_id();
        let result = if identifier.contains('@') {
            self.users.find_by_email(tenant_id, identifier).await
        } else {
            self.users.find_by_username(tenant_id, identifier).await
        };
        result.map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// Returns the permission codes the target user holds with the requested tenant as scope (order unspecified).
    pub async fn list(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<Vec<String>, PermissionManagementError> {
        self.ensure_user_in_tenant(tenant, target).await?;
        self.permissions
            .list_codes_for_user(tenant.tenant_id(), target)
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// Grants a permission code to the target user with the requested tenant as scope (idempotent).
    /// Returns the held codes after granting. Granting `idp.system.admin` can only be done by holders
    /// (ADR-0009 §4. scope = root is guaranteed with defense in depth by the DB CHECK constraint).
    pub async fn grant(
        &self,
        tenant: TenantContext,
        target: Uuid,
        code: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, PermissionManagementError> {
        let code = PermissionCode::parse(code).map_err(|_| {
            PermissionManagementError::Validation(MessageKey::new("api-permission-unknown"))
        })?;
        self.ensure_user_in_tenant(tenant, target).await?;
        self.ensure_system_admin_change_allowed(tenant, &code, actor)
            .await?;
        self.ensure_root_scoped_code_stays_in_root(tenant, &code)
            .await?;

        self.permissions
            .grant(tenant.tenant_id(), target, code.as_str(), self.clock.now())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::UserPermissionGranted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&audit_reason(&code, target)),
                ctx,
            )
            .await;

        self.list(tenant, target).await
    }

    /// Revokes a permission code scoped to the requested tenant from the target user (no error if not held).
    /// Returns the held codes after revoking. Revoking `idp.system.admin` can only be done by holders (ADR-0009 §4).
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        target: Uuid,
        code: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<Vec<String>, PermissionManagementError> {
        let code = PermissionCode::parse(code).map_err(|_| {
            PermissionManagementError::Validation(MessageKey::new("api-permission-unknown"))
        })?;
        self.ensure_user_in_tenant(tenant, target).await?;
        self.ensure_system_admin_change_allowed(tenant, &code, actor)
            .await?;

        self.permissions
            .revoke(tenant.tenant_id(), target, code.as_str())
            .await
            .map_err(map_repo_error)?;

        self.audit
            .record(
                AuditEventType::UserPermissionRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&audit_reason(&code, target)),
                ctx,
            )
            .await;

        self.list(tenant, target).await
    }

    /// Confirms that the target user exists and has an **ACTIVE membership** (HOME / GUEST) in the requested tenant
    /// (ADR-0009 §4). Grant targets aren't distinguished by account origin (HOME or GUEST).
    /// `INVITED` (not yet accepted) guests and users outside the tenant have no ACTIVE membership, so to prevent
    /// cross-tenant existence guessing they fall to the same 404 as nonexistent.
    async fn ensure_user_in_tenant(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<(), PermissionManagementError> {
        // The user exists (a membership row implies the user via FK, but this is stated explicitly to record the intent).
        let exists = self.find_user_by_id(target).await?.is_some();
        // Has an ACTIVE membership (HOME / GUEST) in the requested tenant.
        let active_member = exists
            && self
                .memberships
                .is_active_member(tenant.tenant_id(), target)
                .await
                .map_err(|e| PermissionManagementError::Internal(e.to_string()))?;
        if active_member {
            Ok(())
        } else {
            Err(PermissionManagementError::NotFound)
        }
    }

    /// Looks up by user ID and converts internal errors to `PermissionManagementError::Internal`.
    async fn find_user_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<crate::domain::user::User>, PermissionManagementError> {
        self.users
            .find_by_id(id)
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))
    }

    /// Codes handling resources shared by all tenants (signing keys. `permission::ROOT_SCOPED_CODES`) can only be
    /// granted inside root. If held in a child tenant, its admin would reach the global keys across tenants.
    /// ⚠ Revocation is not blocked (so rows left outside root can be cleaned up).
    async fn ensure_root_scoped_code_stays_in_root(
        &self,
        tenant: TenantContext,
        code: &PermissionCode,
    ) -> Result<(), PermissionManagementError> {
        if !permission::is_root_scoped(code.as_str()) {
            return Ok(());
        }
        let root = self
            .tenants
            .find_root()
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))?
            .ok_or_else(|| PermissionManagementError::Internal("root tenant not found".into()))?;
        if tenant.tenant_id() == root.id {
            Ok(())
        } else {
            Err(PermissionManagementError::Forbidden(MessageKey::new(
                "api-permission-insufficient",
            )))
        }
    }

    /// Granting and revoking `idp.system.admin` can only be performed by holders of `idp.system.admin` (ADR-0009 §4).
    async fn ensure_system_admin_change_allowed(
        &self,
        tenant: TenantContext,
        code: &PermissionCode,
        actor: &AdminActor,
    ) -> Result<(), PermissionManagementError> {
        if code.as_str() != permission::SYSTEM_ADMIN {
            return Ok(());
        }
        // `idp.system.admin` can't be granted to clients (ADR-0037), so a client actor can't hold this permission
        // by definition. **Root permissions never sprouting from machine credentials** is the premise of
        // fine-grained permissions, so reject here without even looking at the repository.
        let Some(actor_user_id) = actor.user_id() else {
            return Err(PermissionManagementError::Forbidden(MessageKey::new(
                "api-permission-system-admin-forbidden",
            )));
        };

        let root = self
            .tenants
            .find_root()
            .await
            .map_err(|e| PermissionManagementError::Internal(e.to_string()))?
            .ok_or_else(|| PermissionManagementError::Internal("root tenant not found".into()))?;

        // 1. This permission can only exist in the root scope (CHECK constraint
        //    `user_permissions_system_admin_scope_chk`. ADR-0009 §4). Granting in a non-root tenant fails at
        //    row insertion anyway, so refuse without even checking the actor's eligibility. **Leaving this to the actor
        //    check would let a root system admin pass the check in a non-root tenant and end in a 500 from the DB
        //    constraint violation.** The grant form's choices are already filtered by `permission::is_grantable_in_tenant`, so
        //    only direct API calls get here.
        if tenant.tenant_id() != root.id {
            return Err(PermissionManagementError::Forbidden(MessageKey::new(
                "api-permission-system-admin-root-only",
            )));
        }

        // 2. The actor holds `idp.system.admin` **in the root scope**. "Is the actor a system admin" is a fact
        //    of the root scope, and looking it up in the requested tenant is the wrong question (even if, after
        //    passing check 1, the result would be the same).
        match self
            .permissions
            .has_permission(root.id, actor_user_id, permission::SYSTEM_ADMIN)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(PermissionManagementError::Forbidden(MessageKey::new(
                "api-permission-system-admin-forbidden",
            ))),
            Err(e) => Err(PermissionManagementError::Internal(e.to_string())),
        }
    }
}

/// `reason` for the audit log (no PII: only internal UUIDs and permission codes).
fn audit_reason(code: &PermissionCode, target: Uuid) -> String {
    format!("permission={code} target={target}")
}

fn map_repo_error(e: DomainError) -> PermissionManagementError {
    match e {
        // Unknown permission codes (not in the `permissions` master) etc. are treated as bad requests.
        DomainError::InvalidValue(_) => {
            PermissionManagementError::Validation(MessageKey::new("api-permission-unknown"))
        }
        other => PermissionManagementError::Internal(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::tenant::{Tenant, TenantId};
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::user::User;
    use crate::domain::values::{TenantStatus, UserStatus};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 6, 12, 0, 0).unwrap()
    }

    fn test_tenant() -> TenantId {
        // Each test must align the user and tenant passed to service(), so these are fixed values.
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn tenant_ctx() -> TenantContext {
        TenantContext::new(test_tenant())
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// A tenant repository that only answers `find_root`. root is [`test_tenant`] ——each test passes
    /// this tenant as the requested tenant, so by default it is "an operation in the root tenant".
    struct FakeTenants;

    fn root_tenant() -> Tenant {
        Tenant {
            id: test_tenant(),
            parent_tenant_id: None,
            name: "root".to_string(),
            status: TenantStatus::Active,
            self_registration_enabled: false,
            email_login_enabled: false,
            created_at: fixed_now(),
            updated_at: fixed_now(),
        }
    }

    fn not_needed(method: &str) -> DomainError {
        DomainError::Repository(format!("{method} is not used by these tests"))
    }

    #[async_trait]
    impl TenantRepository for FakeTenants {
        async fn create(&self, _t: &Tenant) -> DomainResult<()> {
            Err(not_needed("create"))
        }
        async fn find_by_id(&self, id: TenantId) -> DomainResult<Option<Tenant>> {
            Ok((id == test_tenant()).then(root_tenant))
        }
        async fn find_root(&self) -> DomainResult<Option<Tenant>> {
            Ok(Some(root_tenant()))
        }
        async fn list_children(&self, _parent_id: TenantId) -> DomainResult<Vec<Tenant>> {
            Ok(Vec::new())
        }
        async fn update(&self, _t: &Tenant) -> DomainResult<()> {
            Err(not_needed("update"))
        }
        async fn delete(&self, _id: TenantId) -> DomainResult<()> {
            Err(not_needed("delete"))
        }
    }

    /// A sink that only collects audit events (for verifying that grants/revocations are recorded).
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

    struct FakeUsers {
        user: Option<User>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// These tests don't go through the login failure path (SEC13 verification is in login / mfa_login).
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self.user.clone().filter(|u| u.id == id))
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(
            &self,
            tenant_id: TenantId,
            email: &str,
        ) -> DomainResult<Option<User>> {
            Ok(self
                .user
                .clone()
                .filter(|u| u.tenant_id == tenant_id && u.email == email))
        }
        async fn find_by_username(
            &self,
            tenant_id: TenantId,
            username: &str,
        ) -> DomainResult<Option<User>> {
            Ok(self
                .user
                .clone()
                .filter(|u| u.tenant_id == tenant_id)
                .filter(|u| u.preferred_username.as_deref() == Some(username)))
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _c: i32,
            _l: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_password(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _status: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// A fake treating the given (tenant, user) pairs as ACTIVE members (others are non-members).
    #[derive(Default)]
    struct FakeMemberships {
        active: Mutex<Vec<(TenantId, Uuid)>>,
    }
    impl FakeMemberships {
        fn with_active(pairs: Vec<(TenantId, Uuid)>) -> Self {
            Self {
                active: Mutex::new(pairs),
            }
        }
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn update_status(
            &self,
            _t: TenantId,
            _u: Uuid,
            _s: crate::domain::values::MembershipStatus,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn create(&self, _m: &TenantMembership) -> DomainResult<()> {
            unreachable!()
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, tenant_id: TenantId, user_id: Uuid) -> DomainResult<bool> {
            Ok(self
                .active
                .lock()
                .unwrap()
                .iter()
                .any(|(t, u)| *t == tenant_id && *u == user_id))
        }
        async fn find_by_invitation_token_hash(
            &self,
            _h: &str,
        ) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn activate(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// A fake that records grant/revoke calls and keeps the holding state.
    #[derive(Default)]
    struct FakePermissions {
        granted: Mutex<Vec<(TenantId, Uuid, String)>>,
        reject_unknown: bool,
    }
    #[async_trait]
    impl UserPermissionRepository for FakePermissions {
        async fn list_scoped_codes_for_user(
            &self,
            user_id: Uuid,
        ) -> DomainResult<Vec<(TenantId, String)>> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, u, _)| *u == user_id)
                .map(|(t, _, c)| (*t, c.clone()))
                .collect())
        }
        async fn list_available_codes(&self) -> DomainResult<Vec<String>> {
            Ok(vec!["idp.tenant.admin".to_string()])
        }
        async fn list_codes_for_user(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> DomainResult<Vec<String>> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .filter(|(t, u, _)| *t == tenant_id && *u == user_id)
                .map(|(_, _, c)| c.clone())
                .collect())
        }
        async fn has_permission(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            code: &str,
        ) -> DomainResult<bool> {
            Ok(self
                .granted
                .lock()
                .unwrap()
                .iter()
                .any(|(t, u, c)| *t == tenant_id && *u == user_id && c == code))
        }
        async fn grant(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            code: &str,
            _g: DateTime<Utc>,
        ) -> DomainResult<()> {
            if self.reject_unknown {
                return Err(DomainError::InvalidValue(format!(
                    "unknown permission code or user: {code}"
                )));
            }
            let mut g = self.granted.lock().unwrap();
            if !g
                .iter()
                .any(|(t, u, c)| *t == tenant_id && *u == user_id && c == code)
            {
                g.push((tenant_id, user_id, code.to_string()));
            }
            Ok(())
        }
        async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> DomainResult<()> {
            self.granted
                .lock()
                .unwrap()
                .retain(|(t, u, c)| !(*t == tenant_id && *u == user_id && c == code));
            Ok(())
        }
        async fn revoke_all_for_user_in_tenant(
            &self,
            _t: TenantId,
            _u: Uuid,
        ) -> DomainResult<Vec<String>> {
            unreachable!()
        }
    }

    fn test_user(id: Uuid) -> User {
        User {
            id,
            tenant_id: test_tenant(),
            sub: Uuid::new_v4(),
            email: "target@example.com".to_string(),
            email_verified: true,
            preferred_username: Some("target".to_string()),
            name: None,
            language: None,
            theme: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            password_changed_at: None,
            status: UserStatus::Active,
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: fixed_now(),
            updated_at: fixed_now(),
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    fn service_with(
        user: Option<User>,
        memberships: Arc<FakeMemberships>,
        perms: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
    ) -> PermissionManagementService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(fixed_now()))));
        PermissionManagementService::new(
            Arc::new(FakeUsers { user }),
            memberships,
            perms,
            Arc::new(FakeTenants),
            audit,
            Arc::new(FixedClock(fixed_now())),
        )
    }

    /// By default registers the target user as an ACTIVE member of its home tenant (the normal HOME case).
    fn service(
        user: Option<User>,
        perms: Arc<FakePermissions>,
        sink: Arc<CapturingSink>,
    ) -> PermissionManagementService {
        let active = user
            .as_ref()
            .map(|u| vec![(u.tenant_id, u.id)])
            .unwrap_or_default();
        service_with(
            user,
            Arc::new(FakeMemberships::with_active(active)),
            perms,
            sink,
        )
    }

    #[tokio::test]
    async fn grant_persists_and_audits() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms.clone(), sink.clone());

        let codes = svc
            .grant(
                tenant_ctx(),
                target,
                "idp.tenant.admin",
                &AdminActor::User(actor),
                &ctx(),
            )
            .await
            .expect("grant ok");
        assert_eq!(codes, vec!["idp.tenant.admin".to_string()]);

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::UserPermissionGranted);
        assert_eq!(events[0].user_id, Some(actor));
        assert_eq!(events[0].tenant_id, Some(test_tenant()));
        assert!(events[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("idp.tenant.admin"));
    }

    #[tokio::test]
    async fn revoke_removes_and_audits() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let perms = Arc::new(FakePermissions::default());
        perms
            .granted
            .lock()
            .unwrap()
            .push((test_tenant(), target, "idp.tenant.admin".to_string()));
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms.clone(), sink.clone());

        let codes = svc
            .revoke(
                tenant_ctx(),
                target,
                "idp.tenant.admin",
                &AdminActor::User(actor),
                &ctx(),
            )
            .await
            .expect("revoke ok");
        assert!(codes.is_empty());

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::UserPermissionRevoked);
    }

    #[tokio::test]
    async fn grant_rejects_empty_code() {
        let target = Uuid::new_v4();
        let svc = service(
            Some(test_user(target)),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.grant(
                tenant_ctx(),
                target,
                "  ",
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn grant_unknown_code_is_validation_error() {
        let target = Uuid::new_v4();
        let perms = Arc::new(FakePermissions {
            reject_unknown: true,
            ..Default::default()
        });
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms, sink.clone());

        assert!(matches!(
            svc.grant(
                tenant_ctx(),
                target,
                "idp.unknown",
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::Validation(_))
        ));
        // No audit event on failure.
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn find_user_by_identifier_resolves_email_and_username() {
        let target = Uuid::new_v4();
        let svc = service(
            Some(test_user(target)),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        // Resolved by email if it contains `@`, otherwise by user name.
        let by_email = svc
            .find_user_by_identifier(tenant_ctx(), "target@example.com")
            .await
            .expect("lookup ok");
        assert_eq!(by_email.map(|u| u.id), Some(target));
        let by_username = svc
            .find_user_by_identifier(tenant_ctx(), "  target  ")
            .await
            .expect("lookup ok");
        assert_eq!(by_username.map(|u| u.id), Some(target));
        // Unknown identifiers and empty strings give None.
        assert!(svc
            .find_user_by_identifier(tenant_ctx(), "nobody@example.com")
            .await
            .expect("lookup ok")
            .is_none());
        assert!(svc
            .find_user_by_identifier(tenant_ctx(), "   ")
            .await
            .expect("lookup ok")
            .is_none());
        // Not resolved in another tenant's scope (tenant isolation).
        let other = TenantContext::new(TenantId::from(Uuid::now_v7()));
        assert!(svc
            .find_user_by_identifier(other, "target@example.com")
            .await
            .expect("lookup ok")
            .is_none());
    }

    #[tokio::test]
    async fn available_codes_come_from_master() {
        let svc = service(
            None,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert_eq!(
            svc.available_codes().await.expect("ok"),
            vec!["idp.tenant.admin".to_string()]
        );
    }

    #[tokio::test]
    async fn get_user_returns_not_found_when_absent() {
        let svc = service(
            None,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.get_user(tenant_ctx(), Uuid::new_v4()).await,
            Err(PermissionManagementError::NotFound)
        ));
    }

    #[tokio::test]
    async fn missing_target_user_is_not_found() {
        let svc = service(
            None,
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.grant(
                tenant_ctx(),
                Uuid::new_v4(),
                "idp.tenant.admin",
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::NotFound)
        ));
        assert!(matches!(
            svc.list(tenant_ctx(), Uuid::new_v4()).await,
            Err(PermissionManagementError::NotFound)
        ));
    }

    /// `idp.system.admin` can only exist in the root scope (ADR-0009 §4). So in a non-root tenant it can't be granted
    /// **even if the actor is a root system admin**.
    ///
    /// Leaving this to the actor's holding check alone would make the root-scope lookup return true, pass the check,
    /// and proceed to a DB CHECK constraint violation (500). The tenant check is placed before the actor check.
    #[tokio::test]
    async fn system_admin_cannot_be_granted_outside_the_root_tenant() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let child = TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0002));
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        // The actor holds idp.system.admin in the root scope.
        perms
            .granted
            .lock()
            .unwrap()
            .push((test_tenant(), actor, "idp.system.admin".to_string()));
        // The target is an ACTIVE member of a child tenant (`ensure_user_in_tenant` passes).
        let svc = service_with(
            Some(test_user(target)),
            Arc::new(FakeMemberships::with_active(vec![(child, target)])),
            perms,
            sink.clone(),
        );

        assert!(matches!(
            svc.grant(
                TenantContext::new(child),
                target,
                "idp.system.admin",
                &AdminActor::User(actor),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::Forbidden(_))
        ));
        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn system_admin_grant_requires_system_admin_actor() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(Some(test_user(target)), perms.clone(), sink.clone());

        // The actor doesn't hold idp.system.admin -> Forbidden (ADR-0009 §4).
        assert!(matches!(
            svc.grant(
                tenant_ctx(),
                target,
                "idp.system.admin",
                &AdminActor::User(actor),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::Forbidden(_))
        ));
        assert!(sink.events.lock().unwrap().is_empty());

        // If the actor holds it, it can be granted.
        perms
            .granted
            .lock()
            .unwrap()
            .push((test_tenant(), actor, "idp.system.admin".to_string()));
        let codes = svc
            .grant(
                tenant_ctx(),
                target,
                "idp.system.admin",
                &AdminActor::User(actor),
                &ctx(),
            )
            .await
            .expect("grant ok");
        assert_eq!(codes, vec!["idp.system.admin".to_string()]);
    }

    /// Granting to targets without an ACTIVE membership in the tenant, such as INVITED (not yet accepted) guests, falls
    /// to nonexistent (404) (ADR-0009 §4; prevents cross-tenant existence guessing).
    #[tokio::test]
    async fn grant_rejects_non_active_member() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        // The user exists, but has no ACTIVE member registration in the requested tenant (INVITED equivalent).
        let svc = service_with(
            Some(test_user(target)),
            Arc::new(FakeMemberships::default()),
            perms.clone(),
            sink.clone(),
        );

        assert!(matches!(
            svc.grant(
                tenant_ctx(),
                target,
                "idp.tenant.admin",
                &AdminActor::User(actor),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::NotFound)
        ));
        // On failure, neither grant nor audit record happens.
        assert!(perms.granted.lock().unwrap().is_empty());
        assert!(sink.events.lock().unwrap().is_empty());
        // list/revoke are also 404.
        assert!(matches!(
            svc.list(tenant_ctx(), target).await,
            Err(PermissionManagementError::NotFound)
        ));
        assert!(matches!(
            svc.revoke(
                tenant_ctx(),
                target,
                "idp.tenant.admin",
                &AdminActor::User(actor),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::NotFound)
        ));
    }

    /// A user belonging to another tenant stays 404 unless they are an ACTIVE member of the requested tenant
    /// (prevents guessing identifiers outside the tenant).
    #[tokio::test]
    async fn grant_rejects_user_from_other_tenant_without_membership() {
        let target = Uuid::new_v4();
        // The home tenant (HOME) is another tenant.
        let other_tenant =
            TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_00FF));
        let mut guest = test_user(target);
        guest.tenant_id = other_tenant;
        let svc = service_with(
            Some(guest),
            // No membership in the requested tenant (test_tenant).
            Arc::new(FakeMemberships::default()),
            Arc::new(FakePermissions::default()),
            Arc::new(CapturingSink::default()),
        );

        assert!(matches!(
            svc.grant(
                tenant_ctx(),
                target,
                "idp.tenant.admin",
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(PermissionManagementError::NotFound)
        ));
    }

    /// Even a GUEST whose home is another tenant can be granted if they are an ACTIVE member of the requested tenant
    /// (not distinguished by origin. ADR-0009 §4). The grant scope is the requested tenant.
    #[tokio::test]
    async fn grant_succeeds_for_active_guest_from_other_tenant() {
        let target = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let other_tenant =
            TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_00FF));
        let mut guest = test_user(target);
        guest.tenant_id = other_tenant;
        let perms = Arc::new(FakePermissions::default());
        let sink = Arc::new(CapturingSink::default());
        // Registered as an ACTIVE GUEST member of the requested tenant (test_tenant).
        let svc = service_with(
            Some(guest),
            Arc::new(FakeMemberships::with_active(vec![(test_tenant(), target)])),
            perms.clone(),
            sink.clone(),
        );

        let codes = svc
            .grant(
                tenant_ctx(),
                target,
                "idp.tenant.admin",
                &AdminActor::User(actor),
                &ctx(),
            )
            .await
            .expect("grant ok");
        assert_eq!(codes, vec!["idp.tenant.admin".to_string()]);
        // The grant scope is the requested tenant (not the home tenant).
        assert_eq!(
            perms.granted.lock().unwrap().clone(),
            vec![(test_tenant(), target, "idp.tenant.admin".to_string())]
        );
    }
}
