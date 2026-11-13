//! Use case: access control for admin features (ADR-0006 §5 / ADR-0037).
//!
//! Resolves the user from the SSO session cookie value and returns **the permission codes held in the requested tenant**.
//! Per CLAUDE.md "Permission management", permissions are resolved in this Application layer and only the result
//! goes to Presentation. Since ADR-0037, the admin API authorization decision itself is made by the admin token
//! (`ManagementTokenService`), and this service handles **resolving the permission codes that feed it**.
//!
//! Resolution has two parts and checks both **an `ACTIVE` membership in the requested tenant** (MT24) and
//! **permission codes held with the requested tenant as scope**. The former is needed because suspending a
//! guest (`SUSPENDED`) is a reversible operation that keeps the permission rows, so a permission-only check would ignore suspension.
//! While suspended it resolves as "0 permission codes" (= an admin token is issued but nothing passes).
//!
//! Permissions are fetched by **exact match** on "has the requested tenant as scope" (ADR-0009 §4). Implications
//! between codes (`idp.tenant.admin` includes fine-grained codes etc.) have a single source in `domain::permission`.
//!
//! This is a separate axis from OIDC scope (claim control) and is not listed in Discovery's `scopes_supported`.

use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{
    SsoSessionRepository, TenantMembershipRepository, UserPermissionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use std::sync::Arc;
use uuid::Uuid;

/// "Principal + permission codes held in the requested tenant" resolved from the SSO session (ADR-0037).
///
/// What admin tokens are issued from. Returned even with no permission codes (= logged in but without permissions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementGrant {
    pub user_id: Uuid,
    /// Display name (`None` if unset). Shown in the admin console header.
    pub name: Option<String>,
    /// Login identifier (`None` if unset).
    pub preferred_username: Option<String>,
    /// Permission codes held with the requested tenant as scope (order unspecified; empty if none).
    pub permission_codes: Vec<String>,
}

pub struct AdminAccessService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    clock: Arc<dyn Clock>,
}

impl AdminAccessService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            permissions,
            memberships,
            clock,
        }
    }

    /// Resolves the principal and its permissions in the requested tenant from the SSO session cookie value (plain session_id).
    ///
    /// An invalid session, a disabled user or a repository failure all yield `None` (fail-closed = unauthenticated).
    /// **If the membership is not `ACTIVE` or no permission is held, returns `Some` (with empty permission codes).**
    /// The caller must tell "unauthenticated" and "insufficient permission" apart as 401 / 403;
    /// collapsing both here would keep the admin console from deciding to go back to the login screen.
    pub async fn resolve_session_grant(
        &self,
        tenant: TenantContext,
        sso_session_id: Option<&str>,
    ) -> Option<ManagementGrant> {
        let user = self.resolve_session_user(sso_session_id).await?;
        let tenant_id = tenant.tenant_id();

        // Must hold an **ACTIVE membership** in the requested tenant (MT24). Looking only at permission rows,
        // a suspended guest (`SUSPENDED`) keeps its permission rows, so admin operations would pass.
        // Suspension must be reversible and the rows cannot be deleted, so this check makes suspension effective.
        let active_member = match self.memberships.is_active_member(tenant_id, user.id).await {
            Ok(active) => active,
            Err(e) => {
                tracing::error!(error = %e, "failed to check tenant membership for admin access");
                false
            }
        };

        let permission_codes = if active_member {
            match self
                .permissions
                .list_codes_for_user(tenant_id, user.id)
                .await
            {
                Ok(codes) => codes,
                Err(e) => {
                    tracing::error!(error = %e, "failed to load permissions for admin access");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        Some(ManagementGrant {
            user_id: user.id,
            name: user.name.clone(),
            preferred_username: user.preferred_username.clone(),
            permission_codes,
        })
    }

    /// Resolves the internal ID of an authenticated user from the SSO session cookie (permissions not checked).
    ///
    /// Used by flows that only require "being logged in" and no tenant permission, such as accepting an invitation
    /// (`POST /{tenant_id}/invitations/accept`; ADR-0009 §3). An invalid session, a disabled user or a
    /// repository failure all fall to `None` (unauthenticated; fail-closed). The final identity check (is it the invitee)
    /// is done by the calling use case through token matching.
    pub async fn authenticated_user(&self, sso_session_id: Option<&str>) -> Option<Uuid> {
        self.resolve_session_user(sso_session_id)
            .await
            .map(|user| user.id)
    }

    /// Common flow (REF3): cookie plain session_id -> fetch SSO session -> validity check -> user validity check.
    /// `None` if any step fails (fail-closed). If valid, returns the resolved user row
    /// (the caller uses id, display name etc.; avoids extra queries).
    async fn resolve_session_user(&self, sso_session_id: Option<&str>) -> Option<User> {
        let session_id = sso_session_id.filter(|s| !s.is_empty())?;

        // The cookie holds the plain session_id; the DB holds only its SHA-256 (same derivation as sso_session.rs).
        let session_hash = crypto::sha256_hex(session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(session)) => session,
            Ok(None) => return None,
            Err(e) => {
                tracing::error!(error = %e, "failed to load sso session");
                return None;
            }
        };

        if !session.is_valid_at(self.clock.now()) {
            return None;
        }

        // The user must exist and be active (locks out disabled admins).
        match self.users.find_by_id(session.user_id).await {
            Ok(Some(user)) if user.is_active() => Some(user),
            Ok(_) => None,
            Err(e) => {
                tracing::error!(error = %e, "failed to load user for sso session");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::sso_session::SsoSession;
    use crate::domain::tenant::TenantId;
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, TimeZone, Utc};

    const ADMIN_PERM: &str = "idp.tenant.admin";

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 6, 12, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// For tests: holds one SSO session mapped "cookie plain text -> SHA-256 hash" as it would be stored in the DB.
    struct FakeSsoSessions {
        session: Option<SsoSession>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, session_hash: &str) -> DomainResult<Option<SsoSession>> {
            Ok(self
                .session
                .clone()
                .filter(|s| s.session_hash == session_hash))
        }
        async fn extend_idle(&self, _h: &str, _e: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, _user_id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct FakeUsers {
        user: Option<User>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// This test does not go through the login failure path (SEC13 is verified in login / mfa_login).
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
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(&self, _t: TenantId, _u: &str) -> DomainResult<Option<User>> {
            unreachable!()
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

    struct FakePermissions {
        granted: Vec<(TenantId, Uuid, String)>,
    }
    #[async_trait]
    impl UserPermissionRepository for FakePermissions {
        async fn list_scoped_codes_for_user(
            &self,
            user_id: Uuid,
        ) -> DomainResult<Vec<(TenantId, String)>> {
            Ok(self
                .granted
                .iter()
                .filter(|(_, u, _)| *u == user_id)
                .map(|(t, _, c)| (*t, c.clone()))
                .collect())
        }
        async fn list_available_codes(&self) -> DomainResult<Vec<String>> {
            Ok(vec![ADMIN_PERM.to_string()])
        }
        async fn list_codes_for_user(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
        ) -> DomainResult<Vec<String>> {
            Ok(self
                .granted
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
                .iter()
                .any(|(t, u, c)| *t == tenant_id && *u == user_id && c == code))
        }
        async fn grant(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
            _g: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke(&self, _t: TenantId, _u: Uuid, _c: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke_all_for_user_in_tenant(
            &self,
            _t: TenantId,
            _u: Uuid,
        ) -> DomainResult<Vec<String>> {
            unreachable!()
        }
    }

    fn test_user(id: Uuid, tenant_id: TenantId, status: UserStatus) -> User {
        User {
            id,
            tenant_id,
            sub: Uuid::new_v4(),
            email: "admin@example.com".to_string(),
            email_verified: true,
            preferred_username: Some("admin".to_string()),
            name: Some("Administrator".to_string()),
            language: None,
            theme: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            password_changed_at: None,
            status,
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: fixed_now(),
            updated_at: fixed_now(),
        }
    }

    fn test_session(session_id: &str, user_id: Uuid, valid: bool) -> SsoSession {
        let now = fixed_now();
        let (idle, abs) = if valid {
            (now + Duration::minutes(30), now + Duration::hours(8))
        } else {
            (now - Duration::minutes(1), now + Duration::hours(8))
        };
        SsoSession {
            session_hash: crypto::sha256_hex(session_id),
            user_id,
            auth_time: now - Duration::minutes(5),
            idle_expires_at: idle,
            absolute_expires_at: abs,
            authentication_methods: vec![crate::domain::values::AuthenticationMethod::Password],
            authentication_strength: crate::domain::values::AuthenticationStrength::SingleFactor,
            mfa_completed_at: None,
            step_up_at: Some(now),
            user_agent: None,
            ip_address: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// A fake whose membership presence can be toggled (to verify MT24's ACTIVE membership requirement).
    struct FakeMemberships {
        active: bool,
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn create(&self, _m: &TenantMembership) -> DomainResult<()> {
            unreachable!()
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, _t: TenantId, _u: Uuid) -> DomainResult<bool> {
            Ok(self.active)
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
        async fn update_status(
            &self,
            _t: TenantId,
            _u: Uuid,
            _s: crate::domain::values::MembershipStatus,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn service(
        session: Option<SsoSession>,
        user: Option<User>,
        granted: Vec<(TenantId, Uuid, String)>,
    ) -> AdminAccessService {
        service_with_membership(session, user, granted, true)
    }

    fn service_with_membership(
        session: Option<SsoSession>,
        user: Option<User>,
        granted: Vec<(TenantId, Uuid, String)>,
        active_member: bool,
    ) -> AdminAccessService {
        AdminAccessService::new(
            Arc::new(FakeSsoSessions { session }),
            Arc::new(FakeUsers { user }),
            Arc::new(FakePermissions { granted }),
            Arc::new(FakeMemberships {
                active: active_member,
            }),
            Arc::new(FixedClock(fixed_now())),
        )
    }

    /// MT24: even holding permissions, without an ACTIVE membership in the requested tenant there are 0 permissions.
    /// Suspending a guest (`SUSPENDED`) is reversible and keeps the permission rows, so unless it is dropped here
    /// a suspended guest could keep operating with an admin token.
    #[tokio::test]
    async fn resolves_no_permissions_when_membership_is_not_active() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service_with_membership(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
            false,
        );
        let grant = svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .expect("session is valid, so the principal resolves");
        assert_eq!(grant.user_id, uid);
        assert!(grant.permission_codes.is_empty());
    }

    #[tokio::test]
    async fn resolves_the_permissions_held_for_the_requested_tenant() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        let grant = svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .unwrap();
        assert_eq!(
            grant,
            ManagementGrant {
                user_id: uid,
                name: Some("Administrator".to_string()),
                preferred_username: Some("admin".to_string()),
                permission_codes: vec![ADMIN_PERM.to_string()],
            }
        );
    }

    #[tokio::test]
    async fn unauthenticated_when_no_cookie() {
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(None, None, vec![]);
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), None)
            .await
            .is_none());
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), Some(""))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn unauthenticated_when_session_unknown_or_expired() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        // A different session ID (hash mismatch).
        let svc = service(
            Some(test_session("other", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .is_none());

        // An expired session.
        let svc = service(
            Some(test_session("sid", uid, false)),
            Some(test_user(uid, tenant, UserStatus::Active)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn unauthenticated_when_user_disabled() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, tenant, UserStatus::Disabled)),
            vec![(tenant, uid, ADMIN_PERM.to_string())],
        );
        assert!(svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .is_none());
    }

    /// Permissions scoped to other tenants resolve to none in the requested tenant (exact match of ADR-0009 §4).
    #[tokio::test]
    async fn permissions_scoped_to_another_tenant_do_not_resolve() {
        let uid = Uuid::new_v4();
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let svc = service(
            Some(test_session("sid", uid, true)),
            Some(test_user(uid, other, UserStatus::Active)),
            vec![(other, uid, ADMIN_PERM.to_string())],
        );
        let grant = svc
            .resolve_session_grant(TenantContext::new(tenant), Some("sid"))
            .await
            .unwrap();
        assert!(grant.permission_codes.is_empty());
    }
}
