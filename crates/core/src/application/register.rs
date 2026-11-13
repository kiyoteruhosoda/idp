//! User registration use case (design spec §4.1).
//!
//! The MVP has no email verification flow, so registration sets `status = ACTIVE` / `email_verified = false`.
//! The user is created with the target tenant as their home tenant, and a HOME membership is
//! created at the same time (ADR-0009 §2, §3).
//!
//! Self-registration is accepted **only in tenants where the tenant setting `self_registration_enabled` is on**
//! (disabled by default = fail-closed. SEC6). In addition, a per-IP rate limit is applied to curb, by number of attempts,
//! enumeration of email addresses in the tenant via 409 (duplicate email) (full concealment waits for the
//! introduction of the email verification flow. In disabled tenants existence cannot be probed at all).

use crate::application::password_policy::PasswordPolicyService;
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::password::PasswordHasher;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{TenantMembershipRepository, TenantRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::user::User;
use crate::domain::values::{
    validate_email as domain_validate_email,
    validate_preferred_username as domain_validate_preferred_username, UserStatus,
};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct RegisterCommand {
    pub email: String,
    pub preferred_username: Option<String>,
    pub password: String,
    pub name: Option<String>,
}

/// ⚠ Do not show the secret (`password`) in `Debug` (task #593). Fields are chosen by hand so the value
/// does not leak even if dropped into a log with `{:?}`.
impl std::fmt::Debug for RegisterCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterCommand")
            .field("email", &self.email)
            .field("preferred_username", &self.preferred_username)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

pub struct RegisteredUser {
    /// Externally exposed identifier.
    pub sub: Uuid,
    /// Internal ID (used for sending the verification email. Not returned externally).
    pub user_id: Uuid,
    pub status: UserStatus,
    /// Email (used for sending the verification email. The caller already has it, but it is returned for convenience).
    pub email: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    /// Self-registration is disabled in this tenant (SEC6. Default).
    #[error("forbidden: {0}")]
    Forbidden(MessageKey),
    /// Per-IP rate limit exceeded (SEC6).
    #[error("too many registration attempts")]
    RateLimited,
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct RegisterService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    tenants: Arc<dyn TenantRepository>,
    hasher: Arc<dyn PasswordHasher>,
    password_policy: Arc<PasswordPolicyService>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl RegisterService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        tenants: Arc<dyn TenantRepository>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            users,
            memberships,
            tenants,
            hasher,
            password_policy,
            rate_limiter,
            clock,
            ids,
        }
    }

    /// `ip_address` is the rate-limit key (when unavailable, a shared bucket is used for limiting).
    pub async fn register(
        &self,
        tenant: TenantContext,
        cmd: RegisterCommand,
        ip_address: Option<&str>,
    ) -> Result<RegisteredUser, RegisterError> {
        // Per-IP rate limit (SEC6). Checked before validation to curb enumeration and mass-creation attempts.
        if !self
            .rate_limiter
            .check_and_record(ip_address.unwrap_or("unknown"), self.clock.now())
        {
            return Err(RegisterError::RateLimited);
        }

        // Self-registration must be enabled in the tenant settings (disabled by default = fail-closed. SEC6).
        // Read from the repository rather than the ResolvedTenant cache (so setting changes take effect immediately).
        let self_registration_enabled = self
            .tenants
            .find_by_id(tenant.tenant_id())
            .await
            .map_err(internal)?
            .map(|t| t.self_registration_enabled)
            .unwrap_or(false);
        if !self_registration_enabled {
            return Err(RegisterError::Forbidden(MessageKey::new(
                "api-register-self-registration-disabled",
            )));
        }

        let email = cmd.email.trim().to_string();
        validate_email(&email)?;
        // Password policy (AP7). Self-registration has no current password or history, so only
        // length and whether it has been breached are checked. The registering tenant becomes the home tenant as is,
        // so that tenant's policy is used (ADR-0058).
        match self
            .password_policy
            .validate(tenant.tenant_id(), None, None, &cmd.password)
            .await
            .map_err(internal)?
        {
            Ok(()) => {}
            Err(rejection) => return Err(RegisterError::Validation(rejection.message_key())),
        }
        // The sign-in identifier is preferred_username. If omitted, email is used as the default (ADR-0009 §8).
        let preferred_username =
            normalize_optional(cmd.preferred_username).unwrap_or_else(|| email.clone());
        // Reject column-length (VARCHAR(255)) overflow before persisting (email is VARCHAR(320), so defaulting can exceed it).
        domain_validate_preferred_username(&preferred_username)
            .map_err(RegisterError::Validation)?;
        let name = normalize_optional(cmd.name);
        let tenant_id = tenant.tenant_id();

        // Pre-check uniqueness (for an error users can understand). Unique keys are
        // unique within the tenant, e.g. `(tenant_id, email)` (ADR-0009 §2). Final uniqueness is
        // guaranteed by the DB UNIQUE constraint; on conflict create() returns Conflict.
        // The sign-in identifier is looked up **the same way as the resolution path** (AP8. Looking only at `users`
        // would let values already registered as aliases slip through).
        if self
            .users
            .find_by_email(tenant_id, &email)
            .await
            .map_err(internal)?
            .is_some()
        {
            return Err(RegisterError::Conflict(MessageKey::new(
                "api-user-email-conflict",
            )));
        }
        if self
            .users
            .find_by_login_identifier(tenant_id, &preferred_username)
            .await
            .map_err(internal)?
            .is_taken()
        {
            return Err(RegisterError::Conflict(MessageKey::new(
                "api-user-username-conflict",
            )));
        }

        let password_hash = self.hasher.hash(&cmd.password).map_err(internal)?;
        let now = self.clock.now();
        let user = User {
            id: self.ids.new_id(),
            tenant_id,
            sub: self.ids.new_id(),
            email,
            email_verified: false,
            preferred_username: Some(preferred_username),
            name,
            language: None,
            theme: None,
            password_hash,
            must_change_password: false,
            password_changed_at: Some(now),
            status: UserStatus::Active,
            // The user chooses the password on the spot, so this is not a provisional registration (ADR-0064).
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };

        self.users.create(&user).await.map_err(|e| match e {
            // Only a race with the pre-check (concurrent registration). The DB does not tell which unique key it was.
            DomainError::Conflict(_) => {
                RegisterError::Conflict(MessageKey::new("api-user-identity-conflict"))
            }
            other => RegisterError::Internal(other.to_string()),
        })?;

        // HOME membership (the single source of the home tenant is users.tenant_id. This row is auto-generated as a
        // projection for flow decisions. ADR-0009 §3).
        self.memberships
            .create(&TenantMembership::new_home(tenant_id, user.id, now))
            .await
            .map_err(internal)?;

        Ok(RegisteredUser {
            sub: user.sub,
            user_id: user.id,
            status: user.status,
            email: user.email,
        })
    }
}

fn validate_email(email: &str) -> Result<(), RegisterError> {
    domain_validate_email(email).map_err(RegisterError::Validation)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn internal(e: DomainError) -> RegisterError {
    RegisterError::Internal(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::tenant::{Tenant, TenantId};
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::values::TenantStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
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

    struct PlainHasher;
    impl PasswordHasher for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
            Ok(hash == format!("hash:{password}"))
        }
    }

    #[derive(Default)]
    struct FakeUsers {
        rows: Mutex<Vec<User>>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// The production sqlx implementation increments in a single UPDATE (SEC13). The fake only runs in
        /// single-threaded tests, so a naive increment with the same result suffices.
        async fn record_login_failure(
            &self,
            id: Uuid,
            lockout: crate::domain::authentication_policy::LockoutPolicy,
            now: DateTime<Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.iter_mut().find(|u| u.id == id) else {
                return Ok(crate::domain::user::LoginFailureRecord {
                    failed_login_count: 0,
                    locked_until: None,
                });
            };
            row.failed_login_count += 1;
            if let Some(until) = lockout.locked_until_after_failure(row.failed_login_count, now) {
                row.locked_until = Some(until);
            }
            Ok(crate::domain::user::LoginFailureRecord {
                failed_login_count: row.failed_login_count,
                locked_until: row.locked_until.filter(|u| *u > now),
            })
        }
        async fn create(&self, u: &User) -> DomainResult<()> {
            self.rows.lock().unwrap().push(u.clone());
            Ok(())
        }
        async fn find_by_id(&self, _id: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, t: TenantId, e: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.tenant_id == t && u.email == e)
                .cloned())
        }
        async fn find_by_username(&self, _t: TenantId, _n: &str) -> DomainResult<Option<User>> {
            Ok(None)
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

    #[derive(Default)]
    struct FakeMemberships {
        rows: Mutex<Vec<TenantMembership>>,
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
        async fn create(&self, m: &TenantMembership) -> DomainResult<()> {
            self.rows.lock().unwrap().push(m.clone());
            Ok(())
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, _t: TenantId, _u: Uuid) -> DomainResult<bool> {
            unreachable!()
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

    /// Single-tenant fake (used by toggling `self_registration_enabled`).
    struct FakeTenants {
        tenant: Tenant,
    }
    #[async_trait]
    impl crate::domain::repositories::TenantRepository for FakeTenants {
        async fn create(&self, _t: &Tenant) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: TenantId) -> DomainResult<Option<Tenant>> {
            Ok(Some(self.tenant.clone()).filter(|t| t.id == id))
        }
        async fn find_root(&self) -> DomainResult<Option<Tenant>> {
            unreachable!()
        }
        async fn list_children(&self, _p: TenantId) -> DomainResult<Vec<Tenant>> {
            unreachable!()
        }
        async fn update(&self, _t: &Tenant) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: TenantId) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// Rate-limit fake that allows only the first `limit` times.
    struct CountingLimiter {
        limit: usize,
        calls: AtomicUsize,
    }
    impl LoginRateLimiter for CountingLimiter {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst) < self.limit
        }
    }

    fn tenant(id: TenantId, self_registration_enabled: bool) -> Tenant {
        Tenant {
            id,
            parent_tenant_id: None,
            name: "Root".to_string(),
            status: TenantStatus::Active,
            self_registration_enabled,
            email_login_enabled: false,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn service(tenant: Tenant, limiter_allowance: usize) -> (RegisterService, Arc<FakeUsers>) {
        let users = Arc::new(FakeUsers::default());
        let svc = RegisterService::new(
            users.clone(),
            Arc::new(FakeMemberships::default()),
            Arc::new(FakeTenants { tenant }),
            Arc::new(PlainHasher),
            Arc::new(
                crate::application::password_policy::PasswordPolicyService::without_history(
                    crate::application::tenant_settings::testing::tenant_settings_with_global(&[(
                        "PASSWORD_HISTORY_COUNT",
                        "0",
                    )]),
                    Arc::new(PlainHasher),
                    Arc::new(FixedClock),
                ),
            ),
            Arc::new(CountingLimiter {
                limit: limiter_allowance,
                calls: AtomicUsize::new(0),
            }),
            Arc::new(FixedClock),
            Arc::new(SeqIds(Mutex::new(0))),
        );
        (svc, users)
    }

    fn cmd() -> RegisterCommand {
        RegisterCommand {
            email: "new@example.com".to_string(),
            preferred_username: None,
            password: "longenough".to_string(),
            name: None,
        }
    }

    #[tokio::test]
    async fn register_is_forbidden_when_self_registration_disabled() {
        let t: TenantId = Uuid::now_v7().into();
        // In a default (disabled) tenant registration fails and no user is created (fail-closed. SEC6).
        let (svc, users) = service(tenant(t, false), 100);
        assert!(matches!(
            svc.register(TenantContext::new(t), cmd(), Some("203.0.113.1"))
                .await,
            Err(RegisterError::Forbidden(_))
        ));
        assert!(users.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn register_succeeds_when_enabled() {
        let t: TenantId = Uuid::now_v7().into();
        let (svc, users) = service(tenant(t, true), 100);
        let registered = svc
            .register(TenantContext::new(t), cmd(), Some("203.0.113.1"))
            .await
            .expect("registered");
        assert_eq!(registered.status, UserStatus::Active);
        assert_eq!(users.rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn register_is_rate_limited_per_ip() {
        let t: TenantId = Uuid::now_v7().into();
        // Allow only once -> the second is RateLimited (rejected before the tenant check).
        let (svc, _) = service(tenant(t, true), 1);
        svc.register(TenantContext::new(t), cmd(), Some("203.0.113.1"))
            .await
            .expect("first attempt allowed");
        assert!(matches!(
            svc.register(TenantContext::new(t), cmd(), Some("203.0.113.1"))
                .await,
            Err(RegisterError::RateLimited)
        ));
    }

    #[test]
    fn rejects_invalid_email() {
        assert!(validate_email("not-an-email").is_err());
        assert!(validate_email("a@b").is_ok());
    }

    #[test]
    fn normalizes_empty_optional_to_none() {
        assert_eq!(normalize_optional(Some("  ".to_string())), None);
        assert_eq!(
            normalize_optional(Some("  bob ".to_string())),
            Some("bob".to_string())
        );
        assert_eq!(normalize_optional(None), None);
    }
}
