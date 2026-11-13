//! Login identifier management use case (AP8. spec §4).
//!
//! A tenant admin (`idp.tenant.admin`) assigns **multiple login identifiers** to a user.
//! This lets users log in with values the organization already hands out, such as phone numbers or employee
//! numbers, or hands out a new name while keeping an old user name.
//!
//! # Uniqueness is decided by "trying to resolve it"
//!
//! Whether a value can be added is not decided by the DB unique constraint (duplicates within the registry) alone.
//! During the expand phase the primary login identifier also lives in `users.preferred_username`, and an
//! identifier colliding with it breaks as "it registered, but login returns someone else (or nobody)".
//! So it goes through **the same lookup as the actual resolution path**
//! ([`UserRepository::find_by_login_identifier`]) and rejects values that resolve to someone else.
//! As long as the check and the production path are the same, they can't drift apart.
//!
//! When an email address is used as an identifier, its ownership is not verified (no verification mail). It is an
//! admin assignment, treated the same as an admin email change (MT25) keeping the verified state.
//! No path is offered for users to add one themselves.

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::login_identifier::{LoginIdentifierType, UserLoginIdentifier};
use crate::domain::message::MessageKey;
use crate::domain::repositories::{
    TenantDomainRepository, UserLoginIdentifierRepository, UserRepository,
};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_domain::split_qualified_identifier;
use crate::domain::user::User;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AddLoginIdentifierCommand {
    pub identifier_type: LoginIdentifierType,
    /// The value as the user types it (before normalization).
    pub value: String,
    /// Whether it is active right after being added (default true).
    pub is_active: bool,
}

/// One item of the list.
///
/// `id` is kept as `Option`. Since AP15b the primary identifier is also a registry row and synthesized rows are gone,
/// so it is currently always `Some`, but **the contract (API response) keeps a shape that may return `null`**.
/// Narrowing the type would force a simultaneous rollout to api, web and their consumers, and all it would gain is
/// "can't write `None`".
#[derive(Debug, Clone)]
pub struct LoginIdentifierEntry {
    pub id: Option<Uuid>,
    pub identifier_type: LoginIdentifierType,
    pub display_value: String,
    pub normalized_value: String,
    pub is_active: bool,
    /// Whether this is the primary login identifier (the registry's `primary_of_user` row). The primary identifier is
    /// not subject to per-identifier enable/disable or deletion (edit the profile to change it, disable the account to stop it).
    pub is_primary: bool,
    /// Whether this is the primary email row (ADR-0050). Like the primary identifier, it is not subject to individual operations.
    pub is_primary_email: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserLoginIdentifier> for LoginIdentifierEntry {
    fn from(v: UserLoginIdentifier) -> Self {
        Self {
            id: Some(v.id),
            identifier_type: v.identifier_type,
            display_value: v.display_value,
            normalized_value: v.normalized_value,
            is_active: v.is_active,
            is_primary: v.is_primary,
            is_primary_email: v.is_primary_email,
            created_at: v.created_at,
            updated_at: v.updated_at,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoginIdentifierManagementError {
    #[error("not found")]
    NotFound,
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

fn internal(e: DomainError) -> LoginIdentifierManagementError {
    LoginIdentifierManagementError::Internal(e.to_string())
}

pub struct LoginIdentifierManagementService {
    identifiers: Arc<dyn UserLoginIdentifierRepository>,
    users: Arc<dyn UserRepository>,
    /// Domains assigned to tenants (ADR-0029). Looked up so the availability check covers the same scope as login resolution.
    tenant_domains: Arc<dyn TenantDomainRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl LoginIdentifierManagementService {
    pub fn new(
        identifiers: Arc<dyn UserLoginIdentifierRepository>,
        users: Arc<dyn UserRepository>,
        tenant_domains: Arc<dyn TenantDomainRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            identifiers,
            users,
            tenant_domains,
            audit,
            clock,
            ids,
        }
    }

    /// Lists the user's login identifiers (including inactive rows).
    ///
    /// **The registry rows are everything** (AP15b). The primary identifier exists as a row too, so the rows
    /// "synthesized from `users.preferred_username` on read" added during the expand phase are gone.
    /// The values shown here and the values actually resolved at the login field come from the same single table.
    pub async fn list(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<Vec<LoginIdentifierEntry>, LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let stored = self
            .identifiers
            .list_for_user(user.id)
            .await
            .map_err(internal)?;
        let mut entries: Vec<LoginIdentifierEntry> =
            stored.into_iter().map(LoginIdentifierEntry::from).collect();
        // Pin the primary identifier and primary email to the top (registry rows are in insertion order, so a promoted
        // row lands in the middle). Gathering the two rows that can't be operated on at the top leaves only the rows below actionable.
        entries.sort_by_key(|e| (!e.is_primary, !e.is_primary_email));
        Ok(entries)
    }

    /// Adds a login identifier.
    pub async fn add(
        &self,
        tenant: TenantContext,
        target: Uuid,
        cmd: AddLoginIdentifierCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<UserLoginIdentifier, LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let tenant_id = tenant.tenant_id();
        let raw = cmd.value.trim().to_string();
        let normalized = cmd
            .identifier_type
            .normalize_checked(&raw)
            .map_err(LoginIdentifierManagementError::Validation)?;

        self.ensure_available(tenant_id, user.id, cmd.identifier_type, &raw)
            .await?;

        let now = self.clock.now();
        let identifier = UserLoginIdentifier {
            id: self.ids.new_id(),
            tenant_id,
            user_id: user.id,
            identifier_type: cmd.identifier_type,
            display_value: raw,
            normalized_value: normalized,
            is_active: cmd.is_active,
            // What the admin UI adds are **additional** identifiers (the primary identifier belongs to profile editing).
            is_primary: false,
            is_primary_email: false,
            created_at: now,
            updated_at: now,
        };
        self.identifiers
            .create(&identifier)
            .await
            .map_err(|e| match e {
                DomainError::Conflict(_) => LoginIdentifierManagementError::Conflict(
                    MessageKey::new("api-login-identifier-conflict"),
                ),
                other => internal(other),
            })?;

        self.record(
            AuditEventType::UserLoginIdentifierAdded,
            tenant_id,
            actor,
            &format!("type={}", cmd.identifier_type.as_str()),
            ctx,
        )
        .await;
        Ok(identifier)
    }

    /// Toggles enable/disable per identifier (spec §4).
    ///
    /// The point is being able to stop it without deleting the row; a stopped value stays unregistrable by other users
    /// (the registry's unique constraint ignores `is_active`). Prevents a stopped identifier from silently moving to someone else.
    pub async fn set_active(
        &self,
        tenant: TenantContext,
        target: Uuid,
        identifier_id: Uuid,
        is_active: bool,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<UserLoginIdentifier, LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let identifier = self.find_owned(user.id, identifier_id).await?;
        if !self
            .identifiers
            .set_active(identifier.id, user.id, is_active)
            .await
            .map_err(internal)?
        {
            return Err(LoginIdentifierManagementError::NotFound);
        }
        self.record(
            AuditEventType::UserLoginIdentifierUpdated,
            tenant.tenant_id(),
            actor,
            &format!(
                "type={} active={}",
                identifier.identifier_type.as_str(),
                is_active
            ),
            ctx,
        )
        .await;
        Ok(UserLoginIdentifier {
            is_active,
            updated_at: self.clock.now(),
            ..identifier
        })
    }

    /// Deletes an identifier.
    ///
    /// The primary login identifier (`users.preferred_username`) is not in the registry, so it is not a target
    /// (in the list it appears as a synthesized row with `id` = `null`). To change it, use profile editing (MT25).
    pub async fn remove(
        &self,
        tenant: TenantContext,
        target: Uuid,
        identifier_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let identifier = self.find_owned(user.id, identifier_id).await?;
        if !self
            .identifiers
            .delete(identifier.id, user.id)
            .await
            .map_err(internal)?
        {
            return Err(LoginIdentifierManagementError::NotFound);
        }
        self.record(
            AuditEventType::UserLoginIdentifierRemoved,
            tenant.tenant_id(),
            actor,
            &format!("type={}", identifier.identifier_type.as_str()),
            ctx,
        )
        .await;
        Ok(())
    }

    /// Promotes an alias email address to the primary email (ADR-0052).
    ///
    /// Promotion is **a swap**. The current primary email row is demoted to an ordinary alias, and the chosen row becomes
    /// the copy in `users.email` ——that is, the notification destination (ADR-0050 decision 4).
    ///
    /// Only email-kind rows are targets. If a phone number or employee number could become the primary email,
    /// `users.email` would hold a non-email string and password resets would go there.
    ///
    /// Not refused even if the clicked row is already the primary email. Clicking twice with the screen open is common,
    /// and the result (that row is the primary email) is the same.
    pub async fn promote_email(
        &self,
        tenant: TenantContext,
        target: Uuid,
        identifier_id: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<UserLoginIdentifier, LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let identifier = self.find_owned(user.id, identifier_id).await?;
        if identifier.identifier_type != LoginIdentifierType::Email {
            return Err(LoginIdentifierManagementError::Validation(MessageKey::new(
                "api-login-identifier-not-email",
            )));
        }
        if !self
            .users
            .promote_primary_email(user.id, identifier.id)
            .await
            .map_err(|e| match e {
                DomainError::Conflict(_) => LoginIdentifierManagementError::Conflict(
                    MessageKey::new("api-login-identifier-conflict"),
                ),
                other => internal(other),
            })?
        {
            return Err(LoginIdentifierManagementError::NotFound);
        }
        self.record(
            AuditEventType::UserPrimaryEmailChanged,
            tenant.tenant_id(),
            actor,
            "source=login_identifier",
            ctx,
        )
        .await;
        Ok(UserLoginIdentifier {
            is_active: true,
            is_primary_email: true,
            updated_at: self.clock.now(),
            ..identifier
        })
    }

    /// Confirms that the value being added isn't yet used for anyone's login.
    ///
    /// The check looks at **the same scope** as login resolution (`login_user_resolution`). If they drift,
    /// "values that registered but resolve to someone else" and "values that can't register but hit nobody" appear.
    ///
    /// **Values that resolve to yourself are also refused.** Values resolving to others are obviously dangerous, but if
    /// the same value as your own `users.preferred_username` could also be added to the registry, disabling that row
    /// would still let authentication pass via the fallback to `preferred_username` ——creating an identifier that
    /// "is stopped yet still works". Not allowing duplicates is the simplest way to prevent that state.
    async fn ensure_available(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        identifier_type: LoginIdentifierType,
        raw: &str,
    ) -> Result<(), LoginIdentifierManagementError> {
        // 1. Look up the input as-is, the same way as the first step of login.
        if self
            .users
            .find_by_login_identifier(tenant_id, raw)
            .await
            .map_err(internal)?
            .is_taken()
        {
            return Err(LoginIdentifierManagementError::Conflict(MessageKey::new(
                "api-login-identifier-conflict",
            )));
        }
        // 2. A domain-qualified value whose domain **belongs to this tenant** is also a spelling pointing to "the user
        //    of the local part" (ADR-0029's UPN interpretation). Step 1 only looks up the input as-is, so adding
        //    `alice@corp.example` to someone else would lock `alice` out of that spelling —— on a host tenant's screen
        //    that may be the only way in, so don't let it be taken.
        //
        //    Also refused when it hits your own local part (same reason as 1: if the same person has the same spelling
        //    in two forms, disabling one still lets authentication pass via the other).
        if let Some((local_part, domain)) = split_qualified_identifier(raw) {
            let owner = self
                .tenant_domains
                .find_tenant_by_domain(&domain)
                .await
                .map_err(internal)?;
            if owner == Some(tenant_id)
                && self
                    .users
                    .find_by_login_identifier(tenant_id, local_part)
                    .await
                    .map_err(internal)?
                    .is_taken()
            {
                return Err(LoginIdentifierManagementError::Conflict(MessageKey::new(
                    "api-login-identifier-conflict",
                )));
            }
        }
        // 3. `users.email` is not currently a login entry point, so step 1 doesn't hit it. But if someone else's
        //    email address could become your login identifier, you could impersonate them with their contact info.
        //    Only for the email kind, also check the users table.
        // Making your own email address your own identifier is legitimate ("I want to log in with email"),
        // so only other people's are refused.
        if identifier_type == LoginIdentifierType::Email {
            if let Some(found) = self
                .users
                .find_by_email(tenant_id, raw)
                .await
                .map_err(internal)?
            {
                if found.id != user_id {
                    return Err(LoginIdentifierManagementError::Conflict(MessageKey::new(
                        "api-login-identifier-conflict",
                    )));
                }
            }
        }
        Ok(())
    }

    async fn find_owned(
        &self,
        user_id: Uuid,
        identifier_id: Uuid,
    ) -> Result<UserLoginIdentifier, LoginIdentifierManagementError> {
        match self
            .identifiers
            .find_by_id(identifier_id)
            .await
            .map_err(internal)?
        {
            Some(identifier) if identifier.user_id == user_id => Ok(identifier),
            _ => Err(LoginIdentifierManagementError::NotFound),
        }
    }

    async fn find_home_user(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<User, LoginIdentifierManagementError> {
        match self.users.find_by_id(target).await.map_err(internal)? {
            Some(user) if user.tenant_id == tenant.tenant_id() => Ok(user),
            _ => Err(LoginIdentifierManagementError::NotFound),
        }
    }

    /// Audit record. **The identifier value is not kept** (phone numbers and emails are PII. `CLAUDE.md` "Logging").
    async fn record(
        &self,
        event_type: AuditEventType,
        tenant_id: TenantId,
        actor: &AdminActor,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                event_type,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                Some(reason),
                ctx,
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::clock::Clock;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// A tenant without domains (default implementation). Existing tests don't go through the UPN interpretation check.
    struct NoTenantDomains;

    #[async_trait]
    impl TenantDomainRepository for NoTenantDomains {}

    struct FixedIds(Mutex<u128>);
    impl IdGenerator for FixedIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    struct DiscardingSink;
    #[async_trait]
    impl AuditLogSink for DiscardingSink {
        async fn record(&self, _event: &AuditEvent) -> DomainResult<()> {
            Ok(())
        }
    }

    struct Users {
        rows: Vec<User>,
        /// `(user, identifier)` passed to `promote_primary_email`. The swap itself is owned by the DB
        /// transaction (`SqlxUserRepository`), so this only checks **that it was called with the
        /// right row**.
        promoted: Mutex<Vec<(Uuid, Uuid)>>,
    }

    #[async_trait]
    impl UserRepository for Users {
        async fn create(&self, _user: &User) -> DomainResult<()> {
            Ok(())
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self.rows.iter().find(|u| u.id == id).cloned())
        }
        async fn find_by_sub(&self, _sub: Uuid) -> DomainResult<Option<User>> {
            Ok(None)
        }
        async fn find_by_email(&self, t: TenantId, e: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .iter()
                .find(|u| u.tenant_id == t && u.email.eq_ignore_ascii_case(e))
                .cloned())
        }
        async fn find_by_username(&self, t: TenantId, n: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .iter()
                .find(|u| {
                    u.tenant_id == t
                        && u.preferred_username
                            .as_deref()
                            .is_some_and(|v| v.eq_ignore_ascii_case(n))
                })
                .cloned())
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _c: i32,
            _l: Option<chrono::DateTime<Utc>>,
        ) -> DomainResult<()> {
            Ok(())
        }
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: chrono::DateTime<Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
        async fn update_password(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            Ok(true)
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            Ok(true)
        }
        async fn update_status(&self, _id: Uuid, _s: UserStatus) -> DomainResult<()> {
            Ok(())
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            Ok(())
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            Ok(())
        }
        async fn update_language(&self, _id: Uuid, _l: Option<&str>) -> DomainResult<()> {
            Ok(())
        }
        async fn promote_primary_email(
            &self,
            user_id: Uuid,
            identifier_id: Uuid,
        ) -> DomainResult<bool> {
            self.promoted.lock().unwrap().push((user_id, identifier_id));
            Ok(true)
        }
    }

    #[derive(Default)]
    struct Identifiers {
        rows: Mutex<Vec<UserLoginIdentifier>>,
    }

    #[async_trait]
    impl UserLoginIdentifierRepository for Identifiers {
        async fn create(&self, identifier: &UserLoginIdentifier) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            // Same check as the DB unique key (migration 0041 made it **not include the kind**;
            // the kind decides how to normalize, not who owns the value).
            // The comparison also ignores case —— the column collation is `utf8mb4_unicode_ci`, and the normalization
            // direction differs per kind (user names lowercased, employee numbers uppercased), so comparing with `==`
            // would let the fake pass an `alice` vs `ALICE` collision that the DB rejects.
            if rows.iter().any(|r| {
                r.tenant_id == identifier.tenant_id
                    && r.normalized_value
                        .eq_ignore_ascii_case(&identifier.normalized_value)
            }) {
                return Err(DomainError::Conflict("duplicate".to_string()));
            }
            rows.push(identifier.clone());
            Ok(())
        }
        async fn list_for_user(&self, user_id: Uuid) -> DomainResult<Vec<UserLoginIdentifier>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.user_id == user_id)
                .cloned()
                .collect())
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<UserLoginIdentifier>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.id == id)
                .cloned())
        }
        async fn set_active(&self, id: Uuid, user_id: Uuid, is_active: bool) -> DomainResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            match rows.iter_mut().find(|r| r.id == id && r.user_id == user_id) {
                Some(row) => {
                    row.is_active = is_active;
                    Ok(true)
                }
                None => Ok(false),
            }
        }
        async fn delete(&self, id: Uuid, user_id: Uuid) -> DomainResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|r| !(r.id == id && r.user_id == user_id));
            Ok(rows.len() != before)
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::new(TenantId::from(Uuid::from_u128(1)))
    }

    fn user(id: u128, username: &str, email: &str) -> User {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        User {
            id: Uuid::from_u128(id),
            tenant_id: TenantId::from(Uuid::from_u128(1)),
            sub: Uuid::from_u128(id + 100),
            email: email.to_string(),
            email_verified: true,
            preferred_username: Some(username.to_string()),
            name: None,
            language: None,
            theme: None,
            password_hash: String::new(),
            must_change_password: false,
            password_changed_at: None,
            status: UserStatus::Active,
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn service(
        users: Vec<User>,
    ) -> (
        LoginIdentifierManagementService,
        Arc<Identifiers>,
        Arc<Users>,
    ) {
        let clock = Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap(),
        ));
        let identifiers = Arc::new(Identifiers::default());
        let users = Arc::new(Users {
            rows: users,
            promoted: Mutex::new(Vec::new()),
        });
        let audit = Arc::new(AuditService::new(Arc::new(DiscardingSink), clock.clone()));
        let service = LoginIdentifierManagementService::new(
            identifiers.clone(),
            users.clone(),
            Arc::new(NoTenantDomains),
            audit,
            clock,
            Arc::new(FixedIds(Mutex::new(1000))),
        );
        (service, identifiers, users)
    }

    fn ctx() -> RequestContext {
        RequestContext {
            ip_address: None,
            user_agent: None,
            correlation_id: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn adds_a_phone_identifier_and_normalizes_it() {
        let (service, _, _) = service(vec![user(2, "alice", "alice@example.com")]);
        let added = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::PhoneNumber,
                    value: "090-1234-5678".to_string(),
                    is_active: true,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap();
        // Displayed as registered, compared by the normalized value.
        assert_eq!(added.display_value, "090-1234-5678");
        assert_eq!(added.normalized_value, "09012345678");
    }

    #[tokio::test]
    async fn rejects_a_value_that_resolves_to_another_user() {
        // bob's `preferred_username` can't become alice's identifier (login would return someone else).
        let (service, _, _) = service(vec![
            user(2, "alice", "alice@example.com"),
            user(3, "bob", "bob@example.com"),
        ]);
        let err = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::Username,
                    value: "BOB".to_string(),
                    is_active: true,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::Conflict(_)));
    }

    #[tokio::test]
    async fn rejects_another_users_email_even_though_email_is_not_a_login_route() {
        let (service, _, _) = service(vec![
            user(2, "alice", "alice@example.com"),
            user(3, "bob", "bob@example.com"),
        ]);
        let err = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::Email,
                    value: "Bob@Example.com".to_string(),
                    is_active: true,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::Conflict(_)));
    }

    #[tokio::test]
    async fn deactivating_keeps_the_row_so_nobody_else_can_claim_it() {
        let (service, repo, _) = service(vec![user(2, "alice", "alice@example.com")]);
        let added = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::EmployeeNumber,
                    value: "E-1001".to_string(),
                    is_active: true,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap();
        let updated = service
            .set_active(
                tenant(),
                Uuid::from_u128(2),
                added.id,
                false,
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap();
        assert!(!updated.is_active);
        assert_eq!(repo.rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rejects_a_value_that_already_resolves_to_the_user_themselves() {
        // If your own `preferred_username` could also be added to the registry, disabling that row would still
        // let authentication pass via the fallback to `users` (an identifier that "is stopped yet still works").
        let (service, _, _) = service(vec![user(2, "alice", "alice@example.com")]);
        let err = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::Username,
                    value: "Alice".to_string(),
                    is_active: true,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::Conflict(_)));
    }

    /// The list shows only registry rows (AP15b removed synthesized rows). The primary identifier comes first.
    #[tokio::test]
    async fn the_list_shows_registry_rows_with_the_primary_first() {
        let (service, identifiers, _) = service(vec![user(2, "alice", "alice@example.com")]);
        // The primary identifier exists as a registry row (`UserRepository` creates it; placed directly here).
        let now = chrono::Utc::now();
        identifiers
            .create(&UserLoginIdentifier {
                id: Uuid::from_u128(100),
                tenant_id: tenant().tenant_id(),
                user_id: Uuid::from_u128(2),
                identifier_type: LoginIdentifierType::Username,
                display_value: "alice".to_string(),
                normalized_value: "alice".to_string(),
                is_active: true,
                is_primary: true,
                is_primary_email: false,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::EmployeeNumber,
                    value: "E-1001".to_string(),
                    is_active: true,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap();

        let entries = service.list(tenant(), Uuid::from_u128(2)).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_primary);
        assert_eq!(entries[0].normalized_value, "alice");
        // The primary identifier is also a stored row, so it has an id. It can't be operated on per identifier
        // because the repository rejects it, not because there's no target.
        assert!(entries[0].id.is_some());
        assert!(!entries[1].is_primary);
        assert!(entries[1].id.is_some());
    }

    /// Promotion only works on email-kind rows. If a phone number could become the primary email, `users.email` would
    /// hold a non-email string and password resets would go there.
    #[tokio::test]
    async fn only_an_email_identifier_can_become_the_primary_email() {
        let (service, _, users) = service(vec![user(2, "alice", "alice@example.com")]);
        let phone = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::PhoneNumber,
                    value: "090-1234-5678".to_string(),
                    is_active: true,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap();
        let err = service
            .promote_email(
                tenant(),
                Uuid::from_u128(2),
                phone.id,
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::Validation(_)));
        // It was refused, so the swap was never called.
        assert!(users.promoted.lock().unwrap().is_empty());
    }

    /// The promoted row is returned **active**. A primary email row can't be activated per identifier (the repository
    /// rejects it), so promoting it while inactive would make a row that can never be activated the notification destination.
    #[tokio::test]
    async fn promoting_an_alias_email_returns_it_as_the_active_primary_email() {
        let (service, _, users) = service(vec![user(2, "alice", "alice@example.com")]);
        let alias = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::Email,
                    value: "Alice@Work.example".to_string(),
                    is_active: false,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap();
        assert!(!alias.is_active);

        let promoted = service
            .promote_email(
                tenant(),
                Uuid::from_u128(2),
                alias.id,
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap();
        assert!(promoted.is_primary_email);
        assert!(promoted.is_active);
        assert_eq!(promoted.display_value, "Alice@Work.example");
        assert_eq!(
            users.promoted.lock().unwrap().as_slice(),
            [(Uuid::from_u128(2), alias.id)]
        );
    }

    /// Someone else's row can't be promoted (`find_owned` checks the owner).
    #[tokio::test]
    async fn cannot_promote_an_identifier_that_belongs_to_someone_else() {
        let (service, _, users) = service(vec![
            user(2, "alice", "alice@example.com"),
            user(3, "bob", "bob@example.com"),
        ]);
        let bobs = service
            .add(
                tenant(),
                Uuid::from_u128(3),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::Email,
                    value: "bob@work.example".to_string(),
                    is_active: true,
                },
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap();
        let err = service
            .promote_email(
                tenant(),
                Uuid::from_u128(2),
                bobs.id,
                &AdminActor::User(Uuid::from_u128(9)),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::NotFound));
        assert!(users.promoted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn does_not_touch_users_from_another_tenant() {
        let mut outsider = user(3, "carol", "carol@example.com");
        outsider.tenant_id = TenantId::from(Uuid::from_u128(2));
        let (service, _, _) = service(vec![outsider]);
        let err = service
            .list(tenant(), Uuid::from_u128(3))
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::NotFound));
    }
}
