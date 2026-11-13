//! Use case for admins creating users (ADR-0009 §5, §6).
//!
//! A tenant admin (`idp.tenant.admin`) creates a user whose home tenant is that tenant
//! (`POST /{tenant_id}/admin/users`). Unlike self-registration ([`crate::application::register`]),
//! it **auto-generates the password** (a random string of 32+ chars) and sets `must_change_password = true`.
//! The generated password is returned in plaintext in the response **only this once** (the admin notifies the user separately), and is not
//! output to logs or audits (same pattern as setup links and invitation tokens. ADR-0009 §5, ADR-0062).
//!
//! The initial admin user created by the tenant creation flow ([`crate::application::tenant_management`]) also
//! goes through this service (the single source of the creation logic). Decisions and validation are completed in this Application layer,
//! and only the result is returned to Presentation (`CLAUDE.md` "Permissions").

use crate::application::account_setup::{AccountSetupLinkIssuer, SetupLink};
use crate::application::audit::{AuditService, RequestContext};
use crate::domain::account::AccountRef;
use crate::domain::account_note::normalize_account_note;
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::message::MessageKey;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::{
    AccountNoteRepository, TenantMembershipRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::user::User;
use crate::domain::values::{
    validate_email as domain_validate_email,
    validate_preferred_username as domain_validate_preferred_username, UserStatus,
};
use std::sync::Arc;
use uuid::Uuid;

/// Byte length of the auto-generated password. It is 43 chars in base64url (no padding), meeting ADR-0009 §5's
/// "32 chars or more".
const GENERATED_PASSWORD_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct CreateUserCommand {
    pub email: String,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    /// Admin note (optional. ADR-0063). Attached to the created user's HOME membership.
    pub note: Option<String>,
}

/// Creation result. `generated_password` is returned in plaintext **only this once** (only the hash is stored; not output to logs or audits).
pub struct CreatedUser {
    pub user_id: Uuid,
    pub sub: Uuid,
    /// The **account setup link** handed to the user (ADR-0062). Returned only this once.
    ///
    /// ⚠ **The generated password is not returned.** The created user's hash is filled with a value nobody knows,
    /// and the user can get in only after choosing a passkey or password via this link. This change ends any form
    /// in which the admin ever holds the user's credentials.
    pub setup_link: SetupLink,
}

/// A built (not yet persisted) user. Validation and hashing of the auto-generated password are done, and only persistence
/// remains. Used by tenant provisioning (REF2) to persist the admin in the same transaction as the tenant row.
/// `generated_password` is handled the same as in [`CreatedUser`] (plaintext only once, never logged).
pub struct PreparedUser {
    pub user: User,
    pub generated_password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UserManagementError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct UserManagementService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    hasher: Arc<dyn PasswordHasher>,
    /// Issues the link handed to the user right after creation (ADR-0062). Creation and link issuance are one operation, so
    /// screens and handlers must not call them as two steps (so as not to create a user where only one succeeded).
    account_setup: Arc<AccountSetupLinkIssuer>,
    /// The admin note written together with creation (ADR-0063).
    notes: Arc<dyn AccountNoteRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl UserManagementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        hasher: Arc<dyn PasswordHasher>,
        account_setup: Arc<AccountSetupLinkIssuer>,
        notes: Arc<dyn AccountNoteRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            users,
            memberships,
            account_setup,
            notes,
            hasher,
            audit,
            clock,
            ids,
        }
    }

    /// **Only builds** (does not persist) a user whose home tenant is `tenant`. Performs input validation, uniqueness pre-checks,
    /// password auto-generation and hashing. Used together with persistence (`create_user`, or the tenant
    /// provisioning transaction).
    pub async fn prepare_user(
        &self,
        tenant: TenantContext,
        cmd: CreateUserCommand,
    ) -> Result<PreparedUser, UserManagementError> {
        let email = cmd.email.trim().to_string();
        validate_email(&email)?;
        // The sign-in identifier is preferred_username. If omitted, email is used as the default (ADR-0009 §8).
        let preferred_username =
            normalize_optional(cmd.preferred_username).unwrap_or_else(|| email.clone());
        // Reject column-length (VARCHAR(255)) overflow before persisting (email is VARCHAR(320), so defaulting can exceed it).
        domain_validate_preferred_username(&preferred_username)
            .map_err(UserManagementError::Validation)?;
        let name = normalize_optional(cmd.name);
        let tenant_id = tenant.tenant_id();

        // Pre-check uniqueness (for an error users can understand). Final uniqueness is guaranteed by the DB's
        // `(tenant_id, email)` / `(tenant_id, preferred_username)` UNIQUE constraints and the sign-in identifier
        // registry's unique constraint (AP8). Identifiers are looked up **the same way as the resolution path**
        // (looking only at `users` would let values already registered as aliases slip through).
        if self
            .users
            .find_by_email(tenant_id, &email)
            .await
            .map_err(internal)?
            .is_some()
        {
            return Err(UserManagementError::Conflict(MessageKey::new(
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
            return Err(UserManagementError::Conflict(MessageKey::new(
                "api-user-username-conflict",
            )));
        }

        let generated_password = crypto::random_token(GENERATED_PASSWORD_BYTES);
        let password_hash = self.hasher.hash(&generated_password).map_err(internal)?;
        let now = self.clock.now();
        let user = User {
            id: self.ids.new_id(),
            tenant_id,
            sub: self.ids.new_id(),
            email,
            // Users created by an admin are treated as the admin guaranteeing email ownership, so they are created verified (SEC6b).
            // This way only self-registered (unverified) users hit the email verification gate at sign-in. The initial admin
            // created at tenant creation (via this service) also stays able to sign in.
            email_verified: true,
            preferred_username: Some(preferred_username),
            name,
            language: None,
            theme: None,
            password_hash,
            must_change_password: true,
            password_changed_at: Some(now),
            status: UserStatus::Active,
            // Provisional registration (ADR-0064). Cannot get in from anywhere until the user sets credentials via the setup link.
            pending_setup: true,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };

        Ok(PreparedUser {
            user,
            generated_password,
        })
    }

    /// Creates a user whose home tenant is `tenant`, with an auto-generated password. Creates the HOME membership at the same
    /// time and sets `must_change_password = true`. Returns the generated password only once.
    pub async fn create_user(
        &self,
        tenant: TenantContext,
        cmd: CreateUserCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<CreatedUser, UserManagementError> {
        let tenant_id = tenant.tenant_id();
        // ⚠ Check the note **before writing anything**. Finding out it is too long after creating the user cannot
        //   undo the creation (it would be "created but errored").
        let note = normalize_account_note(cmd.note.as_deref().unwrap_or(""))
            .map_err(UserManagementError::Validation)?;
        let prepared = self.prepare_user(tenant, cmd).await?;
        let user = prepared.user;

        self.users.create(&user).await.map_err(|e| match e {
            // A DB unique constraint violation is either (tenant_id, email) or (tenant_id, preferred_username).
            // It is reached only in a race with the pre-check (concurrent registration), so it is reported as one without identifying which.
            DomainError::Conflict(_) => {
                UserManagementError::Conflict(MessageKey::new("api-user-identity-conflict"))
            }
            other => UserManagementError::Internal(other.to_string()),
        })?;

        // HOME membership (the single source of the home tenant is users.tenant_id. This row is a projection for flow decisions. §3).
        self.memberships
            .create(&TenantMembership::new_home(
                tenant_id,
                user.id,
                user.created_at,
            ))
            .await
            .map_err(internal)?;

        // Only the internal ID is recorded in the audit (the generated password is not output. §5).
        self.audit
            .record(
                AuditEventType::UserCreated,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("user={}", user.id)),
                ctx,
            )
            .await;

        // Admin note (ADR-0063). Same row and same audit shape as writing it from the member screen
        // (the content is not kept in the audit).
        if let Some(text) = note.as_deref() {
            self.notes
                .save(
                    tenant_id,
                    AccountRef::User { user_id: user.id },
                    text,
                    actor.user_id(),
                    self.clock.now(),
                )
                .await
                .map_err(internal)?;
            self.audit
                .record(
                    AuditEventType::AccountNoteUpdated,
                    AuditResult::Success,
                    Some(tenant_id),
                    actor.user_id(),
                    actor.client_id(),
                    Some(&format!("user={}", user.id)),
                    ctx,
                )
                .await;
        }

        // Issue the link handed to the user. ⚠ **If this fails, fail the whole creation**: a user without
        // a link becomes an "account nobody can get into" holding only a password nobody knows.
        let setup_link = self
            .account_setup
            .issue(tenant_id, user.id)
            .await
            .map_err(|e| UserManagementError::Internal(e.to_string()))?;

        Ok(CreatedUser {
            user_id: user.id,
            sub: user.sub,
            setup_link,
        })
    }
}

fn validate_email(email: &str) -> Result<(), UserManagementError> {
    domain_validate_email(email).map_err(UserManagementError::Validation)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn internal(e: DomainError) -> UserManagementError {
    UserManagementError::Internal(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::password::PasswordHasher as PasswordHasherTrait;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::tenant::TenantId;
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

    struct FixedIds(Mutex<u128>);
    impl IdGenerator for FixedIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    struct PlainHasher;
    impl PasswordHasherTrait for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
            Ok(hash == format!("hash:{password}"))
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
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.id == id)
                .cloned())
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
        async fn find_by_username(&self, t: TenantId, name: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.tenant_id == t && u.preferred_username.as_deref() == Some(name))
                .cloned())
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

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    /// A fake that only records written notes (ADR-0063).
    #[derive(Default)]
    struct FakeNotes {
        saved: Mutex<Vec<(TenantId, Uuid, String)>>,
    }
    #[async_trait]
    impl AccountNoteRepository for FakeNotes {
        async fn save(
            &self,
            tenant_id: TenantId,
            account: AccountRef,
            text: &str,
            _updated_by: Option<Uuid>,
            _now: DateTime<Utc>,
        ) -> DomainResult<()> {
            let user_id = account
                .user_id()
                .expect("user creation writes only a person's note");
            self.saved
                .lock()
                .unwrap()
                .push((tenant_id, user_id, text.to_string()));
            Ok(())
        }
        async fn clear(&self, _t: TenantId, _a: AccountRef) -> DomainResult<()> {
            unreachable!("creation never deletes a note")
        }
    }

    fn service(
        users: Arc<FakeUsers>,
        memberships: Arc<FakeMemberships>,
        sink: Arc<CapturingSink>,
    ) -> UserManagementService {
        service_with_notes(users, memberships, sink, Arc::new(FakeNotes::default()))
    }

    fn service_with_notes(
        users: Arc<FakeUsers>,
        memberships: Arc<FakeMemberships>,
        sink: Arc<CapturingSink>,
        notes: Arc<FakeNotes>,
    ) -> UserManagementService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(now()))));
        UserManagementService::new(
            users,
            memberships,
            Arc::new(PlainHasher),
            crate::application::account_setup::testing::link_issuer(
                Arc::new(crate::application::account_setup::testing::FakeSetupTokens::default()),
                Arc::new(FixedClock(now())),
            ),
            notes,
            audit,
            Arc::new(FixedClock(now())),
            Arc::new(FixedIds(Mutex::new(0))),
        )
    }

    #[tokio::test]
    async fn creates_user_with_generated_password_and_home_membership() {
        let tenant: TenantId = Uuid::now_v7().into();
        let users = Arc::new(FakeUsers::default());
        let memberships = Arc::new(FakeMemberships::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(users.clone(), memberships.clone(), sink.clone());

        let created = svc
            .create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "  new@example.com ".to_string(),
                    preferred_username: Some("newbie".to_string()),
                    name: None,
                    note: None,
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("created");

        // The link handed to the user is issued (ADR-0062). ⚠ **The generated password is not returned.**
        assert!(created.setup_link.token.len() >= 32);
        assert!(
            created
                .setup_link
                .url
                .starts_with("https://idp.example.com/"),
            "the link points at the web console: {}",
            created.setup_link.url
        );
        assert!(created.setup_link.url.contains(&created.setup_link.token));
        let stored = users.rows.lock().unwrap()[0].clone();
        // ⚠ **Filled with a password nobody knows** (neither admin nor user can get in. Decided via the link).
        assert!(stored.password_hash.starts_with("hash:"));
        assert!(stored.must_change_password);
        // ADR-0064: provisional until the user finishes setup.
        assert!(stored.pending_setup);
        assert!(!stored.is_active());
        assert_eq!(stored.email, "new@example.com");
        assert_eq!(stored.tenant_id, tenant);
        // The HOME membership is created.
        let m = memberships.rows.lock().unwrap()[0].clone();
        assert!(m.is_home());
        assert_eq!(m.tenant_id, tenant);
        // The link token has not leaked into the audit.
        assert!(sink.events.lock().unwrap().iter().all(|e| e
            .reason
            .as_deref()
            .map(|r| !r.contains(&created.setup_link.token))
            .unwrap_or(true)));
        assert_eq!(
            sink.events.lock().unwrap()[0].event_type,
            AuditEventType::UserCreated
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_email() {
        let tenant: TenantId = Uuid::now_v7().into();
        let users = Arc::new(FakeUsers::default());
        let svc = service(
            users.clone(),
            Arc::new(FakeMemberships::default()),
            Arc::new(CapturingSink::default()),
        );
        let cmd = || CreateUserCommand {
            email: "dup@example.com".to_string(),
            preferred_username: None,
            name: None,
            note: None,
        };
        svc.create_user(
            TenantContext::new(tenant),
            cmd(),
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("first ok");
        assert!(matches!(
            svc.create_user(
                TenantContext::new(tenant),
                cmd(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(UserManagementError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_email() {
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Arc::new(FakeUsers::default()),
            Arc::new(FakeMemberships::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "not-an-email".to_string(),
                    preferred_username: None,
                    name: None,
                    note: None,
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(UserManagementError::Validation(_))
        ));
    }

    /// ADR-0063: a note written together with creation attaches to the created user's HOME membership.
    /// The audit has 2 entries, "created" and "wrote a note", and ⚠ the note content is not kept.
    #[tokio::test]
    async fn a_note_given_at_creation_goes_on_the_home_membership() {
        let tenant: TenantId = Uuid::now_v7().into();
        let sink = Arc::new(CapturingSink::default());
        let notes = Arc::new(FakeNotes::default());
        let svc = service_with_notes(
            Arc::new(FakeUsers::default()),
            Arc::new(FakeMemberships::default()),
            sink.clone(),
            notes.clone(),
        );
        let created = svc
            .create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "family@example.com".to_string(),
                    preferred_username: None,
                    name: None,
                    note: Some("\r\n 家族として作成\r\n".to_string()),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("created");

        let saved = notes.saved.lock().unwrap().clone();
        assert_eq!(
            saved,
            vec![(tenant, created.user_id, "家族として作成".to_string())]
        );
        let events = sink.events.lock().unwrap();
        let kinds: Vec<_> = events.iter().map(|e| e.event_type).collect();
        assert_eq!(
            kinds,
            vec![
                AuditEventType::UserCreated,
                AuditEventType::AccountNoteUpdated
            ]
        );
        assert!(events
            .iter()
            .all(|e| !e.reason.as_deref().unwrap_or("").contains("家族")));
    }

    /// An empty note means "no note". Neither rows nor audits increase.
    #[tokio::test]
    async fn a_blank_note_at_creation_writes_nothing() {
        let tenant: TenantId = Uuid::now_v7().into();
        let sink = Arc::new(CapturingSink::default());
        let notes = Arc::new(FakeNotes::default());
        let svc = service_with_notes(
            Arc::new(FakeUsers::default()),
            Arc::new(FakeMemberships::default()),
            sink.clone(),
            notes.clone(),
        );
        svc.create_user(
            TenantContext::new(tenant),
            CreateUserCommand {
                email: "blank@example.com".to_string(),
                preferred_username: None,
                name: None,
                note: Some("  \n ".to_string()),
            },
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("created");
        assert!(notes.saved.lock().unwrap().is_empty());
        assert_eq!(sink.events.lock().unwrap().len(), 1);
    }

    /// ⚠ A too-long note is refused **before creating the user** (refusing after creating would be "created but errored").
    #[tokio::test]
    async fn a_too_long_note_is_rejected_before_anything_is_created() {
        let tenant: TenantId = Uuid::now_v7().into();
        let users = Arc::new(FakeUsers::default());
        let memberships = Arc::new(FakeMemberships::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(users.clone(), memberships.clone(), sink.clone());
        let result = svc
            .create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "long@example.com".to_string(),
                    preferred_username: None,
                    name: None,
                    note: Some("あ".repeat(crate::domain::account_note::ACCOUNT_NOTE_MAX_LEN + 1)),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await;
        assert!(matches!(result, Err(UserManagementError::Validation(_))));
        assert!(users.rows.lock().unwrap().is_empty());
        assert!(memberships.rows.lock().unwrap().is_empty());
        assert!(sink.events.lock().unwrap().is_empty());
    }
}
