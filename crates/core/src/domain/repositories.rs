//! Repository traits (DIP boundary).
//!
//! The Application layer depends only on these traits, and the Infrastructure layer (sqlx)
//! implements them. `#[async_trait]` is used so they can be injected as trait objects
//! (`Arc<dyn ...>`). Methods are extended as needed when each phase is implemented.
//!
//! # Tenant isolation (ADR-0009 §8)
//!
//! MariaDB has no RLS, so the app layer is the only isolation defense. Methods that read or search
//! tenant-scoped tables take `tenant_id: TenantId`, and implementations always include it in the
//! WHERE clause. The following intentionally take no tenant_id:
//!
//! - **Resolving a user by a globally unique key** (`users.id` / `users.sub`): with guest
//!   participation (§3) the flow's tenant ≠ the home tenant, so the tenant boundary is enforced by
//!   membership checks and the home check (the use case's responsibility).
//! - **SSO sessions**: designed to be shared per host (§8). The boundary is enforced by membership
//!   verification.
//! - **Per-user security operations** (revoking all sessions, all codes / refresh tokens):
//!   these act on the user's own state, and revoking everything across tenants is the safe side.
//! - **Tables without a tenant column** (signing keys, jti revocation list, TOTP, WebAuthn,
//!   challenges).
#![allow(dead_code)]

use crate::domain::account::{AccountFilter, AccountPage, AccountRef, ServiceAccount};
use crate::domain::application::{
    AccountAssignment, Application, ApplicationAssignment, ApplicationBinding,
    ApplicationUserFacts, AssignedServiceAccount, AssignedUser, BindingTarget,
};
use crate::domain::application_log::{
    ApplicationLogEntry, ApplicationLogFilter, ApplicationLogRecord,
};
use crate::domain::audit::{AuditEvent, AuditLogEntry, AuditLogFilter};
use crate::domain::auth_session::{
    AuthSession, AuthSessionIdHash, AuthenticationCompletion, HandoffExchange, HandoffHandleHash,
    PasswordVerification,
};
use crate::domain::authentication_policy::{AuthenticationPolicy, LockoutPolicy};
use crate::domain::authorization_code::{AuthorizationCode, AuthorizationCodeHash};
use crate::domain::backchannel_logout::BackchannelLogoutDelivery;
use crate::domain::client::Client;
use crate::domain::consent::ClientConsent;
use crate::domain::email_verification::EmailVerificationToken;
use crate::domain::error::Result;
use crate::domain::external_idp::{
    ExternalIdentity, ExternalIdentityProvider, ExternalLoginRequest,
};
use crate::domain::login_identifier::{LoginIdentifierMatch, UserLoginIdentifier};
use crate::domain::paging::{Page, PageRequest};
use crate::domain::passkey_challenge::PasskeyChallenge;
use crate::domain::password_reset::PasswordResetToken;
use crate::domain::refresh_token::RefreshToken;
use crate::domain::resource::ProtectedResource;
use crate::domain::revoked_access_token::RevokedAccessToken;
use crate::domain::saml_service_provider::SamlServiceProvider;
use crate::domain::saml_sso_request::SamlSsoRequest;
use crate::domain::session_key::SessionKeyBinding;
use crate::domain::sign_in_history::{SignInAppUse, SignInFailure, SignInRecord, SignInSuccess};
use crate::domain::signing_key::SigningKey;
use crate::domain::ssh_key::{DistributedSshKey, UserSshKey};
use crate::domain::sso_session::SsoSession;
use crate::domain::system_setting::SystemSetting;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::tenant_domain::TenantDomain;
use crate::domain::tenant_membership::{TenantMemberFilter, TenantMemberPage, TenantMembership};
use crate::domain::tenant_setting::{TenantOverridesAcrossTenants, TenantSetting};
use crate::domain::totp_secret::TotpSecret;
use crate::domain::user::{LoginFailureRecord, User};
use crate::domain::user_authenticator::{
    AuthenticatorStatus, AuthenticatorType, UserAuthenticator,
};
use crate::domain::user_device::{CountryCode, DeviceRef, UserDevice};
use crate::domain::values::{
    ApplicationStatus, AssignmentMode, AuthenticationMethod, GrantType, MembershipStatus,
    ResourceStatus, SigningKeyStatus, UserStatus,
};
use crate::domain::webauthn_credential::WebAuthnCredential;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Persistence of tenants (ADR-0009 §1). Tenants are mutually independent administrative
/// boundaries; `parent_tenant_id` is lineage, not an authorization boundary.
#[async_trait]
pub trait TenantRepository: Send + Sync {
    async fn create(&self, tenant: &Tenant) -> Result<()>;
    async fn find_by_id(&self, id: TenantId) -> Result<Option<Tenant>>;
    /// Returns the single row with `parent_tenant_id IS NULL` (root).
    async fn find_root(&self) -> Result<Option<Tenant>>;
    /// Lists the direct child tenants of the given tenant (ADR-0009 §6). There is no upper bound on
    /// the count, so paths returning to screens use [`Self::list_children_page`] (this method is
    /// limited to internal uses needing every row, such as deciding whether deletion is possible).
    async fn list_children(&self, parent_id: TenantId) -> Result<Vec<Tenant>>;
    /// Returns one page of direct child tenants plus the total (`/{tenant_id}/admin/tenants`; G7).
    /// The default implementation slices from fetching all; the sqlx implementation, which can
    /// write `LIMIT`/`OFFSET` in the DB, overrides it.
    async fn list_children_page(
        &self,
        parent_id: TenantId,
        page: PageRequest,
    ) -> Result<Page<Tenant>> {
        Ok(Page::from_all(self.list_children(parent_id).await?, page))
    }
    /// Updates the display name and status (re-parenting `parent_tenant_id` is forbidden; the
    /// caller guarantees it).
    async fn update(&self, tenant: &Tenant) -> Result<()>;
    /// Deletes a tenant. That "there are no child tenants below, and the tenant itself has no
    /// users/clients" is pre-validated by the caller (the DB also protects it with
    /// `ON DELETE RESTRICT`).
    async fn delete(&self, id: TenantId) -> Result<()>;
}

fn unsupported(method: &str) -> crate::domain::error::DomainError {
    crate::domain::error::DomainError::Repository(format!(
        "{method} is not supported by this repository"
    ))
}

/// Domains exclusively assigned to a tenant (ADR-0029).
///
/// When the login field gets input in the form `local@domain`, it is looked up to **determine the
/// single home tenant** from the domain (home realm discovery;
/// `crate::application::login_user_resolution`). Once the home tenant is known, only one tenant's
/// registry needs to be searched, avoiding the cross scan of participating guests.
#[async_trait]
pub trait TenantDomainRepository: Send + Sync {
    /// Looks up the tenant owning a domain (**authentication hot path**).
    ///
    /// Pass `domain` normalized ([`crate::domain::tenant_domain::normalize_domain`]). A single
    /// equality lookup on the unique key `tenant_domains_domain_uk`, so the result is at most one
    /// row (if two could match, the home tenant could not be determined and this table would be
    /// pointless).
    ///
    /// **Not put in the tenant resolution TTL cache**, so that revoking an assignment never stays
    /// ineffective for up to the TTL; the same treatment as the tenant `ACTIVE` check (ADR-0009
    /// §8).
    ///
    /// The default implementation is `Ok(None)` (test fakes without domains go through only the old
    /// resolution).
    async fn find_tenant_by_domain(&self, _domain: &str) -> Result<Option<TenantId>> {
        Ok(None)
    }
    /// Lists the domains assigned to a tenant (admin API).
    ///
    /// The default implementations of the following three **return a failure** (not `Ok(vec![])` or
    /// `Ok(())`). If a test fake meant to replace only the login path silently accepted admin
    /// operations too, it would look as if an assignment succeeded when it did not.
    async fn list_for_tenant(&self, _tenant_id: TenantId) -> Result<Vec<TenantDomain>> {
        Err(unsupported("list_for_tenant"))
    }
    /// Assigns a domain. If **any tenant** already holds it, `Conflict`
    /// (the unique key does not include the tenant; ADR-0029 §1).
    async fn create(&self, _domain: &TenantDomain) -> Result<()> {
        Err(unsupported("create"))
    }
    /// Removes an assignment. Deletes only the row matching `tenant_id` and returns whether one was
    /// deleted (so another tenant's domain cannot be deleted by id).
    async fn delete(&self, _tenant_id: TenantId, _id: Uuid) -> Result<bool> {
        Err(unsupported("delete"))
    }
}

/// Transaction boundary (unit of work) for tenant provisioning (ADR-0009 §5).
///
/// Creating a tenant is meaningful only once all four rows exist: "tenant row, initial admin user,
/// HOME membership, grant of `idp.tenant.admin`" (if any is missing, a tenant without admins = an
/// orphan tenant remains). This port persists that aggregate **in a single transaction** and rolls
/// everything back on partial failure (REF2). Building and validating domain objects is the
/// Application layer's job; the implementation only persists.
#[async_trait]
pub trait TenantProvisioningRepository: Send + Sync {
    /// Atomically persists the tenant, the creator's bootstrap admin membership, and the permission
    /// grant (ADR-0009 §4). The creator user already exists (belonging to the parent tenant), so it
    /// is not created. Unique constraint violations (duplicate root, duplicate membership) return
    /// `Conflict`; if `admin_permission_code` is not in the `permissions` master, returns
    /// `InvalidValue`.
    async fn provision(
        &self,
        tenant: &Tenant,
        admin_membership: &TenantMembership,
        admin_permission_code: &str,
        granted_at: DateTime<Utc>,
    ) -> Result<()>;
}

/// Persistence of tenant memberships (invitations, guest participation; ADR-0009 §3).
#[async_trait]
pub trait TenantMembershipRepository: Send + Sync {
    /// Creates a membership (HOME at user creation, GUEST at invitation creation).
    async fn create(&self, membership: &TenantMembership) -> Result<()>;
    async fn find(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Option<TenantMembership>>;
    /// Whether the user has an `ACTIVE` membership (HOME or GUEST) in the given tenant, and
    /// **that user's home tenant is `ACTIVE`** (membership check for OIDC flows; ADR-0009 §8).
    ///
    /// **The home tenant's state is included.** Disabling the home tenant is the operation "stop
    /// that organization's users", and is not meant to leave a back door via joined tenants.
    /// Setting the home tenant to `DISABLED` makes the tenant's own URL unresolvable
    /// (`TenantResolutionService`), but URLs of the tenants it joined as a guest stay alive, so
    /// without checking here there would be users who "were stopped at home but can still get in
    /// via a joined tenant".
    ///
    /// This does not contradict ADR-0009 §1's "tenant states are independent per tenant (a parent's
    /// `DISABLED` does not propagate to children)". §1 is about **the tenant hierarchy (parent →
    /// child)**; this is about **a user's home → that user**, a different axis.
    ///
    /// The path looking up guests from login field input
    /// (`UserRepository::find_active_guest_by_login_identifier`) imposes the same condition inside
    /// the resolution query (membership check and user resolution are one query).
    async fn is_active_member(&self, tenant_id: TenantId, user_id: Uuid) -> Result<bool>;
    /// Returns every tenant where the user has an `ACTIVE` membership (HOME / GUEST) (for the
    /// tenant switcher UI; ADR-0009 §3). Uses `tenant_memberships_user_idx`. The default
    /// implementation is empty (test fakes are not called; only the production sqlx implementation
    /// overrides it).
    async fn list_active_for_user(&self, _user_id: Uuid) -> Result<Vec<TenantMembership>> {
        Ok(Vec::new())
    }
    /// Finds an `INVITED` row by the invitation token hash (for the accept endpoint).
    async fn find_by_invitation_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<TenantMembership>>;
    /// Accepts an invitation and transitions to `ACTIVE` (the caller clears the token-related
    /// columns).
    async fn activate(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()>;
    /// Updates the membership status (suspend / resume `ACTIVE` ⇄ `SUSPENDED`; MT24). Whether the
    /// transition is allowed is decided by the Application layer (`can_be_suspended` /
    /// `can_be_resumed` of [`crate::domain::tenant_membership::TenantMembership`]); this method
    /// only writes.
    async fn update_status(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        status: MembershipStatus,
    ) -> Result<()>;
    /// Removes a guest membership (removing HOME is forbidden by the caller).
    async fn delete(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()>;
}

/// Queries of the member list (read model) (MT22). Kept separate from writes
/// ([`TenantMembershipRepository`]) (the same split as `AuditLogSink` and `AuditLogQuery`).
///
/// Filters apply to user-side columns (email, name) while pages are per membership, so the
/// implementation resolves with **one query joining** membership and user (loading everything and
/// filtering in the app breaks down in proportion to tenant size, so that is not used).
#[async_trait]
pub trait TenantMemberQuery: Send + Sync {
    /// Returns one page of members matching the conditions in ascending email order (ties by
    /// ascending `user_id`). The order must be stable (so rows are neither duplicated nor missing
    /// across pages).
    async fn search(&self, filter: &TenantMemberFilter) -> Result<TenantMemberPage>;
}

/// Writes admin notes on accounts (ADR-0063 / ADR-0065). Reading is done by joins in the list /
/// detail ([`TenantMemberQuery`], [`AccountQuery`]) (no re-fetching per row in the list).
///
/// A person's note attaches to the membership, so ⚠ **it cannot be written for non-member users**
/// (the foreign key refuses). Callers must confirm before writing that the target is an account of
/// the requested tenant, returning 404 otherwise.
#[async_trait]
pub trait AccountNoteRepository: Send + Sync {
    /// Writes a note (replacing any existing one).
    async fn save(
        &self,
        tenant_id: TenantId,
        account: AccountRef,
        text: &str,
        updated_by: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<()>;
    /// Deletes a note (no error if there is none).
    async fn clear(&self, tenant_id: TenantId, account: AccountRef) -> Result<()>;
}

/// Queries of the account list (people and service accounts; read model) (ADR-0065).
///
/// Paging across kinds can only be done in the DB (fetching each separately and mixing breaks both
/// the total and page boundaries). The implementation resolves both kinds with one `UNION ALL`
/// query.
#[async_trait]
pub trait AccountQuery: Send + Sync {
    /// Returns one page of accounts matching the conditions in ascending heading order (ties by
    /// kind, then ID). The order must be stable (so rows are neither duplicated nor missing across
    /// pages).
    async fn search(&self, filter: &AccountFilter) -> Result<AccountPage>;
    /// Looks up one service account by `client_id` (single-item screen). Clients that are not
    /// service accounts, deleted ones, and other tenants' give `None`.
    async fn find_service_account(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<ServiceAccount>>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Creates a user (`user.tenant_id` = home tenant). Creating the HOME membership at the same
    /// time is the use case's responsibility (ADR-0009 §3).
    async fn create(&self, user: &User) -> Result<()>;
    /// Resolves by the globally unique internal ID (the tenant boundary is enforced by the caller
    /// via the home check and membership checks; see the module comment).
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
    /// Finds by the externally visible identifier `sub` (used by `/userinfo`; globally unique).
    async fn find_by_sub(&self, sub: Uuid) -> Result<Option<User>>;
    /// Finds a user whose home is `tenant_id` by email (the unique key is `(tenant_id, email)`).
    async fn find_by_email(&self, tenant_id: TenantId, email: &str) -> Result<Option<User>>;
    /// Finds a user whose home is `tenant_id` by preferred_username.
    async fn find_by_username(&self, tenant_id: TenantId, username: &str) -> Result<Option<User>>;
    /// Resolves a user from **a value entered in the login field** (AP8).
    ///
    /// Looks up active rows of the registry (`user_login_identifiers`) by per-type normalized keys,
    /// falling back to `users.preferred_username` if none. Multiple login identifiers are a change
    /// that "adds ways to read the input", not one that "adds ways to look up users", so each login
    /// path sees **only this one**, and where it looked is kept inside the implementation.
    ///
    /// The default implementation delegates to `find_by_username` (test fakes without a registry
    /// resolve only by `preferred_username`, as before).
    async fn find_by_login_identifier(
        &self,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        Ok(self.find_by_username(tenant_id, input.trim()).await?.into())
    }
    /// Resolves an ACTIVE GUEST of the tenant from a value entered on **the joined tenant's login
    /// screen** (ADR-0009 §8).
    ///
    /// Guest identifiers live in the home tenant's registry, so [`Self::find_by_login_identifier`],
    /// which searches the requested tenant's registry, does not find them. This looks up "valid
    /// identifiers **in the home tenant** of users with an ACTIVE GUEST membership in `tenant_id`".
    ///
    /// Called only from login paths, and **only when resolution in the home tenant found nothing**
    /// ([`crate::application::login_user_resolution::resolve_login_user`]). The home tenant is
    /// decided first so that merely having a guest with an identifier of the same value join does
    /// not make the tenant's HOME user "ambiguous" and lock them out.
    ///
    /// The default implementation is `NotFound` (test fakes without memberships resolve only in the
    /// home tenant, as before).
    async fn find_active_guest_by_login_identifier(
        &self,
        _tenant_id: TenantId,
        _input: &str,
    ) -> Result<LoginIdentifierMatch> {
        Ok(LoginIdentifierMatch::not_found())
    }
    /// From **the joined tenant's password reset** (`/{tenant_id}/forgot-password`), looks up an
    /// ACTIVE GUEST of that tenant by `users.email` (MT26).
    ///
    /// Unlike login, reset **looks up by `users.email`, not by the registry
    /// (`user_login_identifiers`)**. It is the mail destination itself, and must work even in
    /// tenants that have not enabled email login (ADR-0025 §5). So
    /// [`Self::find_active_guest_by_login_identifier`] cannot be used, and this lookup is needed
    /// separately.
    ///
    /// The condition is the same as guest resolution: "ACTIVE GUEST of the requested tenant × home
    /// tenant ACTIVE". **If several people match, no one is returned** — `users.email` is unique
    /// only within a tenant, and guests from different home tenants can share an address. Since it
    /// cannot be decided whom to send to, nothing is sent (the response is always `Accepted`, so
    /// from the user's view the behavior is the same: "no mail arrives").
    ///
    /// The default implementation is `Ok(None)` (test fakes without memberships resolve only in the
    /// home tenant).
    async fn find_active_guest_by_email(
        &self,
        _tenant_id: TenantId,
        _email: &str,
    ) -> Result<Option<User>> {
        Ok(None)
    }
    /// Looks up **the invitee of a guest invitation** by `users.email` (ADR-0061). Searches across
    /// tenants.
    ///
    /// The invitee is a user whose home is another tenant, so they are not within what the joined
    /// tenant's admin can see (their own tenant's roster). **What the inviter knows is the
    /// invitee's email address.**
    ///
    /// ⚠ **`users.email` is unique only within a tenant** (`(tenant_id, email)`). When users with
    /// the same address exist in two tenants, whom to invite cannot be decided, so **no one is
    /// returned** (the same judgment as password reset's [`Self::find_active_guest_by_email`];
    /// picking one while ambiguous would let index details decide the invitee). Callers guide
    /// toward specifying by internal ID.
    ///
    /// Only **ACTIVE users × home tenant ACTIVE** are counted. Someone who cannot get in even if
    /// invited is not a candidate, and counting them would mean "a single stopped user with the
    /// same address makes the only invitable person uninvitable" (MT26 imposes the state in SQL for
    /// the same reason).
    ///
    /// The default implementation is `Ok(None)` (with test fakes lacking this lookup, invitations
    /// pass only by internal ID).
    async fn find_active_user_by_email_across_tenants(&self, _email: &str) -> Result<Option<User>> {
        Ok(None)
    }
    /// **When the home tenant is known**, looks up only that tenant's registry (ADR-0029).
    ///
    /// Called from login paths only when the input has the form `local@domain` and that domain
    /// resolved to a single tenant via [`TenantDomainRepository::find_tenant_by_domain`]
    /// (home realm discovery). `home_tenant_id` is the home tenant determined that way.
    ///
    /// The resolution condition is the same as [`Self::find_active_guest_by_login_identifier`],
    /// "ACTIVE member in the requested tenant × home tenant ACTIVE", but **it does not filter by
    /// membership kind** (with the home tenant decided, HOME and GUEST can be treated alike). When
    /// the requested tenant itself owns the domain it also goes through this path, and that user is
    /// resolved as a HOME member.
    ///
    /// **Ambiguity cannot arise in principle on this path.** Only one tenant's registry is
    /// searched, and within it one normalized value belongs to one person (migration 0041). The
    /// cross scan of guests ([`Self::find_active_guest_by_login_identifier`]) is the cause of "two
    /// guests with the same name joining locks both out", so avoiding it is itself the purpose of
    /// this method.
    ///
    /// The default implementation is `NotFound` (test fakes without domains go through only the old
    /// resolution).
    async fn find_member_by_login_identifier(
        &self,
        _tenant_id: TenantId,
        _home_tenant_id: TenantId,
        _input: &str,
    ) -> Result<LoginIdentifierMatch> {
        Ok(LoginIdentifierMatch::not_found())
    }
    /// Updates the login failure count and lock expiry (lock policy, design spec §4.3).
    ///
    /// **Not used to record failures** (use [`Self::record_login_failure`]). Reading the value,
    /// adding 1, and writing it back would miss concurrent attempts. This is limited to writing
    /// absolute values, such as "reset on success" or "unlock by an admin".
    async fn update_login_state(
        &self,
        id: Uuid,
        failed_login_count: i32,
        locked_until: Option<DateTime<Utc>>,
    ) -> Result<()>;
    /// Records one login failure and returns the state after recording (SEC13).
    ///
    /// Increments and decides the lock **in one statement**. With "read → +1 → write back", N
    /// attempts arriving concurrently read the same value, and N failures could advance the count
    /// by only 1, never reaching the lock threshold. The lock is one layer of defense in depth
    /// (separate from per-IP rate limiting), so nothing is missed.
    ///
    /// The lock decision is not left to the caller because the failure count compared against the
    /// threshold **is only correctly known inside this UPDATE**.
    async fn record_login_failure(
        &self,
        id: Uuid,
        lockout: LockoutPolicy,
        now: DateTime<Utc>,
    ) -> Result<LoginFailureRecord>;
    /// Updates the password hash and clears `must_change_password` (password change, ADR-0009 §5).
    ///
    /// Rewrites **only if the current hash is still `expected_current_hash`**, returning `true` if
    /// it rewrote. `false` means "another request changed the password between the read and the
    /// write".
    ///
    /// It is conditional because history (AP7) is meaningful only with hashes that were **actually
    /// replaced**. With an unconditional UPDATE, two change requests arriving at once read the same
    /// current hash, the later one overwrites, and **both push the same old hash into history** —
    /// the password written first remains neither current nor in history, and could be reused right
    /// away.
    async fn update_password(
        &self,
        id: Uuid,
        expected_current_hash: &str,
        password_hash: &str,
    ) -> Result<bool>;
    /// Updates the password hash and **sets** `must_change_password` (reissue by an admin; the user
    /// is made to change it at next login; ADR-0009 §5). Condition and return value are the same as
    /// [`Self::update_password`].
    async fn reset_password_forced(
        &self,
        id: Uuid,
        expected_current_hash: &str,
        password_hash: &str,
    ) -> Result<bool>;
    /// Updates the user's status (ACTIVE / DISABLED / LOCKED) (enabling / disabling by an admin).
    async fn update_status(&self, id: Uuid, status: UserStatus) -> Result<()>;
    /// Clears provisional registration (the user set credentials via the setup link; ADR-0064).
    /// Idempotent.
    ///
    /// The default implementation is an unsupported error (same policy as `update_theme`; only the
    /// production sqlx implementation and test fakes exercising provisional registration override
    /// it). ⚠ Callers call it **only for provisional users**.
    async fn finish_setup(&self, _id: Uuid) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "finish_setup is not supported by this repository".to_string(),
        ))
    }
    /// Deletes a user (deletion by an admin; related rows are cleaned up by DB FK CASCADE / SET
    /// NULL).
    async fn delete(&self, id: Uuid) -> Result<()>;
    /// Sets the email-verified flag (when a self-registered account's confirmation link is
    /// consumed; SEC6b).
    async fn mark_email_verified(&self, id: Uuid) -> Result<()>;
    /// Updates the display language setting (MT20; `None` clears it).
    async fn update_language(&self, id: Uuid, language: Option<&str>) -> Result<()>;
    /// Updates the color scheme setting (`light` / `dark` / `system`; `None` clears it). The
    /// default implementation is an unsupported error (only the production sqlx implementation
    /// overrides it; test fakes are not called).
    async fn update_theme(&self, _id: Uuid, _theme: Option<&str>) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "update_theme is not supported by this repository".to_string(),
        ))
    }
    /// Updates the display name (`users.name`) (self-service; `None` clears the display name =
    /// `NULL`). The default implementation is an unsupported error (only the production sqlx
    /// implementation overrides it; test fakes are not called).
    async fn update_name(&self, _id: Uuid, _name: Option<&str>) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "update_name is not supported by this repository".to_string(),
        ))
    }
    /// Updates the profile (email, login identifier, display name) together (edit by an admin;
    /// MT25). `None` for `preferred_username` / `name` means "clear (`NULL`)". Violations of the
    /// in-tenant unique constraints `(tenant_id, email)` / `(tenant_id, preferred_username)` return
    /// `Conflict`. The default implementation is an unsupported error (same policy as
    /// `update_name`; only the production sqlx implementation overrides it).
    async fn update_profile(
        &self,
        _id: Uuid,
        _email: &str,
        _preferred_username: Option<&str>,
        _name: Option<&str>,
    ) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "update_profile is not supported by this repository".to_string(),
        ))
    }
    /// **Promotes** an alias email row in the registry **to the primary email row** (ADR-0052).
    ///
    /// Promotion is a swap: replacing `users.email`, demoting the current primary email row, and
    /// promoting the chosen row are done **in the same transaction**. Failing midway would leave
    /// zero primary email rows (losing the destination) or two (the UNIQUE on
    /// `primary_email_of_user` prevents that, so the write fails).
    ///
    /// When the target is not found, does not belong to the user, is not an email type, or is the
    /// primary login identifier, returns `false` (returns without writing anything).
    ///
    /// The default implementation is an unsupported error (same policy as `update_profile`; only
    /// the production sqlx implementation overrides it).
    async fn promote_primary_email(&self, _user_id: Uuid, _identifier_id: Uuid) -> Result<bool> {
        Err(crate::domain::error::DomainError::Repository(
            "promote_primary_email is not supported by this repository".to_string(),
        ))
    }
}

/// Persistence of the login identifier registry (AP8; `user_login_identifiers`).
///
/// Resolution (lookup at login) lives in [`UserRepository::find_by_login_identifier`]; only **admin
/// operations** (list, add, enable/disable, delete, profile sync) are here. The read hot path and
/// admin writes have different concerns; the same split as `AuditLogSink` and `AuditLogQuery`.
///
/// Default implementations behave as "the registry is empty" (for test fakes without a registry;
/// same policy as AP9's [`UserAuthenticatorRepository`]).
#[async_trait]
pub trait UserLoginIdentifierRepository: Send + Sync {
    /// Registers an identifier. A duplicate `normalized_value` within the tenant gives `Conflict`
    /// (**independent of type**; one normalized value belongs to one person; migration 0041).
    async fn create(&self, _identifier: &UserLoginIdentifier) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "create is not supported by this repository".to_string(),
        ))
    }
    /// Lists a user's identifiers by type and registration order (including inactive rows; for the
    /// admin screen).
    async fn list_for_user(&self, _user_id: Uuid) -> Result<Vec<UserLoginIdentifier>> {
        Ok(Vec::new())
    }
    /// Looks up by internal ID (the caller checks the tenant boundary).
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<UserLoginIdentifier>> {
        Ok(None)
    }
    /// Toggles enabled/disabled. `false` if the target (`(id, user_id)`) does not exist.
    async fn set_active(&self, _id: Uuid, _user_id: Uuid, _is_active: bool) -> Result<bool> {
        Ok(false)
    }
    /// Deletes an identifier. `false` if the target (`(id, user_id)`) does not exist.
    async fn delete(&self, _id: Uuid, _user_id: Uuid) -> Result<bool> {
        Ok(false)
    }
}

/// Records the `jti` of verified client assertions and refuses reuse within the validity period
/// (ADR-0030 decision 5).
///
/// Cleanup of expired rows is done by the shared GC (`ExpiringRecordStore`), not this trait.
///
/// Uniqueness of `jti` can only be required within a client (RFC 7519 §4.1.7 also defines only
/// per-issuer uniqueness), so the key is the triple `(tenant_id, client_id, jti)`.
#[async_trait]
pub trait ClientAssertionReplayRepository: Send + Sync {
    /// If `jti` is unused, records it and returns `true`; if already recorded, returns `false` (=
    /// replay).
    ///
    /// With two steps, "check then write", simultaneous arrivals of the same assertion could both
    /// be judged unused. Implementations must decide with a single insert against a unique
    /// constraint.
    ///
    /// `retain_until` is when the record may be dropped. Pass not the assertion's `exp` itself but
    /// **the time acceptance stops** (`exp` + clock skew allowance). Keeping it only until `exp`
    /// would leave a gap where acceptance continues after cleanup removed the row, allowing the
    /// same assertion to be reused there.
    async fn record_if_unused(
        &self,
        tenant_id: TenantId,
        client_id: &str,
        jti: &str,
        retain_until: DateTime<Utc>,
    ) -> Result<bool>;
}

/// Record making each received DPoP proof usable only once per key (ADR-0075 decision 4).
///
/// Cleanup of expired rows is done by the shared GC (`ExpiringRecordStore`), not this trait.
#[async_trait]
pub trait DpopProofReplayRepository: Send + Sync {
    /// If `proof_hash` (hex of `sha256(jkt ":" jti)`) is unused, records it and returns `true`; if
    /// already recorded, returns `false` (= reuse). Implementations must decide with a single
    /// insert against a unique constraint (if two arrive at once, only one wins).
    ///
    /// `retain_until` is **the time the acceptance window closes** (when it passes the past window
    /// allowed for `iat`).
    async fn record_if_unused(&self, proof_hash: &str, retain_until: DateTime<Utc>)
        -> Result<bool>;
}

#[async_trait]
pub trait ClientRepository: Send + Sync {
    /// `client_id` is unique within a tenant, so it is looked up by `(tenant_id, client_id)`
    /// (ADR-0009 §2).
    async fn find_by_client_id(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Client>>;
    /// Registers a new client (RP) (admin API, design spec §9.3). Registers it in the tenant of
    /// `client.tenant_id`; a duplicate `client_id` within the tenant gives `Conflict`.
    async fn create(&self, client: &Client) -> Result<()>;
    /// Lists **all** registered clients of the given tenant, newest first. A method for internal
    /// uses needing everything, such as collecting CORS allowed origins and resolving back-channel
    /// logout destinations. Paths returning to screens use [`Self::list_page`].
    async fn list(&self, tenant_id: TenantId) -> Result<Vec<Client>>;
    /// Returns one page of registered clients plus the total (`/{tenant_id}/admin/clients`; G7).
    /// The default implementation slices from fetching all; the sqlx implementation, which can
    /// write `LIMIT`/`OFFSET` in the DB, overrides it. Returns one page plus the total. Passing
    /// `grant_type` narrows to clients registered with that grant (ADR-0038; this is how the admin
    /// console's "integrations" and "service accounts" lists are split).
    ///
    /// **Filtering must happen in the same layer as paging.** If the caller thinned a page after
    /// receiving it, neither `total` nor the pager would match the actual count.
    async fn list_page(
        &self,
        tenant_id: TenantId,
        grant_type: Option<GrantType>,
        page: PageRequest,
    ) -> Result<Page<Client>> {
        let all = self.list(tenant_id).await?;
        let filtered = match grant_type {
            Some(grant) => all
                .into_iter()
                .filter(|c| c.allows_grant_type(grant))
                .collect(),
            None => all,
        };
        Ok(Page::from_all(filtered, page))
    }
    /// Updates mutable fields (app_name / redirect_uris / scopes / status / secret_hash etc.). The
    /// target is identified by `(id, tenant_id)` (other tenants' rows cannot be updated).
    /// `NotFound` if there is no target.
    async fn update(&self, client: &Client) -> Result<()>;
}

/// Persistence of SAML SP (client) registrations. The tenant boundary is enforced by `tenant_id`.
#[async_trait]
pub trait SamlServiceProviderRepository: Send + Sync {
    async fn create(&self, provider: &SamlServiceProvider) -> Result<()>;
    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<SamlServiceProvider>>;
    /// Resolves by id within the tenant boundary (bringing another tenant's id does not resolve).
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<SamlServiceProvider>>;
    /// Resolves by entity_id within the tenant boundary (matching the AuthnRequest `Issuer` at the
    /// SSO endpoint; `(tenant_id, entity_id)` is unique).
    async fn find_by_entity_id(
        &self,
        tenant_id: TenantId,
        entity_id: &str,
    ) -> Result<Option<SamlServiceProvider>>;
    /// Updates an existing SP (only the record with the same tenant and id; a duplicate entity_id
    /// gives `Conflict`). `true` if updated; `false` if there is no target (e.g. a race where
    /// another admin deleted it after find).
    async fn update(&self, provider: &SamlServiceProvider) -> Result<bool>;
    /// Deletes an SP within the tenant boundary. `true` if deleted, `false` if there is no target.
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;
}

/// Persistence of SAML SP-initiated SSO progress state (`saml_sso_requests`). Single-use
/// consumption of the handle is enforced by the same atomic UPDATE approach as
/// [`AuthSessionRepository`]. Persistence of SAML SP-initiated SSO progress state.
///
/// Like [`AuthSessionRepository`], it **never receives the plaintext `saml_request_id`**. The
/// `id_hash` argument is the SHA-256 derived by [`crate::domain::saml_sso_request::id_hash`]
/// (SEC6).
#[async_trait]
pub trait SamlSsoRequestRepository: Send + Sync {
    async fn create(&self, request: &SamlSsoRequest) -> Result<()>;
    /// Returns only rows of the tenant that started the flow (bringing another tenant's id does not
    /// resolve).
    async fn find_by_id_hash(
        &self,
        tenant_id: TenantId,
        id_hash: &str,
    ) -> Result<Option<SamlSsoRequest>>;
    /// Looks up a row by the web handoff handle (SHA-256). Tenant restriction is the same as
    /// `find_by_id_hash`.
    async fn find_by_handle(
        &self,
        tenant_id: TenantId,
        handle_hash: &str,
    ) -> Result<Option<SamlSsoRequest>>;
    /// Consumes the handle as single-use (setting `handle_hash` to NULL) and **at the same time
    /// regenerates the id to `new_id_hash`**. If already consumed (lost a concurrent exchange, or
    /// reuse), returns `false`. The reason regeneration is needed is the same as
    /// [`AuthSessionRepository::consume_handle`].
    async fn consume_handle(
        &self,
        id_hash: &str,
        handle_hash: &str,
        new_id_hash: &str,
    ) -> Result<bool>;
    /// Deletes the progress state. It doubles as an **atomic claim** before issuing the response,
    /// so it returns `true` only if it deleted (if it lost a concurrent resume or was already
    /// consumed, `false` = must not issue).
    async fn delete(&self, id_hash: &str) -> Result<bool>;
    /// Deletes expired rows and returns the count (called from G2's bulk GC).
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// Persistence of the AuthSession aggregate (temporary state from `/authorize` to code issuance).
///
/// **This trait never receives the plaintext `auth_session_id`.** It receives only
/// [`AuthSessionIdHash`]; the plaintext exists only above the Application layer (web's cookie,
/// handoff) (SEC6). Having no entry point for plaintext blocks, at the type level, any path that
/// "accidentally stores the raw value".
///
/// State changes take the change returned by the aggregate ([`HandoffExchange`] etc.) and are
/// written **in one statement**. Every change includes re-keying the id (SEC7), so splitting it
/// into separate statements would create "a moment where the state has advanced but the old id can
/// still be looked up".
#[async_trait]
pub trait AuthSessionRepository: Send + Sync {
    async fn create(&self, session: &AuthSession) -> Result<()>;
    /// Returns only auth sessions of the tenant that started the flow (bringing another tenant's
    /// session id does not resolve).
    async fn find(
        &self,
        tenant_id: TenantId,
        id: &AuthSessionIdHash,
    ) -> Result<Option<AuthSession>>;
    /// Looks up an auth session by the web handoff handle (ADR-0018 decision 2). Like
    /// [`Self::find`], limited to the flow's tenant. Expiry / already-exchanged checks are done by
    /// the aggregate ([`AuthSession::exchange_handoff`]).
    async fn find_by_handoff(
        &self,
        tenant_id: TenantId,
        handle: &HandoffHandleHash,
    ) -> Result<Option<AuthSession>>;
    /// Consumes the handle as single-use and re-keys the id in the same statement. If already
    /// consumed (lost a concurrent exchange, or reuse), returns `false` (only the winner gets the
    /// new id).
    async fn save_handoff_exchange(&self, exchange: &HandoffExchange) -> Result<bool>;
    /// Records password verification (awaiting the second step) and re-keys the id in the same
    /// statement.
    ///
    /// ⚠ Previously recorded authentication (`auth_time`, `sid`, methods) is **erased**
    /// ([`AuthSession::record_password_verification`]).
    async fn save_password_verification(&self, verification: &PasswordVerification) -> Result<()>;
    /// Records completion of authentication and re-keys the id in the same statement (e.g. on
    /// `/login` success; SEC7).
    ///
    /// `sid` and the methods are read at code issuance by the path that goes through the consent
    /// screen (`ConsentService::approve`) (G5, ADR-0043). Authentication and code issuance are
    /// separate requests, and at that point neither the SSO cookie nor "what was used to
    /// authenticate" is at hand, so they are stashed in the auth_session here.
    async fn save_authentication(&self, completion: &AuthenticationCompletion) -> Result<()>;
    async fn delete(&self, id: &AuthSessionIdHash) -> Result<()>;
    /// Deletes expired rows and returns the count (called from G2's bulk GC).
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// Persistence of authentication policies (user authentication / auth policy spec §7). The tenant
/// boundary is enforced by `tenant_id`.
///
/// Evaluation ([`crate::domain::authentication_policy::evaluate_policies`]) is done by a pure
/// domain function; this trait only reads and writes rows. The login hot path uses
/// `list_enabled_for_tenant`.
#[async_trait]
pub trait AuthenticationPolicyRepository: Send + Sync {
    /// Creates a policy. A duplicate `(tenant_id, policy_code)` gives `Conflict`.
    async fn create(&self, policy: &AuthenticationPolicy) -> Result<()>;
    /// Returns all policies of the tenant (including disabled) in ascending priority (ties by
    /// ascending policy_code) (for the admin screen).
    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<AuthenticationPolicy>>;
    /// Returns only **enabled** policies of the tenant in ascending priority (for evaluation at
    /// login).
    async fn list_enabled_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<AuthenticationPolicy>>;
    /// Resolves by id within the tenant boundary (bringing another tenant's id does not resolve).
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<AuthenticationPolicy>>;
    /// Updates an existing policy (only the row with the same tenant and id; a duplicate
    /// policy_code gives `Conflict`). `true` if updated, `false` if there is no target.
    async fn update(&self, policy: &AuthenticationPolicy) -> Result<bool>;
    /// Deletes a policy within the tenant boundary. `true` if deleted, `false` if there is no
    /// target.
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;
}

#[async_trait]
pub trait SsoSessionRepository: Send + Sync {
    async fn create(&self, session: &SsoSession) -> Result<()>;
    async fn find_by_hash(&self, session_hash: &str) -> Result<Option<SsoSession>>;
    /// Returns all SSO sessions of the given user, newest first (self-service session list; G10).
    /// Excluding expired rows is done by the caller (Application layer) with `is_valid_at`. The
    /// default implementation is empty (test fakes are not called; only the production sqlx
    /// implementation overrides it).
    async fn list_for_user(&self, _user_id: Uuid) -> Result<Vec<SsoSession>> {
        Ok(Vec::new())
    }
    /// Extends the idle expiry on SSO restore (absolute is not changed; design spec §3.4).
    async fn extend_idle(&self, session_hash: &str, idle_expires_at: DateTime<Utc>) -> Result<()>;
    /// Resets the expiries (when binding to a device key changed the length; task #887, ADR-0074).
    /// The default implementation is an unsupported error (only the production sqlx implementation
    /// overrides it).
    async fn set_lifetime(
        &self,
        _session_hash: &str,
        _idle_expires_at: DateTime<Utc>,
        _absolute_expires_at: DateTime<Utc>,
    ) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "set_lifetime is not supported by this repository".to_string(),
        ))
    }
    /// Records completion of second-factor verification (AP4, AP5; the path where step-up elevates
    /// an existing session). `methods` is the full set of methods after elevation, and the
    /// implementation derives the strength with [`AuthenticationStrength::from_methods`] (callers
    /// do not pass strength, keeping the single source of the derivation rule in the domain). The
    /// default implementation is an unsupported error (only the production sqlx implementation
    /// overrides it).
    async fn record_second_factor(
        &self,
        _session_hash: &str,
        _methods: &[AuthenticationMethod],
        _completed_at: DateTime<Utc>,
    ) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "record_second_factor is not supported by this repository".to_string(),
        ))
    }
    /// Records completion of step-up authentication (AP5). `methods` are the methods verified in
    /// this step-up; `mfa_completed_at` and the strength are updated only if they include a second
    /// factor (the implementation must not downgrade a multi-factor session or restore MFA
    /// freshness with single-factor re-verification). The default implementation is an unsupported
    /// error (only the production sqlx implementation overrides it).
    async fn record_step_up(
        &self,
        _session_hash: &str,
        _methods: &[AuthenticationMethod],
        _verified_at: DateTime<Utc>,
    ) -> Result<()> {
        Err(crate::domain::error::DomainError::Repository(
            "record_step_up is not supported by this repository".to_string(),
        ))
    }
    /// Time a passkey re-verification last passed in this session (task #872; a condition for
    /// device registration).
    ///
    /// A login made with a passkey itself is known from `auth_time` and `authentication_methods`,
    /// so what this returns is the time verified with a passkey **afterwards** (step-up). The
    /// default implementation is `None` (keeps no record).
    async fn passkey_verified_at(&self, _session_hash: &str) -> Result<Option<DateTime<Utc>>> {
        Ok(None)
    }
    async fn delete(&self, session_hash: &str) -> Result<()>;
    /// Deletes all SSO sessions of the given user (invalidating all sessions per user; F5).
    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<()>;

    /// Deletes the given user's SSO sessions **except one**, returning the count deleted
    /// (ADR-0045).
    ///
    /// Used when the user changes their own password.
    /// [`delete_all_for_user`](Self::delete_all_for_user) would **lock out the very user who
    /// changed it on the spot**. The reset-link path (`password_reset`) may delete everything
    /// because it is the path for "people who forgot the password", who have no session at hand to
    /// begin with. The two cannot be treated alike.
    ///
    /// The default implementation is an unsupported error (only the production sqlx implementation
    /// overrides it).
    async fn delete_all_for_user_except(
        &self,
        _user_id: Uuid,
        _keep_session_hash: &str,
    ) -> Result<u64> {
        Err(unsupported("delete_all_for_user_except"))
    }
    /// Deletes expired sessions (idle or absolute exceeded) in bulk and returns the count (GC).
    /// The default implementation does nothing (test fakes are not called).
    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<u64> {
        Ok(0)
    }
}

/// Users' devices (task #872; ADR-0071) and which device an SSO session was created on.
#[async_trait]
pub trait UserDeviceRepository: Send + Sync {
    /// The user's registration of that device (`None` if absent).
    async fn find(&self, user_id: Uuid, device: &DeviceRef) -> Result<Option<UserDevice>>;
    /// Returns the user's registered devices in order of last use (newest first).
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<UserDevice>>;
    /// Registers one. If the same user already has the same mark, `Conflict`.
    async fn insert(&self, device: &UserDevice) -> Result<()>;
    /// Deletes one of the user's devices and returns the deleted row (`None` if the id is someone
    /// else's device).
    async fn delete(&self, user_id: Uuid, device_id: Uuid) -> Result<Option<UserDevice>>;
    /// Records a sign-in on this device (last used time, country, source).
    async fn touch(
        &self,
        device_id: Uuid,
        used_at: DateTime<Utc>,
        country: Option<&CountryCode>,
        ip: Option<&str>,
    ) -> Result<()>;
    /// Deletes devices unused since before `cutoff` and returns the deleted rows (expiry).
    async fn delete_unused_before(&self, cutoff: DateTime<Utc>) -> Result<Vec<UserDevice>>;

    /// Binds a device to an SSO session. Writes **only when not yet bound**, returning `true` if it
    /// wrote.
    async fn link_session(
        &self,
        session_hash: &str,
        device: &DeviceRef,
        country: Option<&CountryCode>,
        observed_at: DateTime<Utc>,
    ) -> Result<bool>;
    /// The device bound to the SSO session (`None` if none).
    async fn session_device(&self, session_hash: &str) -> Result<Option<DeviceRef>>;
    /// Whether the user has signed in on this device before (excluding the current session, judged
    /// by remaining sessions).
    async fn seen_before(
        &self,
        user_id: Uuid,
        device: &DeviceRef,
        except_session_hash: &str,
    ) -> Result<bool>;
    /// `session_hash` of SSO sessions created on this device of the user (cut as collateral of
    /// revocation).
    async fn sessions_for_device(&self, user_id: Uuid, device: &DeviceRef) -> Result<Vec<String>>;
    /// Login names of active people in this tenant who have neither a registered device nor an
    /// authenticator app key (task #916; people who could not get in once the
    /// registered-devices-only setting is enabled). Sorted by name, at most 50.
    async fn home_members_without_trusted_device(&self, tenant_id: TenantId)
        -> Result<Vec<String>>;
}

/// Sign-in history the user sees (task #879; ADR-0073).
///
/// Every write is "a copy for the history", and failures never stop sign-in or token issuance
/// (callers log and continue).
#[async_trait]
pub trait SignInHistoryRepository: Send + Sync {
    /// Writes a successful sign-in. If the same `sid` already exists, does nothing and returns
    /// `false` (a duplicate request).
    async fn record_success(&self, sign_in: &SignInSuccess) -> Result<bool>;
    /// Writes a refused sign-in.
    async fn record_failure(&self, failure: &SignInFailure) -> Result<()>;
    /// Writes that a token was issued to an app for a sign-in (`sid`) (from the second time on,
    /// advances the last time).
    async fn record_app_issue(
        &self,
        user_id: Uuid,
        tenant_id: TenantId,
        sid: &str,
        client_id: &str,
        issued_at: DateTime<Utc>,
        refresh_issued: bool,
    ) -> Result<()>;
    /// Writes that a refresh token was used to refresh. Source and self-identification are those of
    /// **whoever sent the refresh**.
    async fn record_refresh_use(
        &self,
        sid: &str,
        client_id: &str,
        used_at: DateTime<Utc>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<()>;
    /// Writes that a used-up refresh token came again.
    async fn record_refresh_reuse(
        &self,
        sid: &str,
        client_id: &str,
        detected_at: DateTime<Utc>,
    ) -> Result<()>;
    /// Returns the user's history, newest first (passing `before` returns only entries older than
    /// that id).
    async fn list_for_user(
        &self,
        user_id: Uuid,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<SignInRecord>>;
    /// How each sign-in (`sids`) was used by apps. The refresh state is decided at `now`.
    async fn app_usage(
        &self,
        user_id: Uuid,
        sids: &[String],
        now: DateTime<Utc>,
    ) -> Result<Vec<SignInAppUse>>;
}

/// SSH public keys registered by users (task #885; ADR-0072). Keys are held per organization where
/// registered.
#[async_trait]
pub trait UserSshKeyRepository: Send + Sync {
    /// Returns the keys the user registered in that organization, newest registration first.
    async fn list_for_user(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Vec<UserSshKey>>;
    /// Registers one. If the same organization already has a key with the same fingerprint,
    /// `Conflict` (even another user's key).
    async fn insert(&self, key: &UserSshKey) -> Result<()>;
    /// Deletes one of the user's keys and returns the deleted row (`None` if the id is someone
    /// else's key or another organization's).
    async fn delete(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        key_id: Uuid,
    ) -> Result<Option<UserSshKey>>;
    /// The list handed to distributing machines. Only keys of **active users** who are **active
    /// members of that organization** (keys of stopped users or users removed from the organization
    /// are not output). Sorted by user name, then registration.
    async fn list_distributable(&self, tenant_id: TenantId) -> Result<Vec<DistributedSshKey>>;
}

/// Binding between SSO sessions and device keys (DBSC; task #887; ADR-0074). Stored in
/// `sso_session_contexts`.
#[async_trait]
pub trait SessionKeyBindingRepository: Send + Sync {
    /// The binding (`None` if none).
    async fn find(&self, session_hash: &str) -> Result<Option<SessionKeyBinding>>;
    /// Binds. Writes **only when not yet bound**, returning `true` if it wrote.
    async fn bind(&self, session_hash: &str, binding: &SessionKeyBinding) -> Result<bool>;
    /// Records a refresh signed with the key.
    async fn record_refresh(&self, session_hash: &str, at: DateTime<Utc>) -> Result<()>;
}

/// Reads for the "status" the user sees (task #896; ADR-0078). Read-only; writes nothing.
#[async_trait]
pub trait SecurityStatusQuery: Send + Sync {
    /// Context per sign-in state of the user (sign-in states without a context row are not
    /// returned).
    async fn session_contexts(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<crate::domain::security_status::SessionContextStatus>>;
    /// Token kinds per app. Returns apps with consent, apps with valid refresh tokens, and
    /// apps issued tokens since `recent_since`, sorted by name.
    async fn app_tokens(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
        recent_since: DateTime<Utc>,
    ) -> Result<Vec<crate::domain::security_status::AppTokenStatus>>;
    /// Warnings since `since`.
    async fn warnings(
        &self,
        user_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<crate::domain::security_status::SecurityWarnings>;
}

#[async_trait]
pub trait AuthorizationCodeRepository: Send + Sync {
    async fn create(&self, code: &AuthorizationCode) -> Result<()>;
    /// Atomically consumes it one-time. If the issuing tenant matches and it is unused and
    /// unexpired, sets `used_at` and returns that code. If already used, expired, nonexistent, or
    /// issued by another tenant, `None` (the caller treats it as reuse detection).
    async fn consume(
        &self,
        tenant_id: TenantId,
        hash: &AuthorizationCodeHash,
        used_at: DateTime<Utc>,
    ) -> Result<Option<AuthorizationCode>>;
    /// Looks up an **already consumed** code by hash (SEC8). Used when `consume` returns `None` to
    /// distinguish "real reuse" from "nonexistent / expired". Unconsumed, nonexistent, deleted
    /// after expiry, and issued by another tenant all give `None`.
    async fn find_used(
        &self,
        tenant_id: TenantId,
        hash: &AuthorizationCodeHash,
    ) -> Result<Option<AuthorizationCode>>;
    /// On logout, immediately revokes all unconsumed, unexpired codes of the user (sets `used_at`).
    async fn revoke_all_active_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<()>;
}

/// Persistence of password reset tokens (MT18). The DB stores only the SHA-256 hash.
/// A per-user security operation, so no tenant_id is taken (see the module comment;
/// the use case enforces the tenant boundary by matching `users.tenant_id`).
#[async_trait]
pub trait PasswordResetTokenRepository: Send + Sync {
    async fn create(&self, token: &PasswordResetToken) -> Result<()>;
    /// Atomically consumes it one-time. If unused and unexpired, sets `used_at` and returns the
    /// row. Used, expired, or nonexistent gives `None`.
    async fn consume(
        &self,
        token_hash: &str,
        used_at: DateTime<Utc>,
    ) -> Result<Option<PasswordResetToken>>;
    /// Looks up **without consuming** (only unused and unexpired ones; ADR-0062).
    ///
    /// Used by the screen opening the link to know "whose link, for what purpose". ⚠ **Merely
    /// opening it must not consume it** — a link pasted in a chat is fetched by a preview bot
    /// before the recipient. Deferring consumption to the POST (the operation that actually sets
    /// credentials) keeps the link alive even if it was fetched first.
    ///
    /// The default implementation is `Ok(None)` (fakes without this lookup do not reveal the link's
    /// contents).
    async fn find_active(
        &self,
        _token_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<PasswordResetToken>> {
        Ok(None)
    }
    /// Revokes all unused tokens of the user (sets `used_at`; used for replacement on reissue).
    async fn invalidate_all_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<()>;
}

/// History of retired password hashes (AP7's reuse prohibition).
///
/// The current password is in `users.password_hash`, so only **replaced hashes** are pushed here
/// (holding a copy would let history and current drift on a missed update). A per-user security
/// operation, so no tenant_id is taken (the use case enforces the tenant boundary by matching
/// `users.tenant_id`).
#[async_trait]
pub trait PasswordHistoryRepository: Send + Sync {
    /// Pushes one retired hash and deletes old rows, keeping only `retain`.
    ///
    /// Pushing and pruning are not separated because if only one ran, history would grow
    /// monotonically or, conversely, fall below the count needed for decisions (callers are not
    /// trusted to keep the order).
    async fn push(
        &self,
        user_id: Uuid,
        password_hash: &str,
        retired_at: DateTime<Utc>,
        retain: u32,
    ) -> Result<()>;
    /// Returns up to `limit` retired hashes, newest first.
    async fn recent(&self, user_id: Uuid, limit: u32) -> Result<Vec<String>>;
}

/// Persistence of email verification tokens (SEC6b). The DB stores only the SHA-256 hash. The same
/// one-time pattern as `PasswordResetTokenRepository` (no tenant_id; the use case enforces the
/// tenant boundary by matching `users.tenant_id`).
#[async_trait]
pub trait EmailVerificationTokenRepository: Send + Sync {
    async fn create(&self, token: &EmailVerificationToken) -> Result<()>;
    /// Atomically consumes it one-time. If unused and unexpired, sets `used_at` and returns the
    /// row. Used, expired, or nonexistent gives `None`.
    async fn consume(
        &self,
        token_hash: &str,
        used_at: DateTime<Utc>,
    ) -> Result<Option<EmailVerificationToken>>;
    /// Revokes all unused tokens of the user (used for replacement on resend).
    async fn invalidate_all_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<()>;
}

#[async_trait]
pub trait SigningKeyRepository: Send + Sync {
    async fn insert(&self, key: &SigningKey) -> Result<()>;
    /// Inserts `key` **only if there is no key that can sign right now** (an exclusive insert for
    /// bootstrap only). The condition is the same as `find_active` (ACTIVE and within validity) —
    /// successor keys that are merely published, or keys left ACTIVE after expiring, do not count
    /// as "a key exists". Returns `true` if inserted, `false` if a key that can sign already
    /// existed and nothing was done. "Check existence → insert" runs in an exclusive section, and
    /// the implementation guarantees keys are not generated twice even when several instances start
    /// at once (SEC5).
    async fn insert_if_no_active(&self, key: &SigningKey) -> Result<bool>;
    /// Returns the ACTIVE key used for new signatures.
    async fn find_active(&self) -> Result<Option<SigningKey>>;
    /// Returns the keys published in JWKS (ACTIVE + RETIRED with not_after in the future).
    async fn list_published(&self) -> Result<Vec<SigningKey>>;
    async fn find_by_kid(&self, kid: &str) -> Result<Option<SigningKey>>;
    /// Returns all keys in descending creation order (for the admin screen).
    async fn list_all(&self) -> Result<Vec<SigningKey>>;
    /// Updates the status (ACTIVE → RETIRED etc.). `NotFound` if there is no target.
    async fn update_status(&self, kid: &str, status: SigningKeyStatus) -> Result<()>;
    /// Deletes a key. Callers must forbid deleting ACTIVE keys.
    async fn delete(&self, kid: &str) -> Result<()>;
}

#[async_trait]
pub trait AuditLogSink: Send + Sync {
    async fn record(&self, event: &AuditEvent) -> Result<()>;

    /// Deletes audit events past the retention period and returns the count (G8). Deletion is a
    /// write-side concern, so it lives in this trait rather than the read side ([`AuditLogQuery`]).
    ///
    /// The default implementation does nothing (test fakes have no retention period). The
    /// production sqlx implementation overrides it.
    async fn purge_older_than(&self, _older_than: DateTime<Utc>) -> Result<u64> {
        Ok(0)
    }
}

/// Reads of `audit_log` (status screen A3). Kept separate from writes (`AuditLogSink`).
#[async_trait]
pub trait AuditLogQuery: Send + Sync {
    /// Returns audit logs matching the conditions, newest first (`occurred_at` descending, ties by
    /// `id` descending). To prevent cross-tenant viewing, read calls always set `filter.tenant_id`.
    async fn search(&self, filter: &AuditLogFilter) -> Result<Vec<AuditLogEntry>>;

    /// Returns the **last used time** per client of the given tenant (the latest `occurred_at` of
    /// successful token issuance / authorization code issuance). Used by the client status list
    /// (A3). Clients with no usage are not included.
    async fn last_used_per_client(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<(String, DateTime<Utc>)>>;
}

/// Writes of application logs (`log`) (CLAUDE.md "Logging"). Persists `tracing` WARN / ERROR
/// asynchronously in batches. **Failures here are not logged** (to avoid an infinite loop where a
/// log about a failed write triggers another write; the implementation swallows them).
#[async_trait]
pub trait ApplicationLogSink: Send + Sync {
    /// Records several entries at once. An empty slice does nothing.
    async fn record_batch(&self, records: &[ApplicationLogRecord]) -> Result<()>;

    /// Deletes rows older than `older_than` and returns the count (applying the retention period).
    async fn purge_older_than(&self, older_than: DateTime<Utc>) -> Result<u64>;
}

/// Reads of `log` (the admin console's error / warning log screen). Kept separate from writes.
#[async_trait]
pub trait ApplicationLogQuery: Send + Sync {
    /// Returns logs matching the conditions, newest first (`occurred_at` descending, ties by `id`
    /// descending).
    async fn search(&self, filter: &ApplicationLogFilter) -> Result<Vec<ApplicationLogEntry>>;
}

/// Looking up, granting, and revoking permission codes held by users (ADR-0006) (DIP boundary).
///
/// A separate axis from OIDC scopes (a `ClientRepository` concern). Protected use cases decide
/// through this trait "whether the user holds the required permission". Granting / revoking is used
/// by the admin console (A2).
#[async_trait]
pub trait UserPermissionRepository: Send + Sync {
    /// Returns the list of grantable permission codes (the `permissions` master) in ascending
    /// order. Used to present the options in the admin console's (A2) grant form.
    async fn list_available_codes(&self) -> Result<Vec<String>>;
    /// Returns the permission codes the user holds with `tenant_id` as scope (order undefined).
    async fn list_codes_for_user(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Vec<String>>;
    /// Returns the permission codes the user holds **for every scope** as `(scope, code)` (order
    /// undefined). Used before account operations to see "what the target holds where" (including
    /// permissions held as a guest; task #579).
    async fn list_scoped_codes_for_user(&self, user_id: Uuid) -> Result<Vec<(TenantId, String)>>;
    /// Whether the user holds the given permission code with `tenant_id` as scope (exact match;
    /// ADR-0009 §4).
    async fn has_permission(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<bool>;
    /// Whether the user holds **any one** of the given codes (OR check).
    ///
    /// Used on the authorization hot path to bundle "required permission or idp.system.admin" into
    /// one round trip (REF3). The default implementation calls `has_permission` in turn. The DB
    /// implementation overrides it with a single `IN` query.
    async fn has_any_permission(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        codes: &[&str],
    ) -> Result<bool> {
        for &code in codes {
            if self.has_permission(tenant_id, user_id, code).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Grants a permission with `tenant_id` as scope (idempotent: an existing grant does nothing).
    /// `code` must exist in the `permissions` master.
    async fn grant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        code: &str,
        granted_at: DateTime<Utc>,
    ) -> Result<()>;
    /// Revokes a permission scoped to `tenant_id` (no error if it does not exist).
    async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<()>;
    /// Revokes **all** permission rows of the user scoped to `tenant_id` at once and returns the
    /// revoked codes (empty if none; used for cleanup when expelling a guest; ADR-0009 §3). Read
    /// and delete happen atomically.
    async fn revoke_all_for_user_in_tenant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> Result<Vec<String>>;
}

/// Persistence of permissions held by clients (system clients) (ADR-0037).
///
/// No scope argument is taken because `clients.id` already determines the tenant
/// (`clients.tenant_id`). A state where "the client's tenant" and "the permission scope" disagree
/// cannot even be represented (`client_permissions` has no scope column).
#[async_trait]
pub trait ClientPermissionRepository: Send + Sync {
    /// Returns the permission codes the client holds (order undefined; empty if none).
    async fn list_codes_for_client(&self, client_row_id: Uuid) -> Result<Vec<String>>;
    /// Grants a permission (idempotent: an existing grant keeps its `granted_at`).
    /// `code` must exist in the `permissions` master and be grantable to clients
    /// (`domain::permission::is_grantable_to_client`; works twice with the DB CHECK constraint).
    async fn grant(&self, client_row_id: Uuid, code: &str, granted_at: DateTime<Utc>)
        -> Result<()>;
    /// Revokes a permission (no error if it does not exist).
    async fn revoke(&self, client_row_id: Uuid, code: &str) -> Result<()>;
}

/// Persistence of apps (`applications`), their identities (bindings), and assignments (ADR-0054 /
/// ADR-0059).
///
/// The three tables share one trait so that half-finished states such as **an app removed with only
/// its bindings left** are never created. Neither bindings nor assignments mean anything without
/// identifying the app.
#[async_trait]
pub trait ApplicationRepository: Send + Sync {
    /// Registers an app.
    async fn create(&self, application: &Application) -> Result<()>;
    /// Looks up an app in the tenant by surrogate key. Rows of other tenants give `None`.
    async fn find_by_id(&self, tenant_id: TenantId, id: Uuid) -> Result<Option<Application>>;
    /// **Looks up an app from an OIDC `client_id`** (decision hot path).
    ///
    /// The authorization flow only has `clients.client_id` (a string unique within the tenant), so
    /// the translation to the surrogate key is closed here too. Clients without a binding give
    /// `None` — so callers can distinguish pre-migration / missed migration from "no assignment".
    async fn find_by_oidc_client_id(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Application>>;
    /// Looks up an app from a SAML `entity_id` (the resolution path paired with the OIDC side).
    async fn find_by_saml_entity_id(
        &self,
        tenant_id: TenantId,
        entity_id: &str,
    ) -> Result<Option<Application>>;
    /// Looks up an app from an identity (the binding's counterpart) (ADR-0059). One counterpart
    /// belongs to only one app, so the answer is at most one.
    ///
    /// Used by the roster's self endpoint (the app of the calling service account), admin token
    /// issuance (whether the client carries a service account identity), and the "already an
    /// identity of another app" hint.
    async fn find_by_binding_target(
        &self,
        tenant_id: TenantId,
        target: BindingTarget,
    ) -> Result<Option<Application>>;
    /// Lists the apps in the tenant (ascending `display_name`).
    async fn list(&self, tenant_id: TenantId) -> Result<Vec<Application>>;
    /// Updates the display name, status, and assignment mode. `false` if there is no target.
    async fn update(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        display_name: &str,
        status: ApplicationStatus,
        assignment_mode: AssignmentMode,
        updated_at: DateTime<Utc>,
    ) -> Result<bool>;
    /// Deletes an app (bindings and assignments go away by CASCADE). `false` if there is no target.
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;

    /// Lists an app's bindings (in registration order).
    async fn list_bindings(&self, application_id: Uuid) -> Result<Vec<ApplicationBinding>>;
    /// Adds a binding. If the counterpart is already connected to another app,
    /// [`DomainError::Conflict`](crate::domain::error::DomainError::Conflict).
    async fn add_binding(&self, binding: &ApplicationBinding) -> Result<()>;
    /// Removes a binding (within the app boundary; `false` if there is no target).
    async fn remove_binding(&self, application_id: Uuid, binding_id: Uuid) -> Result<bool>;
    /// Moves a binding to another app (ADR-0067). `false` if it is not a binding of
    /// `from_application_id` (another request removed or moved it between the read and the move).
    ///
    /// ⚠ **Do not split into remove + add.** Failing in between would leave a moment where the
    /// counterpart belongs to no app, and if it is a login counterpart it is outside the decision
    /// (passes through) meanwhile (a consequence of ADR-0054). Rewrite it in one statement.
    async fn move_binding(
        &self,
        binding_id: Uuid,
        from_application_id: Uuid,
        to_application_id: Uuid,
        moved_at: DateTime<Utc>,
    ) -> Result<bool>;
    /// Lists the bindings of all apps in the tenant (to annotate identity candidates with "which
    /// app now"; avoids calling [`Self::list_bindings`] once per app).
    async fn list_tenant_bindings(&self, tenant_id: TenantId) -> Result<Vec<ApplicationBinding>>;

    /// Whether this **person** has an assignment for this app (decision hot path).
    async fn is_assigned(&self, application_id: Uuid, user_id: Uuid) -> Result<bool>;
    /// Whether this **service account** has an assignment for this app (addressee token issuance;
    /// ADR-0059 decision 6).
    async fn is_service_account_assigned(
        &self,
        application_id: Uuid,
        client_row_id: Uuid,
    ) -> Result<bool>;
    /// Lists the **people** assigned to an app (ascending email). **Reads the user info in one go**
    /// — re-fetching one by one would add round trips proportional to the roster length.
    async fn list_assigned_users(&self, application_id: Uuid) -> Result<Vec<AssignedUser>>;
    /// Lists the assignments of this **account** (person or service account), limited to apps in
    /// the tenant (ADR-0063 / ADR-0065).
    ///
    /// The flip side of [`Self::list_assigned_users`], which reads the roster from the app side. So
    /// the account screen can show "which apps it may use" without calling [`Self::is_assigned`]
    /// once per app.
    async fn list_account_assignments(
        &self,
        tenant_id: TenantId,
        account: AccountRef,
    ) -> Result<Vec<AccountAssignment>>;
    /// Lists the **service accounts** assigned to an app (ascending `client_id`).
    async fn list_assigned_service_accounts(
        &self,
        application_id: Uuid,
    ) -> Result<Vec<AssignedServiceAccount>>;
    /// Returns the number of **people** assignments (when the list screen wants only the head
    /// count; does not read everything).
    ///
    /// ⚠ Service accounts are not counted. This count is used to decide "individual, yet no one can
    /// get in".
    async fn count_assignments(&self, application_id: Uuid) -> Result<i64>;
    /// Adds an assignment (idempotent: an existing assignment keeps its `id` and `assigned_at`).
    async fn assign(&self, assignment: &ApplicationAssignment) -> Result<()>;
    /// Removes an assignment (no error if not assigned).
    async fn unassign(&self, application_id: Uuid, principal: AccountRef) -> Result<()>;
}

/// A `sub` and the facts read about that person (ADR-0057).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectFacts {
    pub sub: Uuid,
    pub facts: ApplicationUserFacts,
}

/// Roster queries (read model; ADR-0057). Kept separate from writes ([`ApplicationRepository`])
/// (the same split as [`AuditLogSink`] and [`AuditLogQuery`]).
///
/// ⚠ **No decisions are made here.** Only facts are returned; "may they use it" is decided by
/// [`Application::roster_state`](crate::domain::application::Application::roster_state). Writing
/// rules on the SQL side too would put rules in two places, and the decision (where codes are
/// issued) and the roster would disagree.
///
/// The order is fixed to ascending `sub` (unique across all tenants, so no duplicates or gaps
/// across pages).
#[async_trait]
pub trait ApplicationUserQuery: Send + Sync {
    /// Candidates for an "everyone" app = members of the tenant.
    async fn list_tenant_members(
        &self,
        tenant_id: TenantId,
        page: PageRequest,
    ) -> Result<Page<SubjectFacts>>;
    /// Candidates for an "individual" app = users with an assignment.
    async fn list_assigned(
        &self,
        tenant_id: TenantId,
        application_id: Uuid,
        page: PageRequest,
    ) -> Result<Page<SubjectFacts>>;
    /// Facts for the given `sub`s. ⚠ **`sub`s not in the requested tenant return no row**
    /// — callers treat them as "gone" (`unknown`).
    async fn facts_for_subs(
        &self,
        tenant_id: TenantId,
        application_id: Uuid,
        subs: &[Uuid],
    ) -> Result<Vec<SubjectFacts>>;
}

/// Persistence of protected resources (addressees that go into `aud`) (ADR-0042).
#[async_trait]
pub trait ProtectedResourceRepository: Send + Sync {
    /// Registers an addressee. If the same tenant already has the same `resource_uri`,
    /// [`DomainError::Conflict`](crate::domain::error::DomainError::Conflict).
    async fn create(&self, resource: &ProtectedResource) -> Result<()>;
    /// Looks up an addressee in the tenant by surrogate key. Rows of other tenants give `None`.
    async fn find_by_id(&self, tenant_id: TenantId, id: Uuid) -> Result<Option<ProtectedResource>>;
    /// Looks up an addressee in the tenant by URI (**exact match**). The only resolution path token
    /// issuance uses.
    async fn find_by_uri(
        &self,
        tenant_id: TenantId,
        uri: &str,
    ) -> Result<Option<ProtectedResource>>;
    /// Lists the addressees in the tenant (ascending `resource_uri`).
    async fn list(&self, tenant_id: TenantId) -> Result<Vec<ProtectedResource>>;
    /// Changes the status. `false` if there is no target.
    async fn set_status(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        status: ResourceStatus,
        updated_at: DateTime<Utc>,
    ) -> Result<bool>;
    /// Deletes an addressee (permission rows go away by CASCADE too). `false` if there is no
    /// target.
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;
}

/// Persistence of refresh tokens (design spec §9.1). The DB stores the SHA-256 hash.
#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    /// Stores a new refresh token (`token.tenant_id` = issuing tenant).
    async fn create(&self, token: &RefreshToken) -> Result<()>;
    /// Finds by hash the row whose issuing tenant matches. Nonexistent or issued by another tenant
    /// gives `None` (prevents tokens issued by tenant A from being used at tenant B; ADR-0009 §6).
    async fn find_by_hash(
        &self,
        tenant_id: TenantId,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>>;
    /// Revokes the token with the given hash (sets `revoked_at`). Returns the number of rows
    /// revoked. No error if nonexistent or already revoked (idempotent; `0` in that case).
    ///
    /// It returns the row count so `/revoke` can tell "whether it was revoked as a refresh_token"
    /// (RFC 7009 §2.1; if it could not be revoked, it must be retried as an access_token).
    async fn revoke(&self, token_hash: &str, revoked_at: DateTime<Utc>) -> Result<u64>;
    /// Searches the chain by `parent_hash` and returns `true` if one exists (revoked or not).
    /// Used in reuse detection to check whether a double issuance from the same parent occurred.
    async fn exists_by_parent_hash(&self, parent_hash: &str) -> Result<bool>;
    /// Revokes in bulk the token family issued from the same authorization grant (SEC8).
    /// `family_hash` is the value of
    /// [`RefreshToken::family_hash`](crate::domain::refresh_token::RefreshToken::family_hash) or
    /// the SHA-256 of the authorization code. Returns the number of rows revoked (recorded in
    /// audit).
    ///
    /// Revoking only the token presented when reuse is detected would leave **descendants rotated
    /// from it still valid** (if the attacker exchanged first, the attacker's side survives). RFC
    /// 6819 §5.2.2.3 / OAuth 2.1 require revoking tokens from the same grant together.
    async fn revoke_family(
        &self,
        tenant_id: TenantId,
        family_hash: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64>;
    /// Revokes all **currently usable** refresh tokens of the given user (unrevoked and
    /// `expires_at > revoked_at`) (invalidating all sessions per user; F5). Returns the number of
    /// rows revoked (shown in audit and on screen; for ADR-0047's reissue, the count is shown to
    /// users and admins as is so that "there were 0 targets" is not mistaken for "it did not
    /// work").
    ///
    /// **Expired rows are not touched.** They can no longer refresh, so dropping them changes
    /// nothing, and counting them would diverge from the number shown by
    /// [`count_active_for_user`](Self::count_active_for_user) (the screen would say "disabled" with
    /// 0 shown). The range uses the same condition as `count_active_for_user`.
    ///
    /// **Not filtered by tenant.** A refresh token is the user's credential, and one person may
    /// authorize apps in several tenants (same reason as `revoke_all_for_session`). To drop per
    /// tenant, use [`revoke_all_for_user_in_tenant`](Self::revoke_all_for_user_in_tenant).
    async fn revoke_all_for_user(&self, user_id: Uuid, revoked_at: DateTime<Utc>) -> Result<u64>;

    /// Returns the number of **currently usable** refresh tokens of the given user (unrevoked and
    /// `expires_at > now`). Used by the admin console to show "whether there is anything to act on"
    /// before a reissue (ADR-0047).
    ///
    /// **Not filtered by tenant.** The counted range matches what
    /// [`revoke_all_for_user`](Self::revoke_all_for_user) drops (so the shown count and the result
    /// of pressing the button refer to the same range). Expired ones are not counted because they
    /// can no longer refresh and are not "live keys".
    async fn count_active_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<u64>;

    /// Revokes the refresh tokens born from **one SSO session** (ADR-0044).
    /// Returns the number of rows revoked (recorded in audit).
    ///
    /// `sid` is the value [`sid_of`](crate::domain::sso_session::sid_of) derives from
    /// `session_hash`; it is carried at issuance and inherited through rotation. So it points only
    /// at tokens from "that login on that device".
    ///
    /// **Not filtered by tenant.** `SsoSession` has no tenant (it is per user), so one session may
    /// authorize clients in several tenants. Adding the tenant as a condition would **miss some** —
    /// and missed tokens would keep refreshing while still pointing at the session that was
    /// supposedly cut. Filtering together with `user_id` is safe enough.
    async fn revoke_all_for_session(
        &self,
        user_id: Uuid,
        sid: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64>;

    /// Revokes in bulk the refresh tokens issued in the given tenant (suspending a guest; MT24).
    ///
    /// Unlike revoking everything per user ([`revoke_all_for_user`](Self::revoke_all_for_user)), it
    /// **does not hinder use in other tenants**. Suspending a guest is a measure for one tenant and
    /// must not drag in the tokens that user uses in their home tenant.
    async fn revoke_all_for_user_in_tenant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<()>;

    /// Revokes the refresh tokens issued to **one client** in the given tenant (unlinking; G10).
    ///
    /// The unit for when a user unlinks one app, so other apps in the same tenant are not dragged
    /// in. Revoking everything per tenant
    /// ([`revoke_all_for_user_in_tenant`](Self::revoke_all_for_user_in_tenant)) is a measure for
    /// admins suspending guests, a different purpose.
    async fn revoke_all_for_user_and_client(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        client_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<()>;
}

/// Persistence of scopes a user consented to for a client (F3: Consent).
#[async_trait]
pub trait ClientConsentRepository: Send + Sync {
    /// Returns the consent record for `(user_id, tenant_id, client_id)`. `None` if it does not
    /// exist.
    async fn find(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<Option<ClientConsent>>;
    /// UPSERTs a consent record (overwrites if the scope changed).
    async fn upsert(&self, consent: &ClientConsent) -> Result<()>;
    /// Revokes consent (idempotently does nothing if it does not exist).
    async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, client_id: &str) -> Result<()>;
    /// Returns all consent records of the user in the given tenant (for the consent revocation
    /// screen and admin).
    async fn list_for_user(&self, tenant_id: TenantId, user_id: Uuid)
        -> Result<Vec<ClientConsent>>;
}

/// Persistent queue of back-channel logout send requests (G5).
///
/// Logout handling (synchronous) only enqueues requests with [`enqueue`](Self::enqueue); a worker
/// takes them out with [`claim_due`](Self::claim_due) and sends them. A split that satisfies both
/// "HTTP send success or failure never delays the logout response" and "unsent requests are not
/// lost even if the process dies".
#[async_trait]
pub trait BackchannelLogoutDeliveryRepository: Send + Sync {
    /// Enqueues send requests in bulk (an empty slice does nothing).
    async fn enqueue(&self, deliveries: &[BackchannelLogoutDelivery]) -> Result<()>;

    /// Takes out requests due to be sent, **advancing the attempt count and pushing back the next
    /// time** (an atomic claim).
    ///
    /// Targets are rows that are "unsent", "`next_attempt_at <= now`", and
    /// "`attempts < max_attempts`". Splitting take-out and update would send the same row twice
    /// (duplicate delivery from the RP's view), so the implementation does it atomically. Returned
    /// rows reflect the updated state (`attempts` already incremented).
    async fn claim_due(
        &self,
        now: DateTime<Utc>,
        max_attempts: i32,
        limit: u32,
    ) -> Result<Vec<BackchannelLogoutDelivery>>;

    /// Records a successful send (sets `delivered_at`).
    async fn mark_delivered(&self, id: Uuid, delivered_at: DateTime<Utc>) -> Result<()>;

    /// Records a failed send (next attempt time and the latest failure reason). The attempt count
    /// was already incremented in [`claim_due`](Self::claim_due), so it is not advanced here.
    async fn mark_failed(
        &self,
        id: Uuid,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> Result<()>;

    /// Deletes old settled rows (sent successfully, or reached the attempt limit) and returns the
    /// count.
    async fn purge_settled(&self, older_than: DateTime<Utc>, max_attempts: i32) -> Result<u64>;
}

/// jti revocation list of access tokens (F5: token management).
/// JWTs are self-contained, so managing jti in this table achieves immediate revocation.
#[async_trait]
pub trait RevokedAccessTokenRepository: Send + Sync {
    /// Adds a jti to the revocation list (idempotent).
    async fn revoke(&self, token: &RevokedAccessToken) -> Result<()>;
    /// Whether the given jti is in the revocation list.
    async fn is_revoked(&self, jti: &str) -> Result<bool>;
}

/// Users' TOTP secrets (MFA self-enrollment).
///
/// `confirmed_at IS NULL` = provisionally registered (QR confirmation not done).
/// `confirmed_at IS NOT NULL` = enabled (TOTP verification required at login).
#[async_trait]
pub trait TotpSecretRepository: Send + Sync {
    /// Stores a TOTP secret. Overwrites if one exists (UPSERT).
    async fn upsert(&self, secret: &TotpSecret) -> Result<()>;
    /// Returns the user's TOTP secret (whether provisional or enabled).
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TotpSecret>>;
    /// After verifying the confirmation code, sets `confirmed_at` to enable it.
    async fn confirm(&self, user_id: Uuid, confirmed_at: DateTime<Utc>) -> Result<()>;
    /// Deletes the user's TOTP secret (idempotent: no error if it does not exist).
    async fn delete(&self, user_id: Uuid) -> Result<()>;

    /// Records the accepted TOTP time-step. Writes **only when newer than the recorded step**,
    /// returning `true` if written, or `false` if the same or a newer step is already recorded
    /// (replay detection; RFC 6238 §5.2). The check and write happen atomically in one statement,
    /// letting only one of two requests racing with the same code through.
    ///
    /// The default implementation always returns `true` (records nothing, passes through). Only the
    /// real DB implementation needs TOTP replay prevention; test fakes need not have this guard.
    async fn record_totp_step_if_newer(
        &self,
        _user_id: Uuid,
        _step: i64,
        _at: DateTime<Utc>,
    ) -> Result<bool> {
        Ok(true)
    }
}

/// Persistence of external IdP settings (AP10; spec §13). The tenant boundary is enforced by
/// `tenant_id`.
#[async_trait]
pub trait ExternalIdentityProviderRepository: Send + Sync {
    async fn create(&self, provider: &ExternalIdentityProvider) -> Result<()>;
    /// Returns all providers of the tenant in ascending `provider_code` (for the admin screen).
    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<ExternalIdentityProvider>>;
    /// Returns only **enabled** providers of the tenant (for the login screen buttons).
    async fn list_enabled_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ExternalIdentityProvider>>;
    /// Resolves `provider_code` within the tenant boundary (bringing another tenant's code does not
    /// resolve).
    async fn find_by_code(
        &self,
        tenant_id: TenantId,
        provider_code: &str,
    ) -> Result<Option<ExternalIdentityProvider>>;
    /// Resolves by id within the tenant boundary.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<ExternalIdentityProvider>>;
    /// Updates an existing provider. `true` if updated, `false` if there is no target.
    async fn update(&self, provider: &ExternalIdentityProvider) -> Result<bool>;
    /// Deletes within the tenant boundary. `true` if deleted.
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool>;
}

/// Persistence of the mapping between identities at external IdPs and assay users (AP10; spec
/// §13.2).
///
/// The lookup key is `(provider_id, external_subject)`, the only basis for linking. No `tenant_id`
/// is taken because the provider itself belongs to a tenant (= the boundary is decided via the
/// provider).
#[async_trait]
pub trait ExternalIdentityRepository: Send + Sync {
    /// Creates a link. Linking the same external account twice gives `Conflict`.
    async fn create(&self, identity: &ExternalIdentity) -> Result<()>;
    /// Looks up a link from verified `iss` + `sub`.
    ///
    /// The condition includes `external_issuer`, not just `provider_id`. Admins can change a
    /// provider's `issuer` later, so looking up by `provider_id` + `sub` alone would let **an
    /// account with the same `sub` at a different issuer pass as the previously linked user**. It
    /// is correct that it cannot be found unless it matches the issuer at link time (= treated as
    /// unlinked).
    async fn find_by_subject(
        &self,
        provider_id: Uuid,
        external_issuer: &str,
        external_subject: &str,
    ) -> Result<Option<ExternalIdentity>>;
    /// Returns all links of the user (for self-service display and unlinking).
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>>;
    /// Records the time of use.
    async fn touch_last_used(&self, id: Uuid, at: DateTime<Utc>) -> Result<()>;
    /// Removes a link (including the owner check). `true` if deleted.
    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<bool>;
}

/// Persistence of the progress state from the redirect to an external IdP until the callback
/// (AP10).
///
/// `state` is single-use. Consumption is an atomic claim, "whoever deletes it wins" (the same
/// approach as `saml_sso_requests`; reading then deleting would let two simultaneous presentations
/// of the same `state` both pass).
#[async_trait]
pub trait ExternalLoginRequestRepository: Send + Sync {
    async fn create(&self, request: &ExternalLoginRequest) -> Result<()>;
    /// Looks up by the hash of `state` (with the tenant boundary).
    async fn find_by_state(
        &self,
        tenant_id: TenantId,
        state_hash: &str,
    ) -> Result<Option<ExternalLoginRequest>>;
    /// Deletes the progress state. **`true` only if it deleted** (doubles as the single-use claim).
    async fn consume(&self, id: Uuid) -> Result<bool>;
    /// Deletes expired progress states in bulk and returns the count (GC).
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// Unified registry of authenticators (AP9; spec §5).
///
/// A port that answers in one place "which authenticators this user can use", regardless of type
/// (TOTP, WebAuthn, recovery code, email OTP). Type-specific secrets stay in the existing tables
/// (expand phase). The table has no tenant column, so no `tenant_id` is taken (see the module
/// comment; the use case enforces the boundary by matching `users.tenant_id`).
///
/// Read and consume methods have default implementations ("not found"). This keeps test fakes
/// short, and **every default falls on the fail-closed side** (not found = authentication with that
/// authenticator does not pass). Only the write `create` has no default (a silent success would
/// lose the registration). The production sqlx implementation overrides every method.
#[async_trait]
pub trait UserAuthenticatorRepository: Send + Sync {
    /// Registers an authenticator (`pending` or `active`).
    async fn create(&self, authenticator: &UserAuthenticator) -> Result<()>;
    /// Looks up by internal ID.
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<UserAuthenticator>> {
        Ok(None)
    }
    /// Returns all authenticators of the user, newest first (including revoked; for admin and
    /// display).
    async fn list_for_user(&self, _user_id: Uuid) -> Result<Vec<UserAuthenticator>> {
        Ok(Vec::new())
    }
    /// Returns the user's **usable** authenticators (`active` and unexpired), filtered by type
    /// (login hot path). If `authenticator_type` is `None`, all types.
    async fn list_usable_for_user(
        &self,
        _user_id: Uuid,
        _authenticator_type: Option<AuthenticatorType>,
        _now: DateTime<Utc>,
    ) -> Result<Vec<UserAuthenticator>> {
        Ok(Vec::new())
    }
    /// Updates the status (the Application layer checks whether the transition is allowed with
    /// [`AuthenticatorStatus::can_transition_to`] before calling).
    /// `false` if there is no target.
    async fn update_status(
        &self,
        _id: Uuid,
        _user_id: Uuid,
        _status: AuthenticatorStatus,
        _at: DateTime<Utc>,
    ) -> Result<bool> {
        Ok(false)
    }
    /// Updates the display name. `false` if there is no target.
    async fn update_label(&self, _id: Uuid, _user_id: Uuid, _label: &str) -> Result<bool> {
        Ok(false)
    }
    /// Records the time of use (on successful authentication).
    async fn touch_last_used(&self, _id: Uuid, _at: DateTime<Utc>) -> Result<()> {
        Ok(())
    }
    /// **Atomically consumes** a single-use authenticator (recovery code, OTP).
    ///
    /// Sets only `active`, unexpired rows to `revoked` and returns them. If already used, expired,
    /// or nonexistent, `None`. With "look up, check the state, then update", the same code
    /// presented twice at once would pass both times (done atomically for the same reason as
    /// authorization codes).
    async fn consume_single_use(
        &self,
        _user_id: Uuid,
        _authenticator_type: AuthenticatorType,
        _secret_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<UserAuthenticator>> {
        Ok(None)
    }
    /// Revokes in bulk the unrevoked rows of the given type and returns the count (invalidates the
    /// old batch when recovery codes are reissued).
    async fn revoke_all_of_type(
        &self,
        _user_id: Uuid,
        _authenticator_type: AuthenticatorType,
        _at: DateTime<Utc>,
    ) -> Result<u64> {
        Ok(0)
    }
    /// Revokes only rows with an expiry (= issued one-time codes) and returns the count (AP13).
    ///
    /// It is separate from [`Self::revoke_all_of_type`] because the same type mixes **registrations
    /// without a lifetime** (SMS OTP registered phone numbers) and **codes with a lifetime**. Using
    /// `revoke_all_of_type` merely to revoke old codes before issuing a new one would delete the
    /// registration itself.
    async fn revoke_issued_codes_of_type(
        &self,
        _user_id: Uuid,
        _authenticator_type: AuthenticatorType,
        _at: DateTime<Utc>,
    ) -> Result<u64> {
        Ok(0)
    }
    /// Marks a `pending` row **confirmed** by matching it against the presented secret (its
    /// SHA-256) (AP13).
    ///
    /// On success sets `status = active` and clears the confirmation code and expiry. The expiry is
    /// cleared because rows with an expiry are deletion targets of GC ([`ExpiringRecordStore`]);
    /// keeping it would delete the confirmed registration. Update and re-read are one statement so
    /// the same code presented at once is not confirmed twice.
    async fn confirm_pending(
        &self,
        _user_id: Uuid,
        _authenticator_type: AuthenticatorType,
        _secret_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<Option<UserAuthenticator>> {
        Ok(None)
    }
    /// Deletes expired single-use rows and returns the count (GC).
    async fn delete_expired(&self, _now: DateTime<Utc>) -> Result<u64> {
        Ok(0)
    }
}

/// Users' WebAuthn (FIDO2 passkey) credentials.
///
/// One user can register several devices (user × device, 1:N). At authentication the credential is
/// identified by `credential_id`, and `passkey_json` is passed to `webauthn-rs`.
#[async_trait]
pub trait WebAuthnCredentialRepository: Send + Sync {
    /// Registers a new credential. A duplicate `credential_id` gives `Conflict`.
    async fn create(&self, cred: &WebAuthnCredential) -> Result<()>;
    /// Finds by internal UUID.
    async fn find_by_id(&self, id: Uuid) -> Result<Option<WebAuthnCredential>>;
    /// Finds by WebAuthn credential ID (base64url) (for reverse lookup from authentication
    /// responses).
    async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebAuthnCredential>>;
    /// Returns all credentials of the user in ascending creation order.
    async fn list_by_user_id(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>>;
    /// Updates sign_count and last_used_at, and also stores passkey_json (the whole, as updated by
    /// webauthn-rs).
    async fn update_passkey(
        &self,
        id: Uuid,
        passkey_json: &str,
        last_used_at: DateTime<Utc>,
    ) -> Result<()>;
    /// Deletes a credential, also checking the owner (`user_id` match). Nonexistence is
    /// idempotently ignored.
    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<()>;
    /// Deletes all credentials of the user and returns the count (MFA removal by an admin; MT21). A
    /// recovery measure for lost devices, so they are deleted together, not one by one (leftovers
    /// would mean failed recovery).
    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<u64>;
}

/// Persistence of system settings (assay-wide settings managed by root/idp.system.admin; ADR-0009
/// §5, MT14).
///
/// No tenant column; applied uniformly to all of assay (only root can manage it; the check is done
/// by the Presentation layer's `RequirePerms<IdpSystemAdmin>`). Encrypting / decrypting secrets is
/// the Application layer's job; this trait passes stored-form strings (including ciphertext)
/// through.
#[async_trait]
pub trait SystemSettingsRepository: Send + Sync {
    /// Returns all system settings (values in stored form; `is_secret` ones are ciphertext).
    async fn load_all(&self) -> Result<Vec<SystemSetting>>;
    /// UPSERTs a setting (per key; `is_secret` is stored too).
    async fn upsert(&self, setting: &SystemSetting) -> Result<()>;
}

/// Persistence of tenant settings (ADR-0058).
///
/// ⚠ **A tenant having no row means "follow the global value".** No copies of defaults are made —
/// do not add to this trait an entry point that "distributes defaults to every tenant". Encrypting
/// / decrypting secrets is the Application layer's job; stored-form strings (including ciphertext)
/// are passed through (same as `SystemSettingsRepository`).
#[async_trait]
pub trait TenantSettingsRepository: Send + Sync {
    /// Returns all overrides of the tenant (values in stored form). Empty if there are no rows.
    async fn load_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantSetting>>;
    /// UPSERTs an override (per `(tenant_id, key)`; `is_secret` is stored too).
    async fn upsert(&self, setting: &TenantSetting) -> Result<()>;
    /// Deletes an override (= back to following the global value). Nonexistence is idempotently
    /// ignored.
    async fn delete(&self, tenant_id: TenantId, key: &str) -> Result<()>;
    /// ⚠ **The only entry point that reads across tenants.** Used only by the global settings
    /// screen (`idp.system.admin`) to show "tenants deviating from default" and "the number of
    /// tenants following" (ADR-0058 §6). Secrets and empty rows are not included.
    async fn list_overrides_across_tenants(&self) -> Result<TenantOverridesAcrossTenants>;
}

/// Temporary passkey challenge table (WebAuthn begin → complete intermediate state).
///
/// The application layer deletes records past `expires_at`.
#[async_trait]
pub trait PasskeyChallengeRepository: Send + Sync {
    /// Stores a challenge.
    async fn create(&self, challenge: &PasskeyChallenge) -> Result<()>;
    /// Gets a challenge by ID. Nonexistent gives `None`.
    async fn find_by_id(&self, id: Uuid) -> Result<Option<PasskeyChallenge>>;
    /// Consumes (deletes) a challenge (called after use in the complete step). **`true` if it
    /// deleted.** When two arrive at once with the same challenge, only one gets `true` (task #586;
    /// the crux of single use).
    async fn delete(&self, id: Uuid) -> Result<bool>;
    /// Deletes expired challenges in bulk and returns the count (called from G2's bulk GC).
    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// Port for tables that can clean up their own expired rows (G2).
///
/// Tables of progress states and single-use tokens "lose meaning once expired", but deleting them
/// belongs to no use case. Growing a separate background loop per table would create missed
/// cleanups (= tables that grow forever) every time one is added, so **being cleanable is declared
/// through one port** and bundled into one task at startup.
///
/// For tables on the matching hot path, such as `revoked_access_tokens`, bloat turns directly into
/// latency.
#[async_trait]
pub trait ExpiringRecordStore: Send + Sync {
    /// Identifier of the cleanup target (the table name printed in logs).
    fn table_name(&self) -> &'static str;
    /// Deletes rows expired as of `now` and returns the count.
    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

/// Users' authenticator app keys (task #892; ADR-0077) and the sign-in states approved with those
/// keys.
#[async_trait]
pub trait ApproverKeyRepository: Send + Sync {
    /// Registers one. If the same `key_id` already exists, `Conflict`.
    async fn insert(&self, key: &crate::domain::app_approver::ApproverKey) -> Result<()>;
    /// Looks up by the `key_id` the app presents.
    async fn find_by_key_id(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::domain::app_approver::ApproverKey>>;
    /// Returns the user's keys, newest registration first.
    async fn list_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<crate::domain::app_approver::ApproverKey>>;
    /// Deletes one of the user's keys and returns the deleted row (`None` if it is someone else's
    /// key).
    async fn delete(
        &self,
        user_id: Uuid,
        id: Uuid,
    ) -> Result<Option<crate::domain::app_approver::ApproverKey>>;
    /// Records that it was used for approval.
    async fn touch(&self, id: Uuid, used_at: DateTime<Utc>) -> Result<()>;
    /// Records that a sign-in state was approved with this key (creates the context row if absent).
    async fn link_session(&self, session_hash: &str, id: Uuid) -> Result<()>;
    /// Sign-in states approved with this key (their SHA-256).
    async fn approved_sessions(&self, id: Uuid) -> Result<Vec<String>>;
}

/// Intake of key registration (10 minutes). Each stage transition happens once via "write only when
/// in the previous stage".
#[async_trait]
pub trait ApproverEnrollmentRepository: Send + Sync {
    async fn insert(
        &self,
        enrollment: &crate::domain::app_approver::ApproverEnrollment,
    ) -> Result<()>;
    async fn find(
        &self,
        tenant_id: Uuid,
        id: &str,
    ) -> Result<Option<crate::domain::app_approver::ApproverEnrollment>>;
    /// Rewrites the stage. Writes only when the current stage is `expected` (the name of `stage`),
    /// returning `true` if written.
    async fn advance(
        &self,
        enrollment: &crate::domain::app_approver::ApproverEnrollment,
        expected: &str,
    ) -> Result<bool>;
    /// Deletes the intake (enabled or cancelled). `true` if deleted.
    async fn delete(&self, id: &str) -> Result<bool>;
}

/// A "continue with the app" request (5 minutes). Each state transition happens once via "write
/// only when in the previous state".
#[async_trait]
pub trait ApprovalRequestRepository: Send + Sync {
    async fn insert(&self, request: &crate::domain::app_approver::ApprovalRequest) -> Result<()>;
    async fn find(
        &self,
        tenant_id: Uuid,
        id: &str,
    ) -> Result<Option<crate::domain::app_approver::ApprovalRequest>>;
    /// Writes the approval (only when `pending`). `true` if written.
    async fn approve(
        &self,
        id: &str,
        approver_key: Uuid,
        user_id: Uuid,
        code_hash: &str,
        code_expires_at: DateTime<Utc>,
    ) -> Result<bool>;
    /// Moves the state from `from` to `to` (only when `from`). `true` if written.
    async fn transition(
        &self,
        id: &str,
        from: crate::domain::app_approver::ApprovalState,
        to: crate::domain::app_approver::ApprovalState,
    ) -> Result<bool>;
}
