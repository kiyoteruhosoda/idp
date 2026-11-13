//! One-time account setup links (ADR-0062).
//!
//! Encloses here the **issuance** and **consumption** of the "link that opens only once" handed out right after
//! an admin creates a user or reissues a password. It is handed over by the admin (sharing the link shown on screen);
//! email is not assumed: even where sending is not set up, it must be possible to hand it over on the spot.
//!
//! Two things can be done at the link. **Either one completes it**, and the link dies at that moment.
//!
//! 1. **Register a passkey** (primary). From then on the user can sign in without knowing a password
//!    (the passkey login path does not look at `must_change_password`).
//! 2. **Set a password**. In substance the same path as the forgotten-password reset
//!    ([`crate::application::password_reset::PasswordResetService::reset_password`]);
//!    the token table is the same, so it passes as is.
//!
//! ⚠ **Merely opening it does not consume it.** A link pasted into chat gets fetched by a preview bot
//! before the recipient (a one-time link was eaten this way before). Only operations that actually set
//! credentials consume it; [`AccountSetupService::describe`] only reads.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::passkey_registration::{
    PasskeyRegistrationError, PasskeyRegistrationService,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::password_reset::{PasswordResetToken, ResetPurpose};
use crate::domain::repositories::{PasswordResetTokenRepository, UserRepository};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// Byte length of the link token (about 43 chars in base64url; same as the reset link).
const SETUP_TOKEN_BYTES: usize = 32;

/// An issued link. `token` is plain text and returned **only this once** (only the hash is stored).
#[derive(Debug, Clone)]
pub struct SetupLink {
    pub token: String,
    /// Absolute URL handed to the user. **The link's shape is decided only here** (screens and machines hand out the same value).
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

/// Content shown by the screen that opened the link (does not consume).
#[derive(Debug, Clone)]
pub struct SetupLinkView {
    pub user_id: Uuid,
    /// Shows on screen whose link it is. Visible only to the link holder (the token is the key).
    pub email: String,
    pub purpose: ResetPurpose,
    pub expires_at: DateTime<Utc>,
}

impl SetupLinkView {
    /// Whether a passkey may be registered on this screen (decided by the purpose).
    pub fn allows_passkey_registration(&self) -> bool {
        self.purpose.allows_passkey_registration()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountSetupError {
    /// Nonexistent, expired, used, wrong tenant, or the user is not ACTIVE. **Not distinguished**
    /// (telling which would give hints to whoever picked up the link).
    #[error("invalid or expired setup link")]
    InvalidOrExpired,
    /// An operation not allowed for a link of this purpose (e.g. trying to register a passkey with a `reset` link).
    #[error("not allowed for this link")]
    NotAllowed,
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<PasskeyRegistrationError> for AccountSetupError {
    fn from(e: PasskeyRegistrationError) -> Self {
        match e {
            PasskeyRegistrationError::ChallengeNotFound => AccountSetupError::InvalidOrExpired,
            PasskeyRegistrationError::InvalidCredential(m)
            | PasskeyRegistrationError::Internal(m) => AccountSetupError::InvalidCredential(m),
            PasskeyRegistrationError::DuplicateCredential => {
                AccountSetupError::InvalidCredential("duplicate credential".to_string())
            }
            PasskeyRegistrationError::SessionExpired | PasskeyRegistrationError::NotFound => {
                AccountSetupError::InvalidOrExpired
            }
        }
    }
}

/// The side that **issues** links (called as part of an admin operation).
///
/// Issuing needs only the token table and the lifetime; no passkeys and no user reads.
/// ⚠ **Separate types from the consuming side** so that user creation, which only issues, does not drag in the whole WebAuthn set.
pub struct AccountSetupLinkIssuer {
    tokens: Arc<dyn PasswordResetTokenRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    clock: Arc<dyn Clock>,
    /// Public base URL the link is built on (web screens; no trailing slash).
    console_base_url: String,
}

/// The side that **uses** links (called from the screen the user opened).
/// All this use case needs is "add one passkey to a user whose identity has been confirmed".
///
/// Holding the whole WebAuthn set (`PasskeyRegistrationService`) would make even tests that only read the link
/// require fakes for authenticators, challenges and SSO sessions. Only what is needed is taken
/// through a trait (DIP in CLAUDE.md).
#[async_trait::async_trait]
pub trait PasskeyEnrollment: Send + Sync {
    async fn begin(
        &self,
        user_id: Uuid,
        user_name: &str,
    ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError>;
    /// Returns the id of the registered passkey row (to undo it with [`Self::discard`]).
    async fn complete(
        &self,
        user_id: Uuid,
        challenge_id: Uuid,
        name: &str,
        credential: serde_json::Value,
    ) -> Result<Uuid, PasskeyRegistrationError>;
    /// Undoes a registered passkey (when losing the race to consume the link; task #586).
    async fn discard(
        &self,
        user_id: Uuid,
        credential_row_id: Uuid,
    ) -> Result<(), PasskeyRegistrationError>;
}

#[async_trait::async_trait]
impl PasskeyEnrollment for PasskeyRegistrationService {
    async fn begin(
        &self,
        user_id: Uuid,
        user_name: &str,
    ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError> {
        self.begin_for_user(user_id, user_name).await
    }

    async fn complete(
        &self,
        user_id: Uuid,
        challenge_id: Uuid,
        name: &str,
        credential: serde_json::Value,
    ) -> Result<Uuid, PasskeyRegistrationError> {
        self.complete_for_user(user_id, challenge_id, name, credential)
            .await
    }

    async fn discard(
        &self,
        user_id: Uuid,
        credential_row_id: Uuid,
    ) -> Result<(), PasskeyRegistrationError> {
        self.discard_for_user(user_id, credential_row_id).await
    }
}

pub struct AccountSetupService {
    users: Arc<dyn UserRepository>,
    tokens: Arc<dyn PasswordResetTokenRepository>,
    passkeys: Arc<dyn PasskeyEnrollment>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountSetupLinkIssuer {
    pub fn new(
        tokens: Arc<dyn PasswordResetTokenRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        clock: Arc<dyn Clock>,
        console_base_url: String,
    ) -> Self {
        Self {
            tokens,
            settings,
            clock,
            console_base_url: console_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Issues a setup link (called as part of an admin operation).
    ///
    /// **The user's unused links are revoked on every issuance.** With 2 live links at once
    /// it is unclear which was handed over, and there is no way to stop a mis-delivery (same rule as reset).
    pub async fn issue(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> Result<SetupLink, AccountSetupError> {
        let now = self.clock.now();
        let ttl = self
            .settings
            .account_setup_ttl(tenant_id)
            .await
            .map_err(|e| AccountSetupError::Internal(e.to_string()))?;

        self.tokens
            .invalidate_all_for_user(user_id, now)
            .await
            .map_err(|e| AccountSetupError::Internal(e.to_string()))?;

        let token = crypto::random_token(SETUP_TOKEN_BYTES);
        let expires_at = now + ttl;
        let record = PasswordResetToken {
            token_hash: crypto::sha256_hex(&token),
            user_id,
            purpose: ResetPurpose::Setup,
            expires_at,
            used_at: None,
            created_at: now,
        };
        self.tokens
            .create(&record)
            .await
            .map_err(|e| AccountSetupError::Internal(e.to_string()))?;

        let url = format!(
            "{}/{}/account-setup?token={}",
            self.console_base_url, tenant_id, token
        );
        Ok(SetupLink {
            token,
            url,
            expires_at,
        })
    }
}

impl AccountSetupService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        tokens: Arc<dyn PasswordResetTokenRepository>,
        passkeys: Arc<dyn PasskeyEnrollment>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            tokens,
            passkeys,
            audit,
            clock,
        }
    }

    /// Reads the link's content (**does not consume**).
    pub async fn describe(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<SetupLinkView, AccountSetupError> {
        let (record, user) = self.resolve(tenant, token).await?;
        Ok(SetupLinkView {
            user_id: user.id,
            email: user.email,
            purpose: record.purpose,
            expires_at: record.expires_at,
        })
    }

    /// Starts passkey registration. ⚠ **The token is not consumed here yet** (so someone whose registration did not
    /// finish is not locked out along with the link; consumption happens in [`Self::complete_passkey`]).
    pub async fn begin_passkey(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<(Uuid, serde_json::Value), AccountSetupError> {
        let (record, user) = self.resolve(tenant, token).await?;
        if !record.purpose.allows_passkey_registration() {
            return Err(AccountSetupError::NotAllowed);
        }
        // The name shown to the authenticator is a value the user recognizes as their own account (email address).
        let options = self.passkeys.begin(user.id, &user.email).await?;
        Ok(options)
    }

    /// Completes passkey registration. On success the link is consumed (one link registers only one).
    pub async fn complete_passkey(
        &self,
        tenant: TenantContext,
        token: &str,
        challenge_id: Uuid,
        name: &str,
        credential: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<(), AccountSetupError> {
        let (record, user) = self.resolve(tenant, token).await?;
        if !record.purpose.allows_passkey_registration() {
            return Err(AccountSetupError::NotAllowed);
        }

        let registered = self
            .passkeys
            .complete(user.id, challenge_id, name, credential)
            .await?;

        // The user has set credentials, so remove the provisional state (ADR-0064). ⚠ Do it **before consuming the link**:
        // consuming without being able to remove it leaves a person with a passkey who cannot get in, and no link.
        if user.pending_setup {
            self.users
                .finish_setup(user.id)
                .await
                .map_err(|e| AccountSetupError::Internal(e.to_string()))?;
        }

        // ⚠ **Consume only after registration succeeds.** Consuming first would leave someone refused on the
        // authenticator side without a link and stuck (the only way out would be the admin reissuing it).
        let now = self.clock.now();
        match self.tokens.consume(&crypto::sha256_hex(token), now).await {
            Ok(Some(_)) => {}
            // ⚠ **Another request registering with the same link concurrently consumed it first** (task #586). One
            // link registers only one, so undo the registration made here and refuse.
            Ok(None) => {
                if let Err(e) = self.passkeys.discard(user.id, registered).await {
                    tracing::error!(
                        error = %e,
                        "failed to discard a passkey registered by a setup link that was already used"
                    );
                }
                return Err(AccountSetupError::InvalidOrExpired);
            }
            // Registration is done. Even if consumption fails, the link expires anyway, so do not fail here.
            Err(e) => {
                tracing::warn!(error = %e, "failed to consume the setup link after registering a passkey");
            }
        }

        self.audit
            .record(
                AuditEventType::AccountSetupCompleted,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some("method=passkey"),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Resolves "an unused, unexpired, tenant-matching, ACTIVE user" from the token.
    ///
    /// Provisional users (ADR-0064) also pass: this link exists to finish provisional registration.
    ///
    /// ⚠ Refusal reasons are not distinguished (see the comment on [`AccountSetupError::InvalidOrExpired`]).
    async fn resolve(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<(PasswordResetToken, User), AccountSetupError> {
        if token.is_empty() {
            return Err(AccountSetupError::InvalidOrExpired);
        }
        let now = self.clock.now();
        let record = self
            .tokens
            .find_active(&crypto::sha256_hex(token), now)
            .await
            .map_err(|e| AccountSetupError::Internal(e.to_string()))?
            .ok_or(AccountSetupError::InvalidOrExpired)?;

        // The link's route (tenant) must match the home tenant. Do not let it be carried to another tenant's screen.
        match self.users.find_by_id(record.user_id).await {
            Ok(Some(user)) if user.can_finish_setup() && user.tenant_id == tenant.tenant_id() => {
                Ok((record, user))
            }
            Ok(_) => Err(AccountSetupError::InvalidOrExpired),
            Err(e) => Err(AccountSetupError::Internal(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{link_issuer, FakeSetupTokens};
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use chrono::TimeZone;
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 21, 9, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[derive(Default)]
    struct SilentSink;
    #[async_trait::async_trait]
    impl AuditLogSink for SilentSink {
        async fn record(&self, _event: &AuditEvent) -> DomainResult<()> {
            Ok(())
        }
    }

    /// Only counts how many times it was called (no real WebAuthn needed; it is cut off by a trait).
    #[derive(Default)]
    struct FakePasskeys {
        completed: Mutex<Vec<Uuid>>,
        discarded: Mutex<Vec<Uuid>>,
        /// Simulates another request using up the same link during registration (task #586).
        race_with: Mutex<Option<Arc<FakeSetupTokens>>>,
    }
    #[async_trait::async_trait]
    impl PasskeyEnrollment for FakePasskeys {
        async fn begin(
            &self,
            _user_id: Uuid,
            _user_name: &str,
        ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError> {
            Ok((Uuid::new_v4(), serde_json::json!({ "publicKey": {} })))
        }
        async fn complete(
            &self,
            user_id: Uuid,
            _challenge_id: Uuid,
            _name: &str,
            _credential: serde_json::Value,
        ) -> Result<Uuid, PasskeyRegistrationError> {
            self.completed.lock().unwrap().push(user_id);
            if let Some(tokens) = self.race_with.lock().unwrap().as_ref() {
                for row in tokens.rows.lock().unwrap().iter_mut() {
                    row.used_at = Some(now());
                }
            }
            Ok(Uuid::from_u128(7))
        }
        async fn discard(
            &self,
            _user_id: Uuid,
            credential_row_id: Uuid,
        ) -> Result<(), PasskeyRegistrationError> {
            self.discarded.lock().unwrap().push(credential_row_id);
            Ok(())
        }
    }

    struct FakeUsers(Mutex<Vec<User>>);
    #[async_trait::async_trait]
    impl UserRepository for FakeUsers {
        async fn create(&self, _user: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self.0.lock().unwrap().iter().find(|u| u.id == id).cloned())
        }
        async fn find_by_sub(&self, _sub: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(
            &self,
            _tenant_id: TenantId,
            _email: &str,
        ) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(
            &self,
            _tenant_id: TenantId,
            _username: &str,
        ) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: DateTime<Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
        // A route this test never reaches (rewriting credentials is outside the link's path).
        async fn update_login_state(
            &self,
            _id: Uuid,
            _failed_login_count: i32,
            _locked_until: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_password(
            &self,
            _id: Uuid,
            _expected_current_hash: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected_current_hash: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _status: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn finish_setup(&self, id: Uuid) -> DomainResult<()> {
            for user in self.0.lock().unwrap().iter_mut().filter(|u| u.id == id) {
                user.pending_setup = false;
            }
            Ok(())
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

    fn user(tenant: TenantId) -> User {
        User {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            sub: Uuid::new_v4(),
            email: "newbie@example.com".to_string(),
            email_verified: false,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: "nobody-knows".to_string(),
            must_change_password: true,
            password_changed_at: None,
            status: UserStatus::Active,
            // The shape right after an admin created it (ADR-0064).
            pending_setup: true,
            failed_login_count: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    struct Fixture {
        service: AccountSetupService,
        users: Arc<FakeUsers>,
        tokens: Arc<FakeSetupTokens>,
        passkeys: Arc<FakePasskeys>,
        tenant: TenantId,
        user_id: Uuid,
    }

    async fn fixture() -> (Fixture, String) {
        let tenant: TenantId = Uuid::now_v7().into();
        let person = user(tenant);
        let user_id = person.id;
        let tokens = Arc::new(FakeSetupTokens::default());
        let passkeys = Arc::new(FakePasskeys::default());
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(now()));
        let link = link_issuer(tokens.clone(), clock.clone())
            .issue(tenant, user_id)
            .await
            .expect("link issued");
        let users = Arc::new(FakeUsers(Mutex::new(vec![person])));
        let service = AccountSetupService::new(
            users.clone(),
            tokens.clone(),
            passkeys.clone(),
            Arc::new(AuditService::new(Arc::new(SilentSink), clock.clone())),
            clock,
        );
        (
            Fixture {
                service,
                users,
                tokens,
                passkeys,
                tenant,
                user_id,
            },
            link.token,
        )
    }

    /// Opening the link shows whose it is and what can be done.
    #[tokio::test]
    async fn a_setup_link_tells_who_it_belongs_to() {
        let (f, token) = fixture().await;
        let view = f
            .service
            .describe(TenantContext::new(f.tenant), &token)
            .await
            .expect("described");
        assert_eq!(view.email, "newbie@example.com");
        assert!(view.allows_passkey_registration());
    }

    /// ⚠ **Merely opening it does not consume it.** Even if a chat preview bot fetches it first, the link is
    /// alive when the user opens it (one was eaten before).
    #[tokio::test]
    async fn opening_the_link_does_not_consume_it() {
        let (f, token) = fixture().await;
        for _ in 0..3 {
            f.service
                .describe(TenantContext::new(f.tenant), &token)
                .await
                .expect("still open");
        }
        assert!(f.tokens.rows.lock().unwrap()[0].used_at.is_none());
    }

    /// Once a passkey is registered the link dies (one link registers only one).
    #[tokio::test]
    async fn finishing_a_passkey_consumes_the_link() {
        let (f, token) = fixture().await;
        let ctx = RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        };
        f.service
            .complete_passkey(
                TenantContext::new(f.tenant),
                &token,
                Uuid::new_v4(),
                "This device",
                serde_json::json!({}),
                &ctx,
            )
            .await
            .expect("registered");
        assert_eq!(f.passkeys.completed.lock().unwrap().as_slice(), [f.user_id]);
        // ADR-0064: the user set credentials, so the provisional state is removed.
        assert!(
            !f.users.0.lock().unwrap()[0].pending_setup,
            "setup must end the pending state"
        );

        assert!(matches!(
            f.service
                .describe(TenantContext::new(f.tenant), &token)
                .await,
            Err(AccountSetupError::InvalidOrExpired)
        ));
    }

    /// Trying to register 2 at once with the same link undoes the registration of the side that lost consumption (task #586).
    #[tokio::test]
    async fn a_registration_that_loses_the_link_is_discarded() {
        let (f, token) = fixture().await;
        *f.passkeys.race_with.lock().unwrap() = Some(f.tokens.clone());
        let ctx = RequestContext {
            correlation_id: "corr-race".to_string(),
            ip_address: None,
            user_agent: None,
        };
        let result = f
            .service
            .complete_passkey(
                TenantContext::new(f.tenant),
                &token,
                Uuid::new_v4(),
                "Second device",
                serde_json::json!({}),
                &ctx,
            )
            .await;
        assert!(matches!(result, Err(AccountSetupError::InvalidOrExpired)));
        assert_eq!(
            f.passkeys.discarded.lock().unwrap().as_slice(),
            [Uuid::from_u128(7)]
        );
    }

    /// Carrying it to another tenant's screen does not pass.
    #[tokio::test]
    async fn a_link_does_not_work_on_another_tenants_screen() {
        let (f, token) = fixture().await;
        let other: TenantId = Uuid::now_v7().into();
        assert!(matches!(
            f.service.describe(TenantContext::new(other), &token).await,
            Err(AccountSetupError::InvalidOrExpired)
        ));
    }

    /// ⚠ **A forgotten-password reset link may not register a passkey** (decision 2 of ADR-0062).
    #[tokio::test]
    async fn a_password_reset_link_may_not_add_a_passkey() {
        let (f, _) = fixture().await;
        // Put one "reset"-purpose token for the same user.
        let token = "reset-token-plain";
        f.tokens
            .create(&PasswordResetToken {
                token_hash: crypto::sha256_hex(token),
                user_id: f.user_id,
                purpose: ResetPurpose::Reset,
                expires_at: now() + chrono::Duration::hours(1),
                used_at: None,
                created_at: now(),
            })
            .await
            .unwrap();

        assert!(matches!(
            f.service
                .begin_passkey(TenantContext::new(f.tenant), token)
                .await,
            Err(AccountSetupError::NotAllowed)
        ));
    }

    /// ADR-0064: a disabled provisional user cannot get back in with the link at hand.
    #[tokio::test]
    async fn a_disabled_pending_user_cannot_use_the_link() {
        let (f, token) = fixture().await;
        f.users.0.lock().unwrap()[0].status = UserStatus::Disabled;
        assert!(matches!(
            f.service
                .describe(TenantContext::new(f.tenant), &token)
                .await,
            Err(AccountSetupError::InvalidOrExpired)
        ));
    }
}

/// Test assembly.
///
/// The **issuing** side is held by the user creation and password reissue use cases. So that their
/// tests need not write a token table fake every time, one lives here.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// A fake that just remembers issued tokens (also mirrors consumption and revocation plainly).
    #[derive(Default)]
    pub struct FakeSetupTokens {
        pub rows: Mutex<Vec<PasswordResetToken>>,
    }

    #[async_trait]
    impl PasswordResetTokenRepository for FakeSetupTokens {
        async fn create(&self, token: &PasswordResetToken) -> DomainResult<()> {
            self.rows.lock().unwrap().push(token.clone());
            Ok(())
        }

        async fn consume(
            &self,
            token_hash: &str,
            used_at: DateTime<Utc>,
        ) -> DomainResult<Option<PasswordResetToken>> {
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.iter_mut().find(|r| {
                r.token_hash == token_hash && r.used_at.is_none() && r.expires_at > used_at
            }) else {
                return Ok(None);
            };
            row.used_at = Some(used_at);
            Ok(Some(row.clone()))
        }

        async fn find_active(
            &self,
            token_hash: &str,
            now: DateTime<Utc>,
        ) -> DomainResult<Option<PasswordResetToken>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.token_hash == token_hash && r.used_at.is_none() && r.expires_at > now)
                .cloned())
        }

        async fn invalidate_all_for_user(
            &self,
            user_id: Uuid,
            now: DateTime<Utc>,
        ) -> DomainResult<()> {
            for row in self.rows.lock().unwrap().iter_mut() {
                if row.user_id == user_id && row.used_at.is_none() {
                    row.used_at = Some(now);
                }
            }
            Ok(())
        }
    }

    /// Issuing side with the default lifetime (makes `https://idp.example.com` links).
    pub fn link_issuer(
        tokens: Arc<FakeSetupTokens>,
        clock: Arc<dyn Clock>,
    ) -> Arc<AccountSetupLinkIssuer> {
        Arc::new(AccountSetupLinkIssuer::new(
            tokens,
            crate::application::tenant_settings::testing::tenant_settings_with_global(&[(
                "ACCOUNT_SETUP_TTL_SECS",
                "86400",
            )]),
            clock,
            "https://idp.example.com".to_string(),
        ))
    }
}
