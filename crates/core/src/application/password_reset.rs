//! Self-service password reset use case (forgotten password. MT18).
//!
//! From "Forgot your password?" on the login screen: enter an email address -> receive an email with a reset link
//! -> set a new password at the link. SMTP is resolved from system settings (MT14), and mail delivery reuses
//! MT17's [`Mailer`] port. The admin console's login screen uses the same path
//! (no separate admin-only path. Reissue by an admin per ADR-0009 §5 is a different feature).
//!
//! **When SMTP can't send, the link is printed to the server console (stdout).** This is a path for an admin who forgot
//! their password to recover on their own in environments without mail delivery; the operator picks the URL from
//! `docker logs`. "Can't send" isn't limited to SMTP being unset; it includes **failing to read the SMTP settings**
//! (DB failure, password undecryptable due to a `KEY_ENCRYPTION_KEY` mismatch, etc.) —— so a failure doesn't also take away
//! the means of recovery. Therefore it may appear on the console even in environments with SMTP configured.
//! It can be closed with `PASSWORD_RESET_CONSOLE_LINK_ENABLED=false` (then, without SMTP, the feature is unavailable).
//!
//! Security policy:
//! - **Preventing email enumeration**: requests get the same response (`Accepted`) regardless of whether the account
//!   exists or its state. Only when there's no means to deliver the link is it `Unavailable` (account-independent
//!   information, so not enumeration).
//! - **Token**: 32 random bytes. Stored only as SHA-256 hex, with a TTL (default 1 hour),
//!   consumed once. On a new request, the user's unused tokens are revoked (the valid link is always the single latest one).
//! - **Revoke all sessions on successful reset**: a forgotten-password reset may involve leaked credentials, so
//!   SSO sessions, refresh tokens and unconsumed authorization codes are all revoked per user.
//! - **Rate limiting**: the number of requests is limited per IP.
//! - Email addresses never appear in logs or audit (PII policy). Tokens likewise, except for the console output
//!   above, which prints the URL to stdout at INFO (only WARN and above are ingested into the `log` table,
//!   so it doesn't remain in the DB or the admin console's log screen).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::password_policy::PasswordPolicyService;
use crate::application::system_settings::SystemSettingsService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::mailer::{Mailer, OutgoingEmail, SmtpServerConfig};
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::PasswordRejection;
use crate::domain::password_reset::{PasswordResetToken, ResetPurpose};
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{
    AuthorizationCodeRepository, PasswordResetTokenRepository, RefreshTokenRepository,
    SsoSessionRepository, UserRepository,
};
#[cfg(test)]
use crate::domain::system_setting::DeploymentState;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use std::sync::Arc;

/// Byte length of the reset token (about 43 chars in base64url).
const RESET_TOKEN_BYTES: usize = 32;

/// Result of a reset request. Doesn't branch on whether the account exists (enumeration prevention).
pub enum RequestResetOutcome {
    /// Accepted (if the account exists, the link was delivered; the same response if it doesn't).
    Accepted,
    /// No means to deliver the link (SMTP can't send and console output is disabled).
    /// The feature itself is unavailable, independent of accounts, so returning it is not enumeration.
    Unavailable,
    /// Per-IP rate limit exceeded.
    RateLimited,
}

/// Where the reset link goes. Email if SMTP can send; if not (unset, or failed to read the settings),
/// the server console (stdout; read with `docker logs`).
///
/// Console output is a recovery path for environments without mail delivery, and anyone who can read the link
/// can reset that account's password. In environments where non-operators can read the logs,
/// close it with `PASSWORD_RESET_CONSOLE_LINK_ENABLED=false`.
enum ResetLinkDelivery {
    Email(SmtpServerConfig),
    Console,
}

pub enum ResetPasswordOutcome {
    Ok,
    /// The token is invalid, expired, used, or for another tenant.
    InvalidOrExpired,
    /// The new password doesn't satisfy the policy (length, breached, reused. AP7).
    WeakPassword(PasswordRejection),
    Internal(String),
}

pub struct PasswordResetService {
    users: Arc<dyn UserRepository>,
    reset_tokens: Arc<dyn PasswordResetTokenRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    hasher: Arc<dyn PasswordHasher>,
    password_policy: Arc<PasswordPolicyService>,
    system_settings: Arc<SystemSettingsService>,
    mailer: Arc<dyn Mailer>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// Resolution of settings tenants can override (ADR-0058). Looked up every time.
    settings: Arc<dyn EffectiveTenantSettings>,
    /// Public base URL the reset link is built on (web screens; no trailing slash).
    console_base_url: String,
}

impl PasswordResetService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        reset_tokens: Arc<dyn PasswordResetTokenRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        system_settings: Arc<SystemSettingsService>,
        mailer: Arc<dyn Mailer>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        settings: Arc<dyn EffectiveTenantSettings>,
        console_base_url: String,
    ) -> Self {
        Self {
            users,
            reset_tokens,
            sso_sessions,
            refresh_tokens,
            codes,
            hasher,
            password_policy,
            system_settings,
            mailer,
            rate_limiter,
            audit,
            clock,
            settings,
            console_base_url: console_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Resolves the user to reset from the requested tenant (the login screen's tenant) (MT26).
    ///
    /// Looked up in the order **home tenant -> guest in host tenants**. Same order as login field resolution
    /// ([`crate::application::login_user_resolution`]), so guests can also request it from "Forgot your password?"
    /// on a host tenant. Guests can log in from the host tenant's screen (ADR-0009 §8), so limiting only reset
    /// to the home tenant would be a dead end.
    ///
    /// Matched against `users.email` (the mail destination itself); the registry is not looked up.
    /// Reset must work even in tenants that haven't enabled email login (ADR-0025 §5).
    ///
    /// **The domain path (ADR-0029) is not used.** The benefit of pinning the home tenant from a domain qualifier is
    /// reducing "nobody can be returned when ambiguous", but the response here is always `Accepted` regardless,
    /// and the result when ambiguous is "no email arrives" = the same as unresolvable. Adding a path
    /// gains nothing.
    ///
    /// Inactive users (not `is_active`) are excluded. Even if they reset the password, they can't get in.
    async fn find_resettable_user(
        &self,
        tenant: TenantContext,
        email: &str,
    ) -> Result<Option<User>, DomainError> {
        if let Some(user) = self.users.find_by_email(tenant.tenant_id(), email).await? {
            return Ok(user.is_active().then_some(user));
        }
        let guest = self
            .users
            .find_active_guest_by_email(tenant.tenant_id(), email)
            .await?;
        Ok(guest.filter(User::is_active))
    }

    /// Requests a reset. `tenant` is the login screen's tenant (looked up home tenant first, then as a guest in host tenants).
    /// Returns `Accepted` regardless of whether the account exists or its state (enumeration prevention).
    pub async fn request_reset(
        &self,
        tenant: TenantContext,
        email: &str,
        ctx: &RequestContext,
    ) -> RequestResetOutcome {
        if !self.rate_limiter.check_and_record(
            ctx.ip_address.as_deref().unwrap_or("unknown"),
            self.clock.now(),
        ) {
            return RequestResetOutcome::RateLimited;
        }

        // Decide the destination first. Without either SMTP or console output, the feature itself is unavailable
        // (account-independent, so branching here is not enumeration). Whether console output is allowed is checked
        // with the **requested tenant's** value since the user isn't resolved yet (the home tenant's value is checked again after).
        // ⚠ The mail channel is also decided by **the login screen's tenant** (ADR-0058 §8). Deciding by the home tenant
        //   after looking up the user would leak the user's existence through the "unavailable / accepted" difference.
        let delivery = match self
            .system_settings
            .smtp_server_for(tenant.tenant_id())
            .await
        {
            Ok(Some(server)) => ResetLinkDelivery::Email(server),
            Ok(None) => match self.console_link_delivery(tenant.tenant_id()).await {
                Some(delivery) => delivery,
                None => return RequestResetOutcome::Unavailable,
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to load SMTP settings for password reset");
                // Only the settings can't be read; the console path still works (treating it like SMTP unset would
                // lose the recovery means during an outage). **This can be reached even in environments with SMTP configured**,
                // so "configuring SMTP keeps it off the console" doesn't hold (also stated in the settings description and
                // OPERATIONS).
                match self.console_link_delivery(tenant.tenant_id()).await {
                    Some(delivery) => delivery,
                    None => return RequestResetOutcome::Unavailable,
                }
            }
        };

        // From here on, Accepted regardless of account existence, state or send result (enumeration prevention).
        let user = match self.find_resettable_user(tenant, email.trim()).await {
            Ok(Some(user)) => user,
            Ok(None) => return RequestResetOutcome::Accepted,
            Err(e) => {
                tracing::warn!(error = %e, "password reset user lookup failed");
                return RequestResetOutcome::Accepted;
            }
        };

        // The link points at the home tenant and reset only passes there (MT26), so decide by the home tenant's value
        // (ADR-0058). If a guest requested from a host tenant's screen, in addition to the requested tenant's setting above,
        // it is not printed unless the home tenant also allows console output (closed if either closes it).
        if matches!(delivery, ResetLinkDelivery::Console) && user.tenant_id != tenant.tenant_id() {
            match self
                .settings
                .password_reset_console_link_enabled(user.tenant_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    tracing::info!(
                        user_id = %user.id,
                        "password reset link was not issued: the user's home tenant does not allow console links"
                    );
                    return RequestResetOutcome::Accepted;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to resolve the password reset console link setting");
                    return RequestResetOutcome::Accepted;
                }
            }
        }
        // Looked up before revoking old tokens (so a failed lookup doesn't leave no valid link at all).
        let reset_ttl = match self.settings.password_reset_ttl(user.tenant_id).await {
            Ok(ttl) => ttl,
            Err(e) => {
                tracing::warn!(error = %e, "failed to resolve the password reset TTL");
                return RequestResetOutcome::Accepted;
            }
        };

        let now = self.clock.now();
        // On a new request, revoke old tokens so the valid reset link is always the single latest one.
        if let Err(e) = self
            .reset_tokens
            .invalidate_all_for_user(user.id, now)
            .await
        {
            tracing::warn!(error = %e, "failed to invalidate previous reset tokens");
            return RequestResetOutcome::Accepted;
        }

        let token = crypto::random_token(RESET_TOKEN_BYTES);
        let expires_at = now + reset_ttl;
        let record = PasswordResetToken {
            token_hash: crypto::sha256_hex(&token),
            user_id: user.id,
            // A reset requested by the person. ⚠ Links for this purpose don't allow registering a passkey (ADR-0062).
            purpose: ResetPurpose::Reset,
            expires_at,
            used_at: None,
            created_at: now,
        };
        if let Err(e) = self.reset_tokens.create(&record).await {
            tracing::warn!(error = %e, "failed to store password reset token");
            return RequestResetOutcome::Accepted;
        }

        // Only internal IDs are recorded in the audit (no tokens or email addresses).
        self.audit
            .record(
                AuditEventType::PasswordResetRequested,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;

        // The token is base64url (URL-safe), so it can be concatenated as-is.
        // Until MT19 (API i18n), the wording is fixed text in both Japanese and English.
        //
        // **The link points at the home tenant (`user.tenant_id`), not the requested tenant** (MT26).
        // Performing the reset ([`Self::reset_password`]) requires "home tenant of the token's user == requested tenant",
        // so a link pointing at a host tenant would always be rejected. Pointing at the home tenant lets a guest
        // who requested from a host tenant's screen go straight through to the reset.
        let reset_url = format!(
            "{}/{}/password-reset?token={}",
            self.console_base_url, user.tenant_id, token
        );
        match delivery {
            ResetLinkDelivery::Email(server) => {
                let mail = OutgoingEmail {
                    to: user.email.clone(),
                    subject: "パスワード再設定のご案内 / Password reset".to_string(),
                    body_text: format!(
                        "パスワード再設定の要求を受け付けました。\n\
                         次のリンクを開いて新しいパスワードを設定してください。\n\
                         心当たりがない場合は、このメールを破棄してください。\n\
                         \n\
                         A password reset was requested for your account.\n\
                         Open the link below to set a new password.\n\
                         If you did not request this, you can safely ignore this email.\n\
                         \n\
                         {reset_url}\n\
                         \n\
                         有効期限 / Expires at: {}\n",
                        expires_at.to_rfc3339()
                    ),
                };
                if let Err(e) = self.mailer.send(&server, &mail).await {
                    // PII such as the destination is not logged. The response stays Accepted (enumeration prevention).
                    tracing::warn!(error = %e, "password reset email delivery failed");
                }
            }
            // Recovery path for environments without mail delivery. The operator picks the URL from `docker logs`.
            //
            // **Printing at INFO** is intentional. The ingestion layer writes only WARN and above to the `log` table, so
            // at INFO the URL (= reset token) doesn't remain in the DB and doesn't appear in the admin console's log
            // screen. The destination email address is not printed; only the same internal IDs as the audit are attached.
            ResetLinkDelivery::Console => tracing::info!(
                user_id = %user.id,
                expires_at = %expires_at.to_rfc3339(),
                reset_url = %reset_url,
                "password reset link issued to the server console because no usable SMTP configuration is available"
            ),
        }
        RequestResetOutcome::Accepted
    }

    /// Destination when SMTP can't send. `None` if console output is disabled (= the feature can't be offered).
    ///
    /// If the setting can't be read, falls back to `None` (to the closed side; anyone who can read the link can reset the password).
    async fn console_link_delivery(&self, tenant_id: TenantId) -> Option<ResetLinkDelivery> {
        match self
            .settings
            .password_reset_console_link_enabled(tenant_id)
            .await
        {
            Ok(enabled) => enabled.then_some(ResetLinkDelivery::Console),
            Err(e) => {
                tracing::warn!(error = %e, "failed to resolve the password reset console link setting");
                None
            }
        }
    }

    /// Consumes the token and sets a new password. On success, revokes all of the user's SSO sessions,
    /// refresh tokens and unconsumed authorization codes (a forgotten-password reset may involve leaked
    /// credentials).
    pub async fn reset_password(
        &self,
        tenant: TenantContext,
        token: &str,
        new_password: &str,
        ctx: &RequestContext,
    ) -> ResetPasswordOutcome {
        if token.is_empty() {
            return ResetPasswordOutcome::InvalidOrExpired;
        }
        // Check the user-independent requirements (length, breached. AP7) before consuming the token (so a typo
        // doesn't waste the single-use token). The reuse check is done after resolving the user.
        // The requested tenant is confirmed to match the home tenant afterwards (otherwise no token is returned), so
        // what is checked here is the home tenant's policy.
        match self
            .password_policy
            .validate_input(tenant.tenant_id(), new_password)
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(rejection)) => return ResetPasswordOutcome::WeakPassword(rejection),
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        }

        let now = self.clock.now();
        let record = match self
            .reset_tokens
            .consume(&crypto::sha256_hex(token), now)
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => return ResetPasswordOutcome::InvalidOrExpired,
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        };

        // Resolve the token's owner and confirm the link's tenant (the screen's route) matches the home tenant
        // (so a token can't be carried to another tenant's reset screen). Non-ACTIVE users are also refused.
        // ⚠ Provisionally registered users (ADR-0064) are let through **only by setup links**. If a forgotten-password reset link
        //   could complete provisional registration, someone who can temporarily read the email could get in before the person.
        let may_use = |user: &User| match record.purpose {
            ResetPurpose::Setup => user.can_finish_setup(),
            ResetPurpose::Reset => user.is_active(),
        };
        let user = match self.users.find_by_id(record.user_id).await {
            Ok(Some(user)) if may_use(&user) && user.tenant_id == tenant.tenant_id() => user,
            Ok(_) => return ResetPasswordOutcome::InvalidOrExpired,
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        };

        // No reuse of past passwords (AP7). A forgotten-password reset easily becomes a path "back to the old password I remembered",
        // so the same rules as the change path apply. The token is already consumed, so
        // a refused user has to start over from reissue.
        match self
            .password_policy
            .validate_reuse(
                user.tenant_id,
                Some(user.id),
                Some(&user.password_hash),
                new_password,
            )
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(rejection)) => return ResetPasswordOutcome::WeakPassword(rejection),
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        }

        let new_hash = match self.hasher.hash(new_password) {
            Ok(h) => h,
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        };
        // Replace conditioned on the current hash (AP7). `false` means another request changed the password between
        // read and write. The token is consumed, so starting over needs a reissue.
        match self
            .users
            .update_password(user.id, &user.password_hash, &new_hash)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!("password reset lost a concurrent update; a new link is required");
                return ResetPasswordOutcome::InvalidOrExpired;
            }
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        }
        self.password_policy
            .record_change(user.tenant_id, user.id, &user.password_hash)
            .await;

        // The person chose a password, so remove the provisional registration (ADR-0064). ⚠ If it can't be removed, don't report success
        // ——they'd be someone with a password who can't get in, and the link is already used up.
        if user.pending_setup {
            if let Err(e) = self.users.finish_setup(user.id).await {
                return ResetPasswordOutcome::Internal(e.to_string());
            }
        }

        // Revoke all sessions and tokens (not fail-open: failures are only logged. The password is already
        // updated, so login with old credentials is impossible).
        if let Err(e) = self.sso_sessions.delete_all_for_user(user.id).await {
            tracing::warn!(error = %e, "failed to revoke SSO sessions after password reset");
        }
        if let Err(e) = self
            .refresh_tokens
            .revoke_all_for_user(user.id, now)
            .await
            .map(|_| ())
        {
            tracing::warn!(error = %e, "failed to revoke refresh tokens after password reset");
        }
        if let Err(e) = self.codes.revoke_all_active_for_user(user.id, now).await {
            tracing::warn!(error = %e, "failed to revoke authorization codes after password reset");
        }

        self.audit
            .record(
                AuditEventType::PasswordResetCompleted,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;
        ResetPasswordOutcome::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::authorization_code::AuthorizationCode;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::mailer::SmtpServerConfig;
    use crate::domain::refresh_token::RefreshToken;
    use crate::domain::repositories::{AuditLogSink, SystemSettingsRepository};
    use crate::domain::sso_session::SsoSession;
    use crate::domain::system_setting::SystemSetting;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;

    const TEST_KEY: [u8; 32] = *b"unit-test-key-0123456789abcdef!!";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl crate::domain::clock::Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
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
    struct CapturingSink {
        events: Mutex<Vec<crate::domain::audit::AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
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
        /// single-threaded tests, so a naive increment giving the same result is enough.
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
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
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
        async fn find_by_username(&self, _t: TenantId, _n: &str) -> DomainResult<Option<User>> {
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
            id: Uuid,
            expected: &str,
            password_hash: &str,
        ) -> DomainResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            // Same compare-and-swap as the production implementation (rewrite only when the current hash matches).
            match rows
                .iter_mut()
                .find(|u| u.id == id && u.password_hash == expected)
            {
                Some(user) => {
                    user.password_hash = password_hash.to_string();
                    user.must_change_password = false;
                    Ok(true)
                }
                None => Ok(false),
            }
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
        async fn finish_setup(&self, id: Uuid) -> DomainResult<()> {
            for user in self.rows.lock().unwrap().iter_mut().filter(|u| u.id == id) {
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

    #[derive(Default)]
    struct FakeResetTokens {
        rows: Mutex<Vec<PasswordResetToken>>,
    }
    #[async_trait]
    impl PasswordResetTokenRepository for FakeResetTokens {
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
            match rows.iter_mut().find(|t| {
                t.token_hash == token_hash && t.used_at.is_none() && t.expires_at > used_at
            }) {
                Some(row) => {
                    row.used_at = Some(used_at);
                    Ok(Some(row.clone()))
                }
                None => Ok(None),
            }
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

    #[derive(Default)]
    struct FakeSsoSessions {
        revoked_users: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, _h: &str) -> DomainResult<Option<SsoSession>> {
            unreachable!()
        }
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, user_id: Uuid) -> DomainResult<()> {
            self.revoked_users.lock().unwrap().push(user_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRefreshTokens {
        revoked_users: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl RefreshTokenRepository for FakeRefreshTokens {
        async fn revoke_all_for_session(
            &self,
            _u: Uuid,
            _sid: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            unreachable!()
        }
        async fn revoke_family(
            &self,
            _t: TenantId,
            _family: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            unreachable!()
        }
        async fn revoke_all_for_user_in_tenant(
            &self,
            _tenant: TenantId,
            _user_id: Uuid,
            _now: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn create(&self, _t: &RefreshToken) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, _t: TenantId, _h: &str) -> DomainResult<Option<RefreshToken>> {
            unreachable!()
        }
        async fn revoke(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn exists_by_parent_hash(&self, _h: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn revoke_all_for_user(&self, user_id: Uuid, _t: DateTime<Utc>) -> DomainResult<u64> {
            self.revoked_users.lock().unwrap().push(user_id);
            Ok(1)
        }
        async fn count_active_for_user(&self, _u: Uuid, _now: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn revoke_all_for_user_and_client(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeCodes {
        revoked_users: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl AuthorizationCodeRepository for FakeCodes {
        async fn find_used(
            &self,
            _t: TenantId,
            _h: &crate::domain::authorization_code::AuthorizationCodeHash,
        ) -> DomainResult<Option<AuthorizationCode>> {
            unreachable!()
        }
        async fn create(&self, _c: &AuthorizationCode) -> DomainResult<()> {
            unreachable!()
        }
        async fn consume(
            &self,
            _t: TenantId,
            _h: &crate::domain::authorization_code::AuthorizationCodeHash,
            _u: DateTime<Utc>,
        ) -> DomainResult<Option<AuthorizationCode>> {
            unreachable!()
        }
        async fn revoke_all_active_for_user(
            &self,
            user_id: Uuid,
            _now: DateTime<Utc>,
        ) -> DomainResult<()> {
            self.revoked_users.lock().unwrap().push(user_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeSettingsRepo {
        rows: Mutex<Vec<SystemSetting>>,
    }
    #[async_trait]
    impl SystemSettingsRepository for FakeSettingsRepo {
        async fn load_all(&self) -> DomainResult<Vec<SystemSetting>> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn upsert(&self, setting: &SystemSetting) -> DomainResult<()> {
            self.rows.lock().unwrap().push(setting.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeMailer {
        sent: Mutex<Vec<(SmtpServerConfig, OutgoingEmail)>>,
    }
    #[async_trait]
    impl Mailer for FakeMailer {
        async fn send(&self, server: &SmtpServerConfig, mail: &OutgoingEmail) -> DomainResult<()> {
            self.sent
                .lock()
                .unwrap()
                .push((server.clone(), mail.clone()));
            Ok(())
        }
    }

    struct CountingLimiter {
        limit: usize,
        calls: AtomicUsize,
    }
    impl LoginRateLimiter for CountingLimiter {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst) < self.limit
        }
    }

    fn smtp_settings(repo: &FakeSettingsRepo) {
        let rows = vec![
            ("smtp.host", "smtp.example.com"),
            ("smtp.from_address", "noreply@example.com"),
        ];
        *repo.rows.lock().unwrap() = rows
            .into_iter()
            .map(|(k, v)| SystemSetting {
                key: k.to_string(),
                value: v.to_string(),
                is_secret: false,
            })
            .collect();
    }

    fn test_user(id: Uuid, tenant: TenantId, email: &str) -> User {
        User {
            id,
            tenant_id: tenant,
            sub: Uuid::new_v4(),
            email: email.to_string(),
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: "hash:old-password".to_string(),
            must_change_password: false,
            password_changed_at: None,
            status: UserStatus::Active,
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: Some("203.0.113.1".to_string()),
            user_agent: None,
        }
    }

    struct Harness {
        svc: PasswordResetService,
        users: Arc<FakeUsers>,
        tokens: Arc<FakeResetTokens>,
        sso: Arc<FakeSsoSessions>,
        refresh: Arc<FakeRefreshTokens>,
        codes: Arc<FakeCodes>,
        mailer: Arc<FakeMailer>,
        sink: Arc<CapturingSink>,
        settings: crate::application::tenant_settings::testing::TenantSettingsFixture,
    }

    /// Test bed with only SMTP configured (console output disabled).
    fn harness(smtp_configured: bool, limiter_allowance: usize) -> Harness {
        harness_with(smtp_configured, limiter_allowance, false)
    }

    fn harness_with(
        smtp_configured: bool,
        limiter_allowance: usize,
        console_link_enabled: bool,
    ) -> Harness {
        let users = Arc::new(FakeUsers::default());
        let tokens = Arc::new(FakeResetTokens::default());
        let sso = Arc::new(FakeSsoSessions::default());
        let refresh = Arc::new(FakeRefreshTokens::default());
        let codes = Arc::new(FakeCodes::default());
        let mailer = Arc::new(FakeMailer::default());
        let sink = Arc::new(CapturingSink::default());
        // Global values. Tenant rows are put directly into `settings` by each test.
        let settings = crate::application::tenant_settings::testing::tenant_settings();
        settings.set_global("PASSWORD_HISTORY_COUNT", "0");
        settings.set_global("PASSWORD_RESET_TTL_SECS", "3600");
        settings.set_global(
            "PASSWORD_RESET_CONSOLE_LINK_ENABLED",
            &console_link_enabled.to_string(),
        );
        let settings_repo = Arc::new(FakeSettingsRepo::default());
        if smtp_configured {
            smtp_settings(&settings_repo);
        }
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock)));
        let system_settings = Arc::new(SystemSettingsService::new(
            settings_repo,
            Arc::new(crate::application::system_settings::NoTenantSettings),
            TEST_KEY,
            DeploymentState::default(),
            audit.clone(),
            Arc::new(FixedClock),
        ));
        let svc = PasswordResetService::new(
            users.clone(),
            tokens.clone(),
            sso.clone(),
            refresh.clone(),
            codes.clone(),
            Arc::new(PlainHasher),
            Arc::new(
                crate::application::password_policy::PasswordPolicyService::without_history(
                    settings.service.clone(),
                    Arc::new(PlainHasher),
                    Arc::new(FixedClock),
                ),
            ),
            system_settings,
            mailer.clone(),
            Arc::new(CountingLimiter {
                limit: limiter_allowance,
                calls: AtomicUsize::new(0),
            }),
            audit,
            Arc::new(FixedClock),
            settings.service.clone(),
            "https://idp.example.com".to_string(),
        );
        Harness {
            svc,
            users,
            tokens,
            sso,
            refresh,
            codes,
            mailer,
            sink,
            settings,
        }
    }

    /// Sink for verifying console output (stdout).
    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8 log output")
        }
    }

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `future` while capturing console output (INFO and above).
    ///
    /// ⚠ **Tests that go through the path printing the link to the console must always be wrapped in this.** If a thread
    /// with no subscriber hits the same `tracing::info!` first, that call site is cached as "nobody listening" even inside
    /// another test running concurrently, and the output can't be captured (passes locally, fails only in CI).
    async fn capture_console<F: std::future::Future>(future: F) -> (F::Output, String) {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Layer;

        let logs = SharedBuffer::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(logs.clone())
                .with_filter(tracing_subscriber::EnvFilter::new("info")),
        );
        let output = {
            let _guard = tracing::subscriber::set_default(subscriber);
            future.await
        };
        (output, logs.contents())
    }

    /// Extracts the reset token from the sent mail body (from `token=` to end of line).
    fn token_from_mail(mail: &OutgoingEmail) -> String {
        let body = &mail.body_text;
        let start = body.find("token=").expect("token in body") + "token=".len();
        body[start..]
            .split_whitespace()
            .next()
            .expect("token value")
            .to_string()
    }

    #[tokio::test]
    async fn request_is_indistinguishable_for_unknown_accounts() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true, 100);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "known@example.com"));

        // Both existing and nonexistent accounts get Accepted (enumeration prevention).
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(tenant), "known@example.com", &ctx())
                .await,
            RequestResetOutcome::Accepted
        ));
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(tenant), "unknown@example.com", &ctx())
                .await,
            RequestResetOutcome::Accepted
        ));
        // Only one mail is sent, for the existing account, and its body contains the reset link.
        let sent = h.mailer.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1.to, "known@example.com");
        assert!(sent[0].1.body_text.contains(&format!(
            "https://idp.example.com/{tenant}/password-reset?token="
        )));
        // Only the hash is stored.
        let token = token_from_mail(&sent[0].1);
        let rows = h.tokens.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_hash, crypto::sha256_hex(&token));
        assert_ne!(rows[0].token_hash, token);
    }

    /// In environments without SMTP, recovery works by printing the reset link to the server console.
    /// No mail is sent, and only the token hash is stored (same as the mail path).
    #[tokio::test]
    async fn request_prints_the_link_to_the_console_when_smtp_is_missing() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness_with(false, 100, true);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "admin@example.com"));

        let (outcome, printed) = capture_console(h.svc.request_reset(
            TenantContext::new(tenant),
            "admin@example.com",
            &ctx(),
        ))
        .await;
        assert!(matches!(outcome, RequestResetOutcome::Accepted));

        let prefix = format!("https://idp.example.com/{tenant}/password-reset?token=");
        assert!(printed.contains(&prefix), "{printed}");
        // Output is at INFO. The ingestion layer (`application_log::CaptureFilter`) writes only WARN and above to the `log` table,
        // so the link remains neither in the DB nor in the admin console's log screen.
        assert!(printed.contains("INFO"), "{printed}");
        // The destination email address (PII) is not printed.
        assert!(!printed.contains("admin@example.com"), "{printed}");

        // No mail is sent, and only the token hash is stored.
        assert!(h.mailer.sent.lock().unwrap().is_empty());
        let token = printed
            .split_once(&prefix)
            .map(|(_, rest)| {
                rest.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
            .expect("reset url in console output");
        let rows = h.tokens.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_hash, crypto::sha256_hex(&token));
    }

    /// In operations with console output disabled (environments where non-operators can read logs), without SMTP
    /// it returns "unavailable" as before.
    #[tokio::test]
    async fn request_is_unavailable_without_smtp_and_rate_limited() {
        let tenant: TenantId = Uuid::now_v7().into();
        let h = harness(false, 100);
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(tenant), "a@example.com", &ctx())
                .await,
            RequestResetOutcome::Unavailable
        ));

        let h = harness(true, 1);
        h.svc
            .request_reset(TenantContext::new(tenant), "a@example.com", &ctx())
            .await;
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(tenant), "a@example.com", &ctx())
                .await,
            RequestResetOutcome::RateLimited
        ));
    }

    #[tokio::test]
    async fn reset_updates_password_revokes_sessions_and_is_single_use() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true, 100);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));
        h.svc
            .request_reset(TenantContext::new(tenant), "u@example.com", &ctx())
            .await;
        let token = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);

        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &token,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::Ok
        ));
        // The password is updated.
        assert_eq!(
            h.users.rows.lock().unwrap()[0].password_hash,
            "hash:new-password-123"
        );
        // All sessions, refresh tokens and unconsumed codes are revoked.
        assert_eq!(*h.sso.revoked_users.lock().unwrap(), vec![user]);
        assert_eq!(*h.refresh.revoked_users.lock().unwrap(), vec![user]);
        assert_eq!(*h.codes.revoked_users.lock().unwrap(), vec![user]);
        // requested + completed are recorded in the audit, and the token doesn't leak.
        {
            let events = h.sink.events.lock().unwrap();
            assert!(events
                .iter()
                .any(|e| e.event_type == AuditEventType::PasswordResetRequested));
            assert!(events
                .iter()
                .any(|e| e.event_type == AuditEventType::PasswordResetCompleted));
            assert!(events.iter().all(|e| e
                .reason
                .as_deref()
                .map(|r| !r.contains(&token))
                .unwrap_or(true)));
        }

        // Reusing the same token is refused (consumed once).
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &token,
                    "another-password-1",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::InvalidOrExpired
        ));
    }

    #[tokio::test]
    async fn reset_rejects_other_tenant_and_weak_password_keeps_token() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true, 100);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));
        h.svc
            .request_reset(TenantContext::new(tenant), "u@example.com", &ctx())
            .await;
        let token = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);

        // A weak password doesn't consume the token (strength is checked first).
        assert!(matches!(
            h.svc
                .reset_password(TenantContext::new(tenant), &token, "short", &ctx())
                .await,
            ResetPasswordOutcome::WeakPassword(_)
        ));

        // Carrying the token to another tenant's reset screen is refused (it is consumed at that point,
        // because owner matching happens after consumption. Safe side: the attacker can't retry).
        let other: TenantId = Uuid::now_v7().into();
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(other),
                    &token,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::InvalidOrExpired
        ));
        // The password doesn't change.
        assert_eq!(
            h.users.rows.lock().unwrap()[0].password_hash,
            "hash:old-password"
        );
    }

    #[tokio::test]
    async fn new_request_invalidates_previous_token() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true, 100);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));

        h.svc
            .request_reset(TenantContext::new(tenant), "u@example.com", &ctx())
            .await;
        let first = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);
        h.svc
            .request_reset(TenantContext::new(tenant), "u@example.com", &ctx())
            .await;
        let second = token_from_mail(&h.mailer.sent.lock().unwrap()[1].1);

        // The old token is revoked; only the new token works.
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &first,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::InvalidOrExpired
        ));
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &second,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::Ok
        ));
    }

    /// The link lifetime is the value of the user's home tenant. ⚠ Checked with 2 tenants ——a tenant with a row uses
    /// that value, a tenant without a row follows the global value (1 hour).
    #[tokio::test]
    async fn the_link_lifetime_follows_the_home_tenant() {
        let short: TenantId = Uuid::now_v7().into();
        let follower: TenantId = Uuid::now_v7().into();
        let h = harness(true, 100);
        h.settings
            .set_tenant(short, "PASSWORD_RESET_TTL_SECS", "600");
        h.users.rows.lock().unwrap().extend([
            test_user(Uuid::new_v4(), short, "short@example.com"),
            test_user(Uuid::new_v4(), follower, "follower@example.com"),
        ]);

        for (tenant, email) in [
            (short, "short@example.com"),
            (follower, "follower@example.com"),
        ] {
            assert!(matches!(
                h.svc
                    .request_reset(TenantContext::new(tenant), email, &ctx())
                    .await,
                RequestResetOutcome::Accepted
            ));
        }
        let rows = h.tokens.rows.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].expires_at,
            FixedClock.now() + chrono::Duration::seconds(600)
        );
        assert_eq!(
            rows[1].expires_at,
            FixedClock.now() + chrono::Duration::seconds(3600)
        );
    }

    /// Whether console output is allowed is also per tenant. Even if closed globally, it works in a tenant that allows it,
    /// and a tenant without a row follows the global value and can't use it (account-independent `Unavailable`).
    #[tokio::test]
    async fn the_console_link_is_decided_per_tenant() {
        let allows: TenantId = Uuid::now_v7().into();
        let follower: TenantId = Uuid::now_v7().into();
        let h = harness_with(false, 100, false);
        h.settings
            .set_tenant(allows, "PASSWORD_RESET_CONSOLE_LINK_ENABLED", "true");
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(Uuid::new_v4(), allows, "a@example.com"));

        let (outcome, printed) = capture_console(h.svc.request_reset(
            TenantContext::new(allows),
            "a@example.com",
            &ctx(),
        ))
        .await;
        assert!(matches!(outcome, RequestResetOutcome::Accepted));
        assert_eq!(
            h.tokens.rows.lock().unwrap().len(),
            1,
            "the link was issued"
        );
        assert!(
            printed.contains(&format!(
                "https://idp.example.com/{allows}/password-reset?token="
            )),
            "{printed}"
        );
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(follower), "a@example.com", &ctx())
                .await,
            RequestResetOutcome::Unavailable
        ));
    }

    /// Puts a token of the given purpose directly on a provisionally registered user (for ADR-0064 tests).
    fn pending_user_with_token(
        h: &Harness,
        tenant: TenantId,
        purpose: ResetPurpose,
    ) -> (Uuid, String) {
        let user = Uuid::new_v4();
        let mut row = test_user(user, tenant, "pending@example.com");
        row.pending_setup = true;
        h.users.rows.lock().unwrap().push(row);
        let token = format!("token-{}", purpose.as_str());
        h.tokens.rows.lock().unwrap().push(PasswordResetToken {
            token_hash: crypto::sha256_hex(&token),
            user_id: user,
            purpose,
            expires_at: now() + chrono::Duration::hours(1),
            used_at: None,
            created_at: now(),
        });
        (user, token)
    }

    /// ADR-0064: choosing a password via a setup link removes the provisional registration.
    #[tokio::test]
    async fn a_setup_link_ends_the_pending_state() {
        let tenant: TenantId = Uuid::now_v7().into();
        let h = harness(true, 100);
        let (_, token) = pending_user_with_token(&h, tenant, ResetPurpose::Setup);
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &token,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::Ok
        ));
        let row = h.users.rows.lock().unwrap()[0].clone();
        assert!(!row.pending_setup);
        assert!(row.is_active());
    }

    /// ⚠ A forgotten-password reset link doesn't complete provisional registration (someone who can read the email would get in before the person).
    #[tokio::test]
    async fn a_reset_link_cannot_end_the_pending_state() {
        let tenant: TenantId = Uuid::now_v7().into();
        let h = harness(true, 100);
        let (_, token) = pending_user_with_token(&h, tenant, ResetPurpose::Reset);
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &token,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::InvalidOrExpired
        ));
        assert!(h.users.rows.lock().unwrap()[0].pending_setup);
    }
}
