//! User lifecycle operations by admins (disable, enable, delete, password reissue, MFA removal,
//! token reissue, profile editing. ADR-0009 §5, MT21, MT25, ADR-0047).
//!
//! Targets are **only users whose home (HOME) is the requested tenant** (`users.tenant_id` match. A guest's
//! `users` record can be operated only by admins of their home tenant. §3). Operating on oneself is forbidden
//! (to prevent lockout by mistake. Password changes and MFA removal use self-service). However,
//! profile editing ([`UserLifecycleService::update_profile`]) does not cause lockout, so it can also target
//! oneself.
//!
//! Password reissue follows the same policy as creation ([`crate::application::user_management`]): a random password of 32+ chars
//! is auto-generated and `must_change_password = true` is set. The generated password is
//! returned in plaintext **only in that response** and is not output to logs or audits. On reissue, disable and MFA removal, all of that user's
//! SSO sessions, refresh tokens and unconsumed authorization codes are revoked.

use crate::application::account_setup::{AccountSetupLinkIssuer, SetupLink};
use crate::application::audit::{AuditService, RequestContext};
use crate::application::password_policy::PasswordPolicyService;
use crate::application::stop_announcement::SessionStopAnnouncer;
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::message::MessageKey;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::{
    AuthorizationCodeRepository, RefreshTokenRepository, SsoSessionRepository,
    TotpSecretRepository, UserAuthenticatorRepository, UserRepository,
    WebAuthnCredentialRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::user_authenticator::AuthenticatorType;
use crate::domain::values::{
    validate_display_name, validate_email, validate_preferred_username, UserStatus,
};
use std::sync::Arc;
use uuid::Uuid;

/// Byte length of the auto-generated password (43 chars in base64url. Meets ADR-0009 §5's "32 chars or more").
const GENERATED_PASSWORD_BYTES: usize = 32;

/// Result of a password reissue. Both are returned **only this once**.
pub struct ResetUserPassword {
    pub user_id: Uuid,
    /// The **account setup link** handed to the user (ADR-0062).
    ///
    /// ⚠ **The replaced password itself is not returned.** Reissue is an operation that "immediately invalidates
    /// the current password", so a value is generated and set, but ⚠ **left known to nobody**:
    /// this change ends any form in which the admin holds the user's credentials.
    pub setup_link: SetupLink,
}

/// Result of MFA removal (MT21). Tells the admin what was removed (also recorded in the audit at the same granularity).
/// Secrets and credentials themselves are not included (same for values shown in `Debug`).
#[derive(Debug)]
pub struct MfaReset {
    pub user_id: Uuid,
    /// Whether TOTP settings existed and were deleted (`false` if not set).
    pub totp_removed: bool,
    /// Number of deleted passkeys (WebAuthn credentials).
    pub passkeys_removed: u64,
}

/// Result of a token reissue (ADR-0047). `revoked` is the number dropped, and **0 is also success**
/// (there were no live tokens). Returned so the admin can be shown "there was nothing to revoke".
#[derive(Debug)]
pub struct TokenReissue {
    pub user_id: Uuid,
    pub revoked: u64,
}

/// Number of the user's currently valid tokens (task #83). A read result for showing the admin, before pressing reissue (ADR-0047),
/// whether there is anything to revoke.
///
/// ⚠ **Only refresh tokens can be counted**. Access tokens are self-contained JWTs with no rows in the DB,
/// so there is no way to count how many were issued. The field name includes the kind so that
/// the screen does not mistake "what was counted".
#[derive(Debug)]
pub struct ActiveTokenCount {
    pub user_id: Uuid,
    /// Number of unrevoked, unexpired refresh tokens (regardless of tenant. Same scope as what reissue drops).
    pub refresh_tokens: u64,
}

/// Profile edit instruction (MT25). Fields that are `None` are not changed (partial update).
/// Passing an empty string for `preferred_username` / `name` means "clear (`NULL`)".
#[derive(Debug, Default, Clone)]
pub struct UpdateUserProfileCommand {
    pub email: Option<String>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum UserLifecycleError {
    #[error("user not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(MessageKey),
    #[error("validation error: {0}")]
    Validation(MessageKey),
    /// email / preferred_username is already used in the tenant (MT25).
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

fn internal(e: crate::domain::error::DomainError) -> UserLifecycleError {
    UserLifecycleError::Internal(e.to_string())
}

pub struct UserLifecycleService {
    /// Authenticator registry (AP9). MFA removal also revokes on the registry side. Only revocation is needed,
    /// so it takes the repository directly rather than the whole admin use case.
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    hasher: Arc<dyn PasswordHasher>,
    /// Held to push the hash retired by a password reissue onto the history (AP7). Without it,
    /// right after reissue -> the user changes it, **they could change back to the pre-reissue password**.
    password_policy: Arc<PasswordPolicyService>,
    audit: Arc<AuditService>,
    /// Tells RPs about the revocation (ADR-0049 I7). Deleting only inside assay goes unnoticed by RPs.
    stop_announcement: Arc<dyn SessionStopAnnouncer>,
    /// Issues a link handed to the user on every reissue (ADR-0062).
    account_setup: Arc<AccountSetupLinkIssuer>,
    clock: Arc<dyn Clock>,
}

impl UserLifecycleService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        audit: Arc<AuditService>,
        stop_announcement: Arc<dyn SessionStopAnnouncer>,
        account_setup: Arc<AccountSetupLinkIssuer>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            authenticators,
            users,
            sso_sessions,
            refresh_tokens,
            codes,
            totp_secrets,
            webauthn_credentials,
            hasher,
            password_policy,
            audit,
            stop_announcement,
            account_setup,
            clock,
        }
    }

    /// Reissues a user's password (by internal ID). Returns the generated password only once.
    pub async fn reset_password(
        &self,
        tenant: TenantContext,
        target: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ResetUserPassword, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        self.ensure_not_self(user.id, actor)?;
        self.reset_password_for(tenant, &user, actor, ctx).await
    }

    /// Reissues a user's password (by email address. Used by the tenant admin console to target admins of
    /// child tenants). Pass **the target user's home tenant** as `tenant`.
    pub async fn reset_password_by_email(
        &self,
        tenant: TenantContext,
        email: &str,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ResetUserPassword, UserLifecycleError> {
        let email = email.trim();
        if email.is_empty() {
            return Err(UserLifecycleError::Validation(MessageKey::new(
                "api-email-required",
            )));
        }
        let user = self
            .users
            .find_by_email(tenant.tenant_id(), email)
            .await
            .map_err(internal)?
            .ok_or(UserLifecycleError::NotFound)?;
        self.ensure_not_self(user.id, actor)?;
        self.reset_password_for(tenant, &user, actor, ctx).await
    }

    /// Changes a user's status (enable / disable). `LOCKED` is only for sign-in failure lockout, so
    /// admin operations cannot set it. Disabling revokes all sessions and tokens.
    pub async fn set_status(
        &self,
        tenant: TenantContext,
        target: Uuid,
        status: UserStatus,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), UserLifecycleError> {
        if status == UserStatus::Locked {
            return Err(UserLifecycleError::Validation(MessageKey::new(
                "api-user-status-locked-forbidden",
            )));
        }
        let user = self.find_home_user(tenant, target).await?;
        self.ensure_not_self(user.id, actor)?;
        self.users
            .update_status(user.id, status)
            .await
            .map_err(internal)?;
        if status == UserStatus::Disabled {
            self.revoke_credentials(&user).await;
        }
        self.audit
            .record(
                AuditEventType::UserStatusChanged,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("user={} status={}", user.id, status.as_str())),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Revokes all refresh tokens issued to the user at once (shown on screen as "token reissue".
    /// ADR-0047). The same operation the user presses from the security screen, performed by an admin specifying the target.
    ///
    /// **Only tokens are dropped**; sessions and authenticators are not touched. For "the keys handed out to apps
    /// may have leaked", it provides a step that does not need to go as far as disabling (= stopping work) or password reissue
    /// (= forcing the user to reset). To cut off whole devices use disable;
    /// if a device was lost use MFA removal.
    ///
    /// **It can be run on oneself too.** The self-ban on other lifecycle operations is meant to prevent lockout by
    /// mistake, but this operation keeps the browser's signed-in state, so it does not lock anyone out
    /// (same handling as unlocking).
    ///
    /// **If revocation fails, success is not returned** (fail-closed). Unlike password reissue or disabling,
    /// there is no other line of defense here such as "credentials have changed" or "the account is disabled". Since revocation is
    /// the only outcome, if it was missed the operation has failed (same standard as MFA removal).
    pub async fn reissue_tokens(
        &self,
        tenant: TenantContext,
        target: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<TokenReissue, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        let revoked = self
            .refresh_tokens
            .revoke_all_for_user(user.id, self.clock.now())
            .await
            .map_err(internal)?;

        // Only the target and the count go into the audit. Neither token values nor hashes are recorded.
        self.audit
            .record(
                AuditEventType::RefreshTokenRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("user={} refresh_tokens={revoked}", user.id)),
                ctx,
            )
            .await;
        Ok(TokenReissue {
            user_id: user.id,
            revoked,
        })
    }

    /// Counts the user's currently valid refresh tokens (task #83).
    ///
    /// The target is determined by [`Self::find_home_user`], same as reissue (only users whose home is the requested tenant).
    /// Users of other tenants are not counted, and `NotFound` is returned as if missing (existence cannot be guessed).
    /// The counting scope is not narrowed by tenant: reissue drops all of the user's tokens, so
    /// the count shown matches that (ADR-0047 "not narrowed by tenant").
    ///
    /// It is read-only, so nothing is audited (same handling as opening the user's details).
    pub async fn count_active_tokens(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<ActiveTokenCount, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        let refresh_tokens = self
            .refresh_tokens
            .count_active_for_user(user.id, self.clock.now())
            .await
            .map_err(internal)?;
        Ok(ActiveTokenCount {
            user_id: user.id,
            refresh_tokens,
        })
    }

    /// Immediately releases an account lock (AP6. Spec §17.1, §24.6).
    ///
    /// Locks have an expiry (no permanent lock), so they clear if left alone, but as progressive locking extends the time,
    /// "the user just mistyped yet cannot get in until tomorrow" happens. The helpdesk needs a way to
    /// **restore without making them wait**.
    ///
    /// Releasing **always clears `locked_until` and resets the failure count together**. Clearing only the expiry would leave
    /// the failure count over the threshold, so **the next single failure re-locks immediately**, and the progressive
    /// lock advances one stage (longer than before). What was meant as a release makes it worse.
    ///
    /// It can be run on oneself too (the self-ban on other lifecycle operations is meant to prevent lockout, and
    /// unlocking is the opposite operation). Running it on a user who is not locked is treated as success
    /// (idempotent. The outcome "released" is the same, and returning failure would make the screen red for nothing).
    ///
    /// The return value is "whether a lock was actually in place". Used by the screen to distinguish "released" from
    /// "was not locked to begin with".
    pub async fn unlock_account(
        &self,
        tenant: TenantContext,
        target: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<bool, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        let was_locked = user.is_locked_at(self.clock.now());

        self.users
            .update_login_state(user.id, 0, None)
            .await
            .map_err(internal)?;

        self.audit
            .record(
                AuditEventType::UserAccountUnlocked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!(
                    "user={} was_locked={} failed_attempts_cleared={}",
                    user.id, was_locked, user.failed_login_count
                )),
                ctx,
            )
            .await;
        Ok(was_locked)
    }

    /// Edits a user's profile (email, sign-in identifier, display name) (MT25).
    ///
    /// Like other lifecycle operations, targets are **only users whose home (HOME) is the requested tenant**. However,
    /// **one can edit oneself too** (the self-ban on other operations is meant to prevent lockout, and changing display name or email
    /// does not cause lockout. Operations would get stuck if admins could not fix their own email).
    ///
    /// The changed email is **treated as ownership guaranteed by the admin**, and stays verified (`email_verified`)
    /// (same policy as admin-created users. ADR-0009 §5, SEC6b). This avoids the user being unable to sign in
    /// right after an email change.
    ///
    /// `preferred_username` is the sign-in identifier (ADR-0009 §8), and changing it **changes that user's sign-in
    /// name**. An empty string means clearing, but clearing would make password sign-in impossible, so
    /// it is rejected with `Validation`.
    pub async fn update_profile(
        &self,
        tenant: TenantContext,
        target: Uuid,
        cmd: UpdateUserProfileCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<User, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        let tenant_id = tenant.tenant_id();
        let mut changed: Vec<&'static str> = Vec::new();

        let email = match cmd.email.as_deref().map(str::trim) {
            Some(email) if email != user.email => {
                validate_email(email).map_err(UserLifecycleError::Validation)?;
                // Pre-check uniqueness (for an understandable error). The final guarantee is the DB UNIQUE constraint.
                if self
                    .users
                    .find_by_email(tenant_id, email)
                    .await
                    .map_err(internal)?
                    .is_some()
                {
                    return Err(UserLifecycleError::Conflict(MessageKey::new(
                        "api-user-email-conflict",
                    )));
                }
                changed.push("email");
                email.to_string()
            }
            _ => user.email.clone(),
        };

        let preferred_username = match cmd.preferred_username.as_deref().map(str::trim) {
            Some(value) if Some(value) != user.preferred_username.as_deref() => {
                if value.is_empty() {
                    return Err(UserLifecycleError::Validation(MessageKey::new(
                        "api-username-required",
                    )));
                }
                validate_preferred_username(value).map_err(UserLifecycleError::Validation)?;
                // Same lookup as the resolution path (AP8). Renaming to an alias sign-in identifier (a value only in the registry)
                // slips past the unique constraint on `users` but fails when syncing the registry.
                // Even one's own alias causes the same conflict, so it is rejected uniformly (ambiguous values are also "in use".
                // `LoginIdentifierMatch::is_taken`).
                if self
                    .users
                    .find_by_login_identifier(tenant_id, value)
                    .await
                    .map_err(internal)?
                    .is_taken()
                {
                    return Err(UserLifecycleError::Conflict(MessageKey::new(
                        "api-user-username-conflict",
                    )));
                }
                changed.push("preferred_username");
                Some(value.to_string())
            }
            _ => user.preferred_username.clone(),
        };

        let name = match cmd.name.as_deref().map(str::trim) {
            Some(value) => {
                validate_display_name(value).map_err(UserLifecycleError::Validation)?;
                // An empty string clears the display name (`NULL`).
                let next = (!value.is_empty()).then(|| value.to_string());
                if next != user.name {
                    changed.push("name");
                }
                next
            }
            None => user.name.clone(),
        };

        if changed.is_empty() {
            // If nothing changed, neither write nor audit (do not fill the audit log with empty rows).
            return Ok(user);
        }

        self.users
            .update_profile(
                user.id,
                &email,
                preferred_username.as_deref(),
                name.as_deref(),
            )
            .await
            .map_err(|e| match e {
                // Only a race with the pre-check (concurrent update). The DB does not tell which unique key it was.
                crate::domain::error::DomainError::Conflict(_) => {
                    UserLifecycleError::Conflict(MessageKey::new("api-user-identity-conflict"))
                }
                other => internal(other),
            })?;

        // Only the target and "names of changed fields" are recorded in the audit (email and display name themselves are PII, so not output).
        self.audit
            .record(
                AuditEventType::UserProfileUpdated,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("user={} fields={}", user.id, changed.join(","))),
                ctx,
            )
            .await;

        Ok(User {
            email,
            preferred_username,
            name,
            ..user
        })
    }

    /// Deletes a user. Related rows (memberships, permissions, sessions, tokens, MFA credentials) are
    /// cleaned up by the DB's FK CASCADE / SET NULL.
    pub async fn delete_user(
        &self,
        tenant: TenantContext,
        target: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<(), UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        self.ensure_not_self(user.id, actor)?;
        self.users.delete(user.id).await.map_err(internal)?;
        self.audit
            .record(
                AuditEventType::UserDeleted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("user={}", user.id)),
                ctx,
            )
            .await;
        Ok(())
    }

    /// Removes a user's MFA (TOTP, Passkey) (MT21). A recovery means for when the user lost their device and cannot
    /// remove it themselves.
    ///
    /// Removes TOTP and Passkey **both together**. If one remained, the user still could not sign in,
    /// and it would not work as a recovery means. Even if already unset it is not an error; the result says what was removed
    /// (so the admin can confirm "did it take effect").
    ///
    /// Also revokes that user's SSO sessions, refresh tokens and unconsumed codes. The trigger for this operation
    /// is "a lost or stolen device", and that device may hold a live session
    /// (just removing MFA leaves the lost device's signed-in state as is).
    ///
    /// **If revocation fails, the whole operation fails** (unlike other lifecycle operations, not fail-open).
    /// With password reissue or disabling, even if revocation is missed another line of defense remains: the credentials themselves have changed /
    /// the account is disabled. For MFA removal revocation is the only line of defense, and it would create
    /// the mix-up of telling the admin "the stolen device's session was cut" while it is actually alive.
    /// MFA deletion has completed, but re-running is idempotent, so only the revocation can be redone.
    pub async fn reset_mfa(
        &self,
        tenant: TenantContext,
        target: Uuid,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<MfaReset, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        self.ensure_not_self(user.id, actor)?;

        // To return "how many were removed", check whether TOTP exists before deleting (delete is idempotent and returns no count).
        let totp_removed = self
            .totp_secrets
            .find_by_user_id(user.id)
            .await
            .map_err(internal)?
            .is_some();
        if totp_removed {
            self.totp_secrets.delete(user.id).await.map_err(internal)?;
        }
        let passkeys_removed = self
            .webauthn_credentials
            .delete_all_for_user(user.id)
            .await
            .map_err(internal)?;

        // Also revoke the authenticator registry (AP9) in the same operation. If missed, authenticators supposed to be removed
        // remain in the list, and old batches of recovery codes stay alive (= one could get in with the old paper).
        let now = self.clock.now();
        for authenticator_type in [
            AuthenticatorType::Totp,
            AuthenticatorType::WebAuthn,
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::EmailOtp,
        ] {
            self.authenticators
                .revoke_all_of_type(user.id, authenticator_type, now)
                .await
                .map_err(internal)?;
        }

        // If revocation fails, do not return success (the lost device's session would survive). Do not audit either.
        self.revoke_credentials_strict(&user).await?;

        // Only the target and the granularity of removed factors are recorded in the audit (no secrets or credentials).
        self.audit
            .record(
                AuditEventType::UserMfaReset,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!(
                    "user={} totp={} passkeys={}",
                    user.id,
                    if totp_removed { "removed" } else { "absent" },
                    passkeys_removed
                )),
                ctx,
            )
            .await;

        Ok(MfaReset {
            user_id: user.id,
            totp_removed,
            passkeys_removed,
        })
    }

    async fn reset_password_for(
        &self,
        tenant: TenantContext,
        user: &User,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<ResetUserPassword, UserLifecycleError> {
        // ⚠ **Fill with a value given to nobody** (ADR-0062). The purpose of reissue is to "make the current password
        //    stop working", so it is better that the replacing value itself is not known.
        //    The user sets it again via the setup link.
        let unknown_password = crypto::random_token(GENERATED_PASSWORD_BYTES);
        let password_hash = self.hasher.hash(&unknown_password).map_err(internal)?;
        // Replacement conditioned on the current hash (AP7). Returning success after losing would leave the generated
        // password handed to the admin not actually set (the value told to the user would be a lie).
        let replaced = self
            .users
            .reset_password_forced(user.id, &user.password_hash, &password_hash)
            .await
            .map_err(internal)?;
        if !replaced {
            return Err(UserLifecycleError::Conflict(MessageKey::new(
                "api-user-password-changed-concurrently",
            )));
        }
        self.password_policy
            .record_change(user.tenant_id, user.id, &user.password_hash)
            .await;
        // Revoke sessions and tokens issued under the old credentials (not fail-open: failures are only logged.
        // The password has already been updated, and signing in with the old password is impossible).
        self.revoke_credentials(user).await;
        // Only the internal ID is recorded in the audit (the generated password is not output. §5).
        self.audit
            .record(
                AuditEventType::UserPasswordReset,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("user={}", user.id)),
                ctx,
            )
            .await;
        // A link for the user to set it again themselves. ⚠ **If it cannot be issued, return failure**: the old password
        // is already invalid, so returning a result without a link as success would fail to convey only one thing, "someone can no longer get in".
        // Pressing reissue again redoes it with a new link.
        let setup_link = self
            .account_setup
            .issue(user.tenant_id, user.id)
            .await
            .map_err(|e| UserLifecycleError::Internal(e.to_string()))?;

        Ok(ResetUserPassword {
            user_id: user.id,
            setup_link,
        })
    }

    /// Resolves a user whose home (HOME) is the requested tenant. Missing or cross-tenant is uniformly `NotFound`
    /// (prevents guessing existence).
    async fn find_home_user(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<User, UserLifecycleError> {
        match self.users.find_by_id(target).await.map_err(internal)? {
            Some(user) if user.tenant_id == tenant.tenant_id() => Ok(user),
            _ => Err(UserLifecycleError::NotFound),
        }
    }

    /// Refuses operations on oneself (disable, delete, password reissue, etc.).
    ///
    /// A client principal is not a user, so it matches no user (= always passes). There is no path
    /// for a machine to "disable itself and get stuck".
    fn ensure_not_self(&self, target: Uuid, actor: &AdminActor) -> Result<(), UserLifecycleError> {
        if actor.user_id() == Some(target) {
            return Err(UserLifecycleError::Forbidden(MessageKey::new(
                "api-user-self-operation-forbidden",
            )));
        }
        Ok(())
    }

    /// Revokes credentials, **logging failures and moving on** (fail-open).
    ///
    /// Used from password reissue and disabling. For these, even if revocation is missed, other lines of defense remain,
    /// "the password has changed" and "the account is disabled", so failing the whole operation on a transient DB error
    /// does more operational harm. For MFA removal, where revocation is the only line of defense, use
    /// [`revoke_credentials_strict`](Self::revoke_credentials_strict).
    async fn revoke_credentials(&self, user: &User) {
        let user_id = user.id;
        let now = self.clock.now();
        if let Err(e) = self.sso_sessions.delete_all_for_user(user_id).await {
            tracing::warn!(error = %e, "failed to revoke SSO sessions in user lifecycle operation");
        }
        match self.refresh_tokens.revoke_all_for_user(user_id, now).await {
            Ok(count) => tracing::info!(refresh_tokens = count, "revoked refresh tokens"),
            Err(e) => {
                tracing::warn!(error = %e, "failed to revoke refresh tokens in user lifecycle operation")
            }
        }
        if let Err(e) = self.codes.revoke_all_active_for_user(user_id, now).await {
            tracing::warn!(error = %e, "failed to revoke authorization codes in user lifecycle operation");
        }
        self.stop_announcement
            .announce_all_sessions_ended(user.tenant_id, user.sub)
            .await;
    }

    /// Revokes credentials, **reporting to the caller if even one fails** (fail-closed).
    ///
    /// Even if one fails midway the rest are attempted (revoking partially is the safer side). Returns the first error.
    async fn revoke_credentials_strict(&self, user: &User) -> Result<(), UserLifecycleError> {
        let user_id = user.id;
        let now = self.clock.now();
        let mut first_error = None;
        let mut remember = |label: &str, result: crate::domain::error::Result<()>| {
            if let Err(e) = result {
                tracing::error!(error = %e, credential = label, "failed to revoke credentials");
                first_error.get_or_insert_with(|| internal(e));
            }
        };
        remember(
            "sso_session",
            self.sso_sessions.delete_all_for_user(user_id).await,
        );
        remember(
            "refresh_token",
            self.refresh_tokens
                .revoke_all_for_user(user_id, now)
                .await
                .map(|_| ()),
        );
        remember(
            "authorization_code",
            self.codes.revoke_all_active_for_user(user_id, now).await,
        );
        match first_error {
            Some(e) => Err(e),
            None => {
                // Notify only when fully revoked. Saying "stopped" in a failed state would make the RP
                // close while the session remains on the assay side (the inconsistency could not be traced later).
                self.stop_announcement
                    .announce_all_sessions_ended(user.tenant_id, user.sub)
                    .await;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::authorization_code::AuthorizationCode;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::password::PasswordHasher as PasswordHasherTrait;
    use crate::domain::refresh_token::RefreshToken;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::sso_session::SsoSession;
    use crate::domain::tenant::TenantId;
    use crate::domain::totp_secret::TotpSecret;
    use crate::domain::webauthn_credential::WebAuthnCredential;
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

    struct PlainHasher;
    impl PasswordHasherTrait for PlainHasher {
        fn hash(&self, password: &str) -> DomainResult<String> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> DomainResult<bool> {
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
        forced_resets: Mutex<Vec<Uuid>>,
        deleted: Mutex<Vec<Uuid>>,
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
        async fn find_by_username(&self, t: TenantId, n: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.tenant_id == t && u.preferred_username.as_deref() == Some(n))
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
            id: Uuid,
            expected: &str,
            password_hash: &str,
        ) -> DomainResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            // The same compare-and-swap as the production implementation (rewrites only when the current hash matches).
            let Some(user) = rows
                .iter_mut()
                .find(|u| u.id == id && u.password_hash == expected)
            else {
                return Ok(false);
            };
            user.password_hash = password_hash.to_string();
            user.must_change_password = true;
            self.forced_resets.lock().unwrap().push(id);
            Ok(true)
        }
        async fn update_status(&self, id: Uuid, status: UserStatus) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            let user = rows
                .iter_mut()
                .find(|u| u.id == id)
                .ok_or_else(|| DomainError::Repository("not found".into()))?;
            user.status = status;
            Ok(())
        }
        async fn delete(&self, id: Uuid) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|u| u.id != id);
            self.deleted.lock().unwrap().push(id);
            Ok(())
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_profile(
            &self,
            id: Uuid,
            email: &str,
            preferred_username: Option<&str>,
            name: Option<&str>,
        ) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            let user = rows
                .iter_mut()
                .find(|u| u.id == id)
                .ok_or_else(|| DomainError::Repository("not found".into()))?;
            user.email = email.to_string();
            user.preferred_username = preferred_username.map(str::to_string);
            user.name = name.map(str::to_string);
            Ok(())
        }
    }

    /// Fake of the authenticator registry. Records only "which kinds were revoked" by MFA removal
    /// (other methods are fine with the trait's default implementation = not found).
    #[derive(Default)]
    struct FakeAuthenticators {
        revoked_types: Mutex<Vec<AuthenticatorType>>,
    }
    #[async_trait]
    impl UserAuthenticatorRepository for FakeAuthenticators {
        async fn create(
            &self,
            _a: &crate::domain::user_authenticator::UserAuthenticator,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke_all_of_type(
            &self,
            _u: Uuid,
            authenticator_type: AuthenticatorType,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            self.revoked_types.lock().unwrap().push(authenticator_type);
            Ok(0)
        }
    }

    #[derive(Default)]
    struct FakeSsoSessions {
        revoked_users: Mutex<Vec<Uuid>>,
        /// When `true`, revocation fails with a DB error (for verifying fail-closed).
        fail_revoke: Mutex<bool>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, _h: &str) -> DomainResult<Option<SsoSession>> {
            unreachable!()
        }
        async fn extend_idle(&self, _h: &str, _i: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, user_id: Uuid) -> DomainResult<()> {
            if *self.fail_revoke.lock().unwrap() {
                return Err(DomainError::Repository("connection lost".into()));
            }
            self.revoked_users.lock().unwrap().push(user_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRefreshTokens {
        revoked_users: Mutex<Vec<Uuid>>,
        /// Whom `count_active_for_user` counted (to check whether it went to count).
        counted_users: Mutex<Vec<Uuid>>,
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
            // Lifecycle operations revoke everything per user (per-tenant revocation is only for suspending
            // guests (MT24)).
            unreachable!()
        }
        async fn create(&self, _t: &RefreshToken) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(
            &self,
            _tenant: TenantId,
            _h: &str,
        ) -> DomainResult<Option<RefreshToken>> {
            unreachable!()
        }
        async fn revoke(&self, _h: &str, _now: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn exists_by_parent_hash(&self, _p: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn revoke_all_for_user(
            &self,
            user_id: Uuid,
            _now: DateTime<Utc>,
        ) -> DomainResult<u64> {
            self.revoked_users.lock().unwrap().push(user_id);
            Ok(1)
        }
        async fn count_active_for_user(
            &self,
            user_id: Uuid,
            _now: DateTime<Utc>,
        ) -> DomainResult<u64> {
            self.counted_users.lock().unwrap().push(user_id);
            Ok(2)
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
            _tenant: TenantId,
            _code_hash: &crate::domain::authorization_code::AuthorizationCodeHash,
            _now: DateTime<Utc>,
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
    struct FakeTotpSecrets {
        rows: Mutex<Vec<TotpSecret>>,
        deleted: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl TotpSecretRepository for FakeTotpSecrets {
        async fn upsert(&self, secret: &TotpSecret) -> DomainResult<()> {
            self.rows.lock().unwrap().push(secret.clone());
            Ok(())
        }
        async fn find_by_user_id(&self, user_id: Uuid) -> DomainResult<Option<TotpSecret>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.user_id == user_id)
                .cloned())
        }
        async fn confirm(&self, _id: Uuid, _at: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, user_id: Uuid) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|s| s.user_id != user_id);
            self.deleted.lock().unwrap().push(user_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeWebAuthnCredentials {
        rows: Mutex<Vec<(Uuid, Uuid)>>,
    }
    #[async_trait]
    impl WebAuthnCredentialRepository for FakeWebAuthnCredentials {
        async fn create(&self, _c: &WebAuthnCredential) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, _id: Uuid) -> DomainResult<Option<WebAuthnCredential>> {
            unreachable!()
        }
        async fn find_by_credential_id(
            &self,
            _credential_id: &str,
        ) -> DomainResult<Option<WebAuthnCredential>> {
            unreachable!()
        }
        async fn list_by_user_id(&self, _user_id: Uuid) -> DomainResult<Vec<WebAuthnCredential>> {
            unreachable!()
        }
        async fn update_passkey(
            &self,
            _id: Uuid,
            _passkey_json: &str,
            _last_used_at: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid, _user_id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, user_id: Uuid) -> DomainResult<u64> {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|(_, owner)| *owner != user_id);
            Ok((before - rows.len()) as u64)
        }
    }

    fn user(id: Uuid, tenant: TenantId) -> User {
        User {
            id,
            tenant_id: tenant,
            sub: Uuid::new_v4(),
            email: format!("{id}@example.com"),
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: "hash:old".to_string(),
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

    fn totp_secret(user_id: Uuid) -> TotpSecret {
        TotpSecret {
            user_id,
            secret_encrypted: "ciphertext".to_string(),
            confirmed_at: Some(now()),
            created_at: now(),
            updated_at: now(),
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    struct Fixture {
        users: Arc<FakeUsers>,
        sso: Arc<FakeSsoSessions>,
        refresh: Arc<FakeRefreshTokens>,
        codes: Arc<FakeCodes>,
        totp: Arc<FakeTotpSecrets>,
        passkeys: Arc<FakeWebAuthnCredentials>,
        sink: Arc<CapturingSink>,
        announcer: Arc<RecordingAnnouncer>,
        svc: UserLifecycleService,
    }

    /// Looks only at "was the stop told to RPs". Actual delivery is the responsibility of
    /// `StopAnnouncementService`; here the fact that it was called is recorded.
    #[derive(Default)]
    struct RecordingAnnouncer {
        announced: std::sync::Mutex<Vec<(TenantId, Uuid)>>,
    }

    #[async_trait::async_trait]
    impl crate::application::stop_announcement::SessionStopAnnouncer for RecordingAnnouncer {
        async fn announce_all_sessions_ended(&self, tenant_id: TenantId, subject: Uuid) {
            self.announced.lock().unwrap().push((tenant_id, subject));
        }
    }

    fn fixture() -> Fixture {
        let users = Arc::new(FakeUsers::default());
        let sso = Arc::new(FakeSsoSessions::default());
        let refresh = Arc::new(FakeRefreshTokens::default());
        let codes = Arc::new(FakeCodes::default());
        let totp = Arc::new(FakeTotpSecrets::default());
        let passkeys = Arc::new(FakeWebAuthnCredentials::default());
        let sink = Arc::new(CapturingSink::default());
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock(now()))));
        let announcer = Arc::new(RecordingAnnouncer::default());
        let setup_tokens =
            Arc::new(crate::application::account_setup::testing::FakeSetupTokens::default());
        let svc = UserLifecycleService::new(
            Arc::new(FakeAuthenticators::default()),
            users.clone(),
            sso.clone(),
            refresh.clone(),
            codes.clone(),
            totp.clone(),
            passkeys.clone(),
            Arc::new(PlainHasher),
            Arc::new(
                crate::application::password_policy::PasswordPolicyService::without_history(
                    crate::application::tenant_settings::testing::tenant_settings_with_global(&[(
                        "PASSWORD_HISTORY_COUNT",
                        "0",
                    )]),
                    Arc::new(PlainHasher),
                    Arc::new(FixedClock(now())),
                ),
            ),
            audit,
            announcer.clone(),
            crate::application::account_setup::testing::link_issuer(
                setup_tokens.clone(),
                Arc::new(FixedClock(now())),
            ),
            Arc::new(FixedClock(now())),
        );
        Fixture {
            announcer,
            users,
            sso,
            refresh,
            codes,
            totp,
            passkeys,
            sink,
            svc,
        }
    }

    #[tokio::test]
    async fn resets_password_with_forced_change_and_revokes_credentials() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let reset = f
            .svc
            .reset_password(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("reset");

        // ⚠ **Only the link is returned** (ADR-0062). Nobody knows the replaced password.
        assert!(reset.setup_link.token.len() >= 32);
        assert!(reset.setup_link.url.contains(&reset.setup_link.token));
        let stored = f.users.rows.lock().unwrap()[0].clone();
        // The old value no longer passes (replaced by a different value).
        assert!(stored.password_hash.starts_with("hash:"));
        assert_ne!(stored.password_hash, "hash:old-password");
        assert!(stored.must_change_password);
        assert_eq!(*f.sso.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.refresh.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.codes.revoked_users.lock().unwrap(), vec![target]);
        // The link token has not leaked into the audit.
        let events = f.sink.events.lock().unwrap();
        assert_eq!(events[0].event_type, AuditEventType::UserPasswordReset);
        assert!(events.iter().all(|e| e
            .reason
            .as_deref()
            .map(|r| !r.contains(&reset.setup_link.token))
            .unwrap_or(true)));
    }

    #[tokio::test]
    async fn resets_password_by_email_within_tenant() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let reset = f
            .svc
            .reset_password_by_email(
                TenantContext::new(tenant),
                &format!("{target}@example.com"),
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("reset");
        assert_eq!(reset.user_id, target);
    }

    #[tokio::test]
    async fn rejects_cross_tenant_and_self_operations() {
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, other)).await.unwrap();

        // Cross-tenant: NotFound, same as missing.
        assert!(matches!(
            f.svc
                .reset_password(
                    TenantContext::new(tenant),
                    target,
                    &AdminActor::User(Uuid::now_v7()),
                    &ctx()
                )
                .await,
            Err(UserLifecycleError::NotFound)
        ));

        // Oneself: Forbidden.
        let own = Uuid::now_v7();
        f.users.create(&user(own, tenant)).await.unwrap();
        assert!(matches!(
            f.svc
                .delete_user(
                    TenantContext::new(tenant),
                    own,
                    &AdminActor::User(own),
                    &ctx()
                )
                .await,
            Err(UserLifecycleError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn disables_user_and_revokes_credentials() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        f.svc
            .set_status(
                TenantContext::new(tenant),
                target,
                UserStatus::Disabled,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("disable");
        assert_eq!(f.users.rows.lock().unwrap()[0].status, UserStatus::Disabled);
        assert_eq!(*f.sso.revoked_users.lock().unwrap(), vec![target]);

        // Re-enabling does not involve session revocation.
        f.svc
            .set_status(
                TenantContext::new(tenant),
                target,
                UserStatus::Active,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("enable");
        assert_eq!(f.users.rows.lock().unwrap()[0].status, UserStatus::Active);
        assert_eq!(f.sso.revoked_users.lock().unwrap().len(), 1);
    }

    /// ADR-0049 I7: the stop must reach the RPs.
    ///
    /// ⚠ Just deleting sessions on the assay side leaves RPs running on tokens they issued themselves.
    /// Since the reason for stopping is "the account was taken over", stopping is pointless unless this gets through.
    #[tokio::test]
    async fn telling_the_relying_parties_is_part_of_disabling_a_user() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let row = user(target, tenant);
        let sub = row.sub;
        f.users.create(&row).await.unwrap();

        f.svc
            .set_status(
                TenantContext::new(tenant),
                target,
                UserStatus::Disabled,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("disable");

        // Identified by `sub`, not the internal ID. That is the only thing the RP knows.
        assert_eq!(*f.announcer.announced.lock().unwrap(), vec![(tenant, sub)]);
    }

    /// Re-enabling notifies nobody (nothing was revoked).
    #[tokio::test]
    async fn re_enabling_a_user_announces_nothing() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        f.svc
            .set_status(
                TenantContext::new(tenant),
                target,
                UserStatus::Active,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("enable");

        assert!(f.announcer.announced.lock().unwrap().is_empty());
    }

    /// Password reissue and MFA removal also mean "that session can no longer be used", so they are handled the same.
    #[tokio::test]
    async fn resetting_a_password_also_reaches_the_relying_parties() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let row = user(target, tenant);
        let sub = row.sub;
        f.users.create(&row).await.unwrap();

        f.svc
            .reset_password(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("reset");

        assert_eq!(*f.announcer.announced.lock().unwrap(), vec![(tenant, sub)]);
    }

    #[tokio::test]
    async fn rejects_locked_status_from_administrators() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();
        assert!(matches!(
            f.svc
                .set_status(
                    TenantContext::new(tenant),
                    target,
                    UserStatus::Locked,
                    &AdminActor::User(Uuid::now_v7()),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::Validation(_))
        ));
    }

    /// MT21: removes both TOTP and Passkey, and also revokes sessions and tokens held by the lost device.
    #[tokio::test]
    async fn resets_both_mfa_factors_and_revokes_credentials() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let other = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();
        f.totp.upsert(&totp_secret(target)).await.unwrap();
        // Mix others' and the target's entries, and check that only the target's disappear.
        f.passkeys.rows.lock().unwrap().extend([
            (Uuid::now_v7(), target),
            (Uuid::now_v7(), target),
            (Uuid::now_v7(), other),
        ]);

        let reset = f
            .svc
            .reset_mfa(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("reset mfa");

        assert!(reset.totp_removed);
        assert_eq!(reset.passkeys_removed, 2);
        assert!(f.totp.rows.lock().unwrap().is_empty());
        assert_eq!(
            f.passkeys
                .rows
                .lock()
                .unwrap()
                .iter()
                .map(|(_, owner)| *owner)
                .collect::<Vec<_>>(),
            vec![other],
            "other users' passkeys must survive"
        );
        // Do not leave the lost device's live sessions.
        assert_eq!(*f.sso.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.refresh.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.codes.revoked_users.lock().unwrap(), vec![target]);

        let events = f.sink.events.lock().unwrap();
        assert_eq!(events[0].event_type, AuditEventType::UserMfaReset);
        let reason = events[0].reason.clone().unwrap_or_default();
        assert!(reason.contains("totp=removed"), "{reason}");
        assert!(reason.contains("passkeys=2"), "{reason}");
        // Do not output secrets to the audit.
        assert!(!reason.contains("secret"), "{reason}");
    }

    /// Does not fail even for users without MFA (admins operate without knowing whether it is set).
    #[tokio::test]
    async fn resetting_mfa_is_idempotent_when_nothing_is_configured() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let reset = f
            .svc
            .reset_mfa(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("reset mfa");
        assert!(!reset.totp_removed);
        assert_eq!(reset.passkeys_removed, 0);
        assert!(f.totp.deleted.lock().unwrap().is_empty());
    }

    /// MT21: if revocation fails, MFA removal does not return success (fail-closed).
    ///
    /// Prevents the mix-up of telling the admin "the stolen device's session was cut" while it is actually alive.
    /// If this reverted to fail-open, the audit would record success and the response would be 200.
    #[tokio::test]
    async fn mfa_reset_fails_when_credentials_cannot_be_revoked() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();
        f.totp.upsert(&totp_secret(target)).await.unwrap();
        *f.sso.fail_revoke.lock().unwrap() = true;

        let err = f
            .svc
            .reset_mfa(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect_err("revocation failure must fail the reset");
        assert!(matches!(err, UserLifecycleError::Internal(_)), "{err:?}");
        // On failure, no success is recorded in the audit.
        assert!(f.sink.events.lock().unwrap().is_empty());
        // Even if one side could not be revoked, the rest are attempted (revoke even partially).
        assert_eq!(*f.refresh.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.codes.revoked_users.lock().unwrap(), vec![target]);

        // Re-running is idempotent: succeeds once revocation recovers (MFA is already removed, so totp_removed = false).
        *f.sso.fail_revoke.lock().unwrap() = false;
        let reset = f
            .svc
            .reset_mfa(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("retry succeeds");
        assert!(!reset.totp_removed);
        assert_eq!(*f.sso.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(
            f.sink.events.lock().unwrap()[0].event_type,
            AuditEventType::UserMfaReset
        );
    }

    /// Users of other tenants and oneself are handled the same as other lifecycle operations.
    #[tokio::test]
    async fn resetting_mfa_rejects_cross_tenant_and_self() {
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let foreign = Uuid::now_v7();
        f.users.create(&user(foreign, other)).await.unwrap();
        assert!(matches!(
            f.svc
                .reset_mfa(
                    TenantContext::new(tenant),
                    foreign,
                    &AdminActor::User(Uuid::now_v7()),
                    &ctx()
                )
                .await,
            Err(UserLifecycleError::NotFound)
        ));

        let own = Uuid::now_v7();
        f.users.create(&user(own, tenant)).await.unwrap();
        assert!(matches!(
            f.svc
                .reset_mfa(
                    TenantContext::new(tenant),
                    own,
                    &AdminActor::User(own),
                    &ctx()
                )
                .await,
            Err(UserLifecycleError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn deletes_user() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        f.svc
            .delete_user(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("delete");
        assert!(f.users.rows.lock().unwrap().is_empty());
        assert_eq!(*f.users.deleted.lock().unwrap(), vec![target]);
        assert_eq!(
            f.sink.events.lock().unwrap()[0].event_type,
            AuditEventType::UserDeleted
        );
    }

    // ── Profile editing (MT25) ────────────────────────────────────────────────

    #[tokio::test]
    async fn updates_profile_and_audits_only_the_changed_field_names() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let updated = f
            .svc
            .update_profile(
                TenantContext::new(tenant),
                target,
                UpdateUserProfileCommand {
                    email: Some("  renamed@example.com  ".into()),
                    preferred_username: Some("renamed".into()),
                    name: Some("Renamed User".into()),
                },
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("updated");

        assert_eq!(updated.email, "renamed@example.com");
        assert_eq!(updated.preferred_username.as_deref(), Some("renamed"));
        assert_eq!(updated.name.as_deref(), Some("Renamed User"));
        // Treated as ownership guaranteed by the admin, so it stays verified (an email change must not make sign-in impossible).
        assert!(updated.email_verified);

        let stored = f.users.rows.lock().unwrap()[0].clone();
        assert_eq!(stored.email, "renamed@example.com");

        let events = f.sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::UserProfileUpdated);
        let reason = events[0].reason.clone().expect("reason");
        assert!(
            reason.contains("fields=email,preferred_username,name"),
            "{reason}"
        );
        // The values themselves (PII) are not output to the audit.
        assert!(!reason.contains("renamed@example.com"), "{reason}");
        assert!(!reason.contains("Renamed User"), "{reason}");
    }

    #[tokio::test]
    async fn updates_profile_partially_and_clears_the_display_name_with_an_empty_value() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let mut existing = user(target, tenant);
        existing.name = Some("Old Name".into());
        existing.preferred_username = Some("keep-me".into());
        f.users.create(&existing).await.unwrap();

        // Only name as an empty string = clearing the display name. email / preferred_username are unspecified, so unchanged.
        let updated = f
            .svc
            .update_profile(
                TenantContext::new(tenant),
                target,
                UpdateUserProfileCommand {
                    name: Some("   ".into()),
                    ..Default::default()
                },
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("updated");
        assert_eq!(updated.name, None);
        assert_eq!(updated.email, existing.email);
        assert_eq!(updated.preferred_username.as_deref(), Some("keep-me"));

        let reason = f.sink.events.lock().unwrap()[0]
            .reason
            .clone()
            .expect("reason");
        assert!(reason.contains("fields=name"), "{reason}");
    }

    #[tokio::test]
    async fn updating_profile_with_no_change_does_not_write_or_audit() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let existing = user(target, tenant);
        f.users.create(&existing).await.unwrap();

        f.svc
            .update_profile(
                TenantContext::new(tenant),
                target,
                UpdateUserProfileCommand {
                    email: Some(existing.email.clone()),
                    ..Default::default()
                },
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("no-op update");
        assert!(f.sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn updating_profile_rejects_duplicates_within_the_tenant() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();
        let mut other = user(Uuid::now_v7(), tenant);
        other.email = "taken@example.com".into();
        other.preferred_username = Some("taken".into());
        f.users.create(&other).await.unwrap();

        assert!(matches!(
            f.svc
                .update_profile(
                    TenantContext::new(tenant),
                    target,
                    UpdateUserProfileCommand {
                        email: Some("taken@example.com".into()),
                        ..Default::default()
                    },
                    &AdminActor::User(Uuid::now_v7()),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::Conflict(_))
        ));
        assert!(matches!(
            f.svc
                .update_profile(
                    TenantContext::new(tenant),
                    target,
                    UpdateUserProfileCommand {
                        preferred_username: Some("taken".into()),
                        ..Default::default()
                    },
                    &AdminActor::User(Uuid::now_v7()),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn updating_profile_rejects_invalid_input_and_clearing_the_login_identifier() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let mut existing = user(target, tenant);
        existing.preferred_username = Some("alice".into());
        f.users.create(&existing).await.unwrap();

        let invalid = |cmd| {
            let svc = &f.svc;
            async move {
                svc.update_profile(
                    TenantContext::new(tenant),
                    target,
                    cmd,
                    &AdminActor::User(Uuid::now_v7()),
                    &ctx(),
                )
                .await
            }
        };

        assert!(matches!(
            invalid(UpdateUserProfileCommand {
                email: Some("not-an-email".into()),
                ..Default::default()
            })
            .await,
            Err(UserLifecycleError::Validation(_))
        ));
        // Clearing the sign-in identifier would make password sign-in impossible, so it is rejected.
        assert!(matches!(
            invalid(UpdateUserProfileCommand {
                preferred_username: Some("".into()),
                ..Default::default()
            })
            .await,
            Err(UserLifecycleError::Validation(_))
        ));
        // Column length overflow is returned as an input error before persisting.
        assert!(matches!(
            invalid(UpdateUserProfileCommand {
                name: Some("x".repeat(256)),
                ..Default::default()
            })
            .await,
            Err(UserLifecycleError::Validation(_))
        ));
    }

    /// Unlike other lifecycle operations, profile editing can target oneself (it does not cause lockout).
    /// On the other hand, cross-tenant (home is another tenant) is `NotFound`, same as other operations.
    #[tokio::test]
    async fn updating_own_profile_is_allowed_but_cross_tenant_is_not() {
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let me = Uuid::now_v7();
        f.users.create(&user(me, tenant)).await.unwrap();

        f.svc
            .update_profile(
                TenantContext::new(tenant),
                me,
                UpdateUserProfileCommand {
                    name: Some("My Name".into()),
                    ..Default::default()
                },
                &AdminActor::User(me),
                &ctx(),
            )
            .await
            .expect("self edit is allowed");

        assert!(matches!(
            f.svc
                .update_profile(
                    TenantContext::new(other),
                    me,
                    UpdateUserProfileCommand {
                        name: Some("Hijack".into()),
                        ..Default::default()
                    },
                    &AdminActor::User(Uuid::now_v7()),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::NotFound)
        ));
    }

    /// An admin's token reissue drops **only tokens** (ADR-0047).
    ///
    /// Cutting sessions too would stop work and make it indistinguishable from disabling or password reissue.
    /// Since it is placed as a step that "replaces only the handed-out keys", it must not spread to anything else.
    #[tokio::test]
    async fn reissuing_tokens_revokes_tokens_only() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let result = f
            .svc
            .reissue_tokens(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(Uuid::now_v7()),
                &ctx(),
            )
            .await
            .expect("reissue");

        assert_eq!(result.user_id, target);
        assert_eq!(result.revoked, 1);
        assert_eq!(*f.refresh.revoked_users.lock().unwrap(), vec![target]);
        assert!(f.sso.revoked_users.lock().unwrap().is_empty());
        assert!(f.codes.revoked_users.lock().unwrap().is_empty());

        let events = f.sink.events.lock().unwrap();
        assert_eq!(events[0].event_type, AuditEventType::RefreshTokenRevoked);
        assert!(events[0]
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("refresh_tokens=1")));
    }

    /// It can be run on oneself too (unlike disable and delete, it does not lock anyone out).
    #[tokio::test]
    async fn reissuing_your_own_tokens_is_allowed() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        assert!(f
            .svc
            .reissue_tokens(
                TenantContext::new(tenant),
                target,
                &AdminActor::User(target),
                &ctx(),
            )
            .await
            .is_ok());
    }

    /// It does not reach users whose home is another tenant (same check as other lifecycle operations).
    #[tokio::test]
    async fn reissuing_tokens_for_another_tenants_user_is_not_found() {
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, other)).await.unwrap();

        assert!(matches!(
            f.svc
                .reissue_tokens(
                    TenantContext::new(tenant),
                    target,
                    &AdminActor::User(Uuid::now_v7()),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::NotFound)
        ));
        assert!(f.refresh.revoked_users.lock().unwrap().is_empty());
    }

    /// The number of valid tokens is counted only for home users, and nothing is dropped (task #83).
    #[tokio::test]
    async fn counting_active_tokens_reads_without_revoking() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let count = f
            .svc
            .count_active_tokens(TenantContext::new(tenant), target)
            .await
            .expect("count");

        assert_eq!(count.user_id, target);
        assert_eq!(count.refresh_tokens, 2);
        assert_eq!(*f.refresh.counted_users.lock().unwrap(), vec![target]);
        assert!(f.refresh.revoked_users.lock().unwrap().is_empty());
        assert!(
            f.sink.events.lock().unwrap().is_empty(),
            "reads are not audited"
        );
    }

    /// Users whose home is another tenant are not counted (same check as reissue. Existence cannot be guessed either).
    #[tokio::test]
    async fn counting_active_tokens_for_another_tenants_user_is_not_found() {
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, other)).await.unwrap();

        assert!(matches!(
            f.svc
                .count_active_tokens(TenantContext::new(tenant), target)
                .await,
            Err(UserLifecycleError::NotFound)
        ));
        assert!(f.refresh.counted_users.lock().unwrap().is_empty());
    }
}
