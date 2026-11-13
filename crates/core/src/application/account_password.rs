//! Use case: self-service password change (settings screen of a logged-in user; MT15).
//!
//! Separate from the forced change during the login flow ([`crate::application::change_password`], `auth_session` based),
//! this provides a route for **a logged-in user with an SSO session** to change their password voluntarily.
//! It resolves the user from the SSO session cookie, re-verifies the current password, then sets the new one.
//! It is not part of an OIDC flow, so no code reissue or redirect happens (the user stays on the settings screen).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::password_policy::PasswordPolicyService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::PasswordRejection;
use crate::domain::repositories::{
    AuthorizationCodeRepository, RefreshTokenRepository, SsoSessionRepository, UserRepository,
};
use std::sync::Arc;

pub struct AccountPasswordCommand {
    /// Raw value of the SSO session cookie (looked up in the DB by its SHA-256 hash).
    pub sso_session_id: String,
    pub current_password: String,
    pub new_password: String,
}

pub enum AccountPasswordOutcome {
    Ok,
    /// No SSO session, or it has expired (treated as logged out).
    SessionExpired,
    /// The current password does not match.
    InvalidCurrentPassword,
    /// The new password does not satisfy the policy (length, breached, reused; AP7).
    WeakPassword(PasswordRejection),
    Internal(String),
}

pub struct AccountPasswordService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    /// Used to sign out other devices after the change (ADR-0045).
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    hasher: Arc<dyn PasswordHasher>,
    password_policy: Arc<PasswordPolicyService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountPasswordService {
    // These are injected dependencies; bundling them would only make it harder to read (same as `LogoutService::new`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            refresh_tokens,
            codes,
            hasher,
            password_policy,
            audit,
            clock,
        }
    }

    pub async fn change(
        &self,
        cmd: AccountPasswordCommand,
        ctx: &RequestContext,
    ) -> AccountPasswordOutcome {
        let now = self.clock.now();

        // 1. Resolve the user from the SSO session (also checks expiry).
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return AccountPasswordOutcome::SessionExpired,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        let user = match self.users.find_by_id(session.user_id).await {
            Ok(Some(u)) if u.is_active() => u,
            Ok(_) => return AccountPasswordOutcome::SessionExpired,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };

        // 2. Re-verify the current password.
        let verified = match self
            .hasher
            .verify(&cmd.current_password, &user.password_hash)
        {
            Ok(v) => v,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        if !verified {
            return AccountPasswordOutcome::InvalidCurrentPassword;
        }

        // 3. Check the new password satisfies the policy (length, breached, reused; AP7),
        //    then hash and save it.
        match self
            .password_policy
            .validate(
                user.tenant_id,
                Some(user.id),
                Some(&user.password_hash),
                &cmd.new_password,
            )
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(rejection)) => return AccountPasswordOutcome::WeakPassword(rejection),
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        };
        // Replacement conditioned on the current hash (AP7). `false` means another request changed the
        // password between our read and write. Writing here would erase their change and push an
        // already retired hash into the history, so make the user retry.
        match self
            .users
            .update_password(user.id, &user.password_hash, &new_hash)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!("password change lost a concurrent update; asking to retry");
                return AccountPasswordOutcome::InvalidCurrentPassword;
            }
            Err(e) => return AccountPasswordOutcome::Internal(e.to_string()),
        }
        self.password_policy
            .record_change(user.tenant_id, user.id, &user.password_hash)
            .await;

        // 4. After the change, cut off other devices and apps (ADR-0045).
        //
        // Without this it would disagree with the link-based reset (`password_reset`, which drops everything
        // and whose screen states "all existing sessions have been signed out").
        // For someone changing it because "it may have leaked", **an intruder who got in with the old
        // password staying signed in even after the change** defeats the point of this operation.
        //
        // **Only the current session is kept.** Calling `delete_all_for_user` would lock the person who
        // changed it out on the spot. The reset route may delete everything because it is the route for
        // "people who forgot" who have no session at hand; the situation here differs.
        //
        // Refresh tokens are **all dropped, none kept**. Unlike the SSO session, they are duplicate keys
        // held by apps, and once the password changed, they may be made to re-obtain them. The session at
        // hand is alive, so re-obtaining passes straight through SSO.
        //
        // Failure does not stop it (fail-open). **The password has already changed**, and login with the
        // old password is no longer possible. Returning `Internal` here would read as "not changed".
        // The reset route makes the same call and only logs a warning.
        match self
            .sso_sessions
            .delete_all_for_user_except(user.id, &session_hash)
            .await
        {
            Ok(count) => tracing::info!(sessions = count, "signed out other sessions"),
            Err(e) => {
                tracing::warn!(error = %e, "failed to sign out other sessions after password change")
            }
        }
        match self.refresh_tokens.revoke_all_for_user(user.id, now).await {
            Ok(count) => tracing::info!(refresh_tokens = count, "revoked refresh tokens"),
            Err(e) => {
                tracing::warn!(error = %e, "failed to revoke refresh tokens after password change")
            }
        }
        if let Err(e) = self.codes.revoke_all_active_for_user(user.id, now).await {
            tracing::warn!(error = %e, "failed to revoke authorization codes after password change");
        }

        self.audit
            .record(
                AuditEventType::PasswordChanged,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;

        AccountPasswordOutcome::Ok
    }
}
