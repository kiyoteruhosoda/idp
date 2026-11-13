//! MFA login verification use case.
//!
//! Password authentication has been completed by `LoginService` (`auth_sessions.password_verified_at` is set).
//! This service verifies the TOTP code and, on success, issues the SSO session -> consent check -> code issuance.
//! The second half of the flow is shared with `LoginService` (reusing `CodeIssuanceService`).
//!
//! Brute-force countermeasures are the same two layers as `LoginService` (SEC3):
//!
//! * A per-IP sliding window (`LoginRateLimiter`; consumes the same bucket as password authentication)
//! * A per-user failure count and timed lock (`LockoutPolicy`; shares `users.failed_login_count` /
//!   `locked_until` with password authentication)
//!
//! A 6-digit TOTP has a search space of only 10^6, and allowing unlimited attempts during the auth_session's lifetime
//! (600 seconds by default) would let an attacker who stole the password break MFA, so neither can be omitted.
//!
//! The failure counter is reset **here, on TOTP success**. `LoginService` doesn't reset it on password success alone
//! (clearing it there would let the lock be bypassed just by logging in again in between).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::authenticator_management::{
    consume_single_use_code, is_blocked_in_registry,
};
use crate::application::sign_in_completion::{
    AuthorizationContinuation, Establishment, SignIn, SignInCompletion,
};
use crate::application::totp_registration::verify_totp_code;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSessionIdHash;
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{
    AuthSessionRepository, TotpSecretRepository, UserAuthenticatorRepository, UserRepository,
};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::user_authenticator::AuthenticatorType;
use crate::domain::values::AuthenticationMethod;
use std::sync::Arc;
use uuid::Uuid;

pub enum MfaLoginOutcome {
    /// TOTP verified and consented. 302 to redirect_to with the code.
    Success {
        location: String,
        /// Hidden fields to POST for `form_post` (G12). `None` means `query`.
        form_post: Option<Vec<(String, String)>>,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
        /// The user's display language setting (MT20). web overwrites the `lang` cookie with this value.
        user_language: Option<String>,
    },
    /// TOTP verified but consent is needed. Send to the consent screen.
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    /// No AuthSession, expired, or not in the MFA pending state (start over from `/authorize`).
    SessionExpired,
    /// CSRF token mismatch.
    CsrfMismatch,
    /// Invalid TOTP code.
    InvalidCode,
    /// Hit the per-IP rate limit (SEC3).
    RateLimited,
    /// The account is locked (consecutive failures, or already locked by failures on other paths. SEC3).
    Locked,
    /// Denied by the authentication policy (AP2/AP3). Even after passing the second factor, it comes here if the policy
    /// changed to `deny` or the method doesn't satisfy `require_specific_method`.
    /// Authentication passed, but use of this application is not permitted (ADR-0054). ⚠ **Do not return to the RP.**
    /// The SSO session is issued (the user is signed in to assay), so other applications proceed as usual.
    ApplicationNotPermitted {
        /// Application name shown on screen. Without knowing which application refused them, the user
        /// cannot decide whom to ask next.
        application_name: String,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    PolicyDenied,
    /// Internal error.
    /// Authentication passed, but in an organization limited to registered devices this device is not registered (task #916).
    /// No SSO session was created. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
    Internal(String),
}

pub struct MfaLoginCommand {
    pub auth_session_id: Option<String>,
    pub totp_code: String,
    pub csrf_token: String,
}

pub struct MfaLoginService {
    /// The authenticator registry (AP9). Used to consume recovery codes and email OTPs. Only consumption is needed, so
    /// it takes the repository directly rather than the whole management use case (normalization is enclosed in a shared function).
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    users: Arc<dyn UserRepository>,
    /// Shared tail after authentication succeeds (establishing SSO, continuing the authorization flow).
    sign_in: Arc<SignInCompletion>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
    /// Settings tenants can override (ADR-0058). Looked up every time. The default behavior when no policy
    /// matches (AP2, §4) is also taken from here.
    settings: Arc<dyn EffectiveTenantSettings>,
    csrf_secret: [u8; 32],
    /// Authentication policy evaluation (looking up inputs and evaluating. `authentication_policy_gate`).
    policy_gate: Arc<AuthenticationPolicyGate>,
}

impl MfaLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        users: Arc<dyn UserRepository>,
        sign_in: Arc<SignInCompletion>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
        settings: Arc<dyn EffectiveTenantSettings>,
        csrf_secret: [u8; 32],
        policy_gate: Arc<AuthenticationPolicyGate>,
    ) -> Self {
        Self {
            authenticators,
            auth_sessions,
            totp_secrets,
            users,
            sign_in,
            rate_limiter,
            audit,
            clock,
            key_encryption_key,
            settings,
            csrf_secret,
            policy_gate,
        }
    }

    pub async fn verify(
        &self,
        tenant: TenantContext,
        cmd: MfaLoginCommand,
        ctx: &RequestContext,
    ) -> MfaLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Fetch the AuthSession from auth_session_id (limited to the flow's tenant).
        let Some(session_id) = cmd.auth_session_id.as_deref().filter(|s| !s.is_empty()) else {
            return MfaLoginOutcome::SessionExpired;
        };
        let mut session = match self
            .auth_sessions
            .find(tenant_id, &AuthSessionIdHash::of_plain(session_id))
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return MfaLoginOutcome::SessionExpired,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return MfaLoginOutcome::SessionExpired;
        }

        // 2. Check it's in the MFA pending state (password_verified_at must be set).
        let Some(user_id) = session.password_verified_user() else {
            return MfaLoginOutcome::SessionExpired;
        };

        // 3. Verify the CSRF token (same derivation as login_csrf_token).
        if !assay_contracts::csrf::verify(
            &assay_contracts::csrf::login_csrf_token(session_id, &self.csrf_secret),
            &cmd.csrf_token,
        ) {
            return MfaLoginOutcome::CsrfMismatch;
        }

        let client_id = session.client_id().to_string();

        // 4. Per-IP rate limit (SEC3). It consumes the same bucket as password authentication, so the path of logging in
        //    with stolen credentials and then hammering TOTP is subject to the same limit.
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.record_failure(tenant_id, None, &client_id, "ip_rate_limited", ctx)
                    .await;
                return MfaLoginOutcome::RateLimited;
            }
        }

        // 5. Fetch the user and check it is active.
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return MfaLoginOutcome::SessionExpired,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        // 5.1. Check the lock state (SEC3). It looks at the same `locked_until` as password authentication, so
        //      accounts locked by consecutive password failures are also rejected on this path.
        if user.is_locked_at(now) {
            self.audit
                .record(
                    AuditEventType::LoginLocked,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some("account_locked"),
                    ctx,
                )
                .await;
            return MfaLoginOutcome::Locked;
        }
        if !user.is_active() {
            return MfaLoginOutcome::Internal("user not active".to_string());
        }

        // 6. Verify the second factor. There is one input field accepting TOTP, recovery codes or email OTP
        //    (AP9). Making users who lost their authenticator move to a different input screen would make reaching that
        //    screen a precondition for recovery. Instead of branching on the value's format, check them in order (all are
        //    compared against stored secrets, so they can't be mixed up).
        let second_factor = match self
            .verify_second_factor(tenant_id, user_id, &cmd.totp_code, ctx)
            .await
        {
            Ok(Some(method)) => method,
            Ok(None) => {
                return self
                    .handle_totp_failure(tenant_id, &user, &client_id, now, ctx)
                    .await;
            }
            Err(e) => return MfaLoginOutcome::Internal(e),
        };

        // 6.5. Re-evaluate the authentication policy (AP3). Only here is **the final set of authentication methods**
        //      (password + the second factor that actually passed) fixed, so `require_specific_method` is
        //      checked at this point. Checking at the password stage would let a "WebAuthn required" policy be
        //      bypassed just by having TOTP registered.
        let used_methods = [AuthenticationMethod::Password, second_factor];
        let decision = match self
            .policy_gate
            .decide(PolicyQuery {
                tenant_id,
                audience: PolicyAudience::OidcClient(&client_id),
                user_id,
                ip_address: ctx.ip_address.as_deref(),
                requested_acr: &session.request().requested_acr(),
                now,
            })
            .await
        {
            Ok(decision) => decision,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        if let PolicyDecision::Deny { policy_code } = &decision {
            self.record_failure(tenant_id, Some(user_id), &client_id, "policy_denied", ctx)
                .await;
            tracing::info!(policy = %policy_code, "MFA login denied by authentication policy");
            return MfaLoginOutcome::PolicyDenied;
        }
        // WebAuthn doesn't go through this path (passkeys use `PasskeyAuthenticationService`), so
        // User Verification is always treated as not performed.
        if let Some(unmet) = decision.unmet_method_requirement(&used_methods, false) {
            self.record_failure(tenant_id, Some(user_id), &client_id, "method_required", ctx)
                .await;
            tracing::info!(
                policy = %unmet.policy_code,
                required = %unmet.requirement.describe(),
                "MFA login denied: required authentication method not used"
            );
            return MfaLoginOutcome::PolicyDenied;
        }

        // 7. Success: reset the failure counter and lock (same as on password authentication success).
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return MfaLoginOutcome::Internal(e.to_string());
            }
        }

        // 8. Establish the SSO session and continue the authorization flow (consent check -> code issuance).
        let sso = match self
            .sign_in
            .establish_sso(
                SignIn {
                    tenant_id,
                    user_id,
                    home_tenant_id: user.tenant_id,
                    methods: vec![AuthenticationMethod::Password, second_factor],
                    client_id: Some(&client_id),
                    success_event: AuditEventType::LoginSucceeded,
                    success_detail: None,
                },
                ctx,
                now,
            )
            .await
        {
            Ok(Establishment::Established(sso)) => sso,
            Ok(Establishment::DeviceEnrollmentRequired { ticket }) => {
                return MfaLoginOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        let sso_session_id = sso.session_id().to_string();
        let sso_absolute_ttl_secs = sso.absolute_ttl_secs();
        match self
            .sign_in
            .continue_authorization(tenant, &mut session, &sso, now, ctx)
            .await
        {
            Ok(AuthorizationContinuation::ConsentRequired { auth_session_id }) => {
                MfaLoginOutcome::ConsentRequired {
                    auth_session_id,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name }) => {
                MfaLoginOutcome::ApplicationNotPermitted {
                    application_name,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::Authorized(dispatch)) => MfaLoginOutcome::Success {
                location: dispatch.location,
                form_post: dispatch.form_post,
                sso_session_id,
                sso_absolute_ttl_secs,
                user_language: user.language.clone(),
            },
            Err(e) => MfaLoginOutcome::Internal(e.to_string()),
        }
    }

    /// Updates the failure count and decides locking on a TOTP mismatch (SEC3).
    ///
    /// Resolves the user awaiting MFA from `auth_session_id` (AP9; used to decide where to send the email OTP).
    /// Returns `None` unless the password has been verified (`password_verified_at` not NULL)
    /// —— so unauthenticated requests can't trigger sending mail.
    pub async fn pending_mfa_user(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> Option<Uuid> {
        let now = self.clock.now();
        let session = self
            .auth_sessions
            .find(
                tenant.tenant_id(),
                &AuthSessionIdHash::of_plain(auth_session_id),
            )
            .await
            .ok()
            .flatten()?;
        if session.is_expired_at(now) {
            return None;
        }
        session.password_verified_user()
    }

    /// Verifies the second factor (AP9). If it passes, returns the authentication method to record. If nothing matches,
    /// `Ok(None)` (the caller treats it as a failure).
    ///
    /// The check order is TOTP -> recovery code -> email OTP. TOTP is checked first to make the everyday path
    /// shortest (the latter two involve DB access).
    async fn verify_second_factor(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        code: &str,
        ctx: &RequestContext,
    ) -> Result<Option<AuthenticationMethod>, String> {
        // TOTP. If not set up, fall through to the next (users with only recovery codes and no TOTP can exist).
        // A TOTP stopped in the registry doesn't pass even if the secret remains (AP9; suspension and revocation are
        // only written to the registry, so without checking here "an authenticator that was supposedly stopped" would get in).
        let totp_blocked = is_blocked_in_registry(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::Totp,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;

        match self.totp_secrets.find_by_user_id(user_id).await {
            Ok(Some(record)) if record.is_confirmed() && !totp_blocked => {
                let secret = crypto::decrypt(&record.secret_encrypted, &self.key_encryption_key)
                    .map_err(|e| e.to_string())?;
                if let Some(step) = verify_totp_code(&secret, code).map_err(|e| e.to_string())? {
                    // Pass only if the accepted step could be recorded. Failing to record = reuse of the same (or an older)
                    // code, so even the correct 6 digits aren't accepted as a second factor (replay protection).
                    let recorded = self
                        .totp_secrets
                        .record_totp_step_if_newer(user_id, step as i64, self.clock.now())
                        .await
                        .map_err(|e| e.to_string())?;
                    if recorded {
                        return Ok(Some(AuthenticationMethod::Totp));
                    }
                }
            }
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }

        // Recovery code, email OTP, SMS OTP (all one-time). If consumed, accept as the second factor.
        let now = self.clock.now();
        for (authenticator_type, method) in [
            (
                AuthenticatorType::RecoveryCode,
                AuthenticationMethod::RecoveryCode,
            ),
            (AuthenticatorType::EmailOtp, AuthenticationMethod::EmailOtp),
            // SMS OTP (AP13). It's the same kind of "one-time code", so it is consumed on the same path.
            // Rows of registered phone numbers hold no secret, so they don't match here.
            (AuthenticatorType::SmsOtp, AuthenticationMethod::SmsOtp),
        ] {
            if consume_single_use_code(
                self.authenticators.as_ref(),
                user_id,
                authenticator_type,
                code,
                now,
            )
            .await
            .map_err(|e| e.to_string())?
            {
                self.audit
                    .record(
                        AuditEventType::RecoveryCodeUsed,
                        AuditResult::Success,
                        Some(tenant_id),
                        Some(user_id),
                        None,
                        Some(&format!("type={authenticator_type}")),
                        ctx,
                    )
                    .await;
                return Ok(Some(method));
            }
        }

        Ok(None)
    }

    /// The counter advances the same `users.failed_login_count` as password authentication
    /// (`LoginService::handle_password_failure`). A separate counter for MFA would leave room to escape the lock by
    /// spreading N-1 attempts on the password and N-1 on TOTP, so it is shared.
    async fn handle_totp_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        client_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        ctx: &RequestContext,
    ) -> MfaLoginOutcome {
        // The threshold is the value of the user's home tenant (unless it's the same tenant's value as password authentication,
        // the thresholds would disagree even with a shared counter. ADR-0058).
        let lockout = match self.settings.login_lockout(user.tenant_id).await {
            Ok(lockout) => lockout,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        // The increment and lock decision are kept in a single UPDATE statement (SEC13).
        let failure = match self.users.record_login_failure(user.id, lockout, now).await {
            Ok(f) => f,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };

        self.record_failure(tenant_id, Some(user.id), client_id, "invalid_totp", ctx)
            .await;

        if failure.is_locked() {
            self.audit
                .record(
                    AuditEventType::LoginLocked,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(client_id),
                    Some("too_many_failures"),
                    ctx,
                )
                .await;
            return MfaLoginOutcome::Locked;
        }
        MfaLoginOutcome::InvalidCode
    }

    async fn record_failure(
        &self,
        tenant_id: TenantId,
        user_id: Option<Uuid>,
        client_id: &str,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                user_id,
                Some(client_id),
                Some(reason),
                ctx,
            )
            .await;
    }

    /// Helper to get user_id when a user who needs no authentication (no TOTP) comes to the MFA endpoint.
    /// Only checks whether `auth_session_id` is in the MFA pending state.
    pub async fn has_mfa_pending(&self, tenant: TenantContext, auth_session_id: &str) -> bool {
        let Ok(Some(session)) = self
            .auth_sessions
            .find(
                tenant.tenant_id(),
                &AuthSessionIdHash::of_plain(auth_session_id),
            )
            .await
        else {
            return false;
        };
        session.password_verified_user().is_some()
    }
}

/// Whether the user `user_id` has a verified TOTP (for queries from other services).
pub async fn user_has_confirmed_totp(
    totp_secrets: &dyn TotpSecretRepository,
    user_id: Uuid,
) -> Result<bool, crate::domain::error::DomainError> {
    Ok(totp_secrets
        .find_by_user_id(user_id)
        .await?
        .map(|s| s.is_confirmed())
        .unwrap_or(false))
}

#[cfg(test)]
mod tests {
    //! Regression tests for SEC3 (TOTP brute-force countermeasures).
    //!
    //! `verify_totp_code` depends on the real time (`totp-rs`'s `check_current`), so only the success-path
    //! tests generate the current code with the same parameters. Failure paths are fine with a fixed invalid code.

    use super::*;
    use crate::application::code_issuance::CodeIssuanceService;
    use crate::domain::authorization_code::AuthorizationCode;
    use crate::domain::clock::Clock as ClockTrait;
    use crate::domain::consent::ClientConsent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::{
        AuditLogSink, ClientConsentRepository, SsoSessionRepository,
    };
    use crate::domain::sso_session::SsoSession;
    use crate::domain::totp_secret::TotpSecret;
    use crate::domain::values::UserStatus;
    use crate::domain::{auth_session, authorization_request};
    use crate::infrastructure::repositories::in_memory_auth_session::InMemoryAuthSessions;
    use async_trait::async_trait;
    use chrono::Duration;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    const TEST_KEY: [u8; 32] = *b"unit-test-key-0123456789abcdef!!";
    const CSRF_SECRET: [u8; 32] = *b"unit-test-csrf-0123456789abcdef!";
    const SESSION_ID: &str = "auth-session-id";
    const CLIENT_ID: &str = "client-a";
    /// TOTP secret (20 bytes = the recommended length for SHA-1).
    const TOTP_SECRET: &[u8] = b"12345678901234567890";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl ClockTrait for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    /// Generates a TOTP code valid at the real time (same parameters as `verify_totp_code`).
    fn current_totp_code() -> String {
        totp_rs::Builder::new()
            .with_algorithm(totp_rs::Algorithm::SHA1)
            .with_digits(6)
            .with_skew(1)
            .with_step_duration(30)
            .with_secret(TOTP_SECRET)
            .build()
            .expect("build TOTP")
            .generate_current()
            .to_string()
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
    struct FakePolicies;
    #[async_trait]
    impl crate::domain::repositories::AuthenticationPolicyRepository for FakePolicies {
        async fn create(
            &self,
            _p: &crate::domain::authentication_policy::AuthenticationPolicy,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn list_for_tenant(
            &self,
            _t: TenantId,
        ) -> DomainResult<Vec<crate::domain::authentication_policy::AuthenticationPolicy>> {
            unreachable!()
        }
        /// Mimics a tenant with no policies (default allow).
        async fn list_enabled_for_tenant(
            &self,
            _t: TenantId,
        ) -> DomainResult<Vec<crate::domain::authentication_policy::AuthenticationPolicy>> {
            Ok(Vec::new())
        }
        async fn find_by_id(
            &self,
            _t: TenantId,
            _id: Uuid,
        ) -> DomainResult<Option<crate::domain::authentication_policy::AuthenticationPolicy>>
        {
            unreachable!()
        }
        async fn update(
            &self,
            _p: &crate::domain::authentication_policy::AuthenticationPolicy,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _id: Uuid) -> DomainResult<bool> {
            unreachable!()
        }
    }

    /// Fake authenticator registry. Leaves everything to the default implementation (not found) and only blocks `create`.
    /// Reproduces the path of users without recovery codes or email OTP.
    struct FakeAuthenticators;
    #[async_trait]
    impl UserAuthenticatorRepository for FakeAuthenticators {
        async fn create(
            &self,
            _a: &crate::domain::user_authenticator::UserAuthenticator,
        ) -> DomainResult<()> {
            unreachable!()
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
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(&self, _t: TenantId, _n: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn update_login_state(
            &self,
            id: Uuid,
            count: i32,
            locked_until: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|u| u.id == id) {
                row.failed_login_count = count;
                row.locked_until = locked_until;
            }
            Ok(())
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
        async fn update_status(&self, _id: Uuid, _s: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _l: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// Lets us tell from whether TOTP was looked up "whether the rate limit / lock took effect before verification".
    #[derive(Default)]
    struct FakeTotpSecrets {
        row: Mutex<Option<TotpSecret>>,
        lookups: Mutex<usize>,
    }
    #[async_trait]
    impl TotpSecretRepository for FakeTotpSecrets {
        async fn upsert(&self, _s: &TotpSecret) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_user_id(&self, _user_id: Uuid) -> DomainResult<Option<TotpSecret>> {
            *self.lookups.lock().unwrap() += 1;
            Ok(self.row.lock().unwrap().clone())
        }
        async fn confirm(&self, _u: Uuid, _c: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeSsoSessions {
        created: Mutex<Vec<SsoSession>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, s: &SsoSession) -> DomainResult<()> {
            self.created.lock().unwrap().push(s.clone());
            Ok(())
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
        async fn delete_all_for_user(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeConsents;
    #[async_trait]
    impl ClientConsentRepository for FakeConsents {
        async fn find(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
        ) -> DomainResult<Option<ClientConsent>> {
            Ok(None)
        }
        async fn upsert(&self, _c: &ClientConsent) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke(&self, _t: TenantId, _u: Uuid, _c: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn list_for_user(&self, _t: TenantId, _u: Uuid) -> DomainResult<Vec<ClientConsent>> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeCodes {
        created: Mutex<Vec<AuthorizationCode>>,
    }
    #[async_trait]
    impl crate::domain::repositories::AuthorizationCodeRepository for FakeCodes {
        async fn find_used(
            &self,
            _t: TenantId,
            _h: &crate::domain::authorization_code::AuthorizationCodeHash,
        ) -> DomainResult<Option<AuthorizationCode>> {
            unreachable!()
        }
        async fn create(&self, c: &AuthorizationCode) -> DomainResult<()> {
            self.created.lock().unwrap().push(c.clone());
            Ok(())
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
            _u: Uuid,
            _n: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// A limiter that allows `allowed` times and refuses afterwards.
    struct CountingLimiter {
        allowed: usize,
        calls: Mutex<usize>,
    }
    impl LoginRateLimiter for CountingLimiter {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            *calls <= self.allowed
        }
    }

    struct Harness {
        service: MfaLoginService,
        users: Arc<FakeUsers>,
        totp_secrets: Arc<FakeTotpSecrets>,
        sso_sessions: Arc<FakeSsoSessions>,
        sink: Arc<CapturingSink>,
        tenant: TenantContext,
        user_id: Uuid,
    }

    /// Global default. Chosen not to overlap with values used in tests, to tell whether the tenant row is in effect.
    const GLOBAL_MAX_FAILED_ATTEMPTS: &str = "50";

    impl Harness {
        /// Inserts a `LOGIN_MAX_FAILED_ATTEMPTS` row for the user's home tenant (the global value stays 50).
        fn new(rate_limit_allowed: usize, max_failed_attempts: i32) -> Self {
            Self::with_settings(rate_limit_allowed, |settings, home| {
                settings.set_tenant(
                    home,
                    "LOGIN_MAX_FAILED_ATTEMPTS",
                    &max_failed_attempts.to_string(),
                );
            })
        }

        fn with_settings(
            rate_limit_allowed: usize,
            configure: impl FnOnce(
                &crate::application::tenant_settings::testing::TenantSettingsFixture,
                TenantId,
            ),
        ) -> Self {
            let tenant_id: TenantId = Uuid::now_v7().into();
            let settings = crate::application::tenant_settings::testing::tenant_settings();
            settings.set_global("LOGIN_MAX_FAILED_ATTEMPTS", GLOBAL_MAX_FAILED_ATTEMPTS);
            configure(&settings, tenant_id);
            let tenant = TenantContext::new(tenant_id);
            let user_id = Uuid::now_v7();

            let users = Arc::new(FakeUsers::default());
            users.rows.lock().unwrap().push(User {
                id: user_id,
                tenant_id,
                sub: Uuid::now_v7(),
                email: "user@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("user".to_string()),
                name: None,
                language: None,
                theme: None,
                password_hash: "hash".to_string(),
                must_change_password: false,
                password_changed_at: None,
                status: UserStatus::Active,
                pending_setup: false,
                failed_login_count: 0,
                locked_until: None,
                created_at: now(),
                updated_at: now(),
            });

            let auth_sessions = Arc::new(InMemoryAuthSessions::with(vec![
                auth_session::test_support::awaiting_second_step(
                    tenant_id,
                    SESSION_ID,
                    authorization_request::test_support::request(
                        CLIENT_ID,
                        "https://rp.example.com/cb",
                    ),
                    user_id,
                    now(),
                ),
            ]));

            let totp_secrets = Arc::new(FakeTotpSecrets::default());
            *totp_secrets.row.lock().unwrap() = Some(TotpSecret {
                user_id,
                secret_encrypted: crypto::encrypt(TOTP_SECRET, &TEST_KEY).expect("encrypt secret"),
                confirmed_at: Some(now()),
                created_at: now(),
                updated_at: now(),
            });

            let sink = Arc::new(CapturingSink::default());
            let clock: Arc<dyn ClockTrait> = Arc::new(FixedClock);
            let audit = Arc::new(AuditService::new(sink.clone(), clock.clone()));
            let sso_sessions = Arc::new(FakeSsoSessions::default());
            let code_issuance = Arc::new(CodeIssuanceService::new(
                Arc::new(FakeCodes::default()),
                crate::application::application_access::test_support::allow_everything(
                    audit.clone(),
                ),
                audit.clone(),
                clock.clone(),
                std::time::Duration::from_secs(60),
            ));

            let service = MfaLoginService::new(
                Arc::new(FakeAuthenticators),
                auth_sessions.clone(),
                totp_secrets.clone(),
                users.clone(),
                Arc::new(SignInCompletion::new(
                    sso_sessions.clone(),
                    auth_sessions,
                    Arc::new(FakeConsents),
                    code_issuance,
                    audit.clone(),
                    settings.service.clone(),
                )),
                Arc::new(CountingLimiter {
                    allowed: rate_limit_allowed,
                    calls: Mutex::new(0),
                }),
                audit.clone(),
                clock,
                TEST_KEY,
                settings.service.clone(),
                CSRF_SECRET,
                crate::application::authentication_policy_gate::test_support::gate(
                    Arc::new(FakePolicies),
                    settings.service.clone(),
                    audit.clone(),
                ),
            );

            Self {
                service,
                users,
                totp_secrets,
                sso_sessions,
                sink,
                tenant,
                user_id,
            }
        }

        async fn verify(&self, code: &str) -> MfaLoginOutcome {
            let ctx = RequestContext {
                correlation_id: "test-correlation".to_string(),
                ip_address: Some("203.0.113.10".to_string()),
                user_agent: None,
            };
            self.service
                .verify(
                    self.tenant,
                    MfaLoginCommand {
                        auth_session_id: Some(SESSION_ID.to_string()),
                        totp_code: code.to_string(),
                        csrf_token: assay_contracts::csrf::login_csrf_token(
                            SESSION_ID,
                            &CSRF_SECRET,
                        ),
                    },
                    &ctx,
                )
                .await
        }

        fn user(&self) -> User {
            self.users.rows.lock().unwrap()[0].clone()
        }

        fn totp_lookups(&self) -> usize {
            *self.totp_secrets.lookups.lock().unwrap()
        }

        fn audit_reasons(&self) -> Vec<String> {
            self.sink
                .events
                .lock()
                .unwrap()
                .iter()
                .filter_map(|e| e.reason.clone())
                .collect()
        }
    }

    #[tokio::test]
    async fn rate_limited_before_totp_is_checked() {
        // A limiter allowing only once. The second attempt is cut off before checking TOTP.
        let h = Harness::new(1, 10);
        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::InvalidCode
        ));
        assert_eq!(h.totp_lookups(), 1);

        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::RateLimited
        ));
        // TOTP isn't looked up (there's no heavy processing like Argon2, but the decision happens before verification).
        assert_eq!(h.totp_lookups(), 1);
        // The failure counter isn't advanced by the rate limit either (so IP-based attacks can't lock other people out).
        assert_eq!(h.user().failed_login_count, 1);
        assert!(h.audit_reasons().contains(&"ip_rate_limited".to_string()));
    }

    #[tokio::test]
    async fn invalid_code_increments_failed_count_and_locks_at_threshold() {
        let h = Harness::new(100, 3);

        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::InvalidCode
        ));
        assert_eq!(h.user().failed_login_count, 1);
        assert!(h.user().locked_until.is_none());

        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::InvalidCode
        ));
        assert_eq!(h.user().failed_login_count, 2);
        assert!(h.user().locked_until.is_none());

        // Locked on the 3rd attempt.
        assert!(matches!(h.verify("000000").await, MfaLoginOutcome::Locked));
        assert_eq!(h.user().failed_login_count, 3);
        assert_eq!(h.user().locked_until, Some(now() + Duration::seconds(900)));

        let reasons = h.audit_reasons();
        assert_eq!(
            reasons.iter().filter(|r| *r == "invalid_totp").count(),
            3,
            "each failure is audited"
        );
        assert!(reasons.contains(&"too_many_failures".to_string()));
    }

    #[tokio::test]
    async fn locked_account_is_rejected_before_totp_is_checked() {
        let h = Harness::new(100, 10);
        h.users.rows.lock().unwrap()[0].locked_until = Some(now() + Duration::seconds(60));

        // Even a correct code doesn't pass while locked.
        assert!(matches!(
            h.verify(&current_totp_code()).await,
            MfaLoginOutcome::Locked
        ));
        assert_eq!(h.totp_lookups(), 0);
        assert!(h.audit_reasons().contains(&"account_locked".to_string()));
    }

    #[tokio::test]
    async fn successful_verification_resets_failed_count() {
        let h = Harness::new(100, 10);
        {
            let mut rows = h.users.rows.lock().unwrap();
            rows[0].failed_login_count = 2;
        }

        let outcome = h.verify(&current_totp_code()).await;
        assert!(
            matches!(outcome, MfaLoginOutcome::Success { .. }),
            "valid TOTP must complete the flow"
        );
        assert_eq!(h.user().failed_login_count, 0);
        assert!(h.user().locked_until.is_none());
        assert_eq!(h.sso_sessions.created.lock().unwrap().len(), 1);
        assert_eq!(h.user_id, h.sso_sessions.created.lock().unwrap()[0].user_id);
    }

    /// ⚠ "No row = follow the global value". If the tenant has no row, it locks at the global threshold (2 here).
    #[tokio::test]
    async fn a_home_tenant_without_a_row_locks_at_the_global_threshold() {
        let h = Harness::with_settings(100, |settings, _home| {
            settings.set_global("LOGIN_MAX_FAILED_ATTEMPTS", "2");
        });
        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::InvalidCode
        ));
        assert!(matches!(h.verify("000000").await, MfaLoginOutcome::Locked));
    }

    /// The SSO session lifetime is decided by the value of the user's home tenant (not the global value).
    #[tokio::test]
    async fn the_sso_session_lives_as_long_as_the_home_tenant_says() {
        let h = Harness::with_settings(100, |settings, home| {
            settings.set_global("SSO_IDLE_TTL_SECS", "28800");
            settings.set_global("SSO_ABSOLUTE_TTL_SECS", "86400");
            settings.set_tenant(home, "SSO_IDLE_TTL_SECS", "600");
            settings.set_tenant(home, "SSO_ABSOLUTE_TTL_SECS", "1200");
        });
        assert!(matches!(
            h.verify(&current_totp_code()).await,
            MfaLoginOutcome::Success { .. }
        ));
        let created = h.sso_sessions.created.lock().unwrap();
        assert_eq!(created[0].idle_expires_at, now() + Duration::seconds(600));
        assert_eq!(
            created[0].absolute_expires_at,
            now() + Duration::seconds(1200)
        );
    }
}
