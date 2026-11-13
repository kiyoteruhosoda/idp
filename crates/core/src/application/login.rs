//! Login use case (design spec §4.3).
//!
//! Verifies in the order AuthSession (cookie) -> CSRF -> rate limit -> credentials -> account state and lock;
//! on success: issue SSO session -> consent check -> if consented, issue code (shared `code_issuance` module)
//! -> delete AuthSession. If consent is incomplete, send to `/consent` (F3).
//!
//! Lock policy: `LOGIN_MAX_FAILED_ATTEMPTS` consecutive failures per username ->
//! locked for `LOGIN_LOCK_DURATION_SECS` seconds (values of the user's home tenant; default 10 times / 15 minutes). Per-IP rate limit.
//! The failure counter reset (`failed_login_count = 0` / `locked_until = NULL`) happens only **when authentication
//! has fully completed**. Paths that return awaiting MFA don't reset it; on TOTP success
//! [`crate::application::mfa_login::MfaLoginService`] does (SEC3; clearing it on every password success would let
//! an attacker who knows the password bypass the TOTP lock forever).
//!
//! Authentication policy (user authentication & authentication policy spec §7–§9): after the password is verified,
//! the tenant's enabled policies are evaluated; `deny` refuses (`PolicyDenied`), and `require_mfa`
//! refuses if TOTP is not set up (`MfaEnrollmentRequired`) or falls to the existing MFA step if it is.
//! Evaluating after password verification keeps the existence of policies unobservable to attackers without credentials.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::login_user_resolution::resolve_login_user;
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::application::sign_in_completion::{
    AuthorizationContinuation, Establishment, SignIn, SignInCompletion,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSessionIdHash;
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::login_identifier::LoginIdentifierMatch;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::password_change_required;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::TenantDomainRepository;
use crate::domain::repositories::{AuthSessionRepository, TotpSecretRepository, UserRepository};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::values::AuthenticationMethod;
use std::sync::Arc;

/// Derives the CSRF token tied to `auth_session_id`.
///
/// The derivation must match between web (form rendering) and api (verification), so it is centralized in `assay-contracts`
/// (ADR-0007 §6. Synchronizer token pattern; no extra server-side storage needed).
pub fn csrf_token(auth_session_id: &str, key: &[u8]) -> String {
    assay_contracts::csrf::login_csrf_token(auth_session_id, key)
}

pub struct LoginCommand {
    /// Value of the `auth_session_id` cookie.
    pub auth_session_id: Option<String>,
    /// Login identifier (user name = `preferred_username`. ADR-0009 §8).
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

/// ⚠ Don't put secrets (`auth_session_id`, `password`, `csrf_token`) in `Debug` (task #593). Fields are chosen by hand
/// so values don't leak even if logged with `{:?}`.
impl std::fmt::Debug for LoginCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginCommand")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

pub enum LoginOutcome {
    /// Authenticated and consented. 302 to `redirect_uri?code=...&state=...` and issue the SSO cookie.
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
    /// Authenticated but some scopes are not consented. Redirect to the consent screen.
    /// The SSO cookie is already issued (`sso_session_id`). The AuthSession is kept in the authenticated state.
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    /// Password authentication succeeded but MFA (TOTP) is set up. Send to the TOTP input screen.
    /// The `auth_session_id` cookie is kept as-is, and the SSO cookie is not issued yet.
    MfaRequired {
        auth_session_id: String,
    },
    /// Password authentication succeeded but `must_change_password` (ADR-0009 §5). Send to the password change screen.
    /// The `auth_session_id` cookie is kept as-is, and the SSO cookie is not issued yet. The authorization flow
    /// is not completed until the change is done ([`crate::application::change_password::ChangePasswordService`]).
    PasswordChangeRequired {
        auth_session_id: String,
    },
    /// Password authentication succeeded but the self-registered account's email is unverified (SEC6b). Login is not
    /// allowed until the confirmation link is followed. No SSO cookie. Decided after password verification, so
    /// attackers without credentials can't observe the email verification state (enumeration prevention).
    EmailVerificationRequired,
    /// Denied by the authentication policy (spec §7.4 `deny`). The credentials are already confirmed, so
    /// it may be shown with wording distinct from a credential error: "denied by the organization's policy".
    PolicyDenied,
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
    /// Authentication passed, but in an organization limited to registered devices this device is not registered (task #916).
    /// No SSO cookie. web puts `ticket` in a cookie and sends the user to the device registration screen. The AuthSession is kept
    /// (after registering, reopening the login screen continues the authorization flow from the new SSO).
    DeviceEnrollmentRequired {
        ticket: String,
    },
    /// The authentication policy requires MFA, but the user has no usable authenticator (verified TOTP).
    /// Guide the user to set up MFA from the portal. No SSO cookie.
    MfaEnrollmentRequired,
    /// No AuthSession, or expired (start over from `/authorize`).
    SessionExpired,
    /// CSRF token mismatch.
    CsrfMismatch,
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// Invalid credentials (missing user, wrong password and disabled account are not distinguished).
    InvalidCredentials,
    /// Account locked.
    Locked,
    Internal(String),
}

pub struct LoginService {
    users: Arc<dyn UserRepository>,
    /// Domains assigned to tenants (ADR-0029). Looked up when the login input has the form `local@domain`,
    /// to pin down a single home tenant (`login_user_resolution`).
    tenant_domains: Arc<dyn TenantDomainRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    /// Authentication policy evaluation (looking up inputs and evaluating. `authentication_policy_gate`).
    policy_gate: Arc<AuthenticationPolicyGate>,
    /// Shared tail after authentication succeeds (establishing SSO, continuing the authorization flow).
    sign_in: Arc<SignInCompletion>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// Settings tenants can override (ADR-0058). Looked up every time. The default behavior when no policy
    /// matches (AP2, §4) is also taken from here.
    settings: Arc<dyn EffectiveTenantSettings>,
    csrf_secret: [u8; 32],
}

impl LoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        tenant_domains: Arc<dyn TenantDomainRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        policy_gate: Arc<AuthenticationPolicyGate>,
        sign_in: Arc<SignInCompletion>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        settings: Arc<dyn EffectiveTenantSettings>,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            users,
            tenant_domains,
            auth_sessions,
            totp_secrets,
            policy_gate,
            sign_in,
            hasher,
            rate_limiter,
            audit,
            clock,
            settings,
            csrf_secret,
        }
    }

    pub async fn login(
        &self,
        tenant: TenantContext,
        cmd: LoginCommand,
        ctx: &RequestContext,
    ) -> LoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Fetch the AuthSession from the cookie's auth_session_id (limited to the flow's tenant).
        let Some(session_id) = cmd.auth_session_id.as_deref().filter(|s| !s.is_empty()) else {
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "login rejected: auth_session_id cookie missing"
            );
            return LoginOutcome::SessionExpired;
        };
        // mut because the id is regenerated on successful authentication (SEC7). From here on `session.id_hash()` always
        // points at the hash of "the value this browser should hold now".
        let mut session = match self
            .auth_sessions
            .find(tenant_id, &AuthSessionIdHash::of_plain(session_id))
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => {
                tracing::warn!(
                    correlation_id = %ctx.correlation_id,
                    "login rejected: auth session not found (already consumed or wrong tenant)"
                );
                return LoginOutcome::SessionExpired;
            }
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "login rejected: auth session expired"
            );
            return LoginOutcome::SessionExpired;
        }

        // 2. Verify the CSRF token. A mismatch happens not only in attacks but also in legitimate operations such as
        //    "cookie replaced by a new flow in another tab", so it is audited and web re-renders the form (PRG).
        if !assay_contracts::csrf::verify(
            &csrf_token(session_id, &self.csrf_secret),
            &cmd.csrf_token,
        ) {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    None,
                    Some(session.client_id()),
                    Some("csrf_mismatch"),
                    ctx,
                )
                .await;
            return LoginOutcome::CsrfMismatch;
        }

        let client_id = session.client_id().to_string();

        // 3. Per-IP rate limit.
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        Some(&client_id),
                        Some("ip_rate_limited"),
                        ctx,
                    )
                    .await;
                return LoginOutcome::RateLimited;
            }
        }

        // 4. Look up the user (login identifier, resolved via the AP8 registry). Targets are this tenant's ACTIVE
        //    members = home (HOME) users and GUESTs joined by invitation (ADR-0009 §8; resolution rules in
        //    `login_user_resolution`).
        let user = match resolve_login_user(
            self.users.as_ref(),
            self.tenant_domains.as_ref(),
            tenant_id,
            &cmd.username,
        )
        .await
        {
            Ok(LoginIdentifierMatch::Resolved(u)) => u,
            // The response is the same for missing and ambiguous (avoid revealing existence). Only the audit reason differs.
            Ok(LoginIdentifierMatch::Unresolved(reason)) => {
                // Spend one argon2 verification, same as for a real user, so the user's existence can't be
                // inferred from response time (enumeration countermeasure).
                crate::domain::password::verify_against_dummy(self.hasher.as_ref(), &cmd.password);
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        Some(&client_id),
                        Some(reason.audit_code()),
                        ctx,
                    )
                    .await;
                return LoginOutcome::InvalidCredentials;
            }
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };

        // 5. Check the lock state.
        if user.is_locked_at(now) {
            // Spend the same argon2 verification as for a missing user (don't let the state be inferred from response time. task #590).
            crate::domain::password::verify_against_dummy(self.hasher.as_ref(), &cmd.password);
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
            return LoginOutcome::Locked;
        }

        // 6. Check the account state (same response as a credential error to avoid revealing existence).
        if !user.is_active() {
            // Spend the same argon2 verification as for a missing user (don't let the state be inferred from response time. task #590).
            crate::domain::password::verify_against_dummy(self.hasher.as_ref(), &cmd.password);
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some("account_not_active"),
                    ctx,
                )
                .await;
            return LoginOutcome::InvalidCredentials;
        }

        // 7. Verify the password.
        let verified = match self.hasher.verify(&cmd.password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if !verified {
            return self
                .handle_password_failure(tenant_id, &user, &client_id, ctx)
                .await;
        }

        // 8. Password verified. **The failure counter is not reset here** (SEC3).
        //    The reset happens "when authentication has fully completed" (right before 10., or in
        //    `MfaLoginService` on MFA success). Clearing it here would let an attacker who knows the password
        //    repeat "fail TOTP up to just below the limit -> log in again with the correct password to zero the counter"
        //    and bypass the lock forever.
        //
        // 8.1. Email verification gate (SEC6b). Self-registered accounts can't log in until `email_verified` is set.
        //      Admin-created and invited users are created verified, so they aren't affected. Deciding after password
        //      verification keeps the verification state unobservable to attackers without credentials (enumeration prevention).
        if !user.email_verified {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some("email_not_verified"),
                    ctx,
                )
                .await;
            return LoginOutcome::EmailVerificationRequired;
        }

        // 8.2. Authentication policy evaluation (user authentication & authentication policy spec §9). Evaluated after
        //      password verification (attackers without credentials can't observe a policy's existence or content).
        //      `deny` refuses immediately. `require_mfa` is enforced by the later MFA decision (9.).
        // `acr_values` of the authorization request (used by AP3's `requested_acr` condition).
        let requested_acr = session.request().requested_acr();
        let policy_decision = match self
            .policy_gate
            .decide(PolicyQuery {
                tenant_id,
                audience: PolicyAudience::OidcClient(&client_id),
                user_id: user.id,
                ip_address: ctx.ip_address.as_deref(),
                requested_acr: &requested_acr,
                now,
            })
            .await
        {
            Ok(decision) => decision,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if let PolicyDecision::Deny { policy_code } = &policy_decision {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some(&format!("policy={policy_code}")),
                    ctx,
                )
                .await;
            return LoginOutcome::PolicyDenied;
        }

        // 8.5. Forced password change (ADR-0009 §5). Users created or reissued with a generated password are sent to
        //      the password change screen before MFA and consent (no other operations until the change completes).
        //      TOTP verification and the policy's MFA requirement are applied by `ChangePasswordService` on completion
        //      (`must_change_password` is also set when an admin reissues an existing user's password, so
        //      "no MFA check needed for users in this state" does not hold).
        //      Expiry (AP7) goes through the same redirect. Expiry can only be checked at login, and
        //      letting it pass here makes the next chance the next login = the expiry effectively doesn't work.
        // The policy is the value of the user's home tenant (ADR-0058; the password is managed by the home tenant).
        let password_policy = match self.settings.password_policy(user.tenant_id).await {
            Ok(policy) => policy,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if password_change_required(&user, &password_policy, now) {
            let verification = session.record_password_verification(user.id, now);
            if let Err(e) = self
                .auth_sessions
                .save_password_verification(&verification)
                .await
            {
                return LoginOutcome::Internal(e.to_string());
            }
            return LoginOutcome::PasswordChangeRequired {
                auth_session_id: verification.into_issued().into_string(),
            };
        }

        // 9. Check whether MFA (TOTP) is set up. If so, send to the TOTP input step.
        //    If the authentication policy requires MFA (`require_mfa`) but there's no usable authenticator,
        //    single-factor completion is not allowed and it is refused (spec §24.4 "a user who requires MFA must not
        //    complete authentication with a single factor only").
        let has_totp = match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
            Ok(v) => v,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if has_totp {
            // Record password verification success in the AuthSession (MFA pending). Also regenerate the id (SEC7).
            let verification = session.record_password_verification(user.id, now);
            if let Err(e) = self
                .auth_sessions
                .save_password_verification(&verification)
                .await
            {
                return LoginOutcome::Internal(e.to_string());
            }
            return LoginOutcome::MfaRequired {
                auth_session_id: verification.into_issued().into_string(),
            };
        }
        if let PolicyDecision::RequireMfa { policy_code } = &policy_decision {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some(&format!("policy={policy_code} reason=mfa_not_enrolled")),
                    ctx,
                )
                .await;
            return LoginOutcome::MfaEnrollmentRequired;
        }
        // 9.1. `require_specific_method` (AP3. spec §12.2). At this point the only method used is the
        //      password, so if the method requirement isn't met it doesn't complete. Policies requiring TOTP
        //      take the path satisfied by the MFA step above (`has_totp`), where
        //      `MfaLoginService` re-evaluates against the final set of methods. Policies requiring a passkey
        //      are satisfied by the login screen's passkey button (`PasskeyAuthenticationService`).
        if let Some(unmet) =
            policy_decision.unmet_method_requirement(&[AuthenticationMethod::Password], false)
        {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some(&format!(
                        "policy={} reason=method_required required={}",
                        unmet.policy_code,
                        unmet.requirement.describe()
                    )),
                    ctx,
                )
                .await;
            return LoginOutcome::PolicyDenied;
        }

        // 9.5. Reaching here = authentication completed with a single factor (not awaiting MFA). Reset the failure
        //      counter and lock (SEC3; on the MFA-pending path `MfaLoginService` does it on TOTP success).
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return LoginOutcome::Internal(e.to_string());
            }
        }

        // 10. Establish the SSO session and continue the authorization flow (consent check -> code issuance).
        let sso = match self
            .sign_in
            .establish_sso(
                SignIn {
                    tenant_id,
                    user_id: user.id,
                    home_tenant_id: user.tenant_id,
                    methods: vec![AuthenticationMethod::Password],
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
                return LoginOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        let sso_session_id = sso.session_id().to_string();
        let sso_absolute_ttl_secs = sso.absolute_ttl_secs();
        match self
            .sign_in
            .continue_authorization(tenant, &mut session, &sso, now, ctx)
            .await
        {
            Ok(AuthorizationContinuation::ConsentRequired { auth_session_id }) => {
                LoginOutcome::ConsentRequired {
                    auth_session_id,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name }) => {
                LoginOutcome::ApplicationNotPermitted {
                    application_name,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::Authorized(dispatch)) => LoginOutcome::Success {
                location: dispatch.location,
                form_post: dispatch.form_post,
                sso_session_id,
                sso_absolute_ttl_secs,
                user_language: user.language.clone(),
            },
            Err(e) => LoginOutcome::Internal(e.to_string()),
        }
    }

    /// Updates the failure count and decides locking on a password mismatch.
    async fn handle_password_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        client_id: &str,
        ctx: &RequestContext,
    ) -> LoginOutcome {
        let now = self.clock.now();
        // The threshold is the value of the user's home tenant (the lock state lives on the user row. ADR-0058).
        let lockout = match self.settings.login_lockout(user.tenant_id).await {
            Ok(lockout) => lockout,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        // The increment and lock decision are kept in a single UPDATE statement (SEC13).
        let failure = match self.users.record_login_failure(user.id, lockout, now).await {
            Ok(f) => f,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };

        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                Some(user.id),
                Some(client_id),
                Some("invalid_password"),
                ctx,
            )
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
            return LoginOutcome::Locked;
        }
        LoginOutcome::InvalidCredentials
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_token_is_deterministic_and_session_bound() {
        let key = *b"test-key-for-csrf-32-bytes-xxxxx";
        let a = csrf_token("session-a", &key);
        assert_eq!(a, csrf_token("session-a", &key));
        assert_ne!(a, csrf_token("session-b", &key));
        // HMAC-SHA256 hex (64 chars): only characters safe to embed in a form.
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    // ── SEC3: a password success awaiting MFA does not clear the failure counter ──────────────

    use crate::application::code_issuance::CodeIssuanceService;
    use crate::domain::authentication_policy::AuthenticationPolicy;
    use crate::domain::authorization_code::AuthorizationCode;
    use crate::domain::consent::ClientConsent;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::repositories::{
        AuditLogSink, AuthenticationPolicyRepository, AuthorizationCodeRepository,
        ClientConsentRepository, SsoSessionRepository,
    };
    use crate::domain::sso_session::SsoSession;
    use crate::domain::totp_secret::TotpSecret;
    use crate::domain::values::UserStatus;
    use crate::domain::{auth_session, authorization_request};
    use crate::infrastructure::repositories::in_memory_auth_session::InMemoryAuthSessions;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;
    use uuid::Uuid;

    const CSRF_KEY: [u8; 32] = *b"unit-test-csrf-0123456789abcdef!";
    const SESSION_ID: &str = "auth-session-id";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    thread_local! {
        /// Number of times `verify` was called on this test's thread (task #590; counts whether the verification
        /// that equalizes response time ran). `#[tokio::test]` runs on one thread, so tests don't mix.
        static VERIFIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    struct PlainHasher;
    impl PasswordHasher for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
            VERIFIES.with(|n| n.set(n.get() + 1));
            Ok(hash == format!("hash:{password}"))
        }
    }

    struct AllowAll;
    impl LoginRateLimiter for AllowAll {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct DiscardingSink;
    #[async_trait]
    impl AuditLogSink for DiscardingSink {
        async fn record(&self, _event: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
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
        async fn find_by_id(&self, _id: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
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

    /// A fake that only toggles TOTP set up / not set up.
    struct FakeTotpSecrets {
        confirmed: bool,
    }
    #[async_trait]
    impl TotpSecretRepository for FakeTotpSecrets {
        async fn upsert(&self, _s: &TotpSecret) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_user_id(&self, user_id: Uuid) -> DomainResult<Option<TotpSecret>> {
            Ok(self.confirmed.then(|| TotpSecret {
                user_id,
                secret_encrypted: String::new(),
                confirmed_at: Some(now()),
                created_at: now(),
                updated_at: now(),
            }))
        }
        async fn confirm(&self, _u: Uuid, _c: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    /// A tenant without domains (the default, not taking the ADR-0029 path). The trait's default implementation
    /// returns "no assignment", so login resolution uses the previous two steps (home tenant -> guest scan).
    struct NoTenantDomains;

    #[async_trait]
    impl crate::domain::repositories::TenantDomainRepository for NoTenantDomains {}

    struct FakeSsoSessions;
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
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
    struct FakePolicies;
    #[async_trait]
    impl AuthenticationPolicyRepository for FakePolicies {
        async fn create(&self, _p: &AuthenticationPolicy) -> DomainResult<()> {
            unreachable!()
        }
        async fn list_for_tenant(&self, _t: TenantId) -> DomainResult<Vec<AuthenticationPolicy>> {
            unreachable!()
        }
        async fn list_enabled_for_tenant(
            &self,
            _t: TenantId,
        ) -> DomainResult<Vec<AuthenticationPolicy>> {
            Ok(Vec::new())
        }
        async fn find_by_id(
            &self,
            _t: TenantId,
            _id: Uuid,
        ) -> DomainResult<Option<AuthenticationPolicy>> {
            unreachable!()
        }
        async fn update(&self, _p: &AuthenticationPolicy) -> DomainResult<bool> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _id: Uuid) -> DomainResult<bool> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeCodes;
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

    struct Harness {
        service: LoginService,
        users: Arc<FakeUsers>,
        auth_sessions: Arc<InMemoryAuthSessions>,
        tenant: TenantContext,
        user_id: Uuid,
    }

    /// Setup that logs in once as a user whose `failed_login_count` is `initial_failures`.
    fn harness(has_totp: bool, initial_failures: i32) -> Harness {
        let tenant_id: TenantId = Uuid::now_v7().into();
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
            password_hash: "hash:correct-password".to_string(),
            must_change_password: false,
            password_changed_at: None,
            status: UserStatus::Active,
            pending_setup: false,
            failed_login_count: initial_failures,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        });

        let auth_sessions = Arc::new(InMemoryAuthSessions::with(vec![
            auth_session::test_support::awaiting_login(
                tenant_id,
                SESSION_ID,
                authorization_request::test_support::request(
                    "client-a",
                    "https://rp.example.com/cb",
                ),
                now(),
            ),
        ]));

        let clock: Arc<dyn Clock> = Arc::new(FixedClock);
        let audit = Arc::new(AuditService::new(Arc::new(DiscardingSink), clock.clone()));
        let code_issuance = Arc::new(CodeIssuanceService::new(
            Arc::new(FakeCodes),
            crate::application::application_access::test_support::allow_everything(audit.clone()),
            audit.clone(),
            clock.clone(),
            std::time::Duration::from_secs(60),
        ));

        let settings = crate::application::tenant_settings::testing::tenant_settings().service;
        let service = LoginService::new(
            users.clone(),
            Arc::new(NoTenantDomains),
            auth_sessions.clone(),
            Arc::new(FakeTotpSecrets {
                confirmed: has_totp,
            }),
            crate::application::authentication_policy_gate::test_support::gate(
                Arc::new(FakePolicies),
                settings.clone(),
                audit.clone(),
            ),
            Arc::new(SignInCompletion::new(
                Arc::new(FakeSsoSessions),
                auth_sessions.clone(),
                Arc::new(FakeConsents),
                code_issuance,
                audit.clone(),
                settings.clone(),
            )),
            Arc::new(PlainHasher),
            Arc::new(AllowAll),
            audit,
            clock,
            settings,
            CSRF_KEY,
        );

        Harness {
            service,
            users,
            auth_sessions,
            tenant: TenantContext::new(tenant_id),
            user_id,
        }
    }

    impl Harness {
        async fn login(&self) -> LoginOutcome {
            let ctx = RequestContext {
                correlation_id: "test-correlation".to_string(),
                ip_address: Some("203.0.113.10".to_string()),
                user_agent: None,
            };
            self.service
                .login(
                    self.tenant,
                    LoginCommand {
                        auth_session_id: Some(SESSION_ID.to_string()),
                        username: "user".to_string(),
                        password: "correct-password".to_string(),
                        csrf_token: csrf_token(SESSION_ID, &CSRF_KEY),
                    },
                    &ctx,
                )
                .await
        }

        fn failed_count(&self) -> i32 {
            self.users.rows.lock().unwrap()[0].failed_login_count
        }

        /// Current id_hash of the stored auth_session.
        fn stored_session_id_hash(&self) -> String {
            self.auth_sessions.rows()[0].id_hash().as_str().to_string()
        }
    }

    /// Core of SEC3: paths that stop awaiting MFA don't clear the failure counter. Clearing it would let an attacker
    /// who knows the password repeat "fail TOTP up to just below the limit -> log in again to zero the counter"
    /// and bypass the lock forever.
    #[tokio::test]
    async fn mfa_pending_login_keeps_the_failure_counter() {
        let h = harness(true, 4);
        assert!(matches!(h.login().await, LoginOutcome::MfaRequired { .. }));
        assert_eq!(h.failed_count(), 4, "not reset while awaiting MFA");
    }

    /// SEC7: `auth_session_id` is regenerated once password verification passes. Reusing the cookie value issued
    /// before authentication would let an attacker who planted the value in advance ride along on the authorization
    /// session awaiting MFA (`sso_session_id` is regenerated on every login; don't make them asymmetric).
    #[tokio::test]
    async fn mfa_pending_login_rotates_the_auth_session_id() {
        let h = harness(true, 0);
        let LoginOutcome::MfaRequired { auth_session_id } = h.login().await else {
            panic!("expected MfaRequired");
        };
        assert_ne!(
            auth_session_id, SESSION_ID,
            "pre-authentication value must not be reused"
        );
        assert_eq!(
            h.stored_session_id_hash(),
            AuthSessionIdHash::of_plain(&auth_session_id).into_string(),
            "the DB side is also replaced by the new id's hash and can't be found by the old id"
        );
        assert_ne!(
            h.stored_session_id_hash(),
            auth_session_id,
            "the DB must not hold plaintext (SEC6)"
        );
    }

    /// SEC7: also regenerated on paths that proceed to completed authentication. Here the auth_session is deleted
    /// after code issuance so the id can't be observed directly, but **the row being gone** proves deletion worked
    /// with the regenerated id (if the id differed between recording and deletion, the row would remain).
    #[tokio::test]
    async fn completed_login_deletes_the_session_through_the_rotated_id() {
        let h = harness(false, 0);
        assert!(matches!(h.login().await, LoginOutcome::Success { .. }));
        assert!(
            h.auth_sessions.rows().is_empty(),
            "auth_session remains after code issuance = deletion with the regenerated id failed"
        );
    }

    /// Even for disabled or locked accounts, spend the same password verification as for a missing one (task #590).
    /// Returning early would let "the account exists (but is stopped)" be inferred from response time.
    #[tokio::test]
    async fn disabled_and_locked_accounts_spend_the_same_password_check() {
        let h = harness(false, 0);
        h.users.rows.lock().unwrap()[0].status = crate::domain::values::UserStatus::Disabled;
        VERIFIES.with(|n| n.set(0));
        assert!(matches!(h.login().await, LoginOutcome::InvalidCredentials));
        assert_eq!(VERIFIES.with(|n| n.get()), 1, "disabled account");

        let h = harness(false, 0);
        h.users.rows.lock().unwrap()[0].locked_until = Some(now() + chrono::Duration::hours(1));
        VERIFIES.with(|n| n.set(0));
        assert!(matches!(h.login().await, LoginOutcome::Locked));
        assert_eq!(VERIFIES.with(|n| n.get()), 1, "locked account");
    }

    /// Paths where single-factor authentication completes (TOTP not set up) reset as before.
    #[tokio::test]
    async fn completed_single_factor_login_resets_the_failure_counter() {
        let h = harness(false, 4);
        let outcome = h.login().await;
        assert!(
            matches!(outcome, LoginOutcome::Success { .. }),
            "without TOTP, single-factor login completes"
        );
        assert_eq!(h.failed_count(), 0);
        let _ = h.user_id;
    }
}
