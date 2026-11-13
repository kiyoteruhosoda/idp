//! Use case: login to the admin console (A2) (ADR-0006 §6).
//!
//! A normal OIDC login ([`crate::application::login`]) is tied to the `auth_session_id` issued by `/authorize`,
//! and on success issues an authorization code and returns to the RP's `redirect_uri`. The admin console is
//! not an OIDC RP but the IdP's own screen, and on first deployment there is not a single client,
//! so that path cannot be used (a chicken-and-egg problem: you want into the console to register a client,
//! but login needs a client).
//!
//! So this use case verifies credentials, confirms the user holds tenant admin permission (`idp.tenant.admin` / `idp.system.admin`), and **issues an SSO session
//! directly** (no code issuance or redirect). Lockout (design spec §4.3) and IP rate limits are
//! applied with the same policy as normal login.
//!
//! Authentication policies (AP2; user authentication and authentication policy spec §7-§9) are also applied with the same rules as OIDC login.
//! The admin console has no client context, so the evaluation context's `client_id` is `None` (policies with
//! `client_ids` conditions do not match). The admin console in particular cannot be exempt from `deny` / `require_mfa`
//! (it is the screen the most privileged users enter; if it passed straight through, policies would be effectively void). The issued SSO session uses the same mechanism as normal login
//! (`sso_session_id` cookie = plain text, DB = SHA-256), and `RequirePerms<IdpAdmin>` verifies it as is.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::device_enrollment::{Admission, AdmissionAttempt, DeviceGate};
use crate::application::login_user_resolution::resolve_login_user;
use crate::application::passkey_assertion::{
    PasskeyAssertionError, PasskeyAssertionService, PasskeyFlow,
};
use crate::application::password_policy::PasswordPolicyService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::login_identifier::LoginIdentifierMatch;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::{password_change_required, PasswordRejection};
use crate::domain::permission;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::TenantDomainRepository;
use crate::domain::repositories::{
    SsoSessionRepository, TotpSecretRepository, UserPermissionRepository, UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::values::AuthenticationMethod;
use std::sync::Arc;

// Derivation of the admin login form's CSRF synchronizer token (`admin_csrf_token`) moved to the web side (`assay-web`'s
// `csrf` module) when ADR-0007 moved the admin console into the web crate. api (core) does not hold it.

pub struct AdminLoginCommand {
    /// Login identifier (username = `preferred_username`; ADR-0009 §8).
    pub username: String,
    pub password: String,
}

/// ⚠ Do not print the secret (`password`) in `Debug` (task #593). Fields are picked by hand so the value
/// does not leak even if `{:?}` lands in a log.
impl std::fmt::Debug for AdminLoginCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminLoginCommand")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// Command for admin login with a passkey (WebAuthn). Takes neither login identifier nor password
/// (the discoverable credential names its owner).
#[derive(Debug)]
pub struct AdminPasskeyLoginCommand {
    /// Challenge ID returned by `POST /internal/passkey/login/begin`.
    pub challenge_id: uuid::Uuid,
    /// Assertion returned by the browser's `navigator.credentials.get()`.
    pub credential: serde_json::Value,
}

/// Command for admin login with a forced password change (ADR-0009 §5). Admin console login has no temporary
/// state like `auth_session_id`, so everything, including the current password, is fully re-verified every time.
pub struct AdminChangePasswordCommand {
    /// Login identifier (username = `preferred_username`; ADR-0009 §8).
    pub username: String,
    pub current_password: String,
    pub new_password: String,
}

/// ⚠ Do not print the secrets (`current_password`, `new_password`) in `Debug` (task #593). Fields are picked by hand
/// so values do not leak even if `{:?}` lands in a log.
impl std::fmt::Debug for AdminChangePasswordCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminChangePasswordCommand")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// Result of admin login. Presentation maps it to the screen (HTML).
pub enum AdminLoginOutcome {
    /// Authenticated and holds `idp.tenant.admin`. Issues the SSO cookie and 302s to the admin console.
    Success {
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry; ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    /// Authenticated and holds admin permission, but `must_change_password` (ADR-0009 §5). Leads to the password change screen.
    /// SSO is not issued yet (no other operation is allowed until the change completes).
    PasswordChangeRequired {
        username: String,
    },
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// Invalid credentials (missing user, password mismatch and disabled account are not distinguished).
    InvalidCredentials,
    /// Account is locked.
    Locked,
    /// Credentials are correct but no tenant admin permission is held.
    Forbidden,
    /// The new password does not meet strength requirements (`change_password` only).
    /// The new password does not satisfy the policy (length, breached, reused; AP7).
    WeakPassword(PasswordRejection),
    /// Refused by an authentication policy (AP2; spec §7.4 `deny`).
    PolicyDenied,
    /// The passkey challenge is missing, expired, or for another purpose (passkey path only). Prompts a retry.
    PasskeyChallengeNotFound,
    /// An authentication policy required MFA, but there is no usable authenticator (confirmed TOTP) (AP2).
    /// The admin console has no TOTP input step, so admins required to use MFA must register an
    /// authenticator via the portal, or pass the second factor via portal login.
    MfaEnrollmentRequired,
    /// An authentication policy required MFA and the user has an authenticator (AP2). Admin console login
    /// has no second-factor input step, so it guides the user to go through MFA via portal login (`/{tenant_id}/login`)
    /// before entering the admin console.
    MfaRequired,
    /// Authenticated, but on an unregistered device in an organization limited to registered devices (task #916). No SSO was created.
    DeviceEnrollmentRequired {
        ticket: String,
    },
    Internal(String),
}

pub struct AdminLoginService {
    users: Arc<dyn UserRepository>,
    /// WebAuthn ceremony (for passkey login). Shared with login in the OIDC authorization flow.
    passkey_assertion: Arc<PasskeyAssertionService>,
    /// Domains assigned to tenants (ADR-0029). When the login field input has the form `local@domain`,
    /// it is looked up to narrow down the home tenant to one (`login_user_resolution`).
    tenant_domains: Arc<dyn TenantDomainRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    /// Authentication policy evaluation (fetching inputs and evaluating; `authentication_policy_gate`).
    policy_gate: Arc<AuthenticationPolicyGate>,
    hasher: Arc<dyn PasswordHasher>,
    password_policy: Arc<PasswordPolicyService>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// Settings tenants can override (ADR-0058). Looked up on every use. The default effect when no policy matches
    /// (AP2, §4) also comes from here.
    settings: Arc<dyn EffectiveTenantSettings>,
    /// The registered device gate (task #916). `None` means no gate (tests only; api always attaches it).
    device_gate: Option<Arc<DeviceGate>>,
}

/// Conclusion of trying to create SSO in the admin console.
enum AdminSso {
    Issued(String, u64),
    /// It was an unregistered device (task #916).
    EnrollmentRequired(String),
}

impl AdminLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        passkey_assertion: Arc<PasskeyAssertionService>,
        tenant_domains: Arc<dyn TenantDomainRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        policy_gate: Arc<AuthenticationPolicyGate>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> Self {
        Self {
            users,
            passkey_assertion,
            tenant_domains,
            sso_sessions,
            permissions,
            totp_secrets,
            policy_gate,
            hasher,
            password_policy,
            rate_limiter,
            audit,
            clock,
            settings,
            device_gate: None,
        }
    }

    /// Attaches the registered device gate (task #916. ⚠ Always call it when assembling api).
    pub fn with_device_gate(mut self, gate: Arc<DeviceGate>) -> Self {
        self.device_gate = Some(gate);
        self
    }

    /// Evaluates authentication policies and decides whether SSO may be issued (AP2).
    ///
    /// `Ok(())` means it may be issued. `Err(outcome)` becomes the caller's return value as is.
    ///
    /// `used` / `user_verified` are **the authentication methods this path actually passed**. Password login is
    /// single-factor (`[Password]`, no UV), and since the admin console has no second-factor input step,
    /// `require_mfa` varies its guidance by whether an authenticator exists and **issues no SSO either way**. Passkey
    /// login is `[WebAuthn]` with UV, which satisfies `require_mfa` as multi-factor (possession + User Verification),
    /// phishing-resistant authentication (ADR-0020 §3; same rule as the passkey path).
    async fn check_policy(
        &self,
        tenant_id: TenantId,
        user_id: uuid::Uuid,
        used: &[AuthenticationMethod],
        user_verified: bool,
        ctx: &RequestContext,
    ) -> Result<(), AdminLoginOutcome> {
        let decision = self
            .policy_gate
            .decide(PolicyQuery {
                tenant_id,
                audience: PolicyAudience::Unaddressed,
                user_id,
                ip_address: ctx.ip_address.as_deref(),
                // Admin console login is not an OIDC authorization request, so there are no `acr_values`.
                requested_acr: &[],
                now: self.clock.now(),
            })
            .await
            .map_err(|e| AdminLoginOutcome::Internal(e.to_string()))?;
        match decision {
            PolicyDecision::Allow { .. } => Ok(()),
            PolicyDecision::Deny { policy_code } => {
                self.record_policy_denied(
                    tenant_id,
                    user_id,
                    &format!("policy={policy_code}"),
                    ctx,
                )
                .await;
                Err(AdminLoginOutcome::PolicyDenied)
            }
            PolicyDecision::RequireMfa { policy_code } => {
                // A passkey alone satisfies multiple factors, so no second-factor input step is needed.
                if used.contains(&AuthenticationMethod::WebAuthn) {
                    return Ok(());
                }
                let has_totp = match crate::application::mfa_login::user_has_confirmed_totp(
                    self.totp_secrets.as_ref(),
                    user_id,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => return Err(AdminLoginOutcome::Internal(e.to_string())),
                };
                let reason = if has_totp {
                    format!("policy={policy_code} reason=mfa_step_not_available")
                } else {
                    format!("policy={policy_code} reason=mfa_not_enrolled")
                };
                self.record_policy_denied(tenant_id, user_id, &reason, ctx)
                    .await;
                Err(if has_totp {
                    AdminLoginOutcome::MfaRequired
                } else {
                    AdminLoginOutcome::MfaEnrollmentRequired
                })
            }
            // `require_specific_method` (AP3). Admin console login only passes password (+ TOTP) or
            // passkey, so requirements those cannot satisfy are refused.
            PolicyDecision::RequireMethods { .. } => {
                let Some(unmet) = decision.unmet_method_requirement(used, user_verified) else {
                    return Ok(());
                };
                // A passkey has no further factor to add on this path (there is no TOTP input step, and a method
                // requirement a passkey cannot satisfy cannot be satisfied on other paths either). Refuse without separate guidance.
                if used.contains(&AuthenticationMethod::WebAuthn) {
                    let reason = format!(
                        "policy={} reason=method_required required={}",
                        unmet.policy_code,
                        unmet.requirement.describe()
                    );
                    self.record_policy_denied(tenant_id, user_id, &reason, ctx)
                        .await;
                    return Err(AdminLoginOutcome::PolicyDenied);
                }
                // Users who could satisfy it by adding TOTP are sent to the MFA step (same as `require_mfa`).
                // The final decision is made on the path where this method is called again after TOTP verification.
                let has_totp = match crate::application::mfa_login::user_has_confirmed_totp(
                    self.totp_secrets.as_ref(),
                    user_id,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => return Err(AdminLoginOutcome::Internal(e.to_string())),
                };
                let reason = format!(
                    "policy={} reason=method_required required={}",
                    unmet.policy_code,
                    unmet.requirement.describe()
                );
                if has_totp && decision.satisfied_by_adding(used, AuthenticationMethod::Totp, false)
                {
                    self.record_policy_denied(tenant_id, user_id, &reason, ctx)
                        .await;
                    return Err(AdminLoginOutcome::MfaRequired);
                }
                self.record_policy_denied(tenant_id, user_id, &reason, ctx)
                    .await;
                Err(AdminLoginOutcome::PolicyDenied)
            }
        }
    }

    /// Records a policy refusal in the audit (AP2; same event type and reason format as OIDC login).
    async fn record_policy_denied(
        &self,
        tenant_id: TenantId,
        user_id: uuid::Uuid,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::LoginPolicyDenied,
                AuditResult::Failure,
                Some(tenant_id),
                Some(user_id),
                None,
                Some(reason),
                ctx,
            )
            .await;
    }

    pub async fn login(
        &self,
        tenant: TenantContext,
        cmd: AdminLoginCommand,
        ctx: &RequestContext,
    ) -> AdminLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Per-IP rate limit (after CSRF verification, before credential verification; same order as normal login).
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        None,
                        Some("ip_rate_limited"),
                        ctx,
                    )
                    .await;
                return AdminLoginOutcome::RateLimited;
            }
        }

        // 2. User lookup (login identifier, resolved via the AP8 registry). Targets are ACTIVE members of this tenant
        //    (HOME / GUEST; ADR-0009 §8; resolution rules in `login_user_resolution`).
        //    Guest admins are resolved here: a tenant creator becomes an ACTIVE GUEST of the created tenant
        //    (§4), so without this they could not log in directly to the admin console of the tenant they created.
        let user = match resolve_login_user(
            self.users.as_ref(),
            self.tenant_domains.as_ref(),
            tenant_id,
            &cmd.username,
        )
        .await
        {
            Ok(LoginIdentifierMatch::Resolved(u)) => u,
            // The response is the same for missing and ambiguous (avoids revealing existence). Only the audited reason differs.
            Ok(LoginIdentifierMatch::Unresolved(reason)) => {
                // Spend one argon2 verification like a real user so that response time does not reveal
                // whether the user exists (anti-enumeration).
                crate::domain::password::verify_against_dummy(self.hasher.as_ref(), &cmd.password);
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        None,
                        Some(reason.audit_code()),
                        ctx,
                    )
                    .await;
                return AdminLoginOutcome::InvalidCredentials;
            }
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };

        // 3. Check lock state.
        if user.is_locked_at(now) {
            // Spend as much argon2 verification as in the missing case (response time must not reveal state; task #590).
            crate::domain::password::verify_against_dummy(self.hasher.as_ref(), &cmd.password);
            self.audit
                .record(
                    AuditEventType::LoginLocked,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    None,
                    Some("account_locked"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::Locked;
        }

        // 4. Check account state (same response as a credential error to avoid revealing existence).
        if !user.is_active() {
            // Spend as much argon2 verification as in the missing case (response time must not reveal state; task #590).
            crate::domain::password::verify_against_dummy(self.hasher.as_ref(), &cmd.password);
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    None,
                    Some("account_not_active"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::InvalidCredentials;
        }

        // 5. Verify the password.
        let verified = match self.hasher.verify(&cmd.password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if !verified {
            return self
                .handle_password_failure(tenant_id, &user, "invalid_password", ctx)
                .await;
        }

        // 6. Permission check (lock out users with correct credentials but no admin permission).
        //    Decided by exact match of admin permission scoped to the logged-in tenant (ADR-0009 §4;
        //    idp.system.admin exists only in root scope and includes managing root itself, so it is allowed as an alternative).
        //    The password is correct, so the failure counter is not incremented (not subject to lockout).
        let has_admin = match self
            .permissions
            .has_any_permission(
                tenant_id,
                user.id,
                &[permission::TENANT_ADMIN, permission::SYSTEM_ADMIN],
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if !has_admin {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    None,
                    Some("missing_admin_permission"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::Forbidden;
        }

        // 6.4. Authentication policy evaluation (AP2). Gates after credential and permission checks, before issuing SSO.
        if let Err(outcome) = self
            .check_policy(
                tenant_id,
                user.id,
                &[AuthenticationMethod::Password],
                false,
                ctx,
            )
            .await
        {
            return outcome;
        }

        // 6.5. Forced password change (ADR-0009 §5). SSO is not issued yet; lead to the change screen.
        //      Expiry is measured by the policy of the user's home tenant (ADR-0058).
        let password_policy = match self.password_policy.policy(user.tenant_id).await {
            Ok(policy) => policy,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if password_change_required(&user, &password_policy, now) {
            return AdminLoginOutcome::PasswordChangeRequired {
                username: cmd.username,
            };
        }

        // 7. Success: reset the failure counter and lock.
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return AdminLoginOutcome::Internal(e.to_string());
            }
        }

        // 8. Issue the SSO session (session_id in the cookie, SHA-256 hash in the DB; same mechanism as login.rs).
        match self
            .issue_sso(
                tenant_id,
                user.id,
                user.tenant_id,
                vec![AuthenticationMethod::Password],
                ctx,
                now,
            )
            .await
        {
            Ok(AdminSso::Issued(sso_session_id, sso_absolute_ttl_secs)) => {
                AdminLoginOutcome::Success {
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AdminSso::EnrollmentRequired(ticket)) => {
                AdminLoginOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => AdminLoginOutcome::Internal(e),
        }
    }

    /// Admin console login with a passkey (WebAuthn).
    ///
    /// It differs from the password path ([`Self::login`]) in three points, all the same rules as passkey login
    /// in the OIDC authorization flow ([`crate::application::passkey_authentication`]):
    ///
    /// 1. No login identifier resolution and no lockout increment. The discoverable credential itself names
    ///    the owner, and there is no secret to brute-force.
    /// 2. Satisfies `require_mfa` (multi-factor, phishing-resistant: possession + User Verification).
    ///    **Admins under `require_mfa` who cannot enter via the password path can enter only via this path.**
    /// 3. Ignores forced password change (`must_change_password`). This path does not use passwords,
    ///    so forcing a change is meaningless.
    ///
    /// Admin permission check, authentication policy evaluation and SSO issuance go through exactly the same steps as the password path.
    pub async fn login_with_passkey(
        &self,
        tenant: TenantContext,
        cmd: AdminPasskeyLoginCommand,
        ctx: &RequestContext,
    ) -> AdminLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Per-IP rate limit (same order and limit as the password path).
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        None,
                        Some("ip_rate_limited"),
                        ctx,
                    )
                    .await;
                return AdminLoginOutcome::RateLimited;
            }
        }

        // 2. Verify the WebAuthn assertion. Account validity and the tenant boundary (ADR-0009 §8) are
        //    confirmed here. `Direct` requires the challenge to be outside the authorization flow.
        let verified = match self
            .passkey_assertion
            .verify(
                tenant_id,
                cmd.challenge_id,
                cmd.credential,
                PasskeyFlow::Direct,
                ctx,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return e.into(),
        };
        let user_id = verified.user_id;

        // 3. Permission check (same decision as step 6 of the password path; ADR-0009 §4).
        let has_admin = match self
            .permissions
            .has_any_permission(
                tenant_id,
                user_id,
                &[permission::TENANT_ADMIN, permission::SYSTEM_ADMIN],
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if !has_admin {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    None,
                    Some("missing_admin_permission"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::Forbidden;
        }

        // 4. Authentication policy evaluation (AP2). The method used is a single passkey, with User Verification.
        if let Err(outcome) = self
            .check_policy(
                tenant_id,
                user_id,
                &[AuthenticationMethod::WebAuthn],
                true,
                ctx,
            )
            .await
        {
            return outcome;
        }

        // 5. Issue the SSO session (same mechanism as the password path; only the method is WebAuthn).
        match self
            .issue_sso(
                tenant_id,
                user_id,
                verified.home_tenant_id,
                vec![AuthenticationMethod::WebAuthn],
                ctx,
                now,
            )
            .await
        {
            Ok(AdminSso::Issued(sso_session_id, sso_absolute_ttl_secs)) => {
                AdminLoginOutcome::Success {
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AdminSso::EnrollmentRequired(ticket)) => {
                AdminLoginOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => AdminLoginOutcome::Internal(e),
        }
    }

    /// Issues the SSO session and records it in the audit (session_id in the cookie, SHA-256 hash in the DB;
    /// same mechanism as `login.rs`). Shared by the three paths: password, forced password change, passkey.
    ///
    /// The lifetime is decided by the user's **home** tenant (`home_tenant_id`). The SSO session is shared across
    /// tenants, so it is not decided by the tenant of the screen logged in from (ADR-0058).
    async fn issue_sso(
        &self,
        tenant_id: TenantId,
        user_id: uuid::Uuid,
        home_tenant_id: TenantId,
        methods: Vec<AuthenticationMethod>,
        ctx: &RequestContext,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AdminSso, String> {
        if let Some(gate) = &self.device_gate {
            let admission = gate
                .admit(
                    AdmissionAttempt {
                        tenant_id,
                        user_id,
                        home_tenant_id,
                        methods: &methods,
                        client_id: None,
                        app_approved: false,
                    },
                    ctx,
                    now,
                )
                .await
                .map_err(|e| e.to_string())?;
            if let Admission::EnrollmentRequired { ticket } = admission {
                return Ok(AdminSso::EnrollmentRequired(ticket));
            }
        }
        let lifetime = self
            .settings
            .sso_session_lifetime(home_tenant_id)
            .await
            .map_err(|e| e.to_string())?;
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession::establish(
            crypto::sha256_hex(&sso_session_id),
            user_id,
            now,
            lifetime.idle,
            lifetime.absolute,
            methods,
            ctx.user_agent.clone(),
            ctx.ip_address.clone(),
        );
        if let Err(e) = self.sso_sessions.create(&sso).await {
            return Err(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::LoginSucceeded,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                None,
                ctx,
            )
            .await;
        Ok(AdminSso::Issued(sso_session_id, sso.absolute_ttl_secs()))
    }

    /// Forced password change (ADR-0009 §5). Fully re-verifies admin login including the current password, and on success
    /// saves the new password and issues the SSO session (the same verification as `login` is redone every time, because
    /// admin login has no temporary state like `auth_session_id`).
    pub async fn change_password(
        &self,
        tenant: TenantContext,
        cmd: AdminChangePasswordCommand,
        ctx: &RequestContext,
    ) -> AdminLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                return AdminLoginOutcome::RateLimited;
            }
        }

        let user = match resolve_login_user(
            self.users.as_ref(),
            self.tenant_domains.as_ref(),
            tenant_id,
            &cmd.username,
        )
        .await
        {
            Ok(LoginIdentifierMatch::Resolved(u)) => u,
            Ok(LoginIdentifierMatch::Unresolved(_)) => {
                // Spend one argon2 verification like a real user so that response time does not reveal
                // whether the user exists (anti-enumeration).
                crate::domain::password::verify_against_dummy(
                    self.hasher.as_ref(),
                    &cmd.current_password,
                );
                return AdminLoginOutcome::InvalidCredentials;
            }
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };

        if user.is_locked_at(now) {
            return AdminLoginOutcome::Locked;
        }
        if !user.is_active() {
            return AdminLoginOutcome::InvalidCredentials;
        }
        // Detecting duplicate submission (idempotency): a resend right after the previous submission succeeded and cleared
        // `must_change_password` would fail to match the old current_password against the new hash and wrongly show "current password is wrong".
        // If `new_password` matches the current hash, treat it as a resend of the same change, skip saving, and
        // proceed to the same follow-up as on success (admin permission check -> SSO issuance) (the match is a full verification
        // of the current password, so authentication strength equals normal login).
        // Whether a change is required (forced flag, or expired; AP7).
        let password_policy = match self.password_policy.policy(user.tenant_id).await {
            Ok(policy) => policy,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        let change_required = password_change_required(&user, &password_policy, now);
        let duplicate_submit = if change_required {
            false
        } else {
            match self.hasher.verify(&cmd.new_password, &user.password_hash) {
                Ok(v) => v,
                Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
            }
        };
        if !change_required && !duplicate_submit {
            // Reaching this endpoint when no change is needed is unexpected. Fail closed
            // (same response as a credential error to avoid user enumeration). The `new_password` match above acts as
            // a password correctness oracle, so it is put under the same failure count and lock decision as normal login,
            // so this path does not become a guessing route bypassing lockout.
            return self
                .handle_password_failure(tenant_id, &user, "password_change_not_required", ctx)
                .await;
        }

        if !duplicate_submit {
            let verified = match self
                .hasher
                .verify(&cmd.current_password, &user.password_hash)
            {
                Ok(v) => v,
                Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
            };
            if !verified {
                return self
                    .handle_password_failure(tenant_id, &user, "invalid_password", ctx)
                    .await;
            }
        }

        let has_admin = match self
            .permissions
            .has_any_permission(
                tenant_id,
                user.id,
                &[permission::TENANT_ADMIN, permission::SYSTEM_ADMIN],
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if !has_admin {
            return AdminLoginOutcome::Forbidden;
        }

        // Authentication policy evaluation (AP2). This path also issues SSO, so the same rules as `login` apply.
        if let Err(outcome) = self
            .check_policy(
                tenant_id,
                user.id,
                &[AuthenticationMethod::Password],
                false,
                ctx,
            )
            .await
        {
            return outcome;
        }

        // For duplicate submissions (change already applied), skip saving and auditing and proceed to the same follow-up as on success.
        if !duplicate_submit {
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
                Ok(Err(rejection)) => return AdminLoginOutcome::WeakPassword(rejection),
                Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
            }
            let new_hash = match self.hasher.hash(&cmd.new_password) {
                Ok(h) => h,
                Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
            };
            // Replacement conditioned on the current hash (AP7). The failure counter is not incremented
            // (credentials are correct; what lost was a race, not a guess).
            match self
                .users
                .update_password(user.id, &user.password_hash, &new_hash)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        "admin password change lost a concurrent update; asking to retry"
                    );
                    return AdminLoginOutcome::InvalidCredentials;
                }
                Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
            }
            self.password_policy
                .record_change(user.tenant_id, user.id, &user.password_hash)
                .await;
            self.audit
                .record(
                    AuditEventType::PasswordChanged,
                    AuditResult::Success,
                    Some(tenant_id),
                    Some(user.id),
                    None,
                    None,
                    ctx,
                )
                .await;
        }

        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return AdminLoginOutcome::Internal(e.to_string());
            }
        }

        match self
            .issue_sso(
                tenant_id,
                user.id,
                user.tenant_id,
                vec![AuthenticationMethod::Password],
                ctx,
                now,
            )
            .await
        {
            Ok(AdminSso::Issued(sso_session_id, sso_absolute_ttl_secs)) => {
                AdminLoginOutcome::Success {
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AdminSso::EnrollmentRequired(ticket)) => {
                AdminLoginOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => AdminLoginOutcome::Internal(e),
        }
    }

    /// Logout from the admin console. Deletes the SSO session from the DB and records it in the audit.
    /// Cookie expiry is done by Presentation (the handler). Unknown or invalid sessions do nothing (idempotent).
    pub async fn logout(&self, tenant: TenantContext, sso_session_id: &str, ctx: &RequestContext) {
        if sso_session_id.is_empty() {
            return;
        }
        let session_hash = crypto::sha256_hex(sso_session_id);
        // Fetch the session before deletion to keep user_id in the audit (best-effort).
        let user_id = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(session)) => Some(session.user_id),
            _ => None,
        };
        if let Err(e) = self.sso_sessions.delete(&session_hash).await {
            tracing::warn!(error = %e, "failed to delete sso session on admin logout");
            return;
        }
        self.audit
            .record(
                AuditEventType::SsoSessionTerminated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                user_id,
                None,
                Some("admin_logout"),
                ctx,
            )
            .await;
    }

    /// Updates the failure count on password mismatch and decides lockout (same policy as login.rs).
    async fn handle_password_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        reason: &str,
        ctx: &RequestContext,
    ) -> AdminLoginOutcome {
        let now = self.clock.now();
        // The threshold is the user's home tenant's value (lock state is on the user row; ADR-0058).
        let lockout = match self.settings.login_lockout(user.tenant_id).await {
            Ok(lockout) => lockout,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        // Increment and lock decision are enclosed in one UPDATE statement (SEC13).
        let failure = match self.users.record_login_failure(user.id, lockout, now).await {
            Ok(f) => f,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };

        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                Some(user.id),
                None,
                Some(reason),
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
                    None,
                    Some("too_many_failures"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::Locked;
        }
        AdminLoginOutcome::InvalidCredentials
    }
}

impl From<PasskeyAssertionError> for AdminLoginOutcome {
    fn from(e: PasskeyAssertionError) -> Self {
        match e {
            // A challenge for another purpose (trying to complete an authorization-flow one in admin login) is, to the user,
            // just "please try again", so it is treated the same as expired.
            PasskeyAssertionError::ChallengeNotFound | PasskeyAssertionError::WrongFlow => {
                AdminLoginOutcome::PasskeyChallengeNotFound
            }
            // Suspended, revoked, not in the tenant and disabled account also get the same response (anti-enumeration).
            PasskeyAssertionError::InvalidCredential => AdminLoginOutcome::InvalidCredentials,
            PasskeyAssertionError::Internal(msg) => AdminLoginOutcome::Internal(msg),
        }
    }
}

#[cfg(test)]
mod debug_redaction_tests {
    use super::*;

    /// Do not print the password in `Debug` (task #593).
    #[test]
    fn commands_do_not_print_passwords() {
        let login = AdminLoginCommand {
            username: "admin".to_string(),
            password: "pa55-secret".to_string(),
        };
        let change = AdminChangePasswordCommand {
            username: "admin".to_string(),
            current_password: "old-secret".to_string(),
            new_password: "new-secret".to_string(),
        };
        let shown = format!("{login:?} {change:?}");
        for secret in ["pa55-secret", "old-secret", "new-secret"] {
            assert!(!shown.contains(secret), "{shown}");
        }
        assert!(shown.contains("admin"), "{shown}");
    }
}
