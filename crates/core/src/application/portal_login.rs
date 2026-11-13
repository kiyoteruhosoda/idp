//! Use case for logging in to the end-user portal.
//!
//! Normal OIDC login ([`crate::application::login`]) is bound to the `auth_session_id` issued by `/authorize`, and
//! after success issues an authorization code and returns to the RP's `redirect_uri`. This use case, by contrast, is a
//! **client-independent direct login** for entering the IdP's own account screen (`/{tenant_id}/settings`), and like
//! admin console login ([`crate::application::admin_login`]) it **issues the SSO session directly**
//! (no code issuance or redirect).
//!
//! Two differences from admin login:
//! 1. It doesn't require admin permissions (any active user can enter).
//! 2. **It respects TOTP (MFA).** For users with TOTP set up, password authentication alone doesn't issue SSO; a signed
//!    short-lived ticket (`mfa_ticket`) is returned and the user is sent to the TOTP input step. This keeps portal login
//!    from being a loophole that bypasses OIDC login's MFA to obtain SSO.
//!
//! Lockout (design spec §4.3), IP rate limiting, the email verification gate (SEC6b) and forced password change
//! (ADR-0009 §5) are applied with the same policy as normal login.
//!
//! Authentication policies (AP2. User authentication & authentication policy spec §7–§9) are also applied with the same rules as OIDC login.
//! A policy is "a condition to satisfy at authentication", not "a condition to satisfy in the OIDC flow", so
//! if only the portal and admin console were outside the policies, a user who should have been `deny`-ed could
//! obtain an SSO session via the portal (and with that session even pass OIDC SSO restore).
//! The portal has no client context, so the evaluation context's `client_id` is `None`
//! (policies with `client_ids` conditions don't match = `user_ids` conditions and global conditions are the main targets).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::authenticator_management::{
    consume_single_use_code, is_blocked_in_registry,
};
use crate::application::device_enrollment::{Admission, AdmissionAttempt, DeviceGate};
use crate::application::login_user_resolution::resolve_login_user;
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::application::passkey_assertion::{
    PasskeyAssertionError, PasskeyAssertionService, PasskeyFlow,
};
use crate::application::password_policy::PasswordPolicyService;
use crate::application::totp_registration::verify_totp_code;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::login_identifier::LoginIdentifierMatch;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::{password_change_required, PasswordRejection};
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::TenantDomainRepository;
use crate::domain::repositories::{
    SsoSessionRepository, TotpSecretRepository, UserAuthenticatorRepository, UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::user_authenticator::AuthenticatorType;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Lifetime of the MFA ticket (seconds). Time allowed until TOTP input.
const MFA_TICKET_TTL_SECS: i64 = 300;

pub struct PortalLoginCommand {
    /// Login identifier (user name = `preferred_username`. ADR-0009 §8).
    pub username: String,
    pub password: String,
}

/// ⚠ Don't put secrets (`password`) in `Debug` (task #593). Fields are chosen by hand so values don't leak
/// even if logged with `{:?}`.
impl std::fmt::Debug for PortalLoginCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalLoginCommand")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct PortalMfaCommand {
    pub mfa_ticket: String,
    pub totp_code: String,
}

/// Command for portal login with a passkey (WebAuthn). Takes neither a login identifier nor a password
/// (the discoverable credential names its owner).
#[derive(Debug)]
pub struct PortalPasskeyLoginCommand {
    /// The challenge ID returned by `POST /internal/passkey/login/begin`.
    pub challenge_id: Uuid,
    /// The assertion returned by the browser's `navigator.credentials.get()`.
    pub credential: serde_json::Value,
}

/// Command for the portal's forced password change (ADR-0009 §5). Portal login holds no temporary state like
/// `auth_session_id`, so like the admin console it fully re-verifies every time, including the current password.
pub struct PortalChangePasswordCommand {
    /// Login identifier (user name = `preferred_username`).
    pub username: String,
    pub current_password: String,
    pub new_password: String,
}

/// ⚠ Don't put secrets (`current_password`, `new_password`) in `Debug` (task #593). Fields are chosen by hand so values
/// don't leak even if logged with `{:?}`.
impl std::fmt::Debug for PortalChangePasswordCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalChangePasswordCommand")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// Result of portal login. Presentation maps it to a screen (HTML).
pub enum PortalLoginOutcome {
    /// Authenticated (no TOTP). Issue the SSO cookie and 302 to the account screen.
    Success {
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
        user_language: Option<String>,
    },
    /// Password authentication succeeded but TOTP is needed. Turn `mfa_ticket` into a cookie and send to the TOTP input screen.
    MfaRequired {
        mfa_ticket: String,
    },
    /// The self-registered account's email is unverified (SEC6b).
    EmailVerificationRequired,
    /// Forced password change needed (ADR-0009 §5). web sends the user to the forced password change form
    /// (same approach as the admin console; `username` returns the input value to re-display the form).
    PasswordChangeRequired {
        username: String,
    },
    /// Denied by the authentication policy (AP2. spec §7.4 `deny`). Credentials are verified, so it may be shown with
    /// wording distinct from a credential error: "denied by the organization's policy".
    PolicyDenied,
    /// The authentication policy requires MFA, but there is no usable authenticator (verified TOTP) (AP2).
    MfaEnrollmentRequired,
    /// Passkey challenge not found, expired, or for another purpose (passkey path only). Prompt to retry.
    PasskeyChallengeNotFound,
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// Invalid credentials (missing user, wrong password and disabled account are not distinguished).
    InvalidCredentials,
    /// Account locked.
    Locked,
    /// Authentication passed, but in an organization limited to registered devices this device is not registered (task #916). No SSO was created.
    DeviceEnrollmentRequired {
        ticket: String,
    },
    Internal(String),
}

/// Result of the portal's forced password change.
pub enum PortalChangePasswordOutcome {
    /// Changed (no TOTP). Issue the SSO cookie and 302 to the account screen.
    Success {
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
        user_language: Option<String>,
    },
    /// The password change succeeded but TOTP is needed (same MFA gate as `login()`). Turn `mfa_ticket` into a cookie and
    /// send to the TOTP input screen. SSO is not issued yet (prevents bypassing MFA by possession alone).
    MfaRequired {
        mfa_ticket: String,
    },
    /// The self-registered account's email is unverified (SEC6b). This stateless path hasn't gone through `login()`'s email
    /// verification gate, so it is re-checked here (closes the loophole of an admin resetting an unverified user).
    EmailVerificationRequired,
    /// Changed, but denied by the authentication policy (AP2. spec §7.4 `deny`).
    PolicyDenied,
    /// Changed, but the authentication policy requires MFA and there is no usable authenticator (AP2).
    MfaEnrollmentRequired,
    /// Per-IP rate limit exceeded.
    RateLimited,
    /// Invalid credentials (missing user, wrong current password and disabled account are not distinguished).
    InvalidCredentials,
    /// Account locked.
    Locked,
    /// The new password doesn't meet the strength requirements.
    /// The new password doesn't satisfy the policy (length, breached, reused. AP7).
    WeakPassword(PasswordRejection),
    /// Authentication passed, but in an organization limited to registered devices this device is not registered (task #916). No SSO was created.
    DeviceEnrollmentRequired {
        ticket: String,
    },
    Internal(String),
}

/// Result of portal TOTP verification.
pub enum PortalMfaOutcome {
    Success {
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
        user_language: Option<String>,
    },
    /// Invalid TOTP code (can retry while the ticket is valid).
    InvalidCode,
    /// Denied by the authentication policy (AP2; when the policy changed after the ticket was issued).
    PolicyDenied,
    /// The ticket is invalid or expired (start over from login).
    TicketExpired,
    RateLimited,
    /// Authentication passed, but in an organization limited to registered devices this device is not registered (task #916). No SSO was created.
    DeviceEnrollmentRequired {
        ticket: String,
    },
    Internal(String),
}

pub struct PortalLoginService {
    /// The authenticator registry (AP9). Used to consume recovery codes and email OTPs.
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    users: Arc<dyn UserRepository>,
    /// WebAuthn ceremony (for passkey login). Shares the same one as OIDC authorization flow login.
    passkey_assertion: Arc<PasskeyAssertionService>,
    /// Domains assigned to tenants (ADR-0029). Looked up when the login input has the form `local@domain`,
    /// to pin down a single home tenant (`login_user_resolution`).
    tenant_domains: Arc<dyn TenantDomainRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    /// Authentication policy evaluation (looking up inputs and evaluating. `authentication_policy_gate`).
    policy_gate: Arc<AuthenticationPolicyGate>,
    hasher: Arc<dyn PasswordHasher>,
    password_policy: Arc<PasswordPolicyService>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
    /// Signing key for `mfa_ticket`. Reuses the CSRF secret (purposes are namespaced by prefix).
    ticket_secret: [u8; 32],
    /// Settings tenants can override (ADR-0058). Looked up every time. The default behavior when no policy
    /// matches (AP2, §4) is also taken from here.
    settings: Arc<dyn EffectiveTenantSettings>,
    /// The registered-device gate (task #916). `None` means no gate (tests only; api always attaches it).
    device_gate: Option<Arc<DeviceGate>>,
}

/// Conclusion of trying to create SSO in the portal.
enum PortalSso {
    Issued {
        sso_session_id: String,
        sso_absolute_ttl_secs: u64,
    },
    /// It was an unregistered device (task #916).
    EnrollmentRequired { ticket: String },
}

impl PortalLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        users: Arc<dyn UserRepository>,
        passkey_assertion: Arc<PasskeyAssertionService>,
        tenant_domains: Arc<dyn TenantDomainRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        policy_gate: Arc<AuthenticationPolicyGate>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
        ticket_secret: [u8; 32],
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> Self {
        Self {
            authenticators,
            users,
            passkey_assertion,
            tenant_domains,
            sso_sessions,
            totp_secrets,
            policy_gate,
            hasher,
            password_policy,
            rate_limiter,
            audit,
            clock,
            key_encryption_key,
            ticket_secret,
            settings,
            device_gate: None,
        }
    }

    /// Attaches the registered-device gate (task #916. ⚠ always call it when assembling api).
    pub fn with_device_gate(mut self, gate: Arc<DeviceGate>) -> Self {
        self.device_gate = Some(gate);
        self
    }

    /// Evaluates the authentication policy (AP2). The portal has no client context, so `client_id` is `None`.
    async fn evaluate_policy(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        ip_address: Option<&str>,
    ) -> Result<PolicyDecision, String> {
        self.policy_gate
            .decide(PolicyQuery {
                tenant_id,
                audience: PolicyAudience::Unaddressed,
                user_id,
                ip_address,
                // Portal login is not an OIDC authorization request, so there are no `acr_values`.
                requested_acr: &[],
                now: self.clock.now(),
            })
            .await
            .map_err(|e| e.to_string())
    }

    /// Records a policy denial in the audit (AP2; uses the same event type and reason format as OIDC login).
    async fn record_policy_denied(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
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
        cmd: PortalLoginCommand,
        ctx: &RequestContext,
    ) -> PortalLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Per-IP rate limit (before credential verification; same order as normal login).
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.record_failure(tenant_id, None, "ip_rate_limited", ctx)
                    .await;
                return PortalLoginOutcome::RateLimited;
            }
        }

        // 2. Look up the user (login identifier, resolved via the AP8 registry). Targets are this tenant's ACTIVE
        //    members (HOME / GUEST. ADR-0009 §8; resolution rules in `login_user_resolution`).
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
                self.record_failure(tenant_id, None, reason.audit_code(), ctx)
                    .await;
                return PortalLoginOutcome::InvalidCredentials;
            }
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };

        // 3. Check the lock state.
        if user.is_locked_at(now) {
            // Spend the same argon2 verification as for a missing user (don't let the state be inferred from response time. task #590).
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
            return PortalLoginOutcome::Locked;
        }

        // 4. Check the account state (same response as a credential error to avoid revealing existence).
        if !user.is_active() {
            // Spend the same argon2 verification as for a missing user (don't let the state be inferred from response time. task #590).
            crate::domain::password::verify_against_dummy(self.hasher.as_ref(), &cmd.password);
            self.record_failure(tenant_id, Some(user.id), "account_not_active", ctx)
                .await;
            return PortalLoginOutcome::InvalidCredentials;
        }

        // 5. Verify the password.
        let verified = match self.hasher.verify(&cmd.password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };
        if !verified {
            return self.handle_password_failure(tenant_id, &user, ctx).await;
        }

        // 6. Success: reset the failure counter and lock.
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return PortalLoginOutcome::Internal(e.to_string());
            }
        }

        // 7. Email verification gate (SEC6b). Checked after password verification succeeds to prevent enumeration.
        if !user.email_verified {
            self.record_failure(tenant_id, Some(user.id), "email_not_verified", ctx)
                .await;
            return PortalLoginOutcome::EmailVerificationRequired;
        }

        // 7.5. Authentication policy evaluation (AP2. spec §9). Evaluated after password verification (attackers without
        //      credentials can't observe a policy's existence or content). `deny` refuses immediately; `require_mfa` is enforced
        //      by the later MFA gate (9.).
        let policy_decision = match self
            .evaluate_policy(tenant_id, user.id, ctx.ip_address.as_deref())
            .await
        {
            Ok(d) => d,
            Err(e) => return PortalLoginOutcome::Internal(e),
        };
        if let PolicyDecision::Deny { policy_code } = &policy_decision {
            self.record_policy_denied(tenant_id, user.id, &format!("policy={policy_code}"), ctx)
                .await;
            return PortalLoginOutcome::PolicyDenied;
        }

        // 8. Forced password change (ADR-0009 §5). Don't issue SSO yet; send to the forced change form
        //    (same approach as the admin console; `change_password` re-verifies including the current password).
        //    Expiry is measured by the policy of the user's home tenant (ADR-0058).
        let password_policy = match self.password_policy.policy(user.tenant_id).await {
            Ok(policy) => policy,
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };
        if password_change_required(&user, &password_policy, now) {
            return PortalLoginOutcome::PasswordChangeRequired {
                username: cmd.username,
            };
        }

        // 9. If TOTP (MFA) is set up, don't issue SSO; send to the TOTP input step.
        let has_totp = match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
            Ok(v) => v,
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };
        if has_totp {
            let ticket = self.issue_ticket(tenant_id, user.id, now);
            return PortalLoginOutcome::MfaRequired { mfa_ticket: ticket };
        }
        // If the policy requires MFA but there's no usable authenticator, single-factor completion isn't allowed
        // (spec §24.4). Same order and same check as OIDC login (`login.rs`).
        if let PolicyDecision::RequireMfa { policy_code } = &policy_decision {
            self.record_policy_denied(
                tenant_id,
                user.id,
                &format!("policy={policy_code} reason=mfa_not_enrolled"),
                ctx,
            )
            .await;
            return PortalLoginOutcome::MfaEnrollmentRequired;
        }
        // `require_specific_method` (AP3). Reaching here = the only method used when this path completes is the
        // password (users with TOTP left via the MFA step above, and `verify_mfa` re-checks with the
        // final set of methods). If not satisfied, SSO is not issued.
        if let Some(unmet) =
            policy_decision.unmet_method_requirement(&[AuthenticationMethod::Password], false)
        {
            self.record_policy_denied(
                tenant_id,
                user.id,
                &format!(
                    "policy={} reason=method_required required={}",
                    unmet.policy_code,
                    unmet.requirement.describe()
                ),
                ctx,
            )
            .await;
            return PortalLoginOutcome::PolicyDenied;
        }

        // 10. No TOTP: issue the SSO session.
        let (sso_session_id, sso_absolute_ttl_secs) = match self
            .issue_sso(
                tenant_id,
                &user,
                vec![AuthenticationMethod::Password],
                ctx,
                now,
            )
            .await
        {
            Ok(PortalSso::Issued {
                sso_session_id,
                sso_absolute_ttl_secs,
            }) => (sso_session_id, sso_absolute_ttl_secs),
            Ok(PortalSso::EnrollmentRequired { ticket }) => {
                return PortalLoginOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return PortalLoginOutcome::Internal(e),
        };
        PortalLoginOutcome::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language: user.language.clone(),
        }
    }

    /// Portal login with a passkey (WebAuthn).
    ///
    /// The differences from the password path ([`Self::login`]) follow the same rules as passkey login in the OIDC
    /// authorization flow ([`crate::application::passkey_authentication`]):
    ///
    /// 1. No login identifier resolution and no lockout increments (there's no secret to brute-force).
    /// 2. **No TOTP input step.** A passkey is multi-factor (possession + User Verification) and
    ///    phishing-resistant, satisfying `require_mfa`. Requiring "passkey + TOTP" from users with TOTP set up
    ///    gains nothing.
    /// 3. Forced password change (`must_change_password`) is not checked (the path doesn't use a password).
    ///
    /// **The email verification gate (SEC6b) remains.** It decides not credential strength but "may this account
    /// enter the portal", and changing the authentication method is no reason to drop it.
    pub async fn login_with_passkey(
        &self,
        tenant: TenantContext,
        cmd: PortalPasskeyLoginCommand,
        ctx: &RequestContext,
    ) -> PortalLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Per-IP rate limit (same order and same limit as the password path).
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.record_failure(tenant_id, None, "ip_rate_limited", ctx)
                    .await;
                return PortalLoginOutcome::RateLimited;
            }
        }

        // 2. Verify the WebAuthn assertion. Account validity and the tenant boundary (ADR-0009 §8) are
        //    confirmed here. `Direct` requires that the challenge is from outside the authorization flow.
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

        // 3. Look up the user again for the display language and email verification state in the response (validity was decided in 2.).
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return PortalLoginOutcome::InvalidCredentials,
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };

        // 4. Email verification gate (SEC6b). Same check as step 7 of the password path.
        if !user.email_verified {
            self.record_failure(tenant_id, Some(user.id), "email_not_verified", ctx)
                .await;
            return PortalLoginOutcome::EmailVerificationRequired;
        }

        // 5. Authentication policy evaluation (AP2). `deny` refuses; `require_mfa` is satisfied by the passkey.
        let policy_decision = match self
            .evaluate_policy(tenant_id, user.id, ctx.ip_address.as_deref())
            .await
        {
            Ok(d) => d,
            Err(e) => return PortalLoginOutcome::Internal(e),
        };
        if let PolicyDecision::Deny { policy_code } = &policy_decision {
            self.record_policy_denied(tenant_id, user.id, &format!("policy={policy_code}"), ctx)
                .await;
            return PortalLoginOutcome::PolicyDenied;
        }
        // `require_specific_method` (AP3). The method used is a single passkey with User Verification done.
        // No more factors can be added on this path, so if not satisfied, refuse without issuing SSO.
        if let Some(unmet) =
            policy_decision.unmet_method_requirement(&[AuthenticationMethod::WebAuthn], true)
        {
            self.record_policy_denied(
                tenant_id,
                user.id,
                &format!(
                    "policy={} reason=method_required required={}",
                    unmet.policy_code,
                    unmet.requirement.describe()
                ),
                ctx,
            )
            .await;
            return PortalLoginOutcome::PolicyDenied;
        }

        // 6. Issue the SSO session (same mechanism as the password path; only the method is WebAuthn).
        let (sso_session_id, sso_absolute_ttl_secs) = match self
            .issue_sso(
                tenant_id,
                &user,
                vec![AuthenticationMethod::WebAuthn],
                ctx,
                now,
            )
            .await
        {
            Ok(PortalSso::Issued {
                sso_session_id,
                sso_absolute_ttl_secs,
            }) => (sso_session_id, sso_absolute_ttl_secs),
            Ok(PortalSso::EnrollmentRequired { ticket }) => {
                return PortalLoginOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return PortalLoginOutcome::Internal(e),
        };
        PortalLoginOutcome::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language: user.language.clone(),
        }
    }

    /// Forced password change (ADR-0009 §5). Fully re-verifies portal login including the current password, and
    /// on success saves the new password and issues the SSO session (same approach as the admin console's `change_password`;
    /// the only difference is that the portal doesn't require admin permissions). Users in this state can't set up
    /// self-service MFA (that needs SSO), so there's no need to go to the TOTP check again after the change.
    pub async fn change_password(
        &self,
        tenant: TenantContext,
        cmd: PortalChangePasswordCommand,
        ctx: &RequestContext,
    ) -> PortalChangePasswordOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.record_failure(tenant_id, None, "ip_rate_limited", ctx)
                    .await;
                return PortalChangePasswordOutcome::RateLimited;
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
                // Spend one argon2 verification, same as for a real user, so the user's existence can't be
                // inferred from response time (enumeration countermeasure).
                crate::domain::password::verify_against_dummy(
                    self.hasher.as_ref(),
                    &cmd.current_password,
                );
                return PortalChangePasswordOutcome::InvalidCredentials;
            }
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };

        if user.is_locked_at(now) {
            return PortalChangePasswordOutcome::Locked;
        }
        if !user.is_active() {
            return PortalChangePasswordOutcome::InvalidCredentials;
        }

        // Duplicate submission detection (idempotency): if the same form is resubmitted right after the previous submission
        // succeeded and cleared `must_change_password` (double click, reloading the POST response), the old current_password
        // doesn't match the new hash, so "the current password is incorrect" used to be shown wrongly.
        // If `new_password` matches the current hash, it is treated as a resubmission of the same change; saving is skipped and
        // it proceeds to the same follow-up as success (email verification -> TOTP gate -> SSO issuance). Checking `new_password`
        // is a full verification of the current password, so authentication strength equals normal login (no enumeration either).
        // Whether a change is required (forced flag, or expired. AP7).
        let password_policy = match self.password_policy.policy(user.tenant_id).await {
            Ok(policy) => policy,
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };
        let change_required = password_change_required(&user, &password_policy, now);
        let duplicate_submit = if change_required {
            false
        } else {
            match self.hasher.verify(&cmd.new_password, &user.password_hash) {
                Ok(v) => v,
                Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
            }
        };
        if !change_required && !duplicate_submit {
            // Reaching this endpoint when no change is needed is unexpected. Fail closed
            // (same response as a credential error to avoid user enumeration). The `new_password` check above acts as
            // an oracle for password correctness, so it is put on the same failure count and lock decision as normal login
            // so this path can't become a guessing channel that bypasses lockout.
            return self
                .handle_change_password_failure(
                    tenant_id,
                    &user,
                    "password_change_not_required",
                    ctx,
                )
                .await;
        }

        let verified = if duplicate_submit {
            true
        } else {
            match self
                .hasher
                .verify(&cmd.current_password, &user.password_hash)
            {
                Ok(v) => v,
                Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
            }
        };
        if !verified {
            // A current password mismatch is put on the same failure count and lock decision as normal login.
            return self
                .handle_change_password_failure(tenant_id, &user, "invalid_password", ctx)
                .await;
        }

        // Email verification gate (SEC6b). `login()` checks email verification before forced change, but this path is
        // stateless and directly callable, so it can't rely on that. Checked after current password verification to prevent enumeration.
        if !user.email_verified {
            self.record_failure(tenant_id, Some(user.id), "email_not_verified", ctx)
                .await;
            return PortalChangePasswordOutcome::EmailVerificationRequired;
        }

        // For a duplicate submission (change already applied), skip saving and audit and proceed to the same follow-up as success.
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
                Ok(Err(rejection)) => return PortalChangePasswordOutcome::WeakPassword(rejection),
                Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
            }
            let new_hash = match self.hasher.hash(&cmd.new_password) {
                Ok(h) => h,
                Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
            };
            // Replace conditioned on the current hash (AP7; same as `admin_login`).
            match self
                .users
                .update_password(user.id, &user.password_hash, &new_hash)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        "portal password change lost a concurrent update; asking to retry"
                    );
                    return PortalChangePasswordOutcome::InvalidCredentials;
                }
                Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
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
                return PortalChangePasswordOutcome::Internal(e.to_string());
            }
        }

        // Authentication policy evaluation (AP2). This path also issues SSO, so the same rules as `login()` apply
        // (the password change itself completes as self-service; only session issuance is gated).
        let policy_decision = match self
            .evaluate_policy(tenant_id, user.id, ctx.ip_address.as_deref())
            .await
        {
            Ok(d) => d,
            Err(e) => return PortalChangePasswordOutcome::Internal(e),
        };
        if let PolicyDecision::Deny { policy_code } = &policy_decision {
            self.record_policy_denied(tenant_id, user.id, &format!("policy={policy_code}"), ctx)
                .await;
            return PortalChangePasswordOutcome::PolicyDenied;
        }

        // If TOTP (MFA) is set up, don't issue SSO; send to the TOTP input step (same MFA gate as `login()`).
        // Even if an admin resets the password of an existing TOTP user, possessing the generated password alone
        // can't bypass the second factor.
        let has_totp = match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
            Ok(v) => v,
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };
        if has_totp {
            let ticket = self.issue_ticket(tenant_id, user.id, now);
            return PortalChangePasswordOutcome::MfaRequired { mfa_ticket: ticket };
        }
        if let PolicyDecision::RequireMfa { policy_code } = &policy_decision {
            self.record_policy_denied(
                tenant_id,
                user.id,
                &format!("policy={policy_code} reason=mfa_not_enrolled"),
                ctx,
            )
            .await;
            return PortalChangePasswordOutcome::MfaEnrollmentRequired;
        }
        // `require_specific_method` (AP3). The only method fixed on this path is the password.
        if let Some(unmet) =
            policy_decision.unmet_method_requirement(&[AuthenticationMethod::Password], false)
        {
            self.record_policy_denied(
                tenant_id,
                user.id,
                &format!(
                    "policy={} reason=method_required required={}",
                    unmet.policy_code,
                    unmet.requirement.describe()
                ),
                ctx,
            )
            .await;
            return PortalChangePasswordOutcome::PolicyDenied;
        }

        let (sso_session_id, sso_absolute_ttl_secs) = match self
            .issue_sso(
                tenant_id,
                &user,
                vec![AuthenticationMethod::Password],
                ctx,
                now,
            )
            .await
        {
            Ok(PortalSso::Issued {
                sso_session_id,
                sso_absolute_ttl_secs,
            }) => (sso_session_id, sso_absolute_ttl_secs),
            Ok(PortalSso::EnrollmentRequired { ticket }) => {
                return PortalChangePasswordOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return PortalChangePasswordOutcome::Internal(e),
        };
        PortalChangePasswordOutcome::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language: user.language.clone(),
        }
    }

    /// TOTP verification (the second step, presenting the `mfa_ticket` from password authentication).
    pub async fn verify_mfa(
        &self,
        tenant: TenantContext,
        cmd: PortalMfaCommand,
        ctx: &RequestContext,
    ) -> PortalMfaOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Per-IP rate limit.
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                return PortalMfaOutcome::RateLimited;
            }
        }

        // 2. Verify the ticket (signature, tenant, expiry).
        let Some(user_id) = self.verify_ticket(tenant_id, &cmd.mfa_ticket, now) else {
            return PortalMfaOutcome::TicketExpired;
        };

        // 3. Fetch the user and check it is active.
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return PortalMfaOutcome::TicketExpired,
            Err(e) => return PortalMfaOutcome::Internal(e.to_string()),
        };
        if user.is_locked_at(now) || !user.is_active() {
            return PortalMfaOutcome::TicketExpired;
        }

        // 4. Verify the second factor. Like OIDC login, one input field accepts TOTP, recovery codes or email OTP
        //    (AP9; keeps a recovery path for users who lost their authenticator).
        let second_factor = match self
            .verify_second_factor(user_id, &cmd.totp_code, now)
            .await
        {
            Ok(Some(method)) => method,
            Ok(None) => {
                self.record_failure(tenant_id, Some(user_id), "invalid_totp", ctx)
                    .await;
                return PortalMfaOutcome::InvalidCode;
            }
            Err(e) => return PortalMfaOutcome::Internal(e),
        };

        // 4.5. Re-evaluate the authentication policy (AP2/AP3). Even if the policy changed to `deny` after the ticket was issued,
        //      SSO is not issued (so a stale decision isn't honored for the ticket's 5-minute lifetime).
        //      `require_mfa` is satisfied at this point (the second factor is verified), but
        //      `require_specific_method` depends on whether **the second factor actually used** matches the requirement, so
        //      it is checked here against the final set of methods (passing through on `Ok(_)` would let TOTP
        //      bypass a WebAuthn-required policy).
        let used_methods = [AuthenticationMethod::Password, second_factor];
        match self
            .evaluate_policy(tenant_id, user_id, ctx.ip_address.as_deref())
            .await
        {
            Ok(PolicyDecision::Deny { policy_code }) => {
                self.record_policy_denied(
                    tenant_id,
                    user_id,
                    &format!("policy={policy_code}"),
                    ctx,
                )
                .await;
                return PortalMfaOutcome::PolicyDenied;
            }
            Ok(decision) => {
                // The portal doesn't go through WebAuthn, so User Verification is treated as not performed.
                if let Some(unmet) = decision.unmet_method_requirement(&used_methods, false) {
                    self.record_policy_denied(
                        tenant_id,
                        user_id,
                        &format!(
                            "policy={} reason=method_required required={}",
                            unmet.policy_code,
                            unmet.requirement.describe()
                        ),
                        ctx,
                    )
                    .await;
                    return PortalMfaOutcome::PolicyDenied;
                }
            }
            Err(e) => return PortalMfaOutcome::Internal(e),
        }

        // 5. Issue the SSO session.
        let (sso_session_id, sso_absolute_ttl_secs) = match self
            .issue_sso(
                tenant_id,
                &user,
                vec![AuthenticationMethod::Password, second_factor],
                ctx,
                now,
            )
            .await
        {
            Ok(PortalSso::Issued {
                sso_session_id,
                sso_absolute_ttl_secs,
            }) => (sso_session_id, sso_absolute_ttl_secs),
            Ok(PortalSso::EnrollmentRequired { ticket }) => {
                return PortalMfaOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return PortalMfaOutcome::Internal(e),
        };
        PortalMfaOutcome::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language: user.language.clone(),
        }
    }

    /// Issues the SSO session and records it in the audit (same mechanism as `login.rs` / `admin_login.rs`).
    async fn issue_sso(
        &self,
        tenant_id: TenantId,
        user: &User,
        methods: Vec<AuthenticationMethod>,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<PortalSso, String> {
        if let Some(gate) = &self.device_gate {
            let admission = gate
                .admit(
                    AdmissionAttempt {
                        tenant_id,
                        user_id: user.id,
                        home_tenant_id: user.tenant_id,
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
                return Ok(PortalSso::EnrollmentRequired { ticket });
            }
        }
        // The lifetime is the value of the user's home tenant (SSO sessions are shared across all tenants. ADR-0058).
        let lifetime = self
            .settings
            .sso_session_lifetime(user.tenant_id)
            .await
            .map_err(|e| e.to_string())?;
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession::establish(
            crypto::sha256_hex(&sso_session_id),
            user.id,
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
                Some(user.id),
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
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;
        Ok(PortalSso::Issued {
            sso_session_id,
            sso_absolute_ttl_secs: sso.absolute_ttl_secs(),
        })
    }

    /// Resolves the user awaiting MFA from `mfa_ticket` (AP9; used to decide where to send the email OTP).
    /// `None` if the ticket is invalid or expired.
    pub fn pending_mfa_user(&self, tenant: TenantContext, ticket: &str) -> Option<Uuid> {
        self.verify_ticket(tenant.tenant_id(), ticket, self.clock.now())
    }

    /// Verifies the second factor (AP9). If it passes, returns the authentication method to record. Uses the same order and
    /// normalization as `MfaLoginService` (if rules differed per path, codes passing on only one side would appear).
    async fn verify_second_factor(
        &self,
        user_id: Uuid,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthenticationMethod>, String> {
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
                    // Pass only if the accepted step could be recorded (refuses reuse of the same or an older code).
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
                return Ok(Some(method));
            }
        }
        Ok(None)
    }

    /// Issues a signed `mfa_ticket`.
    fn issue_ticket(&self, tenant_id: TenantId, user_id: Uuid, now: DateTime<Utc>) -> String {
        let exp = now.timestamp() + MFA_TICKET_TTL_SECS;
        sign_ticket(&self.ticket_secret, tenant_id.as_uuid(), user_id, exp)
    }

    /// Verifies the `mfa_ticket` and returns `user_id` if valid (tenant match, signature match, not expired).
    fn verify_ticket(&self, tenant_id: TenantId, ticket: &str, now: DateTime<Utc>) -> Option<Uuid> {
        verify_ticket(
            &self.ticket_secret,
            tenant_id.as_uuid(),
            ticket,
            now.timestamp(),
        )
    }

    /// Puts credential mismatches on the forced password change path (current password mismatch, failed check when no
    /// change is needed) on the same failure count and lock decision as normal login (same policy as
    /// [`Self::handle_password_failure`]; only the return type differs).
    async fn handle_change_password_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        reason: &str,
        ctx: &RequestContext,
    ) -> PortalChangePasswordOutcome {
        let now = self.clock.now();
        // The threshold is the value of the user's home tenant (the lock state lives on the user row. ADR-0058).
        let lockout = match self.settings.login_lockout(user.tenant_id).await {
            Ok(lockout) => lockout,
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };
        // The increment and lock decision are kept in a single UPDATE statement (SEC13).
        let failure = match self.users.record_login_failure(user.id, lockout, now).await {
            Ok(f) => f,
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };
        self.record_failure(tenant_id, Some(user.id), reason, ctx)
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
            return PortalChangePasswordOutcome::Locked;
        }
        PortalChangePasswordOutcome::InvalidCredentials
    }

    /// Updates the failure count and decides locking on a password mismatch (same policy as login.rs / admin_login.rs).
    async fn handle_password_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        ctx: &RequestContext,
    ) -> PortalLoginOutcome {
        let now = self.clock.now();
        // The threshold is the value of the user's home tenant (the lock state lives on the user row. ADR-0058).
        let lockout = match self.settings.login_lockout(user.tenant_id).await {
            Ok(lockout) => lockout,
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };
        // The increment and lock decision are kept in a single UPDATE statement (SEC13).
        let failure = match self.users.record_login_failure(user.id, lockout, now).await {
            Ok(f) => f,
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };
        self.record_failure(tenant_id, Some(user.id), "invalid_password", ctx)
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
            return PortalLoginOutcome::Locked;
        }
        PortalLoginOutcome::InvalidCredentials
    }

    async fn record_failure(
        &self,
        tenant_id: TenantId,
        user_id: Option<Uuid>,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                user_id,
                None,
                Some(reason),
                ctx,
            )
            .await;
    }
}

/// Builds a signed `mfa_ticket`. Format: `{tenant}.{user}.{exp}.{hmac_hex}`.
/// The HMAC is computed over `portal-mfa:{tenant}:{user}:{exp}`, preventing cross-tenant use, tampering and reuse.
fn sign_ticket(secret: &[u8; 32], tenant: Uuid, user: Uuid, exp: i64) -> String {
    let sig = ticket_signature(secret, &tenant.to_string(), &user.to_string(), exp);
    format!("{tenant}.{user}.{exp}.{sig}")
}

/// Verifies the `mfa_ticket` and returns `user_id` if valid (tenant match, signature match, not expired).
fn verify_ticket(secret: &[u8; 32], tenant: Uuid, ticket: &str, now_ts: i64) -> Option<Uuid> {
    let mut parts = ticket.splitn(4, '.');
    let tenant_str = parts.next()?;
    let user_str = parts.next()?;
    let exp_str = parts.next()?;
    let sig = parts.next()?;

    // Tenant match (prevents ticket reuse).
    if tenant_str != tenant.to_string() {
        return None;
    }
    let exp: i64 = exp_str.parse().ok()?;
    if now_ts > exp {
        return None;
    }
    // Verify the signature with HMAC constant-time verification (`verify_slice`).
    let sig_bytes = hex::decode(sig).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("portal-mfa:{tenant_str}:{user_str}:{exp}").as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;
    Uuid::parse_str(user_str).ok()
}

fn ticket_signature(secret: &[u8; 32], tenant: &str, user: &str, exp: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("portal-mfa:{tenant}:{user}:{exp}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

impl From<PasskeyAssertionError> for PortalLoginOutcome {
    fn from(e: PasskeyAssertionError) -> Self {
        match e {
            // A challenge for another purpose (one for the authorization flow completed in the portal) means only
            // "please try again" to the user, so it is treated the same as expired.
            PasskeyAssertionError::ChallengeNotFound | PasskeyAssertionError::WrongFlow => {
                PortalLoginOutcome::PasskeyChallengeNotFound
            }
            // Suspended, revoked, not in the tenant and disabled accounts all get the same response too (enumeration prevention).
            PasskeyAssertionError::InvalidCredential => PortalLoginOutcome::InvalidCredentials,
            PasskeyAssertionError::Internal(msg) => PortalLoginOutcome::Internal(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];

    #[test]
    fn ticket_round_trips_within_ttl() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 1_000 + MFA_TICKET_TTL_SECS);
        assert_eq!(verify_ticket(&SECRET, tenant, &ticket, 1_000), Some(user));
    }

    #[test]
    fn ticket_rejected_after_expiry() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 1_000);
        // exp (1_000) is below now (1_001) = expired.
        assert_eq!(verify_ticket(&SECRET, tenant, &ticket, 1_001), None);
    }

    #[test]
    fn ticket_rejected_for_other_tenant() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 5_000);
        let other = Uuid::from_u128(99);
        assert_eq!(verify_ticket(&SECRET, other, &ticket, 1_000), None);
    }

    #[test]
    fn ticket_rejected_with_tampered_signature() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 5_000);
        // Rewrite one character of the signature.
        let mut bytes = ticket.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'a' { b'b' } else { b'a' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert_eq!(verify_ticket(&SECRET, tenant, &tampered, 1_000), None);
    }

    #[test]
    fn ticket_rejected_with_wrong_secret() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 5_000);
        let other_secret = [9u8; 32];
        assert_eq!(verify_ticket(&other_secret, tenant, &ticket, 1_000), None);
    }
}
