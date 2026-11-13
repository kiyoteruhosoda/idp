//! Password change use case (ADR-0009 §5).
//!
//! Receives the `must_change_password` detected by `LoginService` (`LoginOutcome::PasswordChangeRequired`)
//! and sets a new password using the in-progress login's `auth_session_id` (password already verified).
//! Limited to the flow "a logged-in user authenticates with the current password and then sets a new one"
//! (ADR-0009 §5), so the current password must be entered again.
//!
//! After success, SSO issuance -> consent check -> code issuance is the same flow as `LoginService` / `MfaLoginService`
//! (reusing `CodeIssuanceService`).
//!
//! This service is **the issuer** of the SSO session and code, so it re-evaluates the authentication policy
//! (user authentication & authentication policy spec §9) before issuing. `must_change_password` is set not only
//! when creating a user with a generated password but also when **an admin reissues an existing user's password**,
//! so "no MFA check needed after the change" does not hold. On a `require_mfa` match, a user with TOTP set up is
//! sent to the MFA step, and one without is refused single-factor completion (same rule as LoginService; spec §24.4).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::application::password_policy::PasswordPolicyService;
use crate::application::sign_in_completion::{
    AuthorizationContinuation, Establishment, SignIn, SignInCompletion,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSessionIdHash;
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::{password_change_required, PasswordRejection};
use crate::domain::repositories::{AuthSessionRepository, TotpSecretRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use std::sync::Arc;

pub struct ChangePasswordCommand {
    pub auth_session_id: Option<String>,
    pub current_password: String,
    pub new_password: String,
    pub csrf_token: String,
}

pub enum ChangePasswordOutcome {
    /// Change succeeded and consent exists. 302 to redirect_to with the code.
    Success {
        location: String,
        /// Hidden fields to POST for `form_post` (G12). `None` means `query`.
        form_post: Option<Vec<(String, String)>>,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    /// Change succeeded but consent is needed. Send to the consent screen.
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    /// Change succeeded, the authentication policy requires MFA, and TOTP is set up. Send to the TOTP input screen
    /// (the `auth_session_id` cookie is kept; SSO is not issued yet).
    MfaRequired {
        auth_session_id: String,
    },
    /// Change succeeded but the authentication policy denies login (spec §7.4 `deny`). SSO is not issued.
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
    /// Change succeeded but the authentication policy requires MFA and there is no usable authenticator (verified TOTP).
    /// Guide the user to set up MFA from the portal. SSO is not issued.
    MfaEnrollmentRequired,
    /// No AuthSession, expired, or not awaiting a password change (start over from `/authorize`).
    SessionExpired,
    /// CSRF token mismatch.
    CsrfMismatch,
    /// Current password does not match.
    InvalidCurrentPassword,
    /// The new password does not satisfy the policy (length, breached, reused. AP7).
    WeakPassword(PasswordRejection),
    /// Authentication passed, but in an organization limited to registered devices this device is not registered (task #916).
    /// No SSO session was created. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
    Internal(String),
}

pub struct ChangePasswordService {
    auth_sessions: Arc<dyn AuthSessionRepository>,
    users: Arc<dyn UserRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    /// Authentication policy evaluation (looking up inputs and evaluating. `authentication_policy_gate`).
    policy_gate: Arc<AuthenticationPolicyGate>,
    /// Shared tail after authentication succeeds (establishing SSO, continuing the authorization flow).
    sign_in: Arc<SignInCompletion>,
    hasher: Arc<dyn PasswordHasher>,
    password_policy: Arc<PasswordPolicyService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    csrf_secret: [u8; 32],
}

impl ChangePasswordService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth_sessions: Arc<dyn AuthSessionRepository>,
        users: Arc<dyn UserRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        policy_gate: Arc<AuthenticationPolicyGate>,
        sign_in: Arc<SignInCompletion>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            auth_sessions,
            users,
            totp_secrets,
            policy_gate,
            sign_in,
            hasher,
            password_policy,
            audit,
            clock,
            csrf_secret,
        }
    }

    pub async fn change(
        &self,
        tenant: TenantContext,
        cmd: ChangePasswordCommand,
        ctx: &RequestContext,
    ) -> ChangePasswordOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Fetch the AuthSession from auth_session_id (limited to the flow's tenant).
        let Some(session_id) = cmd.auth_session_id.as_deref().filter(|s| !s.is_empty()) else {
            return ChangePasswordOutcome::SessionExpired;
        };
        let mut session = match self
            .auth_sessions
            .find(tenant_id, &AuthSessionIdHash::of_plain(session_id))
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return ChangePasswordOutcome::SessionExpired,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return ChangePasswordOutcome::SessionExpired;
        }

        // 2. Check it is awaiting a password change (password_verified_at must be set).
        let Some(user_id) = session.password_verified_user() else {
            return ChangePasswordOutcome::SessionExpired;
        };

        // 3. Verify the CSRF token (same derivation as login_csrf_token).
        if !assay_contracts::csrf::verify(
            &assay_contracts::csrf::login_csrf_token(session_id, &self.csrf_secret),
            &cmd.csrf_token,
        ) {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    Some(session.client_id()),
                    Some("password_change_csrf_mismatch"),
                    ctx,
                )
                .await;
            return ChangePasswordOutcome::CsrfMismatch;
        }

        let client_id = session.client_id().to_string();

        // 4. Fetch the user and check it is active and awaiting a change.
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return ChangePasswordOutcome::SessionExpired,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        // Whether a change is required (forced flag, or expired. AP7). Expiry is measured by the policy
        // of the user's home tenant (ADR-0058).
        let password_policy = match self.password_policy.policy(user.tenant_id).await {
            Ok(policy) => policy,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if !user.is_active() || !password_change_required(&user, &password_policy, now) {
            // Reaching this endpoint when no change is needed is unexpected (double submit etc.). Fail closed.
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "password change rejected: user not in must-change state (duplicate submit?)"
            );
            return ChangePasswordOutcome::SessionExpired;
        }

        // 5. Verify the current password.
        let verified = match self
            .hasher
            .verify(&cmd.current_password, &user.password_hash)
        {
            Ok(v) => v,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if !verified {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some("invalid_current_password"),
                    ctx,
                )
                .await;
            return ChangePasswordOutcome::InvalidCurrentPassword;
        }

        // 6. Check the new password satisfies the policy (length, breached, reused. AP7),
        //    then hash and store it.
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
            Ok(Err(rejection)) => return ChangePasswordOutcome::WeakPassword(rejection),
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        // Replace conditioned on the current hash (AP7; same reason as `account_password`).
        match self
            .users
            .update_password(user.id, &user.password_hash, &new_hash)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    correlation_id = %ctx.correlation_id,
                    "forced password change lost a concurrent update; asking to retry"
                );
                return ChangePasswordOutcome::InvalidCurrentPassword;
            }
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
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
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 6.5. Evaluate the authentication policy (spec §9). This service issues SSO and codes, so apply
        //      the same rules as LoginService before issuing (`must_change_password` is also set when an admin
        //      reissues an existing user's password, so users with TOTP set up can take this path too).
        //      The password change itself completes as self-service; only session issuance is gated.
        // `acr_values` of the authorization request (used by AP3's `requested_acr` condition).
        let requested_acr = session.request().requested_acr();
        let decision = match self
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
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        match &decision {
            PolicyDecision::Deny { policy_code } => {
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
                return ChangePasswordOutcome::PolicyDenied;
            }
            PolicyDecision::RequireMfa { policy_code } => {
                let has_totp =
                    match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
                        Ok(v) => v,
                        Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
                    };
                if has_totp {
                    // The AuthSession has `authenticated_user_id` and `password_verified_at` set
                    // (equivalent to MFA pending), so it can be handed to the TOTP verification step as-is.
                    return ChangePasswordOutcome::MfaRequired {
                        auth_session_id: session_id.to_string(),
                    };
                }
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
                return ChangePasswordOutcome::MfaEnrollmentRequired;
            }
            // `require_specific_method` (AP3). When this path completes, the only method used is the password.
            PolicyDecision::RequireMethods { .. } => {
                let used = [AuthenticationMethod::Password];
                if let Some(unmet) = decision.unmet_method_requirement(&used, false) {
                    // Users who can satisfy it by adding a second factor go to the MFA step (same as `require_mfa`).
                    // The AuthSession has `authenticated_user_id` and `password_verified_at` set
                    // (equivalent to MFA pending), so it can be handed to `MfaLoginService` as-is. That service
                    // re-checks with the final set of methods, so an unsatisfying second factor cannot pass.
                    let has_totp =
                        match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
                            Ok(v) => v,
                            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
                        };
                    if has_totp
                        && decision.satisfied_by_adding(&used, AuthenticationMethod::Totp, false)
                    {
                        return ChangePasswordOutcome::MfaRequired {
                            auth_session_id: session_id.to_string(),
                        };
                    }
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
                    return ChangePasswordOutcome::PolicyDenied;
                }
            }
            PolicyDecision::Allow { .. } => {}
        }

        // 7. Establish the SSO session and continue the authorization flow (consent check -> code issuance).
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
                return ChangePasswordOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        let sso_session_id = sso.session_id().to_string();
        let sso_absolute_ttl_secs = sso.absolute_ttl_secs();
        match self
            .sign_in
            .continue_authorization(tenant, &mut session, &sso, now, ctx)
            .await
        {
            Ok(AuthorizationContinuation::ConsentRequired { auth_session_id }) => {
                ChangePasswordOutcome::ConsentRequired {
                    auth_session_id,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name }) => {
                ChangePasswordOutcome::ApplicationNotPermitted {
                    application_name,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::Authorized(dispatch)) => ChangePasswordOutcome::Success {
                location: dispatch.location,
                form_post: dispatch.form_post,
                sso_session_id,
                sso_absolute_ttl_secs,
            },
            Err(e) => ChangePasswordOutcome::Internal(e.to_string()),
        }
    }
}
