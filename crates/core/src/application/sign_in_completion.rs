//! The common tail after authentication succeeds (establish SSO -> continue the authorization flow).
//!
//! The 5 paths (sign-in, MFA, passkey, password change, external IdP) each verify the user in their own way
//! and then finish with the same steps:
//!
//! 1. [`SignInCompletion::establish_sso`]: create and save the SSO session and audit it
//! 2. [`SignInCompletion::continue_authorization`]: if coming from the middle of an authorization flow, record
//!    the authentication in that AuthSession (re-keying its id. SEC7), check consent, issue a code, and
//!    delete the AuthSession
//!
//! # Save the SSO session first
//!
//! The SSO session is saved before recording the authentication (handing the `sid` to the AuthSession). In the reverse order,
//! if saving the SSO failed, "an authenticated AuthSession holding the `sid` of a nonexistent SSO session" would
//! remain, and accepting consent could issue a code with it. In this order, what remains on failure is only an SSO row
//! whose Cookie was given to no one (it disappears on expiry).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::AuthorizationDispatch;
use crate::application::code_issuance::{CodeIssuance, CodeIssuanceService, IssueCodeCommand};
use crate::application::consent::consent_is_granted;
use crate::application::device_enrollment::{Admission, AdmissionAttempt, DeviceGate};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::{AuthSession, Authentication};
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, SsoSessionRepository,
};
use crate::domain::session_key::{lifetime_for, SessionBinding};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// A successful authentication (who, by which method, where).
pub struct SignIn<'a> {
    /// The tenant authenticated at (the flow's tenant. Audit destination).
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    /// The user's home tenant. The SSO session lifetime uses this tenant's value (since SSO sessions are
    /// shared across all tenants. ADR-0058).
    pub home_tenant_id: TenantId,
    /// The methods actually verified (ADR-0043. Source of the ID Token's `acr` / `amr`).
    pub methods: Vec<AuthenticationMethod>,
    /// The client recorded in the audit (`None` outside an authorization flow).
    pub client_id: Option<&'a str>,
    /// The event to record as success in the audit, and its details.
    pub success_event: AuditEventType,
    pub success_detail: Option<String>,
}

/// An established SSO session (including the plaintext Cookie passed to the web).
pub struct EstablishedSso {
    session: SsoSession,
    session_id: String,
}

impl EstablishedSso {
    /// The value the web puts in a host-only Cookie (plaintext).
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The Cookie's `Max-Age` (seconds until the absolute expiry. ADR-0058).
    pub fn absolute_ttl_secs(&self) -> u64 {
        self.session.absolute_ttl_secs()
    }

    pub fn session(&self) -> &SsoSession {
        &self.session
    }
}

/// Outcome of trying to create an SSO session.
pub enum Establishment {
    /// Created.
    Established(EstablishedSso),
    /// In an organization restricted to registered devices, the device was not registered (task #916. ADR-0079). No SSO session
    /// was created. The web puts the `ticket` in a Cookie and redirects to the device registration screen.
    ///
    /// ⚠ Per-path outcomes must not map this to "signed in".
    DeviceEnrollmentRequired { ticket: String },
}

impl Establishment {
    /// Used where the gate is known to pass, such as tests or right after registration.
    #[cfg(test)]
    pub fn expect_established(self) -> EstablishedSso {
        match self {
            Self::Established(sso) => sso,
            Self::DeviceEnrollmentRequired { .. } => panic!("device enrollment was required"),
        }
    }
}

/// Outcome of continuing the authorization flow.
pub enum AuthorizationContinuation {
    /// Consent is needed. The web proceeds to the consent screen with the new `auth_session_id`.
    ConsentRequired { auth_session_id: String },
    /// Use of this app is not permitted (ADR-0054). ⚠ **Do not return to the RP.**
    ApplicationNotPermitted { application_name: String },
    /// A code was issued. Return to the RP.
    Authorized(AuthorizationDispatch),
}

pub struct SignInCompletion {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    audit: Arc<AuditService>,
    settings: Arc<dyn EffectiveTenantSettings>,
    /// The registered-device gate (task #916). `None` means no gate (tests only. The api always sets it).
    device_gate: Option<Arc<DeviceGate>>,
}

impl SignInCompletion {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        audit: Arc<AuditService>,
        settings: Arc<dyn EffectiveTenantSettings>,
    ) -> Self {
        Self {
            sso_sessions,
            auth_sessions,
            client_consents,
            code_issuance,
            audit,
            settings,
            device_gate: None,
        }
    }

    /// Attaches the registered-device gate (task #916. ⚠ always call this when assembling the api).
    pub fn with_device_gate(mut self, gate: Arc<DeviceGate>) -> Self {
        self.device_gate = Some(gate);
        self
    }

    /// Decides whether the gate passes (passes if there is no gate).
    async fn admit(
        &self,
        sign_in: &SignIn<'_>,
        binding: SessionBinding,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<Admission, DomainError> {
        let Some(gate) = &self.device_gate else {
            return Ok(Admission::Admitted);
        };
        gate.admit(
            AdmissionAttempt {
                tenant_id: sign_in.tenant_id,
                user_id: sign_in.user_id,
                home_tenant_id: sign_in.home_tenant_id,
                methods: &sign_in.methods,
                client_id: sign_in.client_id,
                app_approved: matches!(binding, SessionBinding::AppApproval),
            },
            ctx,
            now,
        )
        .await
    }

    /// Creates and saves the SSO session and audits it (`SsoSessionCreated` and the success event).
    ///
    /// In an organization restricted to registered devices, if the device is not registered, does not create one and
    /// returns [`Establishment::DeviceEnrollmentRequired`] (task #916).
    pub async fn establish_sso(
        &self,
        sign_in: SignIn<'_>,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<Establishment, DomainError> {
        self.establish_sso_with_binding(sign_in, SessionBinding::Unbound, ctx, now)
            .await
    }

    /// Decides the binding kind and creates the SSO session (the lifetime is `session_key::lifetime_for`).
    ///
    /// The only binding decided at establishment is "approve in the app" (task #892. ADR-0077). DBSC binds after
    /// establishment, so it is created as `Unbound` here and extended when bound (ADR-0074).
    pub async fn establish_sso_with_binding(
        &self,
        sign_in: SignIn<'_>,
        binding: SessionBinding,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<Establishment, DomainError> {
        if let Admission::EnrollmentRequired { ticket } =
            self.admit(&sign_in, binding, ctx, now).await?
        {
            return Ok(Establishment::DeviceEnrollmentRequired { ticket });
        }
        let lifetime = self
            .settings
            .sso_session_lifetime(sign_in.home_tenant_id)
            .await?;
        let (idle_expires_at, absolute_expires_at) = lifetime_for(
            now,
            now + lifetime.idle,
            binding,
            false,
            lifetime.absolute,
            lifetime.bound,
        );
        let session_id = crypto::random_hex(32);
        let session = SsoSession::establish(
            crypto::sha256_hex(&session_id),
            sign_in.user_id,
            now,
            idle_expires_at - now,
            absolute_expires_at - now,
            sign_in.methods,
            ctx.user_agent.clone(),
            ctx.ip_address.clone(),
        );
        self.sso_sessions.create(&session).await?;
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(sign_in.tenant_id),
                Some(sign_in.user_id),
                sign_in.client_id,
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                sign_in.success_event,
                AuditResult::Success,
                Some(sign_in.tenant_id),
                Some(sign_in.user_id),
                sign_in.client_id,
                sign_in.success_detail.as_deref(),
                ctx,
            )
            .await;
        Ok(Establishment::Established(EstablishedSso {
            session,
            session_id,
        }))
    }

    /// Continues the authorization flow: records the authentication (re-keying the id), checks consent, issues a code.
    ///
    /// The authentication time is `now`; `sid` and methods come from the established SSO session.
    pub async fn continue_authorization(
        &self,
        tenant: TenantContext,
        session: &mut AuthSession,
        sso: &EstablishedSso,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> Result<AuthorizationContinuation, DomainError> {
        let authentication = Authentication::new(
            sso.session.user_id,
            now,
            Some(sso.session.sid()),
            Some(sso.session.authentication_methods.clone()),
        );
        let completion = session.complete_authentication(authentication.clone());
        self.auth_sessions.save_authentication(&completion).await?;

        let consented = consent_is_granted(
            self.client_consents.as_ref(),
            tenant.tenant_id(),
            authentication.user_id(),
            session.request(),
        )
        .await?;
        if !consented {
            // Consent not complete: keep the AuthSession authenticated.
            return Ok(AuthorizationContinuation::ConsentRequired {
                auth_session_id: completion.into_issued().into_string(),
            });
        }

        let issuance = self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    request: session.request().clone(),
                    authentication,
                },
                ctx,
            )
            .await?;
        let code = match issuance {
            CodeIssuance::Issued(code) => code,
            // Authenticated, but use of this app is not permitted (ADR-0054). Do not return to the RP.
            CodeIssuance::ApplicationDenied { application_name } => {
                return Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name });
            }
        };

        // A code was issued, so the AuthSession has done its job (the web expires the Cookie).
        if let Err(e) = self.auth_sessions.delete(session.id_hash()).await {
            tracing::warn!(error = %e, "failed to delete auth session after code issuance");
        }
        Ok(AuthorizationContinuation::Authorized(
            session.request().success_response(&code).into(),
        ))
    }
}
