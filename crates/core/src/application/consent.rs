//! Consent use case (F3: design spec §9.2).
//!
//! The user grants or denies consent for scopes to a client.
//! After consent is granted, an authorization code is issued and the user is redirected to the RP.
//! When consent is denied, an `access_denied` error is redirected to the RP.
//!
//! The authenticated `AuthSession` is reused as the consent session.
//! The AuthSession is deleted after the code is issued (same as the login flow).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::AuthorizationDispatch;
use crate::application::code_issuance::{CodeIssuance, CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::{AuthSession, AuthSessionId};
use crate::domain::authorization_request::AuthorizationRequest;
use crate::domain::clock::Clock;
use crate::domain::consent::ClientConsent;
use crate::domain::error::{DomainError, OAuthErrorCode};
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, ClientRepository,
};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

/// Display data needed before moving to the consent screen.
#[derive(Debug)]
pub struct ConsentInfo {
    pub auth_session_id: String,
    pub client_name: String,
    pub client_id: String,
    /// Scopes to ask consent for (excluding `openid`).
    pub requested_scopes: Vec<String>,
    /// This authorization request's `redirect_uri` (the one that exactly matched a registered value).
    ///
    /// Source of the origin that web allows in the consent screen's CSP `form-action`. Submitting the consent form
    /// ends in a redirect to the RP, and Chrome applies `form-action` to redirect targets after a form submit
    /// too, so without this the browser cannot return to the RP.
    pub redirect_uri: String,
}

pub enum ConsentOutcome {
    /// Consent granted and code issued. 302 to `redirect_uri?code=...&state=...`.
    Approved {
        location: String,
        /// Hidden fields to POST for `form_post` (G12). `None` means `query`.
        form_post: Option<Vec<(String, String)>>,
    },
    /// Consent denied. For `query`, 302 to `location`; for `form_post`, POST hidden fields to `location`
    /// (errors are returned with the same `response_mode` as success. G12).
    Denied {
        location: String,
        form_post: Option<Vec<(String, String)>>,
    },
    /// Consent was granted, but use of this application is not permitted (ADR-0054). ⚠ **Do not return to the RP.**
    /// The SSO cookie was issued before reaching this path, so only showing a screen is needed here.
    ApplicationNotPermitted {
        /// Application name shown on screen.
        application_name: String,
    },
    /// No AuthSession, expired, or no authenticated user set (start over from `/authorize`).
    SessionExpired,
    /// api internal error.
    Internal(String),
}

pub struct ConsentService {
    auth_sessions: Arc<dyn AuthSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    clients: Arc<dyn ClientRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl ConsentService {
    pub fn new(
        auth_sessions: Arc<dyn AuthSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        clients: Arc<dyn ClientRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            auth_sessions,
            client_consents,
            clients,
            code_issuance,
            audit,
            clock,
        }
    }

    /// Returns display data for the consent screen.
    ///
    /// Checks that the AuthSession for `auth_session_id` exists and has finished authentication.
    pub async fn info(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> Result<Option<ConsentInfo>, DomainError> {
        let Some(session) = self.live_session(tenant, auth_session_id).await? else {
            return Ok(None);
        };
        // Same entry conditions as approval (`approve`): at a stage where authentication is not finished
        // (e.g. password passed and waiting for the second step), don't show a screen whose button cannot succeed.
        if session.completed_authentication().is_none() {
            return Ok(None);
        }
        let request = session.request();

        // Fetch client info (the display name is needed).
        let client_name = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), request.client_id())
            .await?
        {
            Some(c) => c.app_name,
            None => request.client_id().to_string(),
        };

        Ok(Some(ConsentInfo {
            auth_session_id: auth_session_id.to_string(),
            client_name,
            client_id: request.client_id().to_string(),
            requested_scopes: request.scopes_needing_consent(),
            redirect_uri: request.redirect_uri().to_string(),
        }))
    }

    /// Grants consent and issues an authorization code.
    pub async fn approve(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
        ctx: &RequestContext,
    ) -> ConsentOutcome {
        let session = match self.live_session(tenant, auth_session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return ConsentOutcome::SessionExpired,
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };
        // The only basis on which consent issues a code is "the authentication completed in this flow".
        let Some(authentication) = session.completed_authentication().cloned() else {
            return ConsentOutcome::SessionExpired;
        };
        let request = session.request();
        let now = self.clock.now();

        // UPSERT the consent record.
        let consent = ClientConsent {
            user_id: authentication.user_id(),
            tenant_id: tenant.tenant_id(),
            client_id: request.client_id().to_string(),
            scopes: request.scope().to_vec(),
            granted_at: now,
            updated_at: now,
        };
        if let Err(e) = self.client_consents.upsert(&consent).await {
            return ConsentOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::ConsentGranted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(authentication.user_id()),
                Some(request.client_id()),
                None,
                ctx,
            )
            .await;

        // Issue the authorization code. With a consent screen in between, this is the only way to obtain
        // the `sid` recorded at login (G5) and the authentication methods (ADR-0043) (both are in `authentication`).
        let code = match self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    request: request.clone(),
                    authentication,
                },
                ctx,
            )
            .await
        {
            Ok(CodeIssuance::Issued(code)) => code,
            // Consent passed, but use of this application is not permitted (ADR-0054). Do not return to the RP.
            Ok(CodeIssuance::ApplicationDenied { application_name }) => {
                return ConsentOutcome::ApplicationNotPermitted { application_name }
            }
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };

        // Delete the AuthSession (code issuance done).
        if let Err(e) = self.auth_sessions.delete(session.id_hash()).await {
            tracing::warn!(error = %e, "failed to delete auth session after consent");
        }

        let dispatch = AuthorizationDispatch::from(request.success_response(&code));
        ConsentOutcome::Approved {
            location: dispatch.location,
            form_post: dispatch.form_post,
        }
    }

    /// Denies consent and error-redirects to the RP.
    pub async fn deny(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
        ctx: &RequestContext,
    ) -> ConsentOutcome {
        let session = match self.live_session(tenant, auth_session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return ConsentOutcome::SessionExpired,
            Err(e) => return ConsentOutcome::Internal(e.to_string()),
        };

        self.audit
            .record(
                AuditEventType::ConsentDenied,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                session.identified_user(),
                Some(session.client_id()),
                Some("user_denied"),
                ctx,
            )
            .await;

        // Delete the AuthSession.
        if let Err(e) = self.auth_sessions.delete(session.id_hash()).await {
            tracing::warn!(error = %e, "failed to delete auth session after consent denial");
        }

        let dispatch = AuthorizationDispatch::from(
            session
                .request()
                .error_response(OAuthErrorCode::AccessDenied, "user denied consent"),
        );
        ConsentOutcome::Denied {
            location: dispatch.location,
            form_post: dispatch.form_post,
        }
    }

    /// Looks up an unexpired AuthSession (an expired one is deleted on the spot and yields `None`).
    async fn live_session(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> Result<Option<AuthSession>, DomainError> {
        let Some(id) = AuthSessionId::from_presented(auth_session_id) else {
            return Ok(None);
        };
        let Some(session) = self
            .auth_sessions
            .find(tenant.tenant_id(), &id.hash())
            .await?
        else {
            return Ok(None);
        };
        if session.is_expired_at(self.clock.now()) {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return Ok(None);
        }
        Ok(Some(session))
    }
}

/// Whether the user has consented to every scope of this authorization request.
///
/// `openid` is implicitly consented, so if only that is requested, `true` without looking at consent records
/// (no lookup, so no storage failure can occur in that case).
pub async fn consent_is_granted(
    consents: &dyn ClientConsentRepository,
    tenant_id: TenantId,
    user_id: Uuid,
    request: &AuthorizationRequest,
) -> Result<bool, DomainError> {
    let needed = request.scopes_needing_consent();
    if needed.is_empty() {
        return Ok(true);
    }
    Ok(consents
        .find(tenant_id, user_id, request.client_id())
        .await?
        .is_some_and(|consent| consent.covers(&needed)))
}
