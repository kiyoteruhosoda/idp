//! SAML SP-initiated SSO use case (`/{tenant_id}/saml/sso`).
//!
//! Uses the same handoff scheme as the OIDC authorization flow (ADR-0018 decision 2). The api does not read
//! browser Cookies, so [`SamlSsoService::begin`] validates the AuthnRequest, creates a [`SamlSsoRequest`], and puts
//! a **single-use, short-lived handle** in the redirect URL to the web (`{web}/{tenant}/saml/continue?handle=...`).
//! The web calls `/internal/saml/resume` ([`SamlSsoService::resume`]) together with its own domain's host-only
//! `sso_session_id` Cookie, and if SSO is valid, receives a signed
//! SAML Response and renders a form that auto-POSTs it to the ACS. If SSO is not established, it
//! turns `saml_request_id` into a Cookie and leads to the portal sign-in, and after a successful sign-in resumes
//! the same resume with `saml_request_id`.
//!
//! # This is also SAML's "may this app be used" gate (ADR-0054)
//!
//! The only path that can issue assertions is [`SamlSsoService::resume`], and every portal
//! sign-in (password, MFA, passkey, external IdP) comes back here after establishing SSO.
//! As with OIDC's code issuance point (`CodeIssuanceService::issue`), the check is placed right before issuance.
//! If refused, nothing is POSTed to the ACS; it is told on assay's screen (decision 2).
//!
//! Error policy: errors before a verified ACS (registered SP) is settled have no trustworthy return destination, so
//! they are returned to the caller as 400 without redirecting to the RP (protocol errors are not translated. CLAUDE.md).

use crate::application::application_access::{ApplicationAccessService, ApplicationGate};
use crate::application::audit::{AuditService, RequestContext};
use crate::application::key_service::KeyService;
use crate::application::sso_restore::SsoRestorer;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::issuer::tenant_issuer;
use crate::domain::repositories::{
    SamlServiceProviderRepository, SamlSsoRequestRepository, UserRepository,
};
use crate::domain::saml_authn_request::{
    decode_post_binding, decode_redirect_binding, parse_authn_request,
};
use crate::domain::saml_response::{
    build_signed_response_xml, generate_saml_id, SamlResponseInput, SamlSigner,
};
use crate::domain::saml_service_provider::SamlServiceProvider;
use crate::domain::saml_sso_request::{self as saml_sso_request, SamlSsoRequest};
use crate::domain::tenant_context::TenantContext;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Duration;
use std::sync::Arc;

/// Expiry (seconds) of the web handoff handle. It only needs to cover the one-way trip from the web receiving
/// the 302 of `/saml/sso` to passing it to `/internal/saml/resume` (same value as OIDC authorize).
const HANDLE_TTL_SECS: i64 = 60;

/// Expiry of issued assertions (`NotOnOrAfter` / `SubjectConfirmationData`).
/// A short value assuming an immediate POST via the browser (same idea as the authorization code in design spec §2.2).
const ASSERTION_TTL_SECS: i64 = 300;

/// Input limits matching DB column widths (`saml_sso_requests.request_id` / `relay_state`).
const MAX_REQUEST_ID_LEN: usize = 1024;
const MAX_RELAY_STATE_LEN: usize = 1024;

/// Receiving binding of `SAMLRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlSsoBinding {
    /// HTTP-Redirect (GET query. base64 + raw DEFLATE).
    Redirect,
    /// HTTP-POST (form. base64).
    Post,
}

/// What `/saml/sso` received.
pub struct SamlBeginCommand {
    pub binding: SamlSsoBinding,
    pub saml_request: String,
    pub relay_state: Option<String>,
}

pub enum SamlBeginOutcome {
    /// Validation succeeded. 302 to the web's `/saml/continue` with the single-use handle in the URL.
    HandoffToWeb { handle: String },
    /// The AuthnRequest is invalid (unregistered SP, ACS mismatch, parse failure). There is no verified return destination,
    /// so 400 is returned without redirecting (`reason` is fixed English text for RP developers).
    BadRequest { reason: String },
    /// Internal error.
    Internal(String),
}

/// Command for `/internal/saml/resume`. The first time uses `handle` (single-use exchange); resuming after sign-in
/// uses `saml_request_id` (the web's host-only Cookie).
pub struct SamlResumeCommand {
    pub handle: Option<String>,
    pub saml_request_id: Option<String>,
    /// Value of the web's host-only `sso_session_id` Cookie (not signed in if absent).
    pub sso_session_id: Option<String>,
}

pub enum SamlResumeOutcome {
    /// SSO valid. The web renders a form that auto-POSTs the signed SAML Response (base64) to the ACS.
    Completed {
        acs_url: String,
        /// `SAMLResponse` form value (already base64).
        saml_response: String,
        relay_state: Option<String>,
    },
    /// Authentication required. The web turns `saml_request_id` into a host-only Cookie and leads to the portal sign-in.
    LoginRequired { saml_request_id: String },
    /// Authenticated, but use of this app is not permitted (ADR-0054). ⚠ **Do not POST to the ACS.**
    /// The progress state is consumed (redoing from the SP gives the same answer until the assignment changes).
    ApplicationNotPermitted { application_name: String },
    /// The handle/request is invalid, expired, or used (redo from the SP).
    Expired,
    /// Internal error.
    Internal(String),
}

/// Result of issuing an assertion (refusal is not mixed into `Err`, for the same reason as `CodeIssuance`).
enum SamlIssuance {
    /// Issued (the base64-encoded `SAMLResponse`).
    Issued(String),
    /// Use of this app is not permitted. ⚠ **Do not send to the ACS.**
    ApplicationDenied { application_name: String },
}

pub struct SamlSsoService {
    service_providers: Arc<dyn SamlServiceProviderRepository>,
    requests: Arc<dyn SamlSsoRequestRepository>,
    users: Arc<dyn UserRepository>,
    sso_restorer: Arc<SsoRestorer>,
    applications: Arc<ApplicationAccessService>,
    keys: Arc<KeyService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// Base issuer (`config.issuer()`). Used to compose the tenant issuer = IdP entityID.
    base_issuer: String,
    request_ttl: Duration,
}

impl SamlSsoService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service_providers: Arc<dyn SamlServiceProviderRepository>,
        requests: Arc<dyn SamlSsoRequestRepository>,
        users: Arc<dyn UserRepository>,
        sso_restorer: Arc<SsoRestorer>,
        applications: Arc<ApplicationAccessService>,
        keys: Arc<KeyService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        base_issuer: String,
        request_ttl: std::time::Duration,
    ) -> Self {
        Self {
            service_providers,
            requests,
            users,
            sso_restorer,
            applications,
            keys,
            audit,
            clock,
            base_issuer,
            request_ttl: Duration::from_std(request_ttl).expect("SAML request TTL out of range"),
        }
    }

    /// Validates the AuthnRequest, creates a [`SamlSsoRequest`], and issues the web handoff handle.
    pub async fn begin(
        &self,
        tenant: TenantContext,
        cmd: SamlBeginCommand,
        ctx: &RequestContext,
    ) -> SamlBeginOutcome {
        // 1. Decode and parse.
        let decoded = match cmd.binding {
            SamlSsoBinding::Redirect => decode_redirect_binding(&cmd.saml_request),
            SamlSsoBinding::Post => decode_post_binding(&cmd.saml_request),
        };
        let xml = match decoded {
            Ok(xml) => xml,
            Err(e) => return self.reject(tenant, None, &e.to_string(), ctx).await,
        };
        let parsed = match parse_authn_request(&xml) {
            Ok(parsed) => parsed,
            Err(e) => return self.reject(tenant, None, &e.to_string(), ctx).await,
        };

        // 2. Resolve the registered SP (within the tenant boundary. ADR-0009 §8).
        let provider = match self
            .service_providers
            .find_by_entity_id(tenant.tenant_id(), &parsed.issuer)
            .await
        {
            Ok(Some(p)) => p,
            Ok(None) => {
                return self
                    .reject(
                        tenant,
                        Some(&parsed.issuer),
                        "unknown SAML service provider",
                        ctx,
                    )
                    .await
            }
            Err(e) => return SamlBeginOutcome::Internal(e.to_string()),
        };
        if !provider.enabled {
            return self
                .reject(
                    tenant,
                    Some(&parsed.issuer),
                    "SAML service provider is disabled",
                    ctx,
                )
                .await;
        }

        // 3. ACS URL: if the AuthnRequest specifies one, require an exact match with the registered value (do not send assertions
        //    to unverified destinations). If omitted, use the registered value.
        if let Some(requested_acs) = parsed.acs_url.as_deref() {
            if requested_acs != provider.acs_url {
                return self
                    .reject(
                        tenant,
                        Some(&parsed.issuer),
                        "AssertionConsumerServiceURL does not match the registered ACS URL",
                        ctx,
                    )
                    .await;
            }
        }
        if parsed
            .request_id
            .as_deref()
            .is_some_and(|id| id.len() > MAX_REQUEST_ID_LEN)
        {
            return self
                .reject(
                    tenant,
                    Some(&parsed.issuer),
                    "AuthnRequest ID is too long",
                    ctx,
                )
                .await;
        }
        let relay_state = cmd.relay_state.filter(|s| !s.is_empty());
        if relay_state
            .as_deref()
            .is_some_and(|s| s.len() > MAX_RELAY_STATE_LEN)
        {
            return self
                .reject(tenant, Some(&parsed.issuer), "RelayState is too long", ctx)
                .await;
        }

        // 4. Create the progress state and hand off to the web with a single-use handle (same scheme as ADR-0018 decision 2).
        let now = self.clock.now();
        let handle = crypto::random_hex(32);
        // The plaintext `saml_request_id` is not handed to anyone here (only the single-use handle goes to the web).
        // The value the web receives is created at handle exchange (`resume`).
        let request = SamlSsoRequest {
            id_hash: saml_sso_request::id_hash(&crypto::random_hex(32)),
            tenant_id: tenant.tenant_id(),
            service_provider_id: provider.id,
            sp_entity_id: provider.entity_id.clone(),
            acs_url: provider.acs_url.clone(),
            request_id: parsed.request_id,
            relay_state,
            handle_hash: Some(crypto::sha256_hex(&handle)),
            handle_expires_at: Some(now + Duration::seconds(HANDLE_TTL_SECS)),
            expires_at: now + self.request_ttl,
            created_at: now,
        };
        if let Err(e) = self.requests.create(&request).await {
            return SamlBeginOutcome::Internal(e.to_string());
        }

        SamlBeginOutcome::HandoffToWeb { handle }
    }

    /// Resumes the web handoff. If SSO is valid, issues a signed SAML Response; otherwise
    /// returns a sign-in redirect (`LoginRequired`).
    pub async fn resume(
        &self,
        tenant: TenantContext,
        cmd: SamlResumeCommand,
        ctx: &RequestContext,
    ) -> SamlResumeOutcome {
        let now = self.clock.now();

        // 1. Resolve the progress state. The first time consumes the handle once; resuming after sign-in looks up by row id.
        //    The DB holds only hashes (SEC6), so on the handle exchange side the plaintext returned to the web is created here.
        let (request, saml_request_id) =
            if let Some(handle) = cmd.handle.as_deref().filter(|h| !h.is_empty()) {
                let handle_hash = crypto::sha256_hex(handle);
                let mut request = match self
                    .requests
                    .find_by_handle(tenant.tenant_id(), &handle_hash)
                    .await
                {
                    Ok(Some(r)) => r,
                    Ok(None) => return SamlResumeOutcome::Expired,
                    Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
                };
                if !request.handle_is_valid_at(now) || request.is_expired_at(now) {
                    return SamlResumeOutcome::Expired;
                }
                let rotated_id = crypto::random_hex(32);
                let rotated_id_hash = saml_sso_request::id_hash(&rotated_id);
                match self
                    .requests
                    .consume_handle(&request.id_hash, &handle_hash, &rotated_id_hash)
                    .await
                {
                    Ok(true) => request.id_hash = rotated_id_hash,
                    // Lost to a concurrent exchange, or reused -> refused as single-use.
                    Ok(false) => return SamlResumeOutcome::Expired,
                    Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
                }
                (request, rotated_id)
            } else if let Some(id) = cmd.saml_request_id.as_deref().filter(|s| !s.is_empty()) {
                match self
                    .requests
                    .find_by_id_hash(tenant.tenant_id(), &saml_sso_request::id_hash(id))
                    .await
                {
                    Ok(Some(r)) if !r.is_expired_at(now) => (r, id.to_string()),
                    Ok(_) => return SamlResumeOutcome::Expired,
                    Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
                }
            } else {
                return SamlResumeOutcome::Expired;
            };

        // 2. SSO restore (same checks as OIDC, including membership verification).
        let restored = match cmd.sso_session_id.as_deref().filter(|s| !s.is_empty()) {
            Some(session_id) => match self.sso_restorer.try_resume(tenant, session_id, ctx).await {
                Ok(restored) => restored,
                Err(e) => {
                    tracing::error!(error = %e, "failed to check SSO session for SAML SSO");
                    // An SSO check failure is not fatal. Fall back to sign-in.
                    None
                }
            },
            None => None,
        };
        let Some(restored) = restored else {
            return SamlResumeOutcome::LoginRequired { saml_request_id };
        };

        // 3. Re-resolve the SP (respect deletion/disablement during the flow even after SSO is established).
        let provider = match self
            .service_providers
            .find_by_id(tenant.tenant_id(), request.service_provider_id)
            .await
        {
            Ok(Some(p)) if p.enabled => p,
            Ok(_) => {
                let _ = self.requests.delete(&request.id_hash).await;
                return SamlResumeOutcome::Expired;
            }
            Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
        };

        // 4. Atomically consume (claim) the progress state before issuing the response. Of concurrent resumes with the same
        //    `saml_request_id`, only one succeeds in deleting (1 row), and the loser becomes Expired
        //    (prevents double issuance of successful assertions for one AuthnRequest).
        match self.requests.delete(&request.id_hash).await {
            Ok(true) => {}
            Ok(false) => return SamlResumeOutcome::Expired,
            Err(e) => return SamlResumeOutcome::Internal(e.to_string()),
        }
        match self
            .issue_response(tenant, &request, &provider, restored.user_id, restored, ctx)
            .await
        {
            Ok(SamlIssuance::Issued(saml_response)) => SamlResumeOutcome::Completed {
                acs_url: request.acs_url,
                saml_response,
                relay_state: request.relay_state,
            },
            Ok(SamlIssuance::ApplicationDenied { application_name }) => {
                SamlResumeOutcome::ApplicationNotPermitted { application_name }
            }
            // A failure after claiming cannot be resumed since the progress state is consumed (redo from the SP).
            Err(e) => SamlResumeOutcome::Internal(e),
        }
    }

    /// Builds a signed SAML Response (base64).
    ///
    /// The assignment check (ADR-0054) is done **before building**. It is placed after consuming (claiming) the progress
    /// state so that concurrent resumes do not record the check twice for the same AuthnRequest.
    async fn issue_response(
        &self,
        tenant: TenantContext,
        request: &SamlSsoRequest,
        provider: &SamlServiceProvider,
        user_id: uuid::Uuid,
        restored: crate::application::sso_restore::RestoredSso,
        ctx: &RequestContext,
    ) -> Result<SamlIssuance, String> {
        if let ApplicationGate::Denied {
            application_name, ..
        } = self
            .applications
            .check_saml(
                tenant.tenant_id(),
                provider.id,
                &request.sp_entity_id,
                user_id,
                ctx,
            )
            .await
        {
            return Ok(SamlIssuance::ApplicationDenied { application_name });
        }

        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err("SSO user not found".to_string()),
            Err(e) => return Err(e.to_string()),
        };

        // NameID: follows the Format of the SP registration. emailAddress uses the email; anything else (persistent, etc.)
        // uses the externally exposed subject identifier (`sub`. Same value as OIDC's `sub`).
        let name_id = if provider.name_id_format.contains("emailAddress") {
            user.email.clone()
        } else {
            user.sub.to_string()
        };

        let active_key = self
            .keys
            .active_signing_key()
            .await
            .map_err(|e| format!("no active signing key: {e}"))?;
        let signer = SamlSigner::from_pem(&active_key.algorithm, &active_key.private_pem)
            .map_err(|e| e.to_string())?;

        let now = self.clock.now();
        let input = SamlResponseInput {
            response_id: &generate_saml_id(),
            assertion_id: &generate_saml_id(),
            issued_at: now,
            idp_entity_id: &tenant_issuer(&self.base_issuer, tenant.tenant_id()),
            sp_entity_id: &request.sp_entity_id,
            acs_url: &request.acs_url,
            in_response_to: request.request_id.as_deref(),
            name_id: &name_id,
            name_id_format: &provider.name_id_format,
            authn_instant: restored.auth_time,
            session_index: &format!("_{}", restored.session_hash),
            not_on_or_after: now + Duration::seconds(ASSERTION_TTL_SECS),
            email: Some(&user.email),
        };
        let xml = build_signed_response_xml(&input, &signer).map_err(|e| e.to_string())?;

        self.audit
            .record(
                AuditEventType::SamlResponseIssued,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user.id),
                Some(&request.sp_entity_id),
                None,
                ctx,
            )
            .await;

        Ok(SamlIssuance::Issued(STANDARD.encode(xml)))
    }

    /// Audits the AuthnRequest refusal and returns a 400 response (traces of probing for unregistered SPs are also kept).
    async fn reject(
        &self,
        tenant: TenantContext,
        sp_entity_id: Option<&str>,
        reason: &str,
        ctx: &RequestContext,
    ) -> SamlBeginOutcome {
        self.audit
            .record(
                AuditEventType::SamlResponseIssued,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                None,
                sp_entity_id,
                Some(reason),
                ctx,
            )
            .await;
        SamlBeginOutcome::BadRequest {
            reason: reason.to_string(),
        }
    }
}
