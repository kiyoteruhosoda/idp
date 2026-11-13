//! External IdP login use case (AP10. User authentication & authentication policy spec §13).
//!
//! Two stages:
//!
//! 1. [`start`](ExternalLoginService::start) — builds the URL sent to the external IdP's authorization endpoint
//!    and stores `state` / `nonce` / the PKCE `code_verifier` as in-progress state.
//! 2. [`callback`](ExternalLoginService::callback) — **consumes the in-progress state once** using the returned `state`,
//!    exchanges the authorization code for an ID Token, resolves the user by the verified claims' `iss` + `sub`, and
//!    issues the SSO session.
//!
//! # Resolving the user (§13.2)
//!
//! If an `iss` + `sub` link already exists, that user. Otherwise:
//!
//! - If the provider has `allow_auto_link` enabled and the email the external IdP **claims is verified**
//!   matches an existing user in the tenant, a link to that user is created.
//! - Otherwise it is refused (`NotLinked`). **Users are never created on the fly** — turning anyone who can
//!   authenticate at the external IdP into a tenant user would make the admin entry points (invitation, permission grants) meaningless.
//!
//! # Authentication policy
//!
//! Even when identity is verified by the external IdP, the tenant's authentication policies (AP2/AP4) apply the same way.
//! "Authenticated externally" is no reason to escape `deny`.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::sign_in_completion::{
    AuthorizationContinuation, EstablishedSso, Establishment, SignIn, SignInCompletion,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSessionIdHash;
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::external_idp::{ExternalIdentity, ExternalIdpConfig, ExternalLoginRequest};
use crate::domain::external_oidc_port::{ExternalOidcClient, ExternalTokenRequest};
use crate::domain::id_generator::IdGenerator;
use crate::domain::pkce;
use crate::domain::repositories::{
    AuthSessionRepository, ExternalIdentityProviderRepository, ExternalIdentityRepository,
    ExternalLoginRequestRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use crate::domain::{saml_external_idp, saml_response};
use chrono::{DateTime, Duration, Utc};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::sync::Arc;

/// Lifetime of the in-progress state. Long enough for login at the external IdP (including consent and MFA).
const REQUEST_TTL_SECS: i64 = 600;
/// Random bytes for `state` / `nonce` (256 bits each).
const STATE_BYTES: usize = 32;

/// Result of starting an external IdP login.
pub enum StartOutcome {
    /// 302 to the external IdP's authorization endpoint.
    Redirect {
        location: String,
        /// A value given only to the browser that started (web puts it in a cookie. task #581). Without presenting it
        /// at the return endpoint, the flow can't proceed. Only its hash is kept in the DB.
        browser_binding: String,
    },
    /// Provider missing or disabled.
    ProviderUnavailable,
    Internal(String),
}

pub struct CallbackCommand {
    /// The `state` returned from the external IdP.
    pub state: String,
    /// Authorization code.
    pub code: String,
    /// The value from the start held by the returning browser (cookie. task #581).
    pub browser_binding: Option<String>,
}

/// Values received by the SAML ACS (`AssertionConsumerService`). The browser carries them via HTTP-POST.
pub struct SamlAcsCommand {
    /// `SAMLResponse` (base64(XML)). An **unverified** value.
    pub saml_response: String,
    /// `RelayState` (the `state` issued at start). The key to look up the in-progress state.
    pub relay_state: String,
    /// The value from the start held by the returning browser (cookie. task #581).
    pub browser_binding: Option<String>,
}

/// Result of completing an external IdP login.
pub enum CallbackOutcome {
    /// Authentication succeeded. Issue the SSO cookie.
    ///
    /// `location` is where to go after authentication. If it came from the middle of an OIDC authorization flow, it is
    /// **the `redirect_uri` with the code** (= back to the RP); otherwise a return destination within this service. Don't let
    /// web build this (the authorization request parameters exist only in auth_session).
    Success {
        location: SuccessLocation,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
        user_language: Option<String>,
    },
    /// Authentication at the external IdP passed, but consent for the RP is still missing. Send to the consent screen
    /// (same as other login paths; authenticating externally doesn't replace consent).
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
        user_language: Option<String>,
    },
    /// Authentication passed, but use of this application is not permitted (ADR-0054). ⚠ **Do not return to the RP.**
    /// The SSO session is issued (the user is signed in to assay), so other applications proceed as usual.
    ApplicationNotPermitted {
        /// Application name shown on screen. Without knowing which application refused them, the user
        /// cannot decide whom to ask next.
        application_name: String,
        sso_session_id: String,
        /// `Max-Age` of the SSO cookie (seconds until the established session's absolute expiry. ADR-0058).
        sso_absolute_ttl_secs: u64,
        user_language: Option<String>,
    },
    /// `state` invalid, expired, or reused (start over from the external IdP).
    StateExpired,
    /// Authentication at the external IdP passed, but there is no matching user in assay (neither a link nor auto-link).
    NotLinked,
    /// A matching user exists but is disabled or locked.
    UserUnavailable,
    /// Denied by the authentication policy.
    PolicyDenied,
    /// Communication with the external IdP or token verification failed.
    ExternalFailure,
    /// Authentication passed, but in an organization limited to registered devices this device is not registered (task #916).
    /// No SSO session was created. web puts `ticket` in a cookie and sends the user to the device registration screen.
    DeviceEnrollmentRequired {
        ticket: String,
    },
    Internal(String),
}

/// Where to go after successful authentication.
pub enum SuccessLocation {
    /// Continuation of the OIDC authorization flow. `location` is the `redirect_uri` with the code for `query`,
    /// or the form target for `form_post` (G12; when `form_post` is `Some`, an auto-submitting form is rendered).
    Redirect {
        location: String,
        form_post: Option<Vec<(String, String)>>,
    },
    /// Came from outside the authorization flow. web returns to its own screen (account settings).
    Account,
}

pub struct ExternalLoginService {
    providers: Arc<dyn ExternalIdentityProviderRepository>,
    identities: Arc<dyn ExternalIdentityRepository>,
    requests: Arc<dyn ExternalLoginRequestRepository>,
    users: Arc<dyn UserRepository>,
    /// Dependency for continuing when coming from the middle of an OIDC authorization flow (shared with other login paths).
    auth_sessions: Arc<dyn AuthSessionRepository>,
    /// Shared tail after authentication succeeds (establishing SSO, continuing the authorization flow).
    sign_in: Arc<SignInCompletion>,
    /// Authentication policy evaluation (looking up inputs and evaluating. `authentication_policy_gate`).
    policy_gate: Arc<AuthenticationPolicyGate>,
    oidc: Arc<dyn ExternalOidcClient>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    key_encryption_key: [u8; 32],
    /// Public base URL of web that receives the callback (`{base}/{tenant}/external/{code}/callback`).
    public_web_base_url: String,
}

impl ExternalLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        providers: Arc<dyn ExternalIdentityProviderRepository>,
        identities: Arc<dyn ExternalIdentityRepository>,
        requests: Arc<dyn ExternalLoginRequestRepository>,
        users: Arc<dyn UserRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        sign_in: Arc<SignInCompletion>,
        policy_gate: Arc<AuthenticationPolicyGate>,
        oidc: Arc<dyn ExternalOidcClient>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        key_encryption_key: [u8; 32],
        public_web_base_url: String,
    ) -> Self {
        Self {
            providers,
            identities,
            requests,
            users,
            auth_sessions,
            sign_in,
            policy_gate,
            oidc,
            audit,
            clock,
            ids,
            key_encryption_key,
            public_web_base_url,
        }
    }

    /// Builds the authorization request to the external IdP.
    pub async fn start(
        &self,
        tenant: TenantContext,
        provider_code: &str,
        auth_session_id: Option<String>,
    ) -> StartOutcome {
        let provider = match self
            .providers
            .find_by_code(tenant.tenant_id(), provider_code)
            .await
        {
            Ok(Some(p)) if p.enabled => p,
            Ok(_) => return StartOutcome::ProviderUnavailable,
            Err(e) => return StartOutcome::Internal(e.to_string()),
        };

        let now = self.clock.now();
        // `state` (`RelayState` in SAML) is common to both protocols. It is the key to look up the in-progress state.
        let state = crypto::random_token(STATE_BYTES);
        // A value given only to the browser that started. Unlike `state`, it doesn't pass through the external IdP (task #581).
        let browser_binding = crypto::random_token(STATE_BYTES);

        // Per protocol, decide "the URL sent to the peer" and "the value the peer returns". How the in-progress state is
        // made (single use, TTL, caller's auth_session) is shared, so only this part differs.
        let (location, echoed_value, code_verifier_encrypted) = match &provider.config {
            ExternalIdpConfig::Oidc(oidc) => {
                let nonce = crypto::random_token(STATE_BYTES);
                // PKCE is always added so the exchange is safe even if the external IdP registered us as a public client
                // (S256 only; same policy as assay itself enforces at `/authorize`).
                let code_verifier = crypto::random_token(STATE_BYTES);
                let code_challenge = pkce::s256_challenge(&code_verifier);
                let encrypted =
                    match crypto::encrypt(code_verifier.as_bytes(), &self.key_encryption_key) {
                        Ok(v) => v,
                        Err(e) => return StartOutcome::Internal(e.to_string()),
                    };

                let redirect_uri = self.redirect_uri(tenant, &provider.provider_code);
                let encode = |v: &str| utf8_percent_encode(v, NON_ALPHANUMERIC).to_string();
                let separator = if oidc.authorization_endpoint.contains('?') {
                    '&'
                } else {
                    '?'
                };
                let location = format!(
                    "{}{separator}response_type=code&client_id={}&redirect_uri={}&scope={}\
                     &state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
                    oidc.authorization_endpoint,
                    encode(&oidc.client_id),
                    encode(&redirect_uri),
                    encode(&oidc.effective_scopes().join(" ")),
                    encode(&state),
                    encode(&nonce),
                    encode(&code_challenge),
                );
                (location, nonce, Some(encrypted))
            }
            ExternalIdpConfig::Saml(saml) => {
                // SAML has neither PKCE nor `nonce`. What the peer returns is the `ID` of the `AuthnRequest`
                // (the response's `InResponseTo`), so that is stored in the in-progress state.
                let request_id = saml_response::generate_saml_id();
                let xml = saml_external_idp::build_authn_request_xml(
                    &saml_external_idp::AuthnRequestInput {
                        request_id: &request_id,
                        issued_at: now,
                        sp_entity_id: &self.saml_sp_entity_id(tenant),
                        acs_url: &self.saml_acs_url(tenant, &provider.provider_code),
                        sso_url: &saml.sso_url,
                        name_id_format: &saml.name_id_format,
                    },
                );
                let location =
                    match saml_external_idp::redirect_binding_location(&saml.sso_url, &xml, &state)
                    {
                        Ok(v) => v,
                        Err(e) => return StartOutcome::Internal(e.to_string()),
                    };
                (location, request_id, None)
            }
        };

        let request = ExternalLoginRequest {
            id: self.ids.new_id(),
            tenant_id: tenant.tenant_id(),
            provider_id: provider.id,
            state_hash: crypto::sha256_hex(&state),
            nonce: echoed_value,
            code_verifier_encrypted,
            auth_session_id_hash: auth_session_id
                .as_deref()
                .map(|id| AuthSessionIdHash::of_plain(id).into_string()),
            browser_binding_hash: Some(crypto::sha256_hex(&browser_binding)),
            expires_at: now + Duration::seconds(REQUEST_TTL_SECS),
            created_at: now,
        };
        if let Err(e) = self.requests.create(&request).await {
            return StartOutcome::Internal(e.to_string());
        }

        StartOutcome::Redirect {
            location,
            browser_binding,
        }
    }

    /// Handles the callback from the external IdP.
    pub async fn callback(
        &self,
        tenant: TenantContext,
        cmd: CallbackCommand,
        ctx: &RequestContext,
    ) -> CallbackOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Look up the in-progress state by `state`; **only the side that managed to delete it** continues (single use).
        let state_hash = crypto::sha256_hex(&cmd.state);
        let request = match self.requests.find_by_state(tenant_id, &state_hash).await {
            Ok(Some(r)) => r,
            Ok(None) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        match self.requests.consume(request.id).await {
            Ok(true) => {}
            Ok(false) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        }
        if request.is_expired_at(now) {
            return CallbackOutcome::StateExpired;
        }
        // Is this the browser that started (task #581)? If not, it was made to follow a return URL someone else had advanced partway.
        // ⚠ Leave the in-progress state consumed (don't let a value that failed matching be reused).
        if !request.is_bound_to(cmd.browser_binding.as_deref()) {
            self.record_browser_mismatch(tenant, &request, ctx).await;
            return CallbackOutcome::StateExpired;
        }

        // 2. Reload the provider settings (it may have been disabled meanwhile).
        let provider = match self
            .providers
            .find_by_id(tenant_id, request.provider_id)
            .await
        {
            Ok(Some(p)) if p.enabled => p,
            Ok(_) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };

        // 3. This path is OIDC-only. A SAML provider is not accepted here (a request that mixed up the in-progress
        //    state; the correct path is the ACS ([`Self::saml_acs`])).
        let Some(oidc) = provider.config.as_oidc() else {
            return CallbackOutcome::StateExpired;
        };

        // 4. Decrypt the secret.
        let Some(encrypted_verifier) = request.code_verifier_encrypted.as_deref() else {
            return CallbackOutcome::StateExpired;
        };
        let code_verifier = match crypto::decrypt(encrypted_verifier, &self.key_encryption_key) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(v) => v,
                Err(e) => return CallbackOutcome::Internal(e.to_string()),
            },
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        let client_secret = match oidc.client_secret_encrypted.as_deref() {
            Some(encrypted) => match crypto::decrypt(encrypted, &self.key_encryption_key) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(v) => Some(v),
                    Err(e) => return CallbackOutcome::Internal(e.to_string()),
                },
                Err(e) => return CallbackOutcome::Internal(e.to_string()),
            },
            None => None,
        };

        // 5. Exchange the code and verify the ID Token (verification is enclosed in the port's implementation).
        let redirect_uri = self.redirect_uri(tenant, &provider.provider_code);
        let claims = match self
            .oidc
            .exchange_code(ExternalTokenRequest {
                token_endpoint: &oidc.token_endpoint,
                jwks_uri: &oidc.jwks_uri,
                expected_issuer: &provider.issuer,
                client_id: &oidc.client_id,
                client_secret: client_secret.as_deref(),
                redirect_uri: &redirect_uri,
                code: &cmd.code,
                code_verifier: &code_verifier,
                expected_nonce: &request.nonce,
            })
            .await
        {
            Ok(c) => c,
            Err(e) => {
                // This includes external-IdP-side issues (certificates, keys, misconfiguration), so no details go to the user;
                // they are only kept in the operations log.
                tracing::warn!(
                    error = %e,
                    provider = %provider.provider_code,
                    "external idp token exchange or verification failed"
                );
                self.record_failure(tenant, &provider.provider_code, "token_verification", ctx)
                    .await;
                return CallbackOutcome::ExternalFailure;
            }
        };

        self.complete(tenant, &provider, &request, claims, ctx)
            .await
    }

    /// Handles a SAML response from the external IdP (ACS with HTTP-POST binding).
    ///
    /// After consuming the in-progress state once by `RelayState`, verifying the assertion and extracting the claims, it goes
    /// through **the same second half as OIDC** (resolving the user, checking state, authentication policy, SSO issuance,
    /// resuming the authorization flow). The protocols differ only up to "how to confirm who was authenticated"; the
    /// decisions after that should be the same.
    pub async fn saml_acs(
        &self,
        tenant: TenantContext,
        cmd: SamlAcsCommand,
        ctx: &RequestContext,
    ) -> CallbackOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Look up the in-progress state by `RelayState`; **only the side that managed to delete it** continues (single use).
        let state_hash = crypto::sha256_hex(&cmd.relay_state);
        let request = match self.requests.find_by_state(tenant_id, &state_hash).await {
            Ok(Some(r)) => r,
            Ok(None) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        match self.requests.consume(request.id).await {
            Ok(true) => {}
            Ok(false) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        }
        if request.is_expired_at(now) {
            return CallbackOutcome::StateExpired;
        }
        // Is this the browser that started (task #581)? If not, it was made to follow a return URL someone else had advanced partway.
        // ⚠ Leave the in-progress state consumed (don't let a value that failed matching be reused).
        if !request.is_bound_to(cmd.browser_binding.as_deref()) {
            self.record_browser_mismatch(tenant, &request, ctx).await;
            return CallbackOutcome::StateExpired;
        }

        let provider = match self
            .providers
            .find_by_id(tenant_id, request.provider_id)
            .await
        {
            Ok(Some(p)) if p.enabled => p,
            Ok(_) => return CallbackOutcome::StateExpired,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        // This path is SAML-only (don't let OIDC in-progress state be brought in).
        let Some(saml) = provider.config.as_saml() else {
            return CallbackOutcome::StateExpired;
        };

        // 2. Verify the signature before reading the claims. Values that don't pass here are indistinguishable from attacker-written ones.
        let assertion = match saml_external_idp::consume_response(
            &cmd.saml_response,
            &saml_external_idp::ResponseVerification {
                expected_issuer: &provider.issuer,
                sp_entity_id: &self.saml_sp_entity_id(tenant),
                expected_in_response_to: &request.nonce,
                certificates: &saml.certificates,
                now,
            },
        ) {
            Ok(v) => v,
            Err(e) => {
                // This includes external-IdP-side issues (missed certificate renewal, misconfiguration), so no details
                // go to the user; they are only kept in the operations log. The values themselves (NameID, email) are PII and not output.
                tracing::warn!(
                    error = %e,
                    provider = %provider.provider_code,
                    "external saml assertion verification failed"
                );
                self.record_failure(
                    tenant,
                    &provider.provider_code,
                    "assertion_verification",
                    ctx,
                )
                .await;
                return CallbackOutcome::ExternalFailure;
            }
        };

        // 3. From here on it's the same as OIDC. `Issuer` + `NameID` correspond to `iss` + `sub`.
        //
        //    `email_verified` is set to **false**. SAML assertions have no standard claim expressing email ownership
        //    verification; it just arrives as an attribute. Setting true would make
        //    `allow_auto_link` treat the "verified email match" condition as met, letting anyone who merely claims an
        //    email get into an existing account (ADR-0023).
        let claims = crate::domain::external_idp::ExternalClaims {
            issuer: assertion.issuer,
            subject: assertion.name_id,
            email: assertion.email,
            email_verified: false,
            name: assertion.display_name,
            nonce: None,
        };
        self.complete(tenant, &provider, &request, claims, ctx)
            .await
    }

    /// Shared processing after identity is verified at the external IdP (protocol-independent).
    async fn complete(
        &self,
        tenant: TenantContext,
        provider: &crate::domain::external_idp::ExternalIdentityProvider,
        request: &ExternalLoginRequest,
        claims: crate::domain::external_idp::ExternalClaims,
        ctx: &RequestContext,
    ) -> CallbackOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();
        // 5. Resolve the user by `iss` + `sub`.
        let identity = match self
            .identities
            .find_by_subject(provider.id, &claims.issuer, &claims.subject)
            .await
        {
            Ok(v) => v,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        let user_id = match identity.as_ref() {
            Some(existing) => existing.user_id,
            None => match self.auto_link(tenant, provider, &claims).await {
                Ok(Some(id)) => id,
                Ok(None) => {
                    self.record_failure(tenant, &provider.provider_code, "not_linked", ctx)
                        .await;
                    return CallbackOutcome::NotLinked;
                }
                Err(e) => return CallbackOutcome::Internal(e),
            },
        };

        // 6. Check the user's state.
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) if u.is_active() && !u.is_locked_at(now) => u,
            Ok(_) => {
                self.record_failure(tenant, &provider.provider_code, "user_unavailable", ctx)
                    .await;
                return CallbackOutcome::UserUnavailable;
            }
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };

        // 7. Authentication policy (AP2/AP3). Authenticating externally is no reason to escape `deny`.
        //
        //    If it came from the middle of an OIDC authorization flow, look up that auth_session **before evaluating**
        //    and put the application and `acr_values` into the context. Evaluating with an empty context would let policies
        //    conditioned on `application_ids` or `requested_acr` fail to match, so conditional denials and method requirements
        //    could be bypassed via an external IdP (this auth_session is used to issue the code later, so it's not true that
        //    "there is no client context"). If started from the portal, leaving it empty is fine.
        let originating_session = match request.auth_session_id_hash.as_deref() {
            Some(id_hash) => match self
                .auth_sessions
                .find(
                    tenant_id,
                    &AuthSessionIdHash::from_stored(id_hash.to_string()),
                )
                .await
            {
                Ok(session) => session,
                Err(e) => return CallbackOutcome::Internal(e.to_string()),
            },
            None => None,
        };
        let requested_acr = originating_session
            .as_ref()
            .map(|s| s.request().requested_acr())
            .unwrap_or_default();
        // The target of the authentication policy is the application (ADR-0054 decision 5). Outside the authorization flow
        // (linking started from account settings) there is no client.
        let audience = match originating_session.as_ref() {
            Some(session) => PolicyAudience::OidcClient(session.client_id()),
            None => PolicyAudience::Unaddressed,
        };
        let decision = match self
            .policy_gate
            .decide(PolicyQuery {
                tenant_id,
                audience,
                user_id: user.id,
                ip_address: ctx.ip_address.as_deref(),
                requested_acr: &requested_acr,
                now,
            })
            .await
        {
            Ok(decision) => decision,
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };
        match &decision {
            PolicyDecision::Allow { .. } => {}
            PolicyDecision::Deny { policy_code } => {
                self.record_policy_denied(tenant, user.id, &format!("policy={policy_code}"), ctx)
                    .await;
                return CallbackOutcome::PolicyDenied;
            }
            PolicyDecision::RequireMfa { policy_code } => {
                // From assay's point of view, external IdP authentication is single-factor (MFA on the external side isn't observable.
                // §13.3). Users subject to an MFA-required policy are not let through on this path.
                self.record_policy_denied(
                    tenant,
                    user.id,
                    &format!("policy={policy_code} reason=external_idp_is_single_factor"),
                    ctx,
                )
                .await;
                return CallbackOutcome::PolicyDenied;
            }
            PolicyDecision::RequireMethods { .. } => {
                // The only method recorded via an external IdP is `external_idp`. If it disagrees with the requirement, it doesn't pass
                // (which authenticator was used on the external side can't be observed, so the requirement can't be considered met).
                if let Some(unmet) =
                    decision.unmet_method_requirement(&[AuthenticationMethod::ExternalIdp], false)
                {
                    self.record_policy_denied(
                        tenant,
                        user.id,
                        &format!(
                            "policy={} reason=method_required required={}",
                            unmet.policy_code,
                            unmet.requirement.describe()
                        ),
                        ctx,
                    )
                    .await;
                    return CallbackOutcome::PolicyDenied;
                }
            }
        }

        // 8. Update the link's last-used time (on first link, `auto_link` already created it).
        if let Some(existing) = identity {
            if let Err(e) = self.identities.touch_last_used(existing.id, now).await {
                tracing::warn!(error = %e, "failed to record external identity usage");
            }
        }

        // 9. Issue the SSO session (it ends here too when coming from outside the authorization flow).
        let sso = match self
            .sign_in
            .establish_sso(
                SignIn {
                    tenant_id,
                    user_id: user.id,
                    home_tenant_id: user.tenant_id,
                    methods: vec![AuthenticationMethod::ExternalIdp],
                    client_id: None,
                    success_event: AuditEventType::ExternalLoginSucceeded,
                    success_detail: Some(format!("provider={}", provider.provider_code)),
                },
                ctx,
                now,
            )
            .await
        {
            Ok(Establishment::Established(sso)) => sso,
            Ok(Establishment::DeviceEnrollmentRequired { ticket }) => {
                return CallbackOutcome::DeviceEnrollmentRequired { ticket }
            }
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };

        // 10. If it came from the middle of an OIDC authorization flow, proceed with the rest (consent check -> code issuance).
        //     Without proceeding here, the authorization request parameters (client_id, redirect_uri, PKCE, nonce) exist
        //     only in auth_session, so it couldn't get back to the RP.
        let Some(auth_session_id_hash) = request.auth_session_id_hash.clone() else {
            return CallbackOutcome::Success {
                location: SuccessLocation::Account,
                sso_session_id: sso.session_id().to_string(),
                sso_absolute_ttl_secs: sso.absolute_ttl_secs(),
                user_language: user.language.clone(),
            };
        };
        self.resume_authorization(tenant, &auth_session_id_hash, &user, &sso, now, ctx)
            .await
    }

    /// Resumes the interrupted OIDC authorization flow for a user authenticated at the external IdP.
    ///
    /// The steps are the same as other login paths (`SignInCompletion::continue_authorization`). All this owns is
    /// handling the auth_session expiring during the round trip to the external IdP: authentication at the external IdP
    /// itself succeeded, so the SSO stays issued and the user is returned to the account screen (they can't get back to
    /// the RP, but don't need to log in again).
    async fn resume_authorization(
        &self,
        tenant: TenantContext,
        auth_session_id_hash: &str,
        user: &crate::domain::user::User,
        sso: &EstablishedSso,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) -> CallbackOutcome {
        let sso_session_id = sso.session_id().to_string();
        let sso_absolute_ttl_secs = sso.absolute_ttl_secs();
        let user_language = user.language.clone();
        let mut session = match self
            .auth_sessions
            .find(
                tenant.tenant_id(),
                &AuthSessionIdHash::from_stored(auth_session_id_hash.to_string()),
            )
            .await
        {
            Ok(Some(session)) if !session.is_expired_at(now) => session,
            Ok(_) => {
                // Authorization can't be resumed, but the login itself succeeded.
                tracing::info!("external login finished after its auth session had expired");
                return CallbackOutcome::Success {
                    location: SuccessLocation::Account,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                    user_language,
                };
            }
            Err(e) => return CallbackOutcome::Internal(e.to_string()),
        };

        match self
            .sign_in
            .continue_authorization(tenant, &mut session, sso, now, ctx)
            .await
        {
            Ok(AuthorizationContinuation::ConsentRequired { auth_session_id }) => {
                CallbackOutcome::ConsentRequired {
                    auth_session_id,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                    user_language,
                }
            }
            Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name }) => {
                CallbackOutcome::ApplicationNotPermitted {
                    application_name,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                    user_language,
                }
            }
            Ok(AuthorizationContinuation::Authorized(dispatch)) => CallbackOutcome::Success {
                location: SuccessLocation::Redirect {
                    location: dispatch.location,
                    form_post: dispatch.form_post,
                },
                sso_session_id,
                sso_absolute_ttl_secs,
                user_language,
            },
            Err(e) => CallbackOutcome::Internal(e.to_string()),
        }
    }

    /// Links to an existing user by a verified email match (only if the provider allows it).
    ///
    /// Even if a user matches, no link is made unless the external IdP claims `email_verified`.
    /// Linking by an unclaimed email would let anyone who can register at the external IdP into someone else's account.
    async fn auto_link(
        &self,
        tenant: TenantContext,
        provider: &crate::domain::external_idp::ExternalIdentityProvider,
        claims: &crate::domain::external_idp::ExternalClaims,
    ) -> Result<Option<uuid::Uuid>, String> {
        if !provider.allow_auto_link || !claims.email_verified {
            return Ok(None);
        }
        let Some(email) = claims
            .email
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
        else {
            return Ok(None);
        };
        let user = self
            .users
            .find_by_email(tenant.tenant_id(), email)
            .await
            .map_err(|e| e.to_string())?;
        let Some(user) = user.filter(|u| u.is_active()) else {
            return Ok(None);
        };

        let now = self.clock.now();
        let identity = ExternalIdentity {
            id: self.ids.new_id(),
            user_id: user.id,
            provider_id: provider.id,
            external_issuer: claims.issuer.clone(),
            external_subject: claims.subject.clone(),
            created_at: now,
            last_used_at: Some(now),
        };
        match self.identities.create(&identity).await {
            Ok(()) => Ok(Some(user.id)),
            // If the same link was created concurrently, use the winner's link (don't recreate).
            Err(crate::domain::error::DomainError::Conflict(_)) => {
                let existing = self
                    .identities
                    .find_by_subject(provider.id, &claims.issuer, &claims.subject)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(existing.map(|i| i.user_id))
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Callback URL (must exactly match the `redirect_uri` registered at the external IdP).
    /// assay's entityID as an SP (SAML `Issuer` / `Audience`). Separate per tenant
    /// ——using the same entityID for all tenants would let an assertion meant for one tenant be carried into
    /// another tenant's login.
    fn saml_sp_entity_id(&self, tenant: TenantContext) -> String {
        format!(
            "{}/{}/saml/sp",
            self.public_web_base_url,
            tenant.tenant_id()
        )
    }

    /// URL that receives assertions (ACS). It's where the browser POSTs, so it lives on the web side.
    fn saml_acs_url(&self, tenant: TenantContext, provider_code: &str) -> String {
        format!(
            "{}/{}/external/{provider_code}/saml/acs",
            self.public_web_base_url,
            tenant.tenant_id()
        )
    }

    fn redirect_uri(&self, tenant: TenantContext, provider_code: &str) -> String {
        format!(
            "{}/{}/external/{provider_code}/callback",
            self.public_web_base_url,
            tenant.tenant_id()
        )
    }

    /// Records in the audit that the returning browser was not the one that started (task #581).
    async fn record_browser_mismatch(
        &self,
        tenant: TenantContext,
        request: &ExternalLoginRequest,
        ctx: &RequestContext,
    ) {
        let provider_code = match self
            .providers
            .find_by_id(tenant.tenant_id(), request.provider_id)
            .await
        {
            Ok(Some(p)) => p.provider_code,
            _ => String::from("unknown"),
        };
        self.record_failure(tenant, &provider_code, "browser_binding", ctx)
            .await;
    }

    async fn record_failure(
        &self,
        tenant: TenantContext,
        provider_code: &str,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::ExternalLoginFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                None,
                None,
                Some(&format!("provider={provider_code} reason={reason}")),
                ctx,
            )
            .await;
    }

    async fn record_policy_denied(
        &self,
        tenant: TenantContext,
        user_id: uuid::Uuid,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::LoginPolicyDenied,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                Some(user_id),
                None,
                Some(reason),
                ctx,
            )
            .await;
    }
}
