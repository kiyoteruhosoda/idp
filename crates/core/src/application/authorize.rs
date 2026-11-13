//! Authorization endpoint use case (design spec §4.2, ADR-0018 decisions 2 and 3).
//!
//! `/authorize` neither reads nor writes browser cookies. It validates the authorization request, creates an AuthSession,
//! and issues a **single-use, short-lived handle** that it puts on the handoff to web (`{web}/{tenant}/login?auth_session=...`)
//! ([`AuthorizeService::authorize`]). SSO restore, consent check and code issuance happen when web passes the
//! handle and its own domain's `sso_session_id` via `/internal/authorize/resume`
//! ([`AuthorizeService::resume`]). Evaluation of `prompt` / `max_age` is also deferred to resume.
//!
//! Error policy: if `client_id` / `redirect_uri` is invalid, don't redirect;
//! other errors are returned with an error code appended to `redirect_uri`.

use crate::application::audit::RequestContext;
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::code_issuance::{CodeIssuance, CodeIssuanceService, IssueCodeCommand};
use crate::application::consent::consent_is_granted;
use crate::application::sso_restore::SsoRestorer;
use crate::application::tenant_resolution::TenantResolutionService;
use crate::domain::auth_session::{
    AuthSession, AuthSessionId, Authentication, AuthenticationProgress, HandoffHandle,
};
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::authorization_request::{
    AuthorizationParameters, AuthorizationRequest, AuthorizationRequestRejection,
};
use crate::domain::clock::Clock;
use crate::domain::error::OAuthErrorCode;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, ClientRepository,
};
use crate::domain::response_mode::AuthorizationResponse;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// Expiry of the web handoff handle (seconds). It only needs to cover the one-way trip from web receiving `/authorize`'s 302
/// to passing it to `/internal/authorize/resume`, so it is much shorter than the auth_session's own
/// TTL (single-use, short-lived, fixed binding. ADR-0018 decision 3).
const HANDLE_TTL_SECS: i64 = 60;

pub enum AuthorizeOutcome {
    /// Validation succeeded and the AuthSession is created. 302 to web's `/login` with the single-use handle in the URL
    /// (web checks for SSO at resume. ADR-0018 decision 2).
    HandoffToWeb { handle: String },
    /// 302 with the error appended to `redirect_uri`.
    ErrorRedirect { location: String },
    /// An error that can't be redirected (client_id / redirect_uri invalid).
    FatalError {
        error: OAuthErrorCode,
        description: String,
    },
}

/// Command for `/internal/authorize/resume` (web forwards the handle and the SSO cookie value).
#[derive(Debug)]
pub struct ResumeCommand {
    /// The single-use handle `/authorize` put in the URL.
    pub handle: String,
    /// Value of web's host-only `sso_session_id` cookie (not logged in if absent).
    pub sso_session_id: Option<String>,
}

/// Command for `/internal/authorize/continue` (web forwards `auth_session_id` and the SSO cookie value).
///
/// Used when, after the login screen was shown, the user **finished authenticating in another tab** and reopened the original tab.
/// The handle was consumed on first receipt, so the same authorization request is looked up again from the `auth_session_id` at hand.
#[derive(Debug)]
pub struct ContinueCommand {
    /// Value of web's host-only `auth_session_id` cookie.
    pub auth_session_id: String,
    /// Value of web's host-only `sso_session_id` cookie (not logged in if absent).
    pub sso_session_id: Option<String>,
}

pub enum ResumeOutcome {
    /// Code issued thanks to SSO restore and existing consent. For `query`, 302 to `location`; for `form_post`,
    /// render an auto-submitting form that POSTs hidden fields to `location` (G12).
    Redirect {
        location: String,
        form_post: Option<Vec<(String, String)>>,
        /// Time until the restored SSO session's absolute expiry (seconds). The `Max-Age` when web reissues the cookie
        /// (ADR-0058).
        sso_absolute_ttl_secs: u64,
    },
    /// The request can't continue (not logged in or not consented with `prompt=none`, etc.). Return an error to the RP.
    /// Like success, it follows the requested `response_mode` (G12): if `form_post` is `Some`,
    /// POST hidden fields to `location`.
    ErrorRedirect {
        location: String,
        form_post: Option<Vec<(String, String)>>,
    },
    /// SSO valid but consent needed. web turns `auth_session_id` into a cookie and goes to `/consent`.
    ConsentRequired {
        auth_session_id: String,
        /// Same as `Redirect` (time until the restored SSO session's absolute expiry).
        sso_absolute_ttl_secs: u64,
    },
    /// Authentication needed. web turns `auth_session_id` into a cookie and shows the login form.
    LoginRequired { auth_session_id: String },
    /// SSO was restored, but use of this application is not permitted (ADR-0054). ⚠ **Do not return to the RP.**
    /// The SSO cookie is already at hand, so only showing a screen is needed here.
    ApplicationNotPermitted {
        /// Application name shown on screen.
        application_name: String,
    },
    /// Handle invalid, expired or used (start over from `/authorize`). For `continue`,
    /// when `auth_session_id` is invalid or expired.
    ExpiredHandle,
    /// Internal error (a failure at a stage where even the redirect to the RP can't be built).
    Internal(String),
}

/// Result of fetching the login screen context (`/internal/authorize/login-context`. G12).
pub enum LoginContextOutcome {
    /// Display hints brought by the in-progress authorization request (`None` if none specified).
    Ok {
        login_hint: Option<String>,
        ui_locales: Option<String>,
        /// This authorization request's `redirect_uri`. Source of the origin web allows in the login
        /// screen's CSP `form-action` (if SSO and consent are in place, submitting the login form
        /// redirects straight to the RP).
        redirect_uri: String,
        /// Display name of the client that sent the authorization request (`Clients.app_name`). Used by the login screen
        /// to show "which application you are logging in to". `None` if the display name can't be looked up
        /// (`client_id` is **not shown**; it means nothing to users and only clutters the screen).
        client_name: Option<String>,
        /// Display name of the flow's tenant (`Tenants.name`). The same IdP serves several organizations, so this
        /// shows "which organization's account you are signing in with". `None` if it can't be looked up.
        tenant_name: Option<String>,
    },
    /// `auth_session_id` invalid or expired (web continues rendering without context).
    SessionExpired,
    /// Internal error.
    Internal(String),
}

/// Conclusion of the policy check on a restored SSO session.
enum RestoredPolicy {
    /// May be restored.
    Ok,
    /// Restore not allowed, but logging in again may pass (treated the same as exceeding `max_age`).
    Reauthenticate,
    /// Denied. Logging in again won't pass either, so the flow ends.
    Denied,
    Internal(String),
}

pub struct AuthorizeService {
    clients: Arc<dyn ClientRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    /// Shared SSO restore checks (shared with SAML SSO. [`crate::application::sso_restore`]).
    sso_restorer: Arc<SsoRestorer>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    clock: Arc<dyn Clock>,
    auth_session_ttl: Duration,
    /// Authentication policy evaluation (looking up inputs and evaluating. `authentication_policy_gate`).
    policy_gate: Arc<AuthenticationPolicyGate>,
    /// Where the tenant display name for the login screen is looked up (used only by `login_context`).
    /// It goes through the resolver service instead of holding the repository directly because the same row is already
    /// looked up at the same request's entrance (`TenantResolver`), and this rides on its TTL cache.
    tenants: Arc<TenantResolutionService>,
}

impl AuthorizeService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clients: Arc<dyn ClientRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        sso_restorer: Arc<SsoRestorer>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        clock: Arc<dyn Clock>,
        auth_session_ttl: std::time::Duration,
        policy_gate: Arc<AuthenticationPolicyGate>,
        tenants: Arc<TenantResolutionService>,
    ) -> Self {
        Self {
            clients,
            auth_sessions,
            sso_restorer,
            client_consents,
            code_issuance,
            clock,
            auth_session_ttl: Duration::from_std(auth_session_ttl)
                .expect("auth session TTL out of range"),
            policy_gate,
            tenants,
        }
    }

    pub async fn authorize(
        &self,
        tenant: TenantContext,
        params: AuthorizationParameters,
    ) -> AuthorizeOutcome {
        // 1. Resolve the client (no redirect if invalid). Only clients belonging to the flow's tenant are
        // resolved (tenant isolation. ADR-0009 §8).
        let Some(client_id) = non_empty(params.client_id.as_deref()) else {
            return fatal(OAuthErrorCode::InvalidRequest, "client_id is required");
        };
        let client = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), client_id)
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => return fatal(OAuthErrorCode::InvalidClient, "unknown client_id"),
            Err(e) => {
                tracing::error!(error = %e, "failed to load client");
                return fatal(OAuthErrorCode::ServerError, "internal error");
            }
        };

        // 2. Accept the authorization request (validation is owned by the domain).
        let request = match AuthorizationRequest::accept(&params, &client) {
            Ok(request) => request,
            Err(AuthorizationRequestRejection::NotRedirectable { error, description }) => {
                return fatal(error, description);
            }
            Err(AuthorizationRequestRejection::Redirectable {
                redirect_uri,
                state,
                error,
                description,
            }) => {
                return AuthorizeOutcome::ErrorRedirect {
                    location: error_redirect_with_state(
                        &redirect_uri,
                        error,
                        description,
                        state.as_deref(),
                    ),
                };
            }
        };

        // 3. Create the AuthSession, issue a single-use handle and hand off to web (ADR-0018 decision 2).
        //    The SSO cookie isn't visible from api, so SSO restore and `prompt`/`max_age` evaluation happen at resume.
        let (session, handle) = AuthSession::start(
            tenant.tenant_id(),
            request,
            self.clock.now(),
            self.auth_session_ttl,
            Duration::seconds(HANDLE_TTL_SECS),
        );
        if let Err(e) = self.auth_sessions.create(&session).await {
            tracing::error!(error = %e, "failed to create auth session");
            return AuthorizeOutcome::ErrorRedirect {
                location: redirect_with_error(
                    session.request(),
                    OAuthErrorCode::ServerError,
                    "failed to start authorization",
                ),
            };
        }

        AuthorizeOutcome::HandoffToWeb {
            handle: handle.into_string(),
        }
    }

    /// Resuming the web handoff (`/internal/authorize/resume`. ADR-0018 decision 2).
    ///
    /// Consumes the handle once to identify the AuthSession, and with the `sso_session_id` passed from web does
    /// SSO restore -> `max_age` -> consent check -> code issuance (the checks `/authorize` used to do with cookies).
    /// A `prompt=none` failure is returned as an error redirect to the RP.
    pub async fn resume(
        &self,
        tenant: TenantContext,
        cmd: ResumeCommand,
        ctx: &RequestContext,
    ) -> ResumeOutcome {
        let now = self.clock.now();

        // 1. Identify the AuthSession from the handle and consume it as single-use.
        let (mut session, auth_session_id) =
            match self.exchange_handoff(tenant, &cmd.handle, now).await {
                Ok(exchanged) => exchanged,
                Err(outcome) => return outcome,
            };

        // 2. If SSO restore can complete it, finish there.
        if let Some(outcome) = self
            .complete_with_sso(
                tenant,
                &mut session,
                cmd.sso_session_id.as_deref(),
                ctx,
                now,
            )
            .await
        {
            return outcome;
        }

        // 3. SSO can't complete it: prompt=none can't show the login screen, so it's an error (flow ends).
        if session.request().forbids_interaction() {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return resume_error(
                session.request(),
                OAuthErrorCode::LoginRequired,
                "login required",
            );
        }

        ResumeOutcome::LoginRequired {
            auth_session_id: auth_session_id.into_string(),
        }
    }

    /// When the login screen is reopened, continues authorization from an SSO session established since
    /// (`/internal/authorize/continue`).
    ///
    /// If it can't be restored, returns `LoginRequired` with the same `auth_session_id` and web re-renders the form.
    /// Sessions where authentication is partway (waiting for a second factor or password change) are not touched
    /// ——their continuation belongs to that screen.
    pub async fn continue_with_sso(
        &self,
        tenant: TenantContext,
        cmd: ContinueCommand,
        ctx: &RequestContext,
    ) -> ResumeOutcome {
        let now = self.clock.now();
        let Some(auth_session_id) = AuthSessionId::from_presented(&cmd.auth_session_id) else {
            return ResumeOutcome::ExpiredHandle;
        };
        let mut session = match self
            .auth_sessions
            .find(tenant.tenant_id(), &auth_session_id.hash())
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return ResumeOutcome::ExpiredHandle,
            Err(e) => return ResumeOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            return ResumeOutcome::ExpiredHandle;
        }
        if *session.progress() != AuthenticationProgress::Anonymous {
            return ResumeOutcome::LoginRequired {
                auth_session_id: auth_session_id.into_string(),
            };
        }
        if let Some(outcome) = self
            .complete_with_sso(
                tenant,
                &mut session,
                cmd.sso_session_id.as_deref(),
                ctx,
                now,
            )
            .await
        {
            return outcome;
        }
        ResumeOutcome::LoginRequired {
            auth_session_id: auth_session_id.into_string(),
        }
    }

    /// Exchanges the handle for `auth_session_id` (single-use; of concurrent exchanges only one wins).
    async fn exchange_handoff(
        &self,
        tenant: TenantContext,
        handle: &str,
        now: DateTime<Utc>,
    ) -> Result<(AuthSession, AuthSessionId), ResumeOutcome> {
        let Some(handle) = HandoffHandle::from_presented(handle) else {
            return Err(ResumeOutcome::ExpiredHandle);
        };
        let mut session = match self
            .auth_sessions
            .find_by_handoff(tenant.tenant_id(), &handle.hash())
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return Err(ResumeOutcome::ExpiredHandle),
            Err(e) => return Err(ResumeOutcome::Internal(e.to_string())),
        };
        let Ok(exchange) = session.exchange_handoff(now) else {
            return Err(ResumeOutcome::ExpiredHandle);
        };
        match self.auth_sessions.save_handoff_exchange(&exchange).await {
            Ok(true) => Ok((session, exchange.into_issued())),
            // Lost a concurrent exchange, or reuse -> refused as single-use.
            Ok(false) => Err(ResumeOutcome::ExpiredHandle),
            Err(e) => Err(ResumeOutcome::Internal(e.to_string())),
        }
    }

    /// Restores the SSO session and completes authorization. `None` if it can't complete (= go to login).
    ///
    /// `prompt=login` / `prompt=select_account` always re-authenticate. A failed SSO check is not fatal;
    /// it falls back to login.
    async fn complete_with_sso(
        &self,
        tenant: TenantContext,
        session: &mut AuthSession,
        sso_session_id: Option<&str>,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Option<ResumeOutcome> {
        if session.request().forces_reauthentication() {
            return None;
        }
        let sso_session_id = non_empty(sso_session_id)?;
        let restored = match self
            .sso_restorer
            .try_resume(tenant, sso_session_id, ctx)
            .await
        {
            Ok(restored) => restored?,
            Err(e) => {
                tracing::error!(error = %e, "failed to check SSO session");
                return None;
            }
        };

        // Evaluate the authentication policy (AP2/AP3) **in the context of this authorization request**. The client and
        // `acr_values` may differ from when the session being restored was established. Without evaluating, even if the RP
        // triggers a WebAuthn-required policy via `acr_values`, an existing SSO established with only a password would be
        // silently reused. If not satisfied, treat it like exceeding `max_age` (= fall back to re-authentication). Only deny
        // policies won't pass even after re-authenticating, so the flow ends right there.
        let policy = self
            .evaluate_for_restored_session(
                tenant,
                session.request(),
                restored.user_id,
                &restored.authentication_methods,
                ctx,
                now,
            )
            .await;
        match policy {
            RestoredPolicy::Ok => {}
            RestoredPolicy::Reauthenticate => return None,
            RestoredPolicy::Denied => {
                let _ = self.auth_sessions.delete(session.id_hash()).await;
                return Some(resume_error(
                    session.request(),
                    OAuthErrorCode::AccessDenied,
                    "denied by authentication policy",
                ));
            }
            RestoredPolicy::Internal(e) => return Some(ResumeOutcome::Internal(e)),
        }
        // `max_age` exceeded -> to login (SSO is not restored).
        if session
            .request()
            .authentication_is_too_old(restored.auth_time, now)
        {
            return None;
        }

        // The `sid` put in the ID Token (G5) is derived from the restored session.
        let authentication = Authentication::new(
            restored.user_id,
            restored.auth_time,
            Some(crate::domain::sso_session::sid_of(&restored.session_hash)),
            Some(restored.authentication_methods),
        );
        Some(
            self.authorize_restored(
                tenant,
                session,
                authentication,
                restored.absolute_ttl_secs,
                ctx,
            )
            .await,
        )
    }

    /// With the restored SSO's authentication, checks consent and issues the code (to the consent screen if not consented).
    async fn authorize_restored(
        &self,
        tenant: TenantContext,
        session: &mut AuthSession,
        authentication: Authentication,
        sso_absolute_ttl_secs: u64,
        ctx: &RequestContext,
    ) -> ResumeOutcome {
        // Consent check (existing consent is ignored with `prompt=consent`).
        let request = session.request();
        if !request.forces_consent()
            && self
                .check_consent(tenant, authentication.user_id(), request)
                .await
        {
            return self
                .issue_restored_code(tenant, session, authentication, sso_absolute_ttl_secs, ctx)
                .await;
        }

        // Not consented (or `prompt=consent`). With `prompt=none` the consent screen can't be shown, so it's an error.
        if request.forbids_interaction() {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return resume_error(request, OAuthErrorCode::ConsentRequired, "consent required");
        }

        // To the consent screen: put the AuthSession in the authenticated state and return to web. The id is regenerated
        // even when restoring from SSO (SEC7). The `auth_session_id` passed to the consent screen is the regenerated value.
        let completion = session.complete_authentication(authentication);
        if let Err(e) = self.auth_sessions.save_authentication(&completion).await {
            tracing::error!(error = %e, "failed to mark session for consent");
            return resume_error(
                session.request(),
                OAuthErrorCode::ServerError,
                "failed to start consent",
            );
        }
        ResumeOutcome::ConsentRequired {
            auth_session_id: completion.into_issued().into_string(),
            sso_absolute_ttl_secs,
        }
    }

    /// Issues the code on an SSO restore with consent, and deletes the AuthSession.
    async fn issue_restored_code(
        &self,
        tenant: TenantContext,
        session: &AuthSession,
        authentication: Authentication,
        sso_absolute_ttl_secs: u64,
        ctx: &RequestContext,
    ) -> ResumeOutcome {
        let cmd = IssueCodeCommand {
            tenant,
            request: session.request().clone(),
            authentication,
        };
        match self.code_issuance.issue(cmd, ctx).await {
            // The restored SSO passes, but use of this application is not permitted (ADR-0054).
            // `prompt=none` promises no screen, so return `access_denied` to the RP (the RP shows its own
            // entry point. task #648). Otherwise don't return to the RP; refuse on assay's screen.
            Ok(CodeIssuance::ApplicationDenied { .. })
                if session.request().forbids_interaction() =>
            {
                let _ = self.auth_sessions.delete(session.id_hash()).await;
                resume_error(
                    session.request(),
                    OAuthErrorCode::AccessDenied,
                    "application not permitted",
                )
            }
            Ok(CodeIssuance::ApplicationDenied { application_name }) => {
                ResumeOutcome::ApplicationNotPermitted { application_name }
            }
            Ok(CodeIssuance::Issued(code)) => {
                if let Err(e) = self.auth_sessions.delete(session.id_hash()).await {
                    tracing::warn!(
                        error = %e,
                        "failed to delete auth session after SSO code issuance"
                    );
                }
                let dispatch =
                    AuthorizationDispatch::from(session.request().success_response(&code));
                ResumeOutcome::Redirect {
                    location: dispatch.location,
                    form_post: dispatch.form_post,
                    sso_absolute_ttl_secs,
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to issue authorization code");
                resume_error(
                    session.request(),
                    OAuthErrorCode::ServerError,
                    "failed to issue authorization code",
                )
            }
        }
    }

    /// Applies the authentication policy to the restored SSO session in the context of this authorization request (AP2/AP3).
    ///
    /// The input is "the authentication methods recorded by the restored session" (AP4). `require_mfa` is satisfied by a
    /// session established with multiple factors, and `require_specific_method` checks whether the recorded methods match
    /// the requirement. User Verification isn't recorded, so only sessions including WebAuthn are considered
    /// UV-done (passkey registration and authentication are done with UV required).
    async fn evaluate_for_restored_session(
        &self,
        tenant: TenantContext,
        request: &AuthorizationRequest,
        user_id: Uuid,
        methods: &[AuthenticationMethod],
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> RestoredPolicy {
        let decision = match self
            .policy_gate
            .decide(PolicyQuery {
                tenant_id: tenant.tenant_id(),
                audience: PolicyAudience::OidcClient(request.client_id()),
                user_id,
                ip_address: ctx.ip_address.as_deref(),
                requested_acr: &request.requested_acr(),
                now,
            })
            .await
        {
            Ok(decision) => decision,
            Err(e) => return RestoredPolicy::Internal(e.to_string()),
        };
        let user_verified = methods.contains(&AuthenticationMethod::WebAuthn);
        match &decision {
            PolicyDecision::Deny { .. } => RestoredPolicy::Denied,
            PolicyDecision::RequireMfa { .. } if methods.iter().any(|m| m.is_second_factor()) => {
                RestoredPolicy::Ok
            }
            PolicyDecision::RequireMfa { .. } => RestoredPolicy::Reauthenticate,
            PolicyDecision::RequireMethods { .. }
                if decision
                    .unmet_method_requirement(methods, user_verified)
                    .is_none() =>
            {
                RestoredPolicy::Ok
            }
            PolicyDecision::RequireMethods { .. } => RestoredPolicy::Reauthenticate,
            PolicyDecision::Allow { .. } => RestoredPolicy::Ok,
        }
    }

    /// Consent check: confirms the user has consented to all scopes for the client.
    ///
    /// If the check fails, it is treated as "not consented" (it only goes to the consent screen; it never wrongly issues a code).
    async fn check_consent(
        &self,
        tenant: TenantContext,
        user_id: Uuid,
        request: &AuthorizationRequest,
    ) -> bool {
        match consent_is_granted(
            self.client_consents.as_ref(),
            tenant.tenant_id(),
            user_id,
            request,
        )
        .await
        {
            Ok(granted) => granted,
            Err(e) => {
                tracing::error!(error = %e, "failed to check consent");
                false
            }
        }
    }

    /// Login screen context (`/internal/authorize/login-context`. G12).
    ///
    /// Looks up the `login_hint` / `ui_locales` brought by the authorization request again from the in-progress `auth_session_id`.
    /// web can't keep these at hand across resume's 303, so an endpoint to refetch them on every render is needed.
    ///
    /// It also returns display names so the login screen can show "where you are logging in"
    /// (the client's `app_name` and the tenant's `name`). The screen can't have this information otherwise, and
    /// without it users would enter credentials without knowing which application of which organization they're entering.
    ///
    /// It returns **only display hints** and doesn't touch the user or consent state (`auth_session_id` is a
    /// bearer credential that can operate the authorization session if presented, but this path only reads).
    pub async fn login_context(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> LoginContextOutcome {
        let Some(auth_session_id) = AuthSessionId::from_presented(auth_session_id) else {
            return LoginContextOutcome::SessionExpired;
        };
        let session = match self
            .auth_sessions
            .find(tenant.tenant_id(), &auth_session_id.hash())
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return LoginContextOutcome::SessionExpired,
            Err(e) => return LoginContextOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(self.clock.now()) {
            return LoginContextOutcome::SessionExpired;
        }
        let request = session.request();
        // Display names are just decoration "shown if available", and login must continue even if they can't be looked up.
        // Even if fetching fails, don't drop the whole context; just leave that field empty.
        let client_name = match self
            .clients
            .find_by_client_id(tenant.tenant_id(), request.client_id())
            .await
        {
            Ok(client) => client.map(|c| c.app_name),
            Err(e) => {
                tracing::warn!(error = %e, "could not read the client name for the login page");
                None
            }
        };
        let tenant_name = match self.tenants.resolve(tenant.tenant_id()).await {
            Ok(t) => t.map(|t| t.name),
            Err(e) => {
                tracing::warn!(error = %e, "could not read the tenant name for the login page");
                None
            }
        };
        LoginContextOutcome::Ok {
            login_hint: request.login_hint().map(str::to_string),
            ui_locales: request.ui_locales().map(str::to_string),
            redirect_uri: request.redirect_uri().to_string(),
            client_name,
            tenant_name,
        }
    }
}

fn non_empty(v: Option<&str>) -> Option<&str> {
    v.filter(|s| !s.is_empty())
}

fn fatal(error: OAuthErrorCode, description: &str) -> AuthorizeOutcome {
    AuthorizeOutcome::FatalError {
        error,
        description: description.to_string(),
    }
}

/// URL returning an `/authorize` failure to `redirect_uri` (`state` passed through).
///
/// ⚠ **Only `/authorize` failures are returned in the query without looking at `response_mode`.** This is where api
/// returns a 302 directly to the browser, and api doesn't render screens (auto-submitting forms; only web renders HTML).
/// What is returned are validation and storage failures, with no code. Failures from resume onward are returned by
/// [`resume_error`] according to `response_mode`.
fn redirect_with_error(
    request: &AuthorizationRequest,
    error: OAuthErrorCode,
    description: &str,
) -> String {
    error_redirect_with_state(
        request.redirect_uri(),
        error,
        description,
        Some(request.state()),
    )
}

/// Returns failures from resume onward to the RP. Like success, follows the requested `response_mode` (the RP waits at the same
/// endpoint. OAuth 2.0 Form Post Response Mode). web returns it with a 302 or an auto-submitting form.
fn resume_error(
    request: &AuthorizationRequest,
    error: OAuthErrorCode,
    description: &str,
) -> ResumeOutcome {
    let dispatch = AuthorizationDispatch::from(request.error_response(error, description));
    ResumeOutcome::ErrorRedirect {
        location: dispatch.location,
        form_post: dispatch.form_post,
    }
}

/// Builds a URL with query parameters added to `redirect_uri`.
///
/// `redirect_uri` has passed the exact match against registered values, but **don't panic here** (SEC12).
/// A single value that slipped past registration-time validation (direct DB edit, a row from older loose validation)
/// would make every authorization request using that RP fail. If it can't be parsed, the query is naively
/// concatenated and returned, so only that RP's configuration is broken.
fn append_query(redirect_uri: &str, pairs: &[(&str, &str)]) -> String {
    if let Ok(mut url) = url::Url::parse(redirect_uri) {
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in pairs {
                query.append_pair(key, value);
            }
        }
        return url.to_string();
    }
    tracing::error!("redirect_uri is not a parsable URL; falling back to query concatenation");
    let encoded: Vec<String> = pairs
        .iter()
        .map(|(key, value)| {
            let value =
                percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC);
            format!("{key}={value}")
        })
        .collect();
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{separator}{}", encoded.join("&"))
}

/// The shape in which the authorization response is put into each use case's outcome (G12).
///
/// `location` is **the complete 302 target URL for `query`, and the form target for `form_post`**
/// (= `redirect_uri` without parameters). When `form_post` is `Some`,
/// the caller renders an auto-submitting form that POSTs hidden fields to `location`.
///
/// The two shapes aren't merged into one type but kept as "URL + optional fields" so the existing path
/// (`query`) needn't be touched. A path that overlooks `form_post` does a 302 to `location`, and
/// the RP gets "a return without a code" and errors ——better to fail visibly than to have the authorization code in the URL
/// left in history and `Referer`.
#[derive(Debug, Clone, Default)]
pub struct AuthorizationDispatch {
    pub location: String,
    /// For `form_post`, the hidden fields to POST (`code` / `state`, or the error).
    pub form_post: Option<Vec<(String, String)>>,
}

impl From<AuthorizationResponse> for AuthorizationDispatch {
    fn from(response: AuthorizationResponse) -> Self {
        Self {
            location: response.location(),
            form_post: response.is_form_post().then(|| response.parameters.clone()),
        }
    }
}

/// Builds `redirect_uri?code=...&state=...` (state passed through, design spec §2.2).
///
/// It doesn't look at `response_mode`, so paths that have the authorization session at hand use
/// [`AuthorizationRequest::success_response`].
pub fn code_redirect(redirect_uri: &str, code: &str, state: &str) -> String {
    append_query(redirect_uri, &[("code", code), ("state", state)])
}

/// Builds `redirect_uri?error=...&error_description=...&state=...` (state optional).
pub fn error_redirect_with_state(
    redirect_uri: &str,
    error: OAuthErrorCode,
    description: &str,
    state: Option<&str>,
) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("error", error.as_str()),
        ("error_description", description),
    ];
    if let Some(state) = state {
        pairs.push(("state", state));
    }
    append_query(redirect_uri, &pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_redirect_urls_with_encoded_query() {
        let location = code_redirect("https://client.example.com/cb?keep=1", "c o+de", "st&ate");
        assert!(location.starts_with("https://client.example.com/cb?keep=1&"));
        assert!(location.contains("code=c+o%2Bde"));
        assert!(location.contains("state=st%26ate"));

        let location = error_redirect_with_state(
            "https://client.example.com/cb",
            OAuthErrorCode::InvalidScope,
            "scope must include `openid`",
            Some("xyz"),
        );
        assert!(location.contains("error=invalid_scope"));
        assert!(location.contains("state=xyz"));
    }
}
