//! Login screen (`GET /login`) and login processing (`POST /login`, design spec §4.3).
//!
//! ADR-0007: web only renders forms and redirects; credential verification and SSO/code issuance are delegated to the api's
//! `POST /internal/authenticate`. web forwards connection origin information (IP from `X-Forwarded-For`, User-Agent),
//! and on success stores the `sso_session_id` returned by the api in a cookie and 302s to `redirect_to`. Errors are
//! localized and re-rendered. CSRF uses a synchronizer token derived from `auth_session_id` (`assay-contracts`),
//! verified by the api's LoginService.
//!
//! Screen wording is managed in `fluent` translation resources (en / ja switched by `Accept-Language`).

use super::{api_internal_error, internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::{LoginForm, LoginPageQuery};
use crate::handlers::{form_retry_error_key, forwarded_context, found, portal, see_other};
use crate::i18n::Messages;
use crate::login_context::RpLoginContext;
use crate::state::WebState;
use crate::templates::{render, LoginTemplate, MessagePage};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAuthenticateRequest, InternalAuthenticateResponse, InternalAuthorizeContinueRequest,
    InternalAuthorizeResumeRequest, InternalAuthorizeResumeResponse,
};
use assay_contracts::csrf::login_csrf_token;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

/// Shows the login form. The OIDC flow continues via the hand-off from the api's `/authorize`
/// (the single-use handle `?auth_session=`; ADR-0018 decision 2) or the host-only `auth_session_id`
/// cookie.
pub async fn login_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    Extension(rp_context): Extension<RpLoginContext>,
    headers: HeaderMap,
    Query(query): Query<LoginPageQuery>,
) -> Response {
    // Hand-off received: immediately exchange the handle via `/internal/authorize/resume` (including the SSO check),
    // move `auth_session_id` into a host-only cookie on our domain and remove it from the URL with a 303.
    if let Some(handle) = query.auth_session.filter(|h| !h.is_empty()) {
        return resume_authorize_handoff(
            &state,
            &correlation,
            &client_ip,
            &tenant,
            &headers,
            handle,
        )
        .await;
    }

    // Error banner when returning via PRG (CSRF mismatch → `?error=csrf`).
    let error_key = form_retry_error_key(query.error.as_deref());

    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        // Direct access without OIDC's `auth_session_id` is treated as the portal login for entering the IdP's own
        // account screen (so `/{tenant_id}/login` can be opened on its own).
        // Note: `Messages` (FluentBundle) is !Send, so it must not be created before crossing an await.
        return portal::login_page(&state, &correlation, &tenant, &headers, error_key).await;
    };
    // Reopened after authenticating in another tab: continue authorization with that SSO session.
    // If it cannot continue (not signed in, `prompt=login` etc.), show the form as usual.
    if let Some(response) = continue_with_sso(
        &state,
        &correlation,
        &client_ip,
        &tenant,
        &headers,
        &auth_session_id,
    )
    .await
    {
        return response;
    }
    let messages = Messages::new(locale(&headers));
    let body = render_form(
        &messages,
        &tenant.prefix(),
        &login_csrf_token(&auth_session_id, state.config.csrf_secret()),
        error_key,
        // Put the authorization request's `login_hint` in the username field (G12). An empty string is not used as the initial value.
        rp_context.login_hint.as_deref().filter(|h| !h.is_empty()),
        // Show on screen which organization of which app is being entered. Display names looked up by the api from registered values;
        // if not found, nothing is shown (not even an empty string).
        display_name(rp_context.client_name.as_deref()),
        display_name(rp_context.tenant_name.as_deref()),
        state.config.app_approver_enabled(),
    );
    // If SSO and consent are in place, submitting the login form ends in a redirect straight to the RP.
    // Chrome applies `form-action` to post-submission redirect targets too, so allow only that RP's origin
    // (SEC3; same situation as the consent screen).
    crate::security_headers::html_with_form_action_csp(
        rp_context.redirect_uri.as_deref().unwrap_or_default(),
        body,
    )
}

/// Resumes the `/authorize` hand-off (ADR-0018 decision 2). web reads our domain's `sso_session_id` and
/// passes it to the api with the single-use handle. If SSO is valid, an RP URL with a code is returned and the flow
/// completes without showing the login screen (same behavior as the SSO restoration the api used to do with cookies).
async fn resume_authorize_handoff(
    state: &WebState,
    correlation: &CorrelationId,
    client_ip: &ClientIp,
    tenant: &WebTenant,
    headers: &HeaderMap,
    handle: String,
) -> Response {
    let ctx = forwarded_context(headers, correlation, client_ip);
    let sso_session_id = cookies::get(headers, cookies::SSO_SESSION_COOKIE);
    let request = InternalAuthorizeResumeRequest {
        tenant_id: Some(tenant.0.clone()),
        handle,
        sso_session_id: sso_session_id.clone(),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authorize_resume(&ctx.correlation_id, &request)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "authorize resume call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    match restored_response(state, tenant, headers, sso_session_id.as_deref(), outcome) {
        Ok(response) => response,
        Err(InternalAuthorizeResumeResponse::LoginRequired { auth_session_id }) => (
            state
                .set_cookies()
                .set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &auth_session_id,
                    state.config.auth_session_ttl_secs(),
                )
                .into_headers(),
            // Switch to our own URL with 303, removing the handle from the address bar and history.
            see_other(&format!("{}/login", tenant.prefix())),
        )
            .into_response(),
        Err(InternalAuthorizeResumeResponse::ExpiredHandle) => {
            // A handle already consumed by a reload etc. If the cookie from the first receipt remains, fall back to the normal display.
            if cookies::get(headers, cookies::AUTH_SESSION_COOKIE).is_some() {
                see_other(&format!("{}/login", tenant.prefix()))
            } else {
                error_page(
                    &Messages::new(locale(headers)),
                    StatusCode::BAD_REQUEST,
                    "login-error-session-expired",
                )
            }
        }
        Err(_) => api_internal_error("authorize_resume"),
    }
}

/// When the login screen is reopened, continue authorization from an SSO session established in another tab.
///
/// Without an SSO cookie at hand, the api is not called. When it cannot continue (not signed in, including api failures)
/// it returns `None` and the caller draws the form — the screen is not broken here (even when hitting an old api without
/// this endpoint during the few seconds of rollover, it just falls back to the usual form).
async fn continue_with_sso(
    state: &WebState,
    correlation: &CorrelationId,
    client_ip: &ClientIp,
    tenant: &WebTenant,
    headers: &HeaderMap,
    auth_session_id: &str,
) -> Option<Response> {
    let sso_session_id =
        cookies::get(headers, cookies::SSO_SESSION_COOKIE).filter(|s| !s.is_empty())?;
    let ctx = forwarded_context(headers, correlation, client_ip);
    let request = InternalAuthorizeContinueRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: auth_session_id.to_string(),
        sso_session_id: Some(sso_session_id.clone()),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authorize_continue(&ctx.correlation_id, &request)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::warn!(error = %e, "authorize continue call to api failed; showing the login form");
            return None;
        }
    };
    restored_response(state, tenant, headers, Some(&sso_session_id), outcome).ok()
}

/// Turns the SSO restoration results that finish without showing the login form (return to the RP, go to consent, refuse)
/// into a response. Results that show the form or start over are returned as is in `Err`, and the caller decides.
fn restored_response(
    state: &WebState,
    tenant: &WebTenant,
    headers: &HeaderMap,
    sso_session_id: Option<&str>,
    outcome: InternalAuthorizeResumeResponse,
) -> Result<Response, InternalAuthorizeResumeResponse> {
    // In a response where SSO restoration succeeded, reissue the local `sso_session_id` as host-only.
    // While `COOKIE_DOMAIN` (cleanup of the old ADR-0012 setup) is set, deletion of the old `Domain`-scoped cookie is sent
    // alongside, so existing sessions that never went through an explicit login/logout also migrate to host-only at silent
    // restoration, closing the exposure of bearer credentials still being sent under the old parent domain (ADR-0018 decision 4).
    let refresh_sso = |set_cookies: crate::cookies::SetCookies, ttl_secs: u64| match sso_session_id
    {
        Some(sso) => set_cookies.set_session(cookies::SSO_SESSION_COOKIE, sso, ttl_secs),
        None => set_cookies,
    };

    let messages = Messages::new(locale(headers));
    let auth_session_ttl = state.config.auth_session_ttl_secs();
    // The 302 back to the RP is allowed even in the round trip tried without showing a screen (hidden frame) (task #888, ADR-0076).
    // Responses that render (auto-submit form, consent, refusal screens) are not framed
    let framed = |mut response: Response| {
        if response.status() == StatusCode::FOUND {
            crate::security_headers::allow_silent_auth_framing(
                &mut response,
                state.config.silent_auth_frame_ancestors(),
            );
        }
        response
    };
    Ok(match outcome {
        // Code already issued by SSO restoration. Clean up the leftover old auth_session cookie and return to the RP.
        InternalAuthorizeResumeResponse::Redirect {
            redirect_to,
            form_post,
            sso_absolute_ttl_secs,
        } => framed(
            (
                refresh_sso(
                    state
                        .set_cookies()
                        .expire_session(cookies::AUTH_SESSION_COOKIE),
                    sso_absolute_ttl_secs,
                )
                .into_headers(),
                crate::authorization_response::respond(&messages, &redirect_to, form_post),
            )
                .into_response(),
        ),
        // An error ending the flow (prompt=none failure etc.). Return the error to the RP.
        InternalAuthorizeResumeResponse::ErrorRedirect {
            redirect_to,
            form_post,
        } => framed(
            (
                state
                    .set_cookies()
                    .expire_session(cookies::AUTH_SESSION_COOKIE)
                    .into_headers(),
                crate::authorization_response::respond(&messages, &redirect_to, form_post),
            )
                .into_response(),
        ),
        InternalAuthorizeResumeResponse::ConsentRequired {
            auth_session_id,
            sso_absolute_ttl_secs,
        } => (
            refresh_sso(
                state.set_cookies().set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &auth_session_id,
                    auth_session_ttl,
                ),
                sso_absolute_ttl_secs,
            )
            .into_headers(),
            see_other(&format!("{}/consent", tenant.prefix())),
        )
            .into_response(),
        // SSO was restored, but use of this app is not permitted (ADR-0054). Do not return to the RP.
        InternalAuthorizeResumeResponse::ApplicationNotPermitted { application_name } => (
            state
                .set_cookies()
                .expire_session(cookies::AUTH_SESSION_COOKIE)
                .into_headers(),
            crate::application_denied::page(&messages, &tenant.prefix(), &application_name),
        )
            .into_response(),
        other => return Err(other),
    })
}

/// Renders the login form HTML from the template. Embedded values (translated wording, CSRF token) are
/// auto-escaped by the template.
#[allow(clippy::too_many_arguments)]
fn render_form(
    messages: &Messages,
    tenant_prefix: &str,
    csrf: &str,
    error_key: Option<&str>,
    login_hint: Option<&str>,
    client_name: Option<&str>,
    tenant_name: Option<&str>,
    app_approval_offered: bool,
) -> String {
    render(&LoginTemplate {
        messages,
        tenant_prefix,
        csrf,
        error_key,
        login_hint,
        client_name,
        tenant_name,
        app_approval_offered,
    })
}

/// Performs login. Calls the api's internal authentication and, on success, issues the SSO cookie and 302s to `redirect_to`.
pub async fn login(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    Extension(rp_context): Extension<RpLoginContext>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);

    // A POST without OIDC's `auth_session_id` is processed as portal login (client-independent).
    if auth_session_id.is_none() {
        return portal::login(&state, &correlation, &client_ip, &tenant, &headers, form).await;
    }

    let request = InternalAuthenticateRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: auth_session_id.clone(),
        username: form.username,
        password: form.password,
        csrf_token: form.csrf_token,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };

    let outcome = match state.api.authenticate(&ctx.correlation_id, &request).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "internal authenticate call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    // FluentBundle is not Send, so create it here so it does not live across an await.
    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalAuthenticateResponse::Success {
            redirect_to,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => {
            // Issue the SSO cookie and expire the short-lived auth_session_id cookie.
            let mut set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            // If the user has a DB language setting, sync it into the lang cookie (MT20: DB > Cookie priority).
            if let Some(lang) = user_language
                .as_deref()
                .and_then(crate::i18n::Locale::from_tag)
            {
                set_cookies = set_cookies.set_local(
                    cookies::LANG_COOKIE,
                    lang.as_tag(),
                    cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
                );
            }
            (
                set_cookies.into_headers(),
                crate::authorization_response::respond(&messages, &redirect_to, form_post),
            )
                .into_response()
        }
        InternalAuthenticateResponse::MfaRequired { auth_session_id } => {
            // Password authenticated, MFA required: keep the auth_session_id cookie and go to the TOTP input screen.
            let set_cookies = state.set_cookies().set_session(
                cookies::AUTH_SESSION_COOKIE,
                &auth_session_id,
                state.config.auth_session_ttl_secs(),
            );
            (
                set_cookies.into_headers(),
                found(&format!("{}/mfa/totp", tenant.prefix())),
            )
                .into_response()
        }
        InternalAuthenticateResponse::PasswordChangeRequired { auth_session_id } => {
            // Password authenticated, forced change required (ADR-0009 §5): keep the auth_session_id cookie and
            // go to the password change screen.
            let set_cookies = state.set_cookies().set_session(
                cookies::AUTH_SESSION_COOKIE,
                &auth_session_id,
                state.config.auth_session_ttl_secs(),
            );
            (
                set_cookies.into_headers(),
                found(&format!("{}/password-change", tenant.prefix())),
            )
                .into_response()
        }
        InternalAuthenticateResponse::SessionExpired => {
            // Clear an expired/invalid auth_session_id here and return to `/login`. Without the cookie the next GET
            // shows the portal login (client-independent), self-healing the state where a leftover abandoned OIDC session
            // cookie keeps end users from entering their own account screen.
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "login failed: auth session expired; clearing cookie and redirecting to /login"
            );
            let set_cookies = state
                .set_cookies()
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            (
                set_cookies.into_headers(),
                found(&format!("{}/login", tenant.prefix())),
            )
                .into_response()
        }
        InternalAuthenticateResponse::CsrfMismatch => {
            // PRG: switch to GET with 303 and automatically re-show the form with a new token derived from the
            // current cookie (previously it just returned an error page, and reloading resent the POST with no recovery).
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "login failed: csrf token mismatch; redirecting to fresh login form"
            );
            see_other(&format!("{}/login?error=csrf", tenant.prefix()))
        }
        InternalAuthenticateResponse::RateLimited => error_page(
            &messages,
            StatusCode::TOO_MANY_REQUESTS,
            "login-error-rate-limited",
        ),
        InternalAuthenticateResponse::InvalidCredentials => reshow_form(
            &messages,
            &tenant.prefix(),
            StatusCode::UNAUTHORIZED,
            auth_session_id.as_deref(),
            "login-error-invalid-credentials",
            state.config.csrf_secret(),
            state.config.app_approver_enabled(),
            &rp_context,
        ),
        InternalAuthenticateResponse::Locked => reshow_form(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            auth_session_id.as_deref(),
            "login-error-locked",
            state.config.csrf_secret(),
            state.config.app_approver_enabled(),
            &rp_context,
        ),
        // Email of a self-registered account not verified (SEC6b). Guide the user to follow the confirmation link.
        InternalAuthenticateResponse::EmailVerificationRequired => error_page(
            &messages,
            StatusCode::FORBIDDEN,
            "login-error-email-not-verified",
        ),
        // Authentication passed, but use of this app is not permitted (ADR-0054). The SSO cookie is issued
        // — the user is signed in to assay, so other apps can proceed as is.
        InternalAuthenticateResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => (
            state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE)
                .into_headers(),
            crate::application_denied::page(&messages, &tenant.prefix(), &application_name),
        )
            .into_response(),
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalAuthenticateResponse::DeviceEnrollmentRequired { ticket } => {
            crate::handlers::device_enrollment::redirect(
                &state,
                &tenant,
                &ticket,
                &format!("{}/login", tenant.prefix()),
            )
        }
        // Denied by the authentication policy. The credentials are verified, so show wording different from a credential error.
        InternalAuthenticateResponse::PolicyDenied => reshow_form(
            &messages,
            &tenant.prefix(),
            StatusCode::FORBIDDEN,
            auth_session_id.as_deref(),
            "login-error-policy-denied",
            state.config.csrf_secret(),
            state.config.app_approver_enabled(),
            &rp_context,
        ),
        // Policy requires MFA but no authenticator (TOTP) is set up. Guide the user to set it up in the portal.
        InternalAuthenticateResponse::MfaEnrollmentRequired => error_page(
            &messages,
            StatusCode::FORBIDDEN,
            "login-error-mfa-enrollment-required",
        ),
        InternalAuthenticateResponse::ConsentRequired {
            auth_session_id: new_auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            // Issue the SSO cookie and set the auth_session_id cookie for the consent screen.
            // auth_session_id is still valid (used on the consent screen), so keep its expiry as is.
            // The concrete TTL is already set by the api, so the existing cookie is overwritten here.
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &new_auth_session_id,
                    state.config.auth_session_ttl_secs(),
                );
            (
                set_cookies.into_headers(),
                found(&format!("{}/consent", tenant.prefix())),
            )
                .into_response()
        }
        InternalAuthenticateResponse::Internal => api_internal_error("authenticate"),
    }
}

/// Picks the display name shown on screen. A whitespace-only name is treated as absent (so that even if an empty string
/// was registered, the heading does not become blank and the identity does not disappear).
fn display_name(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// Re-shows the form with an error (the AuthSession is still valid, so the user can re-enter).
///
/// **Attach the same CSP as the first render.** Leaving the default here would make only resubmission from a form
/// re-shown after a typo unable to return to the RP — users who succeed the first time pass, and only those who
/// mistyped stop silently, a hard-to-find breakage.
#[allow(clippy::too_many_arguments)]
fn reshow_form(
    messages: &Messages,
    tenant_prefix: &str,
    status: StatusCode,
    auth_session_id: Option<&str>,
    error_key: &str,
    csrf_secret: &[u8],
    app_approval_offered: bool,
    rp_context: &RpLoginContext,
) -> Response {
    match auth_session_id {
        Some(id) => (
            status,
            crate::security_headers::html_with_form_action_csp(
                rp_context.redirect_uri.as_deref().unwrap_or_default(),
                render_form(
                    messages,
                    tenant_prefix,
                    &login_csrf_token(id, csrf_secret),
                    Some(error_key),
                    // On re-display `login_hint` is not re-inserted (if the user entered another identifier and failed,
                    // silently reverting to the RP's value would hide that they need to re-enter it).
                    None,
                    // Heading and identity are the same as the first render. If only the mistyped screen lost "where
                    // am I signing in to", the users retrying would lose the clue the most.
                    display_name(rp_context.client_name.as_deref()),
                    display_name(rp_context.tenant_name.as_deref()),
                    app_approval_offered,
                ),
            ),
        )
            .into_response(),
        None => error_page(
            messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        ),
    }
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("login-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
