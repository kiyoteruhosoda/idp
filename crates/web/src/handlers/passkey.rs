//! Passkey (WebAuthn) web handlers.
//!
//! Provides self-registration (`/account/passkey/*`) and login (`/passkey/login/*`).
//! begin/complete are provided as JSON APIs, called from the browser's WebAuthn JS API.
//! List and deletion are provided as HTML forms.
//!
//! Login is called from 3 screens (OIDC authorization flow, admin console, portal). There are 2 begin endpoints,
//! one for the authorization flow (`/passkey/login/begin`; reads the `auth_session_id` cookie) and one for direct login
//! (`/passkey/login/direct/begin`; does not read it), and 3 complete endpoints, one per screen
//! (because the issued cookies and destinations differ).
//!
//! # Where screens lead
//!
//! HTML paths (list, delete) **return to the list instead of creating dedicated result pages** (PRG). Results are
//! shown in a banner above the list via `?saved=` / `?error=`. Same shape as the authenticator management screen
//! (`handlers::authenticators`). Inserting "a single page without a back link" like a deletion completion page
//! leaves the user with nothing but the browser's back button.
//!
//! When not signed in or the session expired, the user is sent to the login screen for the same reason (aligned with
//! other screens under settings).

use super::{api_internal_error, found, internal_call_status, locale, see_other};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::handlers::forwarded_context;
use crate::handlers::step_up::{self, MANAGE_AUTHENTICATORS};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, PasskeyListTemplate, PasskeyRegisterTemplate};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAdminPasskeyLoginCompleteRequest, InternalAdminPasskeyLoginCompleteResponse,
    InternalPasskeyDeleteRequest, InternalPasskeyDeleteResponse, InternalPasskeyListRequest,
    InternalPasskeyListResponse, InternalPasskeyLoginBeginRequest,
    InternalPasskeyLoginCompleteRequest, InternalPasskeyLoginCompleteResponse,
    InternalPasskeyRegisterBeginRequest, InternalPasskeyRegisterBeginResponse,
    InternalPasskeyRegisterCompleteRequest, InternalPasskeyRegisterCompleteResponse,
    InternalPortalPasskeyLoginCompleteRequest, InternalPortalPasskeyLoginCompleteResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::Form;
use serde::{Deserialize, Serialize};

// ─── Registration flow ──────────────────────────────────────────────────────────────

/// List banner display (returning via PRG from deletion).
#[derive(Debug, Deserialize)]
pub struct PasskeyListQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Passkey list page (`GET /account/passkey`). Requires the SSO cookie.
pub async fn list_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<PasskeyListQuery>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    // Seed of the CSRF token embedded in the delete form (task #587).
    let sso_for_form = sso_session_id.clone();
    let req = InternalPasskeyListRequest { sso_session_id };
    let result = match state.api.passkey_list(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey list call failed");
            return internal_call_status(&e).into_response();
        }
    };
    // FluentBundle is !Send, so create it after the await.
    let messages = Messages::new(locale(&headers));
    match result {
        InternalPasskeyListResponse::Ok { credentials } => Html(render(&PasskeyListTemplate {
            messages: &messages,
            tenant_prefix: &tenant.prefix(),
            credentials: &credentials,
            csrf_token: &console_csrf_token(&sso_for_form, state.config.csrf_secret()),
            saved_key: query.saved.as_deref().and_then(saved_key_for),
            error_key: query.error.as_deref().and_then(error_key_for),
        }))
        .into_response(),
        InternalPasskeyListResponse::SessionExpired => found(&format!("{}/login", tenant.prefix())),
        InternalPasskeyListResponse::Internal => api_internal_error("passkey_list"),
    }
}

/// Passkey registration page (`GET /account/passkey/register`). Requires the SSO cookie.
pub async fn register_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    // Adding an authenticator is subject to step-up (AP5; same reason as TOTP setup).
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/passkey/register", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    // Having reached here, the step-up gate has been passed (without SSO the user was sent to the login screen).
    let messages = Messages::new(locale(&headers));
    Html(render(&PasskeyRegisterTemplate {
        messages: &messages,
        tenant_prefix: &tenant.prefix(),
        error_key: None,
    }))
    .into_response()
}

/// Passkey registration begin JSON API (`POST /passkey/register/begin`). Called from JS.
/// On success: HTTP 200 `{ "result": "ok", "challenge_id": "...", "options": {...} }`
/// On failure: HTTP 401 / 500
#[derive(Debug, Deserialize)]
pub struct RegisterBeginBody {
    pub name: String,
}

pub async fn register_begin_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<RegisterBeginBody>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Subject to step-up like the screen (AP5). **The screen gate alone cannot protect it**: what actually creates
    // the authenticator is this JSON endpoint, which a caller with the cookie can hit directly without the screen.
    if let Err(response) = step_up::require_step_up_api(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/passkey/register", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    // user_name is the name shown on the authenticator. It cannot be obtained from the SSO session, so the entered name is used.
    let req = InternalPasskeyRegisterBeginRequest {
        sso_session_id,
        user_name: body.name.clone(),
    };
    let result = match state.api.passkey_register_begin(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey register begin failed");
            return internal_call_status(&e).into_response();
        }
    };
    match result {
        InternalPasskeyRegisterBeginResponse::Ok { .. } => Json(result).into_response(),
        InternalPasskeyRegisterBeginResponse::SessionExpired => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        InternalPasskeyRegisterBeginResponse::Internal => {
            api_internal_error("passkey_register_begin")
        }
    }
}

/// Passkey registration complete JSON API (`POST /passkey/register/complete`). Called from JS.
/// On success: HTTP 200 `{ "result": "ok", "credential_id": "..." }`
/// On failure: HTTP 200 with an error variant, or 401 / 500
#[derive(Debug, Deserialize)]
pub struct RegisterCompleteBody {
    pub challenge_id: String,
    pub name: String,
    pub credential: serde_json::Value,
}

pub async fn register_complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<RegisterCompleteBody>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Subject to step-up like the screen (AP5). **The screen gate alone cannot protect it**: what actually creates
    // the authenticator is this JSON endpoint, which a caller with the cookie can hit directly without the screen.
    if let Err(response) = step_up::require_step_up_api(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/passkey/register", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let req = InternalPasskeyRegisterCompleteRequest {
        sso_session_id,
        challenge_id: body.challenge_id,
        name: body.name,
        credential: body.credential,
    };
    let result = match state
        .api
        .passkey_register_complete(&correlation.0, &req)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey register complete failed");
            return internal_call_status(&e).into_response();
        }
    };
    match result {
        InternalPasskeyRegisterCompleteResponse::Internal => {
            api_internal_error("passkey_register_complete")
        }
        InternalPasskeyRegisterCompleteResponse::SessionExpired => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        _ => Json(result).into_response(),
    }
}

/// Passkey deletion (`POST /account/passkey/delete`). Called from an HTML form.
///
/// Like TOTP deletion, requires the CSRF synchronizer token (task #587). SameSite=Lax alone cannot stop POSTs
/// from another subdomain of the same site (`*.nolumia.com`).
#[derive(Deserialize)]
pub struct DeleteForm {
    pub credential_id: String,
    #[serde(default)]
    pub csrf_token: String,
}

pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Response {
    let list = format!("{}/account/passkey", tenant.prefix());
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
    };
    // On mismatch do nothing, return to the list and report with the `?error=csrf` banner (checked before step-up).
    if !console_csrf_valid(
        &sso_session_id,
        &form.csrf_token,
        state.config.csrf_secret(),
    ) {
        tracing::warn!("passkey deletion rejected: csrf token mismatch");
        return see_other(&format!("{list}?error=csrf"));
    }
    // Deleting an authenticator is subject to step-up (AP5).
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/passkey", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let req = InternalPasskeyDeleteRequest {
        sso_session_id,
        credential_id: form.credential_id,
    };
    let result = match state.api.passkey_delete(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey delete failed");
            return internal_call_status(&e).into_response();
        }
    };
    match result {
        // Return to the list and report the result in a banner (the remaining passkeys can be checked on the spot).
        InternalPasskeyDeleteResponse::Ok => see_other(&format!("{list}?saved=deleted")),
        InternalPasskeyDeleteResponse::NotFound => see_other(&format!("{list}?error=not-found")),
        InternalPasskeyDeleteResponse::SessionExpired => {
            found(&format!("{}/login", tenant.prefix()))
        }
        InternalPasskeyDeleteResponse::Internal => api_internal_error("passkey_delete"),
    }
}

// ─── Login flow ──────────────────────────────────────────────────────────

/// Passkey authentication begin JSON API (`POST /passkey/login/begin`). Called from the login screen's JS.
/// On success: HTTP 200 `{ "result": "ok", "challenge_id": "...", "options": {...} }`
pub async fn login_begin_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);
    begin(&state, &correlation, auth_session_id).await
}

/// Passkey authentication begin JSON API for direct login (admin console, portal)
/// (`POST /passkey/login/direct/begin`).
///
/// **It is separate from the authorization flow one so that it does not read the `auth_session_id` cookie.** If a cookie
/// of an authorization flow started and abandoned in another tab remains, a shared begin API would return a challenge
/// for the authorization flow, and the direct login complete API would reject it as the wrong purpose (no entry to the admin
/// console until the cookie expires). The endpoint expresses the fact that "this screen is not a continuation of
/// an authorization flow".
pub async fn direct_login_begin_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
) -> Response {
    begin(&state, &correlation, None).await
}

async fn begin(
    state: &WebState,
    correlation: &CorrelationId,
    auth_session_id: Option<String>,
) -> Response {
    let req = InternalPasskeyLoginBeginRequest { auth_session_id };
    let result = match state.api.passkey_login_begin(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey login begin failed");
            return internal_call_status(&e).into_response();
        }
    };
    Json(result).into_response()
}

/// Passkey authentication complete JSON API (`POST /passkey/login/complete`). Called from JS.
/// On success returns `{ redirect_to: "..." }`, and JS redirects.
/// On failure returns `{ error: "..." }`.
#[derive(Debug, Deserialize)]
pub struct LoginCompleteBody {
    pub challenge_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct LoginCompleteJsonResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    /// With `response_mode=form_post`, the hidden fields to POST to `redirect_to` (G12).
    ///
    /// Only passkey login responds with JSON (received by browser JS), so unlike other paths it cannot
    /// render an auto-submit form on the server. The fields are passed as is and **JS builds and submits
    /// the form** (`assets/passkey-login.js`). When `None`, it navigates to `redirect_to`
    /// as before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_post: Option<assay_contracts::auth::FormPostFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn login_complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<LoginCompleteBody>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let req = InternalPasskeyLoginCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        challenge_id: body.challenge_id,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .passkey_login_complete(&ctx.correlation_id, &req)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "passkey login complete call failed");
            return internal_call_status(&e).into_response();
        }
    };

    match outcome {
        InternalPasskeyLoginCompleteResponse::Success {
            redirect_to,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            (
                set_cookies.into_headers(),
                Json(LoginCompleteJsonResponse {
                    redirect_to: Some(redirect_to),
                    form_post,
                    error: None,
                }),
            )
                .into_response()
        }
        InternalPasskeyLoginCompleteResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &auth_session_id,
                    state.config.auth_session_ttl_secs(),
                );
            (
                set_cookies.into_headers(),
                Json(LoginCompleteJsonResponse {
                    redirect_to: Some(format!("{}/consent", tenant.prefix())),
                    // The consent screen is web's own screen, so the authorization response's form_post is not attached.
                    form_post: None,
                    error: None,
                }),
            )
                .into_response()
        }
        InternalPasskeyLoginCompleteResponse::ChallengeNotFound => {
            Json(LoginCompleteJsonResponse {
                redirect_to: None,
                form_post: None,
                error: Some("challenge_not_found".to_string()),
            })
            .into_response()
        }
        InternalPasskeyLoginCompleteResponse::SessionExpired => Json(LoginCompleteJsonResponse {
            redirect_to: None,
            form_post: None,
            error: Some("session_expired".to_string()),
        })
        .into_response(),
        InternalPasskeyLoginCompleteResponse::InvalidCredential => {
            Json(LoginCompleteJsonResponse {
                redirect_to: None,
                form_post: None,
                error: Some("invalid_credential".to_string()),
            })
            .into_response()
        }
        // Authentication passed, but use of this app is not permitted (ADR-0054).
        //
        // Only this path responds with JSON (received by browser JS), so unlike the other 6 paths it cannot return
        // a refusal **page**. The wording is shown on the login screen — which app it concerns is already shown by
        // that screen's heading (`login-title-for-client`).
        // The SSO cookie is issued (the user is signed in to assay, so other apps can proceed as is).
        InternalPasskeyLoginCompleteResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            tracing::info!(
                application = %application_name,
                "passkey login blocked: the user is not assigned to the application"
            );
            (
                state
                    .set_cookies()
                    .set_session(
                        cookies::SSO_SESSION_COOKIE,
                        &sso_session_id,
                        sso_absolute_ttl_secs,
                    )
                    .expire_session(cookies::AUTH_SESSION_COOKIE)
                    .into_headers(),
                Json(LoginCompleteJsonResponse {
                    redirect_to: None,
                    form_post: None,
                    error: Some("application_not_permitted".to_string()),
                }),
            )
                .into_response()
        }
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalPasskeyLoginCompleteResponse::DeviceEnrollmentRequired { ticket } => (
            crate::handlers::device_enrollment::ticket_cookie(&state, &ticket).into_headers(),
            Json(login_redirect(
                &crate::handlers::device_enrollment::enrollment_location(
                    &tenant,
                    &format!("{}/login", tenant.prefix()),
                ),
            )),
        )
            .into_response(),
        // Denied by the authentication policy. The front-end script maps this code to a translation key.
        InternalPasskeyLoginCompleteResponse::PolicyDenied => Json(LoginCompleteJsonResponse {
            redirect_to: None,
            form_post: None,
            error: Some("policy_denied".to_string()),
        })
        .into_response(),
        InternalPasskeyLoginCompleteResponse::RateLimited => Json(LoginCompleteJsonResponse {
            redirect_to: None,
            form_post: None,
            error: Some("rate_limited".to_string()),
        })
        .into_response(),
        InternalPasskeyLoginCompleteResponse::Internal => {
            api_internal_error("passkey_login_complete")
        }
    }
}

/// Admin console passkey login complete JSON API (`POST /{tenant_id}/passkey/login/admin/complete`).
///
/// Unlike the authorization flow's `login_complete_api`, the returned `redirect_to` is the admin console home, not the RP
/// (no `form_post` either, since there is no authorization response to return to an RP).
pub async fn admin_login_complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<LoginCompleteBody>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let req = InternalAdminPasskeyLoginCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        challenge_id: body.challenge_id,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .passkey_login_admin_complete(&ctx.correlation_id, &req)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "admin passkey login complete call failed");
            return internal_call_status(&e).into_response();
        }
    };

    match outcome {
        InternalAdminPasskeyLoginCompleteResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            // Like the password path (`admin_console::login`), set up SSO and discard the CSRF seed.
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_local(&state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE));
            (
                set_cookies.into_headers(),
                Json(login_redirect(&super::admin_console::admin_home_path(
                    &tenant,
                ))),
            )
                .into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::ChallengeNotFound => {
            Json(login_error("challenge_not_found")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::InvalidCredential => {
            Json(login_error("invalid_credential")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::Forbidden => {
            Json(login_error("forbidden")).into_response()
        }
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalAdminPasskeyLoginCompleteResponse::DeviceEnrollmentRequired { ticket } => (
            crate::handlers::device_enrollment::ticket_cookie(&state, &ticket).into_headers(),
            Json(login_redirect(
                &crate::handlers::device_enrollment::enrollment_location(
                    &tenant,
                    &super::admin_console::admin_home_path(&tenant),
                ),
            )),
        )
            .into_response(),
        InternalAdminPasskeyLoginCompleteResponse::PolicyDenied => {
            Json(login_error("policy_denied")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::RateLimited => {
            Json(login_error("rate_limited")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::Internal => {
            api_internal_error("admin_passkey_login_complete")
        }
    }
}

/// Portal passkey login complete JSON API (`POST /{tenant_id}/passkey/login/portal/complete`).
///
/// Destination and cookie building go through the same decisions as the password path (SAML continuation, display language sync)
/// (`portal::sso_success_parts`). A 302 cannot be returned, so the result is put in the JSON `redirect_to`.
pub async fn portal_login_complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<LoginCompleteBody>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let req = InternalPortalPasskeyLoginCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        challenge_id: body.challenge_id,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .passkey_login_portal_complete(&ctx.correlation_id, &req)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "portal passkey login complete call failed");
            return internal_call_status(&e).into_response();
        }
    };

    match outcome {
        InternalPortalPasskeyLoginCompleteResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => {
            let (set_cookies, destination) = super::portal::sso_success_parts(
                &state,
                &headers,
                &sso_session_id,
                sso_absolute_ttl_secs,
                user_language.as_deref(),
                &tenant,
                &[cookies::PORTAL_CSRF_COOKIE],
            );
            (
                set_cookies.into_headers(),
                Json(login_redirect(&destination)),
            )
                .into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::ChallengeNotFound => {
            Json(login_error("challenge_not_found")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::InvalidCredential => {
            Json(login_error("invalid_credential")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::EmailVerificationRequired => {
            Json(login_error("email_verification_required")).into_response()
        }
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalPortalPasskeyLoginCompleteResponse::DeviceEnrollmentRequired { ticket } => (
            crate::handlers::device_enrollment::ticket_cookie(&state, &ticket).into_headers(),
            Json(login_redirect(
                &crate::handlers::device_enrollment::enrollment_location(
                    &tenant,
                    &super::portal::portal_destination(&state, &headers, &tenant),
                ),
            )),
        )
            .into_response(),
        InternalPortalPasskeyLoginCompleteResponse::PolicyDenied => {
            Json(login_error("policy_denied")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::RateLimited => {
            Json(login_error("rate_limited")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::Internal => {
            api_internal_error("portal_passkey_login_complete")
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Success response of direct login (admin console, portal). JS navigates to this `redirect_to`.
fn login_redirect(destination: &str) -> LoginCompleteJsonResponse {
    LoginCompleteJsonResponse {
        redirect_to: Some(destination.to_string()),
        form_post: None,
        error: None,
    }
}

/// Failure response of direct login. `code` is mapped to a translation key by the front-end script (web owns the wording).
fn login_error(code: &str) -> LoginCompleteJsonResponse {
    LoginCompleteJsonResponse {
        redirect_to: None,
        form_post: None,
        error: Some(code.to_string()),
    }
}

/// List banner (success). The only value is `?saved=` set by the deletion PRG.
fn saved_key_for(value: &str) -> Option<&'static str> {
    match value {
        "deleted" => Some("passkey-deleted-message"),
        _ => None,
    }
}

/// List banner (failure). Unknown values show nothing (URL strings are not put on screen).
fn error_key_for(value: &str) -> Option<&'static str> {
    match value {
        "not-found" => Some("passkey-error-not-found"),
        "csrf" => Some("passkey-error-csrf"),
        _ => None,
    }
}
