//! Browser path of external IdP login (web. AP10).
//!
//! - `GET /{tenant_id}/external/{provider}/start` — has the api build the authorization URL and 302s to the external IdP.
//! - `GET /{tenant_id}/external/{provider}/callback` — where the external IdP returns. Has the api verify it and,
//!   on success, issues the SSO cookie and sends the user to the return destination.
//!
//! If it came from the middle of an OIDC authorization flow, continuing it (consent check, code issuance) is also the api's job;
//! web just 302s to the returned destination. The authorization request parameters (`client_id`, `redirect_uri`,
//! PKCE, `nonce`) exist only in the api's auth_session, so web has no way to build it.
//!
//! Generating and verifying `state` / `nonce` / PKCE all happen on the api side (progress state in the DB). web only builds
//! cookies and handles screen transitions (same split of duties as other login paths). **`state` is not put in a cookie**
//! for the same reason as ADR-0018 (the api does not read browser cookies); the design uses only the `state` value
//! returned from the external IdP as the key.
//!
//! ⚠ **However, `state` alone cannot identify the browser** (it travels in the URL via the external IdP, so an
//! attacker can make someone else follow a return URL the attacker started. Login CSRF. task #581).
//! So at start a one-time value returned by the api is placed in a cookie ([`cookies::EXTERNAL_LOGIN_BINDING_COOKIE`])
//! and passed to the api at the return endpoint. The api checks it; web only carries it.

use super::{api_internal_error, internal_call_status};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::handlers::{forwarded_context, found, locale};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, MessagePage};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalExternalCallbackRequest, InternalExternalCallbackResponse,
    InternalExternalStartRequest, InternalExternalStartResponse,
};
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

/// Query returned from the external IdP (`code` + `state` on success, `error` on failure).
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// Error code when the external IdP refused (e.g. the user did not consent).
    #[serde(default)]
    pub error: Option<String>,
}

/// Starts external IdP login (`GET /{tenant_id}/external/{provider}/start`).
pub async fn start(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, provider_code)): Path<(String, String)>,
) -> Response {
    // If it came from the middle of an OIDC authorization flow, carry over `auth_session_id` (used to decide the return destination).
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);
    let request = InternalExternalStartRequest {
        tenant_id: Some(tenant.0.clone()),
        provider_code,
        auth_session_id,
    };
    match state.api.external_start(&correlation.0, &request).await {
        Ok(InternalExternalStartResponse::Redirect {
            location,
            browser_binding,
        }) => {
            let Some(browser_binding) = browser_binding else {
                // Old api (returns no value). It would always be refused at the return endpoint, so stop here.
                tracing::error!("external idp start returned no browser binding");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            (
                state
                    .set_cookies()
                    .set_cross_site_local(
                        &state.origin_bound_cookie(cookies::EXTERNAL_LOGIN_BINDING_COOKIE),
                        &browser_binding,
                        cookies::EXTERNAL_LOGIN_BINDING_MAX_AGE_SECS,
                    )
                    .into_headers(),
                found(&location),
            )
                .into_response()
        }
        Ok(InternalExternalStartResponse::ProviderUnavailable) => {
            let messages = Messages::new(locale(&headers));
            message_page(
                &messages,
                "external-login-error-unavailable",
                StatusCode::NOT_FOUND,
            )
        }
        Ok(InternalExternalStartResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "external idp start call to api failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// Callback from the external IdP (`GET /{tenant_id}/external/{provider}/callback`).
pub async fn callback(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let locale = locale(&headers);

    // The external IdP refused (e.g. the user did not consent). The error code is not shown on screen
    // (showing the external IdP's vocabulary as is does not help users, and the value comes from outside).
    if let Some(error) = query.error.as_deref() {
        tracing::info!(
            correlation_id = %correlation.0,
            external_error = %error,
            "external idp returned an error to the callback"
        );
        let messages = Messages::new(locale);
        return message_page(
            &messages,
            "external-login-error-denied",
            StatusCode::FORBIDDEN,
        );
    }

    let (Some(code), Some(external_state)) = (query.code, query.state) else {
        let messages = Messages::new(locale);
        return message_page(
            &messages,
            "external-login-error-invalid",
            StatusCode::BAD_REQUEST,
        );
    };

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalExternalCallbackRequest {
        tenant_id: Some(tenant.0.clone()),
        state: external_state,
        code,
        browser_binding: browser_binding(&state, &headers),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .external_callback(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "external idp callback call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    render_outcome(&state, &tenant, &headers, locale, outcome)
}

/// Reads the value placed at start ([`cookies::EXTERNAL_LOGIN_BINDING_COOKIE`]).
fn browser_binding(state: &WebState, headers: &HeaderMap) -> Option<String> {
    cookies::get(
        headers,
        &state.origin_bound_cookie(cookies::EXTERNAL_LOGIN_BINDING_COOKIE),
    )
}

/// Receives the assertion an external SAML IdP POSTs via the browser (ACS. AP12).
///
/// No validation whatsoever — verifying the `SAMLResponse` signature is on the api side; web only carries it
/// (web touches neither sqlx nor keys. ADR-0007).
pub async fn saml_acs(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<SamlAcsForm>,
) -> Response {
    let locale = locale(&headers);
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = assay_contracts::auth::InternalExternalSamlAcsRequest {
        tenant_id: Some(tenant.0.clone()),
        saml_response: form.saml_response,
        relay_state: form.relay_state.unwrap_or_default(),
        browser_binding: browser_binding(&state, &headers),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .external_saml_acs(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "external saml acs call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    render_outcome(&state, &tenant, &headers, locale, outcome)
}

/// Form received by the ACS (HTTP-POST binding). `RelayState` is optional per spec, but assay
/// always includes it at start (without it the progress state cannot be looked up, so it fails on the spot).
#[derive(Debug, serde::Deserialize)]
pub struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// Turns a return from the external IdP (OIDC callback / SAML ACS) into a screen or redirect.
///
/// **Not split by protocol.** Even though the way of confirming "who was authenticated" differs, what follows
/// (issuing cookies, leading to the consent screen, presenting failures) should be the same; splitting it would
/// produce states where only one side is fixed.
fn render_outcome(
    state: &WebState,
    tenant: &WebTenant,
    headers: &HeaderMap,
    locale: Locale,
    outcome: InternalExternalCallbackResponse,
) -> Response {
    // The start value is single-use. Delete it regardless of the result (the api-side progress state is consumed too).
    (
        state
            .set_cookies()
            .expire_cross_site_local(
                &state.origin_bound_cookie(cookies::EXTERNAL_LOGIN_BINDING_COOKIE),
            )
            .into_headers(),
        render_callback_result(state, tenant, headers, locale, outcome),
    )
        .into_response()
}

fn render_callback_result(
    state: &WebState,
    tenant: &WebTenant,
    headers: &HeaderMap,
    locale: Locale,
    outcome: InternalExternalCallbackResponse,
) -> Response {
    let messages = Messages::new(locale);
    match outcome {
        InternalExternalCallbackResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            redirect_to,
            form_post,
            user_language,
        } => {
            let mut set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                // If it went as far as authorization, the auth_session was used up on the api side. When coming from
                // outside authorization, there is no reason to keep this cookie either.
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            // If the user has a DB language setting, sync it into the lang cookie (MT20: DB > Cookie).
            if let Some(lang) = user_language.as_deref().and_then(Locale::from_tag) {
                set_cookies = set_cookies.set_local(
                    cookies::LANG_COOKIE,
                    lang.as_tag(),
                    cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
                );
            }
            // If it came from the middle of an OIDC authorization flow, send to the api-built `redirect_uri` with the code
            // (the authorization request parameters exist only in the api's auth_session, so web
            // cannot build it). Otherwise go to the account screen.
            // Outside an authorization flow (linking started from account settings), web decides the return destination.
            // In that case `form_post` is not attached (it is not an authorization response).
            let destination =
                redirect_to.unwrap_or_else(|| format!("{}/settings", tenant.prefix()));
            (
                set_cookies.into_headers(),
                crate::authorization_response::respond(&messages, &destination, form_post),
            )
                .into_response()
        }
        InternalExternalCallbackResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => {
            let mut set_cookies = state
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
            if let Some(lang) = user_language.as_deref().and_then(Locale::from_tag) {
                set_cookies = set_cookies.set_local(
                    cookies::LANG_COOKIE,
                    lang.as_tag(),
                    cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
                );
            }
            (
                set_cookies.into_headers(),
                found(&format!("{}/consent", tenant.prefix())),
            )
                .into_response()
        }
        InternalExternalCallbackResponse::StateExpired => message_page(
            &messages,
            "external-login-error-expired",
            StatusCode::BAD_REQUEST,
        ),
        InternalExternalCallbackResponse::NotLinked => message_page(
            &messages,
            "external-login-error-not-linked",
            StatusCode::FORBIDDEN,
        ),
        InternalExternalCallbackResponse::UserUnavailable => message_page(
            &messages,
            "login-error-invalid-credentials",
            StatusCode::FORBIDDEN,
        ),
        // Authentication at the external IdP succeeded, but use of this app is not permitted (ADR-0054).
        InternalExternalCallbackResponse::ApplicationNotPermitted {
            application_name,
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => {
            let mut set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            if let Some(lang) = user_language.as_deref().and_then(Locale::from_tag) {
                set_cookies = set_cookies.set_local(
                    cookies::LANG_COOKIE,
                    lang.as_tag(),
                    cookies::PREFERENCE_COOKIE_MAX_AGE_SECS,
                );
            }
            (
                set_cookies.into_headers(),
                crate::application_denied::page(&messages, &tenant.prefix(), &application_name),
            )
                .into_response()
        }
        // Organization limited to registered devices, and this device is not registered (task #916). Place the ticket and go to enrollment.
        InternalExternalCallbackResponse::DeviceEnrollmentRequired { ticket } => {
            // In the middle of an authorization flow, go to the login screen (reopening continues from the SSO created after enrollment).
            let next = if cookies::get(headers, cookies::AUTH_SESSION_COOKIE).is_some() {
                format!("{}/login", tenant.prefix())
            } else {
                crate::handlers::portal::portal_destination(state, headers, tenant)
            };
            crate::handlers::device_enrollment::redirect(state, tenant, &ticket, &next)
        }
        InternalExternalCallbackResponse::PolicyDenied => message_page(
            &messages,
            "login-error-policy-denied",
            StatusCode::FORBIDDEN,
        ),
        InternalExternalCallbackResponse::ExternalFailure => message_page(
            &messages,
            "external-login-error-failed",
            StatusCode::BAD_GATEWAY,
        ),
        InternalExternalCallbackResponse::Internal => api_internal_error("external_callback"),
    }
}

fn message_page(messages: &Messages, key: &str, status: StatusCode) -> Response {
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("external-login-title"),
        message: messages.get(key),
    });
    (status, Html(body)).into_response()
}
