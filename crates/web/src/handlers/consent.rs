//! Consent screen (`GET /consent`) and consent processing (`POST /consent`, F3).
//!
//! ADR-0007: web only renders forms and redirects; recording consent and issuing codes is delegated to the api's
//! `/internal/consent-info`, `/internal/consent/approve` and `/internal/consent/deny`.

use super::{api_internal_error, internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::ConsentForm;
use crate::handlers::{forwarded_context, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConsentTemplate, MessagePage};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalConsentApproveRequest, InternalConsentApproveResponse, InternalConsentDenyRequest,
    InternalConsentDenyResponse, InternalConsentInfoResponse,
};
use assay_contracts::csrf::consent_csrf_token;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

/// Shows the consent screen. Requires the `auth_session_id` cookie (a host-only cookie issued by web on
/// receiving the `/authorize` hand-off or on successful login; ADR-0018 decision 2).
pub async fn consent_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "consent-error-session-expired",
        );
    };

    // FluentBundle is not Send, so create it here so it does not live across an await.
    let result = state
        .api
        .consent_info(&correlation.0, &tenant.0, &auth_session_id)
        .await;
    let messages = Messages::new(locale(&headers));

    match result {
        Ok(InternalConsentInfoResponse::Ok {
            auth_session_id: session_id,
            client_name,
            client_id: _,
            requested_scopes,
            redirect_uri,
        }) => {
            let csrf = consent_csrf_token(&session_id, state.config.csrf_secret());
            let body = render(&ConsentTemplate {
                messages: &messages,
                csrf: &csrf,
                auth_session_id: &session_id,
                client_name: &client_name,
                requested_scopes: &requested_scopes,
            });
            // Submitting consent ends with a 302 to the RP's `redirect_uri`. Chrome applies `form-action`
            // to post-submission redirect targets too, so allow only that origin (SEC3).
            // Without this, the browser cannot return to the RP even though consent and code issuance succeeded.
            // `None` means an old api (a few seconds during rollover). Render without the allowance — the navigation
            // is blocked, but the consent screen itself is shown.
            crate::security_headers::html_with_form_action_csp(
                redirect_uri.as_deref().unwrap_or_default(),
                body,
            )
        }
        Ok(InternalConsentInfoResponse::SessionExpired) => error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "consent-error-session-expired",
        ),
        Err(e) => {
            tracing::error!(error = %e, "consent_page: api call failed");
            internal_call_status(&e).into_response()
        }
    }
}

/// Processes the consent form. `action` = `approve` grants consent, `deny` denies it.
pub async fn consent(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);

    // Consent applies to the **`auth_session_id` cookie**, not the form value (SEC12).
    // Since it used to work from the form value alone, an attacker could plant the id of an authorization session
    // they prepared into a form and make the victim's browser show "consent to the attacker's flow".
    // The cookie is authoritative; the form value is accepted only if it matches (closing the mix-up that
    // exploited having two paths carrying the value).
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "consent-error-session-expired",
        );
    };
    if !assay_contracts::csrf::verify(&auth_session_id, &form.auth_session_id) {
        tracing::warn!(
            correlation_id = %ctx.correlation_id,
            "consent rejected: form auth_session_id does not match the cookie"
        );
        return see_other(&format!("{}/consent", tenant.prefix()));
    }

    // CSRF check (done first so FluentBundle is not used before an await).
    let expected_csrf = consent_csrf_token(&auth_session_id, state.config.csrf_secret());
    if !assay_contracts::csrf::verify(&expected_csrf, &form.csrf_token) {
        // PRG: switch to the consent screen's GET with 303 and automatically re-show the form with a new token
        //(previously it just returned an error page, and reloading resent the POST with no recovery).
        tracing::warn!(
            correlation_id = %ctx.correlation_id,
            "consent failed: csrf token mismatch; redirecting to fresh consent form"
        );
        return see_other(&format!("{}/consent", tenant.prefix()));
    }

    if form.action == "approve" {
        let req = InternalConsentApproveRequest {
            tenant_id: Some(tenant.0.clone()),
            auth_session_id: auth_session_id.clone(),
            ip_address: ctx.ip_address,
            user_agent: ctx.user_agent,
        };
        let result = state.api.consent_approve(&ctx.correlation_id, &req).await;
        let messages = Messages::new(locale(&headers));
        match result {
            Ok(InternalConsentApproveResponse::Success {
                redirect_to,
                form_post,
            }) => {
                let set_cookies = state
                    .set_cookies()
                    .expire_session(cookies::AUTH_SESSION_COOKIE);
                (
                    set_cookies.into_headers(),
                    crate::authorization_response::respond(&messages, &redirect_to, form_post),
                )
                    .into_response()
            }
            // Consent was granted, but use of this app is not permitted (ADR-0054).
            // Drop the auth_session cookie and refuse on an assay screen.
            Ok(InternalConsentApproveResponse::ApplicationNotPermitted { application_name }) => (
                state
                    .set_cookies()
                    .expire_session(cookies::AUTH_SESSION_COOKIE)
                    .into_headers(),
                crate::application_denied::page(&messages, &tenant.prefix(), &application_name),
            )
                .into_response(),
            Ok(InternalConsentApproveResponse::SessionExpired) => error_page(
                &messages,
                StatusCode::BAD_REQUEST,
                "consent-error-session-expired",
            ),
            Ok(InternalConsentApproveResponse::Internal) | Err(_) => {
                api_internal_error("consent_approve")
            }
        }
    } else {
        // deny
        let req = InternalConsentDenyRequest {
            tenant_id: Some(tenant.0.clone()),
            auth_session_id: auth_session_id.clone(),
            ip_address: ctx.ip_address,
            user_agent: ctx.user_agent,
        };
        let result = state.api.consent_deny(&ctx.correlation_id, &req).await;
        let messages = Messages::new(locale(&headers));
        match result {
            Ok(InternalConsentDenyResponse::Ok {
                redirect_to,
                form_post,
            }) => {
                let set_cookies = state
                    .set_cookies()
                    .expire_session(cookies::AUTH_SESSION_COOKIE);
                (
                    set_cookies.into_headers(),
                    crate::authorization_response::respond(&messages, &redirect_to, form_post),
                )
                    .into_response()
            }
            Ok(InternalConsentDenyResponse::SessionExpired) => error_page(
                &messages,
                StatusCode::BAD_REQUEST,
                "consent-error-session-expired",
            ),
            Ok(InternalConsentDenyResponse::Internal) | Err(_) => {
                api_internal_error("consent_deny")
            }
        }
    }
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("consent-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
