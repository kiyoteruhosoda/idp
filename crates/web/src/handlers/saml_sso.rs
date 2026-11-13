//! SAML SSO continuation screen (`GET /{tenant_id}/saml/continue`).
//!
//! Receives the hand-off from the api's `/{tenant_id}/saml/sso` (same scheme as OIDC's `/login?auth_session=`;
//! ADR-0018 decision 2). Forwards the handle (first time) or the `saml_request_id` cookie (returning after login) and
//! our domain's host-only `sso_session_id` cookie to `/internal/saml/resume`, then
//!
//! - if SSO is valid, renders a form that auto-POSTs the signed `SAMLResponse` to the SP's ACS
//!   (the target is an external origin, so a CSP allowing only the ACS origin in `form-action` is attached)
//! - if authentication is needed, stores `saml_request_id` as a host-only cookie and 303s to the portal login
//!   (on successful login, [`super::portal`] returns to this screen)

use super::{api_internal_error, internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::SamlContinueQuery;
use crate::handlers::{forwarded_context, see_other};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, MessagePage, SamlPostPage};
use crate::tenant::WebTenant;
use assay_contracts::auth::{InternalSamlResumeRequest, InternalSamlResumeResponse};
use axum::extract::{Extension, Query, State};
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};

pub async fn continue_sso(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SamlContinueQuery>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let handle = query.handle.filter(|h| !h.is_empty());
    let saml_request_id = cookies::get(
        &headers,
        &state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE),
    );
    if handle.is_none() && saml_request_id.is_none() {
        // Direct access, neither via the hand-off nor a return.
        let messages = Messages::new(locale(&headers));
        return expired_page(&messages);
    }

    let request = InternalSamlResumeRequest {
        tenant_id: Some(tenant.0.clone()),
        handle,
        saml_request_id,
        sso_session_id: cookies::get(&headers, cookies::SSO_SESSION_COOKIE),
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state.api.saml_resume(&ctx.correlation_id, &request).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "SAML resume call to api failed");
            return internal_call_status(&e).into_response();
        }
    };

    // FluentBundle is not Send, so create it after the api await.
    let messages = Messages::new(locale(&headers));
    match outcome {
        InternalSamlResumeResponse::Completed {
            acs_url,
            saml_response,
            relay_state,
        } => {
            let body = render(&SamlPostPage {
                messages: &messages,
                acs_url: &acs_url,
                saml_response: &saml_response,
                relay_state: relay_state.as_deref(),
            });
            (
                StatusCode::OK,
                [(CONTENT_SECURITY_POLICY, acs_form_action_csp(&acs_url))],
                state
                    .set_cookies()
                    .expire_local(&state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE))
                    .into_headers(),
                Html(body),
            )
                .into_response()
        }
        InternalSamlResumeResponse::LoginRequired { saml_request_id } => {
            // Store the progress state id in a cookie and go to the portal login. The TTL matches the api-side
            // progress state's auth_session TTL. 303 removes the handle from the URL and history.
            let set_cookies = state.set_cookies().set_local(
                &state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE),
                &saml_request_id,
                state.config.auth_session_ttl_secs(),
            );
            (
                set_cookies.into_headers(),
                see_other(&format!("{}/login", tenant.prefix())),
            )
                .into_response()
        }
        // SSO was restored, but use of this app is not permitted (ADR-0054). Do not send to the ACS.
        // Leave the SSO cookie alone: the user is signed in to assay, so other apps can proceed as is.
        InternalSamlResumeResponse::ApplicationNotPermitted { application_name } => (
            state
                .set_cookies()
                .expire_local(&state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE))
                .into_headers(),
            crate::application_denied::page(&messages, &tenant.prefix(), &application_name),
        )
            .into_response(),
        InternalSamlResumeResponse::Expired => {
            let set_cookies = state
                .set_cookies()
                .expire_local(&state.origin_bound_cookie(cookies::SAML_REQUEST_COOKIE));
            (set_cookies.into_headers(), expired_page(&messages)).into_response()
        }
        InternalSamlResumeResponse::Internal => api_internal_error("saml_resume"),
    }
}

/// CSP for the form submission to the SP's ACS. With the default CSP (`form-action 'self'`) the browser blocks
/// POSTs to an external origin, so only the ACS origin is additionally allowed.
///
/// Building it is delegated to [`crate::security_headers::form_action_csp_for`]. When the policy was copied
/// here, it grew separately from the default CSP, and the `'unsafe-inline'` that SEC12 should have removed
/// from `script-src` remained only on this page (the script in `saml_post.html` is the
/// external `/assets/auto-submit.js`; nothing inline is used).
fn acs_form_action_csp(acs_url: &str) -> String {
    crate::security_headers::form_action_csp_for(acs_url)
}

fn expired_page(messages: &Messages) -> Response {
    let body = render(&MessagePage {
        lang: messages.lang(),
        title: messages.get("saml-continue-title"),
        message: messages.get("saml-error-expired"),
    });
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_allows_only_the_acs_origin_as_an_extra_form_action() {
        let csp = acs_form_action_csp("https://sp.example.test/acs?x=1");
        assert!(
            csp.contains("form-action 'self' https://sp.example.test;"),
            "{csp}"
        );
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");

        let csp = acs_form_action_csp("http://localhost:8080/acs");
        assert!(
            csp.contains("form-action 'self' http://localhost:8080;"),
            "{csp}"
        );
    }
}
