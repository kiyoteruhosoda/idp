//! RP-initiated Logout (`GET /{tenant_id}/logout`, OIDC RP-Initiated Logout 1.0, ADR-0018 decision 2).
//!
//! web receives the `end_session_endpoint` (the api does not read browser cookies). web forwards our domain's
//! host-only `sso_session_id` cookie and the query parameters to the api's `POST /internal/logout/rp`.
//! Revoking the SSO session, back-channel notification, validating `post_logout_redirect_uri` and
//! adding `state` are done by the api; web handles **discarding the SSO cookie** and rendering the
//! iframe page when there is front-channel logout.
//!
//! `id_token_hint` is forwarded to the api as is (G12). Signature/issuer verification, matching
//! `post_logout_redirect_uri` by `aud`, and checking `sub` are done by the api (web has no keys).
//! If the hint points to **another user**, the api changes nothing and returns `SubjectMismatch`. Then
//! web does not discard the SSO cookie (discarding it would leave the session only in the DB, unreachable from the browser).
//!
//! ⚠ **A request without `id_token_hint` gets a confirmation screen if signed in** (task #588. OIDC RP-Initiated
//! Logout 1.0 §2). Finishing without confirmation would let anyone sign others out just by making them follow
//! a link (even `<img src>`). The confirmation screen executes via `POST /{tenant_id}/logout/confirm` with a CSRF
//! synchronizer token. Requests with a hint (the legitimate path where the RP attaches its own ID Token) are not confirmed, as before.

use super::{api_internal_error, internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::dto::RpLogoutQuery;
use crate::handlers::{forwarded_context, found};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, MessagePage, RpLogoutConfirmPage, RpLogoutPage};
use crate::tenant::WebTenant;
use assay_contracts::auth::{InternalRpLogoutRequest, InternalRpLogoutResponse};
use axum::extract::{Extension, Form, Query, State};
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};

/// RP-initiated logout endpoint.
pub async fn logout(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<RpLogoutQuery>,
) -> Response {
    let has_hint = query
        .id_token_hint
        .as_deref()
        .is_some_and(|hint| !hint.is_empty());
    if !has_hint {
        // If signed in, insert a confirmation (task #588). If not signed in there is nothing to end,
        // so proceed as is (the api validates the return destination).
        if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
            return confirmation_page(&state, &tenant, &headers, &sso, &query, StatusCode::OK);
        }
    }
    perform(&state, &correlation, &client_ip, &tenant, &headers, query).await
}

/// Sign-out from the confirmation screen (`POST /{tenant_id}/logout/confirm`. task #588).
pub async fn confirm(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(query): Form<RpLogoutQuery>,
) -> Response {
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        let submitted = query.csrf_token.as_deref().unwrap_or_default();
        if !console_csrf_valid(&sso, submitted, state.config.csrf_secret()) {
            tracing::warn!(
                correlation_id = %correlation.0,
                "rp logout confirmation rejected: csrf token mismatch"
            );
            // Do nothing and re-show the confirmation screen (can be pressed again with a new token).
            return confirmation_page(
                &state,
                &tenant,
                &headers,
                &sso,
                &query,
                StatusCode::BAD_REQUEST,
            );
        }
    }
    perform(&state, &correlation, &client_ip, &tenant, &headers, query).await
}

/// The sign-out confirmation screen. RP parameters are carried in hidden fields (only requests without `id_token_hint` come here).
fn confirmation_page(
    state: &WebState,
    tenant: &WebTenant,
    headers: &HeaderMap,
    sso_session_id: &str,
    query: &RpLogoutQuery,
    status: StatusCode,
) -> Response {
    let messages = Messages::new(locale(headers));
    let body = render(&RpLogoutConfirmPage {
        messages: &messages,
        tenant_prefix: &tenant.prefix(),
        csrf_token: &console_csrf_token(sso_session_id, state.config.csrf_secret()),
        client_id: query.client_id.as_deref(),
        post_logout_redirect_uri: query.post_logout_redirect_uri.as_deref(),
        state: query.state.as_deref(),
    });
    (status, Html(body)).into_response()
}

/// Performs the sign-out (delegated to the api's `POST /internal/logout/rp`).
async fn perform(
    state: &WebState,
    correlation: &CorrelationId,
    client_ip: &ClientIp,
    tenant: &WebTenant,
    headers: &HeaderMap,
    query: RpLogoutQuery,
) -> Response {
    let ctx = forwarded_context(headers, correlation, client_ip);
    let request = InternalRpLogoutRequest {
        tenant_id: Some(tenant.0.clone()),
        sso_session_id: cookies::get(headers, cookies::SSO_SESSION_COOKIE),
        client_id: query.client_id,
        id_token_hint: query.id_token_hint,
        post_logout_redirect_uri: query.post_logout_redirect_uri,
        state: query.state,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state.api.rp_logout(&ctx.correlation_id, &request).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "rp logout call to api failed");
            return internal_call_status(&e).into_response();
        }
    };
    let messages = Messages::new(locale(headers));

    match outcome {
        InternalRpLogoutResponse::Ok {
            frontchannel_uris,
            redirect_to,
        } => {
            // web discards the SSO cookie on its own domain (ADR-0018 decision 2).
            let set_cookies = state
                .set_cookies()
                .expire_session(cookies::SSO_SESSION_COOKIE);

            // With front-channel logout, return the iframe page. External RP URIs are loaded in iframes,
            // so override the default CSP (frame-src falls back to default-src 'self') with a CSP allowing
            // the notification target origins (security_headers respects an already-set CSP).
            if !frontchannel_uris.is_empty() {
                let body = render(&RpLogoutPage {
                    messages: &messages,
                    frontchannel_uris: &frontchannel_uris,
                    redirect_to: redirect_to.as_deref(),
                });
                return (
                    StatusCode::OK,
                    [(
                        CONTENT_SECURITY_POLICY,
                        frontchannel_csp(&frontchannel_uris),
                    )],
                    set_cookies.into_headers(),
                    Html(body),
                )
                    .into_response();
            }

            // No front-channel: redirect or the completion page.
            if let Some(uri) = redirect_to {
                (set_cookies.into_headers(), found(&uri)).into_response()
            } else {
                let body = render(&MessagePage {
                    lang: messages.lang(),
                    title: messages.get("logout-title"),
                    message: messages.get("logout-done-message"),
                });
                (set_cookies.into_headers(), Html(body)).into_response()
            }
        }
        // `id_token_hint` pointed to another user (G12). The api changed nothing, so
        // **do not delete the cookie either** — deleting it would leave the session alive in the DB but unreachable
        // from the browser, ultimately breaking the signed-in state of the other user we meant to protect.
        InternalRpLogoutResponse::SubjectMismatch => {
            let body = render(&MessagePage {
                lang: messages.lang(),
                title: messages.get("logout-title"),
                message: messages.get("logout-subject-mismatch-message"),
            });
            (StatusCode::BAD_REQUEST, Html(body)).into_response()
        }
        InternalRpLogoutResponse::Internal => api_internal_error("rp_logout"),
    }
}

/// Builds a CSP allowing only the front-channel notification target origins in `frame-src`
/// (otherwise the same policy as `security_headers::CONTENT_SECURITY_POLICY`).
fn frontchannel_csp(frontchannel_uris: &[String]) -> String {
    let mut origins: Vec<String> = frontchannel_uris
        .iter()
        .map(|uri| crate::security_headers::origin_of(uri))
        // Do not add an allowance for URIs that cannot be parsed (fail-closed).
        .filter(|origin| !origin.is_empty())
        .collect();
    origins.sort();
    origins.dedup();
    format!(
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; \
         frame-ancestors 'none'; frame-src {}",
        origins.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontchannel_csp_allows_only_the_notified_origins() {
        let csp = frontchannel_csp(&[
            "https://rp.example.com/logout?iss=x".to_string(),
            "https://rp.example.com/other".to_string(),
            "http://localhost:3000/fc".to_string(),
        ]);
        assert!(
            csp.ends_with("frame-src http://localhost:3000 https://rp.example.com"),
            "{csp}"
        );
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    }
}
