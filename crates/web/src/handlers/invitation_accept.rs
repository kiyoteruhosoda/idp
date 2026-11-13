//! Invitation acceptance screen (web. `/{tenant_id}/invitations/accept`. ADR-0009 §3, MT17).
//!
//! The invitee opens it from the link (`?token=...`) in the invitation email. Accepting requires an SSO session
//! **signed in at the home tenant** (identity = token possession + signed-in session; §3). If not signed in,
//! it shows guidance to "sign in at your home tenant and reopen" (this screen cannot know the invitee's
//! home tenant, so it does not redirect to a login screen). The actual acceptance is delegated to the api's
//! `POST /{tenant_id}/invitations/accept` by forwarding the SSO cookie.

use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, InvitationAccept};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AcceptQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AcceptForm {
    pub token: String,
    pub csrf_token: String,
}

/// Acceptance page (`GET /{tenant_id}/invitations/accept?token=...`). Shows the confirm form when signed in,
/// otherwise only the guidance.
pub async fn page(
    State(state): State<WebState>,
    Extension(_tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<AcceptQuery>,
) -> Response {
    let messages = Messages::new(locale(&headers));
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        return bad_request(render_page(&messages, false, "", "", None));
    }
    match cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        Some(sso) => {
            let csrf = console_csrf_token(&sso, state.config.csrf_secret());
            Html(render_page(&messages, true, &token, &csrf, None)).into_response()
        }
        None => Html(render_page(&messages, false, &token, "", None)).into_response(),
    }
}

/// Performs the acceptance (`POST /{tenant_id}/invitations/accept`).
/// (`Messages` is not `Send`, so it is created per branch to avoid living across the api call's await.)
pub async fn submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AcceptForm>,
) -> Response {
    let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        let messages = Messages::new(locale(&headers));
        return Html(render_page(&messages, false, &form.token, "", None)).into_response();
    };
    let csrf = console_csrf_token(&sso, state.config.csrf_secret());
    if !assay_contracts::csrf::verify(&csrf, &form.csrf_token) {
        let messages = Messages::new(locale(&headers));
        return bad_request(render_page(
            &messages,
            true,
            &form.token,
            &csrf,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .accept_invitation(&correlation.0, &tenant.0, &sso, &form.token)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(()) => Html(render(&InvitationAccept {
            messages: &messages,
            show_form: false,
            token: "",
            csrf: "",
            success: true,
            error_key: None,
        }))
        .into_response(),
        // SSO expired etc. → guidance to sign in again (no form).
        Err(AdminApiError::Unauthorized) => {
            Html(render_page(&messages, false, &form.token, "", None)).into_response()
        }
        // Tried to accept with another user's session.
        Err(AdminApiError::Forbidden) => bad_request(render_page(
            &messages,
            true,
            &form.token,
            &csrf,
            Some("invitation-accept-error-forbidden"),
        )),
        // Invalid/expired token, or an invitation for another tenant.
        Err(AdminApiError::Validation(_)) | Err(AdminApiError::Conflict(_)) => {
            bad_request(render_page(
                &messages,
                true,
                &form.token,
                &csrf,
                Some("invitation-accept-error-invalid"),
            ))
        }
        Err(_) => bad_request(render_page(
            &messages,
            true,
            &form.token,
            &csrf,
            Some("admin-error-internal"),
        )),
    }
}

fn render_page(
    messages: &Messages,
    show_form: bool,
    token: &str,
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    render(&InvitationAccept {
        messages,
        show_form,
        token,
        csrf,
        success: false,
        error_key,
    })
}

fn locale(headers: &HeaderMap) -> Locale {
    let cookie_lang = cookies::get(headers, cookies::LANG_COOKIE);
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    Locale::resolve(None, None, cookie_lang.as_deref(), accept)
}

fn bad_request(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}
