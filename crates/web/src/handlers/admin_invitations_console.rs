//! Guest invitation creation screen (web. ADR-0009 §3, §6, MT13).
//!
//! Calls the api's JSON admin API (`POST /admin/invitations`) by forwarding the admin's SSO cookie. Invitees
//! are existing users whose home is another tenant, referred to by **email address or internal ID (UUID)** (ADR-0061.
//! Telling them apart and resolving them is confined to the api's application layer; this screen just passes one input).
//! The invitation token is shown only on this result screen.

use super::locale;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, InvitationCreated, InvitationForm};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

/// Invitation form (`GET /{tenant_id}/admin/invitations`).
pub async fn new_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    Html(render_form(&messages, &tenant, &admin, &csrf, "", None)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct InvitationRequestForm {
    /// The person to invite (email address or internal ID).
    pub invitee: String,
    pub csrf_token: String,
}

/// Creates an invitation (`POST /{tenant_id}/admin/invitations`). Shows the invitation token only once.
pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<InvitationRequestForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = console_csrf_from(&headers, state.config.csrf_secret());
        return bad_request(render_form(
            &messages,
            &tenant,
            &admin,
            &csrf,
            &form.invitee,
            Some("admin-error-csrf"),
        ));
    }

    // Carry over the resolved language so the api's validation/conflict messages show on this screen (MT20).
    let result = state
        .api
        .for_locale(locale(&headers))
        .create_invitation(&correlation.0, &tenant.0, &sso(&headers), &form.invitee)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(created) => Html(render(&InvitationCreated {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            token: &created.token,
            expires_at: &created.expires_at,
            email_sent: created.email_sent,
            invitee_email: created.invitee_email.as_deref(),
        }))
        .into_response(),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => {
            let csrf = console_csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_form_with_message(
                &messages,
                &tenant,
                &admin,
                &csrf,
                &form.invitee,
                &m,
            ))
        }
        Err(AdminApiError::NotFound) => {
            let csrf = console_csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_form_with_message(
                &messages,
                &tenant,
                &admin,
                &csrf,
                &form.invitee,
                &messages.get("admin-invitations-error-notfound"),
            ))
        }
        Err(_) => {
            let csrf = console_csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_form_with_message(
                &messages,
                &tenant,
                &admin,
                &csrf,
                &form.invitee,
                &messages.get("admin-error-internal"),
            ))
        }
    }
}

fn render_form(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    csrf: &str,
    invitee: &str,
    error_key: Option<&str>,
) -> String {
    let error = error_key.map(|k| messages.get(k));
    render(&InvitationForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf,
        error: error.as_deref(),
        invitee,
    })
}

fn render_form_with_message(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    csrf: &str,
    invitee: &str,
    error: &str,
) -> String {
    render(&InvitationForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf,
        error: Some(error),
        invitee,
    })
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn bad_request(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}
