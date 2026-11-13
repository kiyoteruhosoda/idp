//! Signing key management console screen (`/{tenant_id}/admin/signing-keys`, K1).
//!
//! Provides the key list, the generation form, and retire/delete operations.
//! The actual operations are delegated to the api's `/admin/signing-keys/*` by forwarding the SSO cookie.

use super::locale;
use crate::admin_dto::SigningKeyView;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConsoleNotice, SigningKeysList};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const SIGNING_KEYS_SEGMENT: &str = "/admin/signing-keys";

macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $tenant:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $tenant, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

/// Signing key list (`GET /{tenant_id}/admin/signing-keys`).
pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);
    let result = state
        .api
        .list_signing_keys(&correlation.0, &tenant.0, &sso)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(keys) => {
            Html(render_list(&messages, &tenant, &admin, &keys, &csrf, None)).into_response()
        }
        Err(e) => map_error(&messages, &tenant, &admin, &headers, e),
    }
}

#[derive(Deserialize)]
pub struct GenerateKeyForm {
    pub algorithm: String,
    /// Request to start signing immediately without a grace period. A checkbox is "sent only when checked",
    /// so it is received as `Option<String>`. **The default (unchecked) is a normal rotation**: the key is only
    /// published to JWKS. It takes over signing after `KEY_ROTATION_PUBLISH_LEAD_HOURS`.
    #[serde(default)]
    pub activate_immediately: Option<String>,
    pub csrf_token: String,
}

/// Generates a new signing key (`POST /{tenant_id}/admin/signing-keys/generate`).
pub async fn generate(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<GenerateKeyForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        // Build Messages after the await (it is non-Send, so it must not live across an await).
        let keys = state
            .api
            .list_signing_keys(&correlation.0, &tenant.0, &sso)
            .await
            .unwrap_or_default();
        let messages = Messages::new(locale(&headers));
        let csrf = console_csrf_from(&headers, state.config.csrf_secret());
        return bad_request(render_list(
            &messages,
            &tenant,
            &admin,
            &keys,
            &csrf,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .for_locale(locale(&headers))
        .generate_signing_key(
            &correlation.0,
            &tenant.0,
            &sso,
            &form.algorithm,
            form.activate_immediately.is_some(),
        )
        .await;
    match result {
        Ok(_) => {
            axum::response::Redirect::to(&format!("{}{SIGNING_KEYS_SEGMENT}", tenant.prefix()))
                .into_response()
        }
        Err(AdminApiError::Validation(m)) => {
            let keys = state
                .api
                .list_signing_keys(&correlation.0, &tenant.0, &sso)
                .await
                .unwrap_or_default();
            let messages = Messages::new(locale(&headers));
            let csrf = console_csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_list(
                &messages,
                &tenant,
                &admin,
                &keys,
                &csrf,
                Some(&m),
            ))
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &tenant, &admin, &headers, e)
        }
    }
}

#[derive(Deserialize)]
pub struct KidForm {
    pub kid: String,
    pub csrf_token: String,
}

/// Retires a signing key (`POST /{tenant_id}/admin/signing-keys/retire`).
pub async fn retire(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<KidForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let keys = state
            .api
            .list_signing_keys(&correlation.0, &tenant.0, &sso)
            .await
            .unwrap_or_default();
        let messages = Messages::new(locale(&headers));
        let csrf = console_csrf_from(&headers, state.config.csrf_secret());
        return bad_request(render_list(
            &messages,
            &tenant,
            &admin,
            &keys,
            &csrf,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .for_locale(locale(&headers))
        .retire_signing_key(&correlation.0, &tenant.0, &sso, &form.kid)
        .await;
    match result {
        Ok(_) => {
            axum::response::Redirect::to(&format!("{}{SIGNING_KEYS_SEGMENT}", tenant.prefix()))
                .into_response()
        }
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            not_found(&messages, &tenant, &admin)
        }
        Err(AdminApiError::Validation(m)) => {
            let keys = state
                .api
                .list_signing_keys(&correlation.0, &tenant.0, &sso)
                .await
                .unwrap_or_default();
            let messages = Messages::new(locale(&headers));
            let csrf = console_csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_list(
                &messages,
                &tenant,
                &admin,
                &keys,
                &csrf,
                Some(&m),
            ))
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &tenant, &admin, &headers, e)
        }
    }
}

/// Deletes a signing key (`POST /{tenant_id}/admin/signing-keys/delete`). Only RETIRED keys.
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<KidForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let keys = state
            .api
            .list_signing_keys(&correlation.0, &tenant.0, &sso)
            .await
            .unwrap_or_default();
        let messages = Messages::new(locale(&headers));
        let csrf = console_csrf_from(&headers, state.config.csrf_secret());
        return bad_request(render_list(
            &messages,
            &tenant,
            &admin,
            &keys,
            &csrf,
            Some("admin-error-csrf"),
        ));
    }

    let result = state
        .api
        .for_locale(locale(&headers))
        .delete_signing_key(&correlation.0, &tenant.0, &sso, &form.kid)
        .await;
    match result {
        Ok(_) => {
            axum::response::Redirect::to(&format!("{}{SIGNING_KEYS_SEGMENT}", tenant.prefix()))
                .into_response()
        }
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            not_found(&messages, &tenant, &admin)
        }
        Err(AdminApiError::Validation(m)) => {
            let keys = state
                .api
                .list_signing_keys(&correlation.0, &tenant.0, &sso)
                .await
                .unwrap_or_default();
            let messages = Messages::new(locale(&headers));
            let csrf = console_csrf_from(&headers, state.config.csrf_secret());
            bad_request(render_list(
                &messages,
                &tenant,
                &admin,
                &keys,
                &csrf,
                Some(&m),
            ))
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &tenant, &admin, &headers, e)
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn render_list(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    keys: &[SigningKeyView],
    csrf: &str,
    error: Option<&str>,
) -> String {
    render(&SigningKeysList {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        keys,
        csrf,
        error,
    })
}

fn not_found(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(render(&ConsoleNotice {
            messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            heading: Some("admin-signing-keys-not-found-title"),
            message: "admin-signing-keys-not-found-message",
            is_error: true,
            back_href: Some(&format!("{}{SIGNING_KEYS_SEGMENT}", tenant.prefix())),
            back_label: "admin-nav-home",
        })),
    )
        .into_response()
}

fn map_error(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    e: AdminApiError,
) -> Response {
    match e {
        AdminApiError::Unauthorized => redirect_to_login(tenant),
        AdminApiError::Forbidden => forbidden_response(headers),
        _ => internal_error(messages, tenant, admin),
    }
}

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(render(&ConsoleNotice {
            messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            heading: None,
            message: "admin-error-internal",
            is_error: true,
            back_href: Some(&format!("{}{SIGNING_KEYS_SEGMENT}", tenant.prefix())),
            back_label: "admin-nav-home",
        })),
    )
        .into_response()
}

fn bad_request(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}
