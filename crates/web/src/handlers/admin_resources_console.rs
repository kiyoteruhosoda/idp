//! Admin console screen for protected resources (names that go into `aud`) (`/{tenant_id}/admin/resources`. ADR-0042).
//!
//! Provides list, registration, disable/enable and deletion. The actual operations are delegated to the api's
//! `/admin/resources/*` by forwarding the SSO cookie (web does not touch sqlx; ADR-0007).
//!
//! Lending (which clients may use that audience) lives in the **client details**,
//! because "who is allowed what" is a client setting, not a setting of the name itself.

use super::locale;
use crate::admin_dto::ResourceView;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConsoleNotice, ResourcesList};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const RESOURCES_SEGMENT: &str = "/admin/resources";

macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $tenant:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $tenant, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

/// List of resource names (`GET /{tenant_id}/admin/resources`).
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
        .list_resources(&correlation.0, &tenant.0, &sso)
        .await;
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    match result {
        Ok(list) => Html(render_list(
            &messages,
            &tenant,
            &admin,
            &list.resources,
            &csrf,
            None,
        ))
        .into_response(),
        Err(e) => map_error(&messages, &tenant, &admin, &headers, e),
    }
}

#[derive(Deserialize)]
pub struct RegisterResourceForm {
    pub resource_uri: String,
    pub display_name: String,
    pub csrf_token: String,
}

/// Registers a resource name (`POST /{tenant_id}/admin/resources/register`).
pub async fn register(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<RegisterResourceForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return reload_with_error(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &sso,
            "admin-error-csrf",
        )
        .await;
    }

    let result = state
        .api
        .for_locale(locale(&headers))
        .register_resource(
            &correlation.0,
            &tenant.0,
            &sso,
            form.resource_uri.trim(),
            form.display_name.trim(),
        )
        .await;
    match result {
        Ok(_) => redirect(&tenant),
        // Input errors (not an absolute URI / reserved = 400, already registered = 409) show the api's message
        // as is. Copying the checks into web would split the rules into two places and one would go stale.
        Err(AdminApiError::Validation(m) | AdminApiError::Conflict(m)) => {
            reload_with_error(&state, &correlation, &tenant, &admin, &headers, &sso, &m).await
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            map_error(&messages, &tenant, &admin, &headers, e)
        }
    }
}

#[derive(Deserialize)]
pub struct ResourceIdForm {
    pub resource_id: String,
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct ResourceStatusForm {
    pub resource_id: String,
    /// `ACTIVE` / `DISABLED`. Sent by the pressed button.
    pub status: String,
    pub csrf_token: String,
}

/// Changes the state of a resource name (`POST /{tenant_id}/admin/resources/status`).
pub async fn set_status(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ResourceStatusForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return reload_with_error(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &sso,
            "admin-error-csrf",
        )
        .await;
    }

    let result = state
        .api
        .for_locale(locale(&headers))
        .update_resource_status(
            &correlation.0,
            &tenant.0,
            &sso,
            &form.resource_id,
            &form.status,
        )
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &sso,
        result.map(|_| ()),
    )
    .await
}

/// Deletes a resource name (`POST /{tenant_id}/admin/resources/delete`).
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ResourceIdForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return reload_with_error(
            &state,
            &correlation,
            &tenant,
            &admin,
            &headers,
            &sso,
            "admin-error-csrf",
        )
        .await;
    }

    let result = state
        .api
        .for_locale(locale(&headers))
        .delete_resource(&correlation.0, &tenant.0, &sso, &form.resource_id)
        .await;
    finish(
        &state,
        &correlation,
        &tenant,
        &admin,
        &headers,
        &sso,
        result,
    )
    .await
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async fn finish(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    sso: &str,
    result: Result<(), AdminApiError>,
) -> Response {
    match result {
        Ok(()) => redirect(tenant),
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(headers));
            not_found(&messages, tenant, admin)
        }
        Err(AdminApiError::Validation(m)) => {
            reload_with_error(state, correlation, tenant, admin, headers, sso, &m).await
        }
        Err(e) => {
            let messages = Messages::new(locale(headers));
            map_error(&messages, tenant, admin, headers, e)
        }
    }
}

/// Re-fetches the list and re-renders with an error (not PRG, so the reason is shown while keeping the input).
async fn reload_with_error(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    sso: &str,
    error: &str,
) -> Response {
    let resources = state
        .api
        .list_resources(&correlation.0, &tenant.0, sso)
        .await
        .map(|list| list.resources)
        .unwrap_or_default();
    // Build Messages after the await (it is non-Send, so it must not live across an await).
    let messages = Messages::new(locale(headers));
    let csrf = console_csrf_from(headers, state.config.csrf_secret());
    (
        StatusCode::BAD_REQUEST,
        Html(render_list(
            &messages,
            tenant,
            admin,
            &resources,
            &csrf,
            Some(error),
        )),
    )
        .into_response()
}

fn redirect(tenant: &WebTenant) -> Response {
    axum::response::Redirect::to(&format!("{}{RESOURCES_SEGMENT}", tenant.prefix())).into_response()
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn render_list(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    resources: &[ResourceView],
    csrf: &str,
    error: Option<&str>,
) -> String {
    render(&ResourcesList {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        resources,
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
            heading: None,
            message: "api-resource-not-found",
            is_error: true,
            back_href: Some(&format!("{}{RESOURCES_SEGMENT}", tenant.prefix())),
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
            back_href: Some(&format!("{}{RESOURCES_SEGMENT}", tenant.prefix())),
            back_label: "admin-nav-home",
        })),
    )
        .into_response()
}
