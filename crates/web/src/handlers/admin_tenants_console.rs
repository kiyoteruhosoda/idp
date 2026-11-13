//! Tenant list and registration screen for the root admin (web).
//!
//! The screen is restructured as a small progressive UI with a React-like reducer/component split;
//! authorization and persistence are delegated to the api's `/{tenant_id}/admin/tenants` (requires `idp.system.admin`).

use super::locale;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::dto::{
    AdminPasswordResetForm, AdminTenantActionForm, AdminTenantCreateForm, AdminTenantUpdateForm,
    TenantsQuery,
};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, PasswordResetResult, TenantCreated, TenantsConsole};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

const TENANTS_SEGMENT: &str = "/admin/tenants";

pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<TenantsQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = sso(&headers);
    let offset = query.offset.unwrap_or(0).max(0);
    // Paging is done on the api (DB) side (G7). web carries over the page position and only builds prev/next links.
    let page = match state
        .api
        .list_tenants(
            &correlation.0,
            &tenant.0,
            &sso,
            &crate::pagination::page_query(offset),
        )
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return forbidden_response(&headers),
        Err(e) => {
            tracing::error!(error = %e, "failed to load tenants");
            crate::admin_dto::TenantListView {
                tenants: Vec::new(),
                total: 0,
                limit: 0,
                offset,
            }
        }
    };
    let links = crate::pagination::pager_links(
        &format!("{}{TENANTS_SEGMENT}", tenant.prefix()),
        &[],
        offset,
        page.limit,
        page.total,
    );
    let messages = Messages::new(locale(&headers));
    Html(render(&TenantsConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        tenants: &page.tenants,
        total: page.total,
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        error_key: query.error.as_deref().and_then(error_key_for),
        saved: query.saved.as_deref() == Some("tenant"),
        prev_href: links.prev,
        next_href: links.next,
    }))
    .into_response()
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminTenantCreateForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{TENANTS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let created = match state
        .api
        .create_tenant(&correlation.0, &tenant.0, &sso, form.name.trim())
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => return found(&format!("{base}?error=validation")),
        Err(AdminApiError::Conflict(_)) => return found(&format!("{base}?error=conflict")),
        Err(e) => {
            tracing::error!(error = %e, "failed to create tenant");
            return found(&format!("{base}?error=internal"));
        }
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&TenantCreated {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        created: &created,
    }))
    .into_response()
}

/// Changes a child tenant's display name and status (`POST /{tenant_id}/admin/tenants/{child_id}/update`. MT23).
/// Delegates to the api's `PATCH /admin/tenants/{child_id}`; on success returns to the list with a completion notice
/// (Post/Redirect/Get). Allowed status values are validated by the api (`TenantStatus::parse`); web only
/// passes values through (invalid values give `?error=validation`).
pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, child_id)): Path<(String, String)>,
    Form(form): Form<AdminTenantUpdateForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{TENANTS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .update_tenant(
            &correlation.0,
            &tenant.0,
            &sso,
            &child_id,
            form.name.trim(),
            form.status.trim(),
        )
        .await
    {
        Ok(_) => found(&format!("{base}?saved=tenant")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=validation")),
        Err(e) => {
            tracing::error!(error = %e, "failed to update tenant");
            found(&format!("{base}?error=internal"))
        }
    }
}

/// Deletes a child tenant (`POST /{tenant_id}/admin/tenants/{child_id}/delete`). If child tenants,
/// users or clients remain under it, the api returns 409 (`?error=delete-conflict`).
pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, child_id)): Path<(String, String)>,
    Form(form): Form<AdminTenantActionForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{TENANTS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .delete_tenant(&correlation.0, &tenant.0, &sso, &child_id)
        .await
    {
        Ok(()) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(AdminApiError::Conflict(_)) => found(&format!("{base}?error=delete-conflict")),
        Err(e) => {
            tracing::error!(error = %e, "failed to delete tenant");
            found(&format!("{base}?error=internal"))
        }
    }
}

/// Reissues the child tenant admin's password
/// (`POST /{tenant_id}/admin/tenants/{child_id}/reset-admin-password`).
/// On success the generated password is shown only once.
pub async fn reset_admin_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, child_id)): Path<(String, String)>,
    Form(form): Form<AdminPasswordResetForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{TENANTS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let email = form.email.trim();
    if email.is_empty() {
        return found(&format!("{base}?error=validation"));
    }
    let reset = match state
        .api
        .reset_tenant_admin_password(&correlation.0, &tenant.0, &sso, &child_id, email)
        .await
    {
        Ok(v) => v,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::NotFound) => return found(&format!("{base}?error=reset-notfound")),
        Err(AdminApiError::Validation(_)) => return found(&format!("{base}?error=validation")),
        Err(e) => {
            tracing::error!(error = %e, "failed to reset tenant admin password");
            return found(&format!("{base}?error=internal"));
        }
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&PasswordResetResult {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        subject: email,
        setup_url: &reset.setup_url,
        setup_expires_at: &reset.setup_expires_at,
        back_href: &base,
        back_label_key: "admin-tenants-back",
    }))
    .into_response()
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-tenants-error-forbidden"),
        "validation" => Some("admin-tenants-error-validation"),
        "conflict" => Some("admin-tenants-error-conflict"),
        "delete-conflict" => Some("admin-tenants-error-delete-conflict"),
        "notfound" => Some("admin-tenants-error-notfound"),
        "reset-notfound" => Some("admin-tenants-error-reset-notfound"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_dto::TenantView;
    use crate::i18n::Locale;

    fn render_list(tenants: &[TenantView], saved: bool) -> String {
        let messages = Messages::new(Locale::Ja);
        render(&TenantsConsole {
            messages: &messages,
            tenant: "/00000000-0000-7000-8000-000000000001",
            admin: Some(crate::templates::ConsoleAdmin {
                label: "admin-1",
                tenant_name: Some("Acme"),
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
            tenants,
            total: tenants.len() as i64,
            csrf: "csrf123",
            error_key: None,
            saved,
            prev_href: None,
            next_href: None,
        })
    }

    fn tenant_view(status: &str) -> TenantView {
        TenantView {
            id: "019f6514-08ea-7138-ad71-838a7bdd3575".into(),
            name: "Child".into(),
            self_registration_enabled: false,
            email_login_enabled: false,
            status: status.into(),
        }
    }

    /// MT23: each list row can edit the display name and status (connected to the api's `PATCH /admin/tenants/{id}`).
    #[test]
    fn edit_form_posts_name_and_status_with_current_values_preselected() {
        let html = render_list(&[tenant_view("DISABLED")], false);
        assert!(html.contains("/admin/tenants/019f6514-08ea-7138-ad71-838a7bdd3575/update"));
        assert!(html.contains("name=\"csrf_token\" value=\"csrf123\""));
        assert!(html.contains("value=\"Child\""));
        // Opens with the current status selected (so it is not accidentally set back to ACTIVE).
        assert!(html.contains("<option value=\"DISABLED\" selected>"));
        assert!(!html.contains("<option value=\"ACTIVE\" selected>"));

        let active = render_list(&[tenant_view("ACTIVE")], false);
        assert!(active.contains("<option value=\"ACTIVE\" selected>"));
    }

    /// The save-complete banner is shown only via `?saved=tenant` after Post/Redirect/Get.
    #[test]
    fn saved_banner_is_shown_only_after_a_successful_update() {
        let messages = Messages::new(Locale::Ja);
        let saved = messages.get("admin-tenants-edit-saved");
        assert!(render_list(&[tenant_view("ACTIVE")], true).contains(&saved));
        assert!(!render_list(&[tenant_view("ACTIVE")], false).contains(&saved));
    }
}
