//! Admin console settings screen (web. `/{tenant_id}/admin/settings`. MT14).
//!
//! Combines on one screen the tenant settings section (own tenant display name; `idp.tenant.admin`) and the
//! system settings section (SMTP) visible only to root (`idp.system.admin`). web only renders forms; updates are
//! delegated to the api's `/{tenant_id}/admin/settings/tenant` (PATCH) and `/{tenant_id}/admin/system-settings` (PUT)
//! by forwarding the SSO cookie. Whether to show the system settings section is decided by "whether the api GET is 403"
//! (web keeps no separate root check; the api is the single source of authorization).

use super::locale;
use crate::api_client::AdminApiError;
use crate::config;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::dto::{
    AdminRuntimeSettingForm, AdminSystemSettingsForm, AdminTenantSettingClearForm,
    AdminTenantSettingForm, AdminTenantSettingsForm, AdminTenantSmtpClearForm, AdminTenantSmtpForm,
    SettingsQuery,
};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::settings_filter::SettingsFilter;
use crate::state::WebState;
use crate::templates::{
    render, setting_label, AdminSettings, AdminTenantSettingConfirm, ConsoleNotice,
};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

const SETTINGS_SEGMENT: &str = "/admin/settings";

/// Settings screen (`GET /{tenant_id}/admin/settings`).
pub async fn page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = sso(&headers);

    // FluentBundle (Messages) is !Send, so finish all api calls (awaits) before creating it.
    let tenant_result = state
        .api
        .get_current_tenant(&correlation.0, &tenant.0, &sso)
        .await;
    // Tenant setting values (ADR-0058). If unreadable (403), the section is not shown.
    let tenant_settings_result = state
        .api
        .list_tenant_settings(&correlation.0, &tenant.0, &sso)
        .await;
    // The tenant's own mail route (ADR-0058 §8). Without `idp.smtp:read` it is 403 and the section is not shown.
    let tenant_smtp_result = state
        .api
        .get_tenant_smtp(&correlation.0, &tenant.0, &sso)
        .await;
    // The system settings section is root (idp.system.admin) only. 403 means "not root", so hide it.
    let system_result = state
        .api
        .get_system_settings(&correlation.0, &tenant.0, &sso)
        .await;
    // Not yet applied to web (MT27): divergence between the shared settings web received at startup and those the api serves now.
    // This happens when only the api was restarted (ADR-0013 §Consequences). It is not shown to admins who cannot see
    // the system settings section (non-root), so in that case it is not queried.
    let stale_web_keys = if system_result.is_ok() {
        stale_web_shared_settings(&state).await
    } else {
        Vec::new()
    };

    let messages = Messages::new(locale(&headers));

    let tenant_view = match tenant_result {
        Ok(t) => t,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => return forbidden_response(&headers),
        Err(_) => return internal_error(&messages, &tenant, &admin),
    };

    let tenant_settings = match tenant_settings_result {
        Ok(list) => Some(list),
        Err(AdminApiError::Forbidden) => None,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(e) => {
            tracing::error!(error = %e, "failed to load tenant settings");
            None
        }
    };

    let tenant_smtp = match tenant_smtp_result {
        Ok(view) => Some(view),
        Err(AdminApiError::Forbidden) => None,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(e) => {
            tracing::error!(error = %e, "failed to load tenant SMTP settings");
            None
        }
    };

    let system = match system_result {
        Ok(s) => Some(s),
        Err(AdminApiError::Forbidden) => None,
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(e) => {
            tracing::error!(error = %e, "failed to load system settings");
            None
        }
    };

    // Keys saved but not yet applied to the api (MT27). The api decides (core is the single source of the rules).
    let pending_api_keys: Vec<String> = system
        .as_ref()
        .map(|s| {
            s.runtime_settings
                .iter()
                .filter(|item| item.pending_restart)
                .map(|item| item.key.clone())
                .collect()
        })
        .unwrap_or_default();

    // Filtering. Note the count before filtering to show "M of N" (the not-applied warning is built from the unfiltered list).
    let filter = SettingsFilter::new(
        query.q.as_deref(),
        query.mine.as_deref(),
        query.runtime.as_deref(),
    );
    let tenant_values_total = tenant_settings.as_ref().map_or(0, |l| l.settings.len());
    let mut tenant_settings = tenant_settings;
    if let Some(list) = tenant_settings.as_mut() {
        list.settings
            .retain(|item| filter.keeps_tenant_value(item, &setting_label(&messages, &item.key)));
    }
    let runtime_total = system.as_ref().map_or(0, |s| s.runtime_settings.len());
    let mut system = system;
    if let Some(sys) = system.as_mut() {
        sys.runtime_settings
            .retain(|item| filter.keeps_runtime_setting(item));
    }

    Html(render(&AdminSettings {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        tenant_id: &tenant_view.id,
        tenant_name: &tenant_view.name,
        tenant_status: &tenant_view.status,
        tenant_self_registration: tenant_view.self_registration_enabled,
        tenant_email_login: tenant_view.email_login_enabled,
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        saved: query.saved.is_some(),
        error_key: query.error.as_deref().and_then(error_key_for),
        tenant_settings: tenant_settings.as_ref(),
        tenant_smtp: tenant_smtp.as_ref(),
        system: system.as_ref(),
        pending_api_keys: &pending_api_keys,
        stale_web_keys: &stale_web_keys,
        filter: &filter,
        tenant_values_total,
        runtime_total,
    }))
    .into_response()
}

/// Compares the shared settings web applied at startup with those the api currently serves and returns the key names
/// **not yet applied to web** (MT27).
///
/// Returns empty if fetching fails (being able to show the settings screen itself is more useful operationally, and a
/// failure here only means "cannot tell", not "nothing unapplied"). Note the purpose differs from the startup
/// fail-fast (ADR-0013 §4): that one avoids running on wrong settings; this one is an auxiliary display.
async fn stale_web_shared_settings(state: &WebState) -> Vec<String> {
    match state.api.fetch_shared_runtime_settings().await {
        Ok(current) => {
            config::stale_shared_settings(state.config.shared_runtime_settings(), &current)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to check shared runtime settings for staleness");
            Vec::new()
        }
    }
}

/// Updates the tenant display name (`POST /{tenant_id}/admin/settings/tenant`).
pub async fn update_tenant(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminTenantSettingsForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .update_current_tenant(
            &correlation.0,
            &tenant.0,
            &sso,
            form.name.trim(),
            form.self_registration_enabled.is_some(),
            form.email_login_enabled.is_some(),
        )
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=validation")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

/// Sets a tenant value (`POST /{tenant_id}/admin/settings/tenant/keys`. ADR-0058).
///
/// ⚠ Values that could lock people out (the api returns 409) are not saved; a confirmation screen is inserted. They are
/// saved only when resent from the confirmation screen with `confirmed` (the api's definitions are the single source).
pub async fn update_tenant_setting(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminTenantSettingForm>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(admin) => admin,
        AdminResolution::Reject(resp) => return resp,
    };
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    let csrf = console_csrf_token(&sso, state.config.csrf_secret());
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let key = form.key.trim();
    let value = form.value.trim();
    let confirmed = form.confirmed.is_some();
    match state
        .api
        .set_tenant_setting(&correlation.0, &tenant.0, &sso, key, value, confirmed)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1#tenant-values")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden#tenant-values")),
        Err(AdminApiError::Validation(_)) => found(&format!(
            "{base}?error=tenant-value-validation#tenant-values"
        )),
        // A value needing confirmation. Re-fetch the list to show the currently effective value and description (confirm anyway if it fails).
        Err(AdminApiError::Conflict(_)) if !confirmed => {
            let current = state
                .api
                .list_tenant_settings(&correlation.0, &tenant.0, &sso)
                .await
                .ok()
                .and_then(|list| list.settings.into_iter().find(|item| item.key == key));
            let messages = Messages::new(locale(&headers));
            let label = setting_label(&messages, key);
            Html(render(&AdminTenantSettingConfirm {
                messages: &messages,
                tenant: &tenant.prefix(),
                admin: Some(admin.chrome()),
                csrf: &csrf,
                key,
                label: &label,
                description: current
                    .as_ref()
                    .map(|item| item.description.as_str())
                    .unwrap_or_default(),
                current_value: current.as_ref().map(|item| item.value.as_str()),
                value,
            }))
            .into_response()
        }
        Err(_) => found(&format!("{base}?error=internal#tenant-values")),
    }
}

/// Removes the tenant override and returns to the global value (`POST /{tenant_id}/admin/settings/tenant/keys/clear`).
pub async fn clear_tenant_setting(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminTenantSettingClearForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .clear_tenant_setting(&correlation.0, &tenant.0, &sso, form.key.trim())
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1#tenant-values")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden#tenant-values")),
        Err(AdminApiError::Validation(_)) => found(&format!(
            "{base}?error=tenant-value-validation#tenant-values"
        )),
        Err(_) => found(&format!("{base}?error=internal#tenant-values")),
    }
}

/// Saves the tenant's own mail route (`POST /{tenant_id}/admin/settings/smtp`. ADR-0058 §8).
///
/// If the password field is empty, the current one is kept. It is deleted only when "delete password" is checked.
/// If all fields defining the route become empty, the api deletes the row and falls back to the global route.
pub async fn update_tenant_smtp(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminTenantSmtpForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf#tenant-smtp"));
    }
    let port: Option<u16> = {
        let trimmed = form.smtp_port.trim();
        if trimmed.is_empty() {
            None
        } else {
            match trimmed.parse::<u16>() {
                Ok(p) => Some(p),
                Err(_) => return found(&format!("{base}?error=validation#tenant-smtp")),
            }
        }
    };
    let password = tenant_smtp_password(form.smtp_password, form.smtp_password_clear.is_some());
    let body = serde_json::json!({
        "smtp_host": form.smtp_host,
        "smtp_port": port,
        "smtp_username": form.smtp_username,
        "smtp_password": password,
        "smtp_from_address": form.smtp_from_address,
        "smtp_use_tls": form.smtp_use_tls.is_some(),
    });
    match state
        .api
        .update_tenant_smtp(&correlation.0, &tenant.0, &sso, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1#tenant-smtp")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden#tenant-smtp")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=validation#tenant-smtp")),
        Err(_) => found(&format!("{base}?error=internal#tenant-smtp")),
    }
}

/// Turns the form's password field into the value sent to the api. `None` = keep / `Some("")` = delete / `Some(x)` = set.
///
/// ⚠ If "delete" is checked, delete even if the field contains something (do not silently save mixed-up input).
fn tenant_smtp_password(input: String, clear: bool) -> Option<String> {
    if clear {
        Some(String::new())
    } else if input.is_empty() {
        None
    } else {
        Some(input)
    }
}

/// Removes the tenant's mail route and falls back to the global route (`POST /{tenant_id}/admin/settings/smtp/clear`).
pub async fn clear_tenant_smtp(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminTenantSmtpClearForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf#tenant-smtp"));
    }
    match state
        .api
        .clear_tenant_smtp(&correlation.0, &tenant.0, &sso)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1#tenant-smtp")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden#tenant-smtp")),
        Err(_) => found(&format!("{base}?error=internal#tenant-smtp")),
    }
}

/// Updates system settings (SMTP) (`POST /{tenant_id}/admin/system-settings`).
pub async fn update_system(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminSystemSettingsForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let port: Option<u16> = {
        let trimmed = form.smtp_port.trim();
        if trimmed.is_empty() {
            None
        } else {
            match trimmed.parse::<u16>() {
                Ok(p) => Some(p),
                Err(_) => return found(&format!("{base}?error=validation")),
            }
        }
    };
    // Empty means "keep current" (sending null keeps it on the api side).
    let password: Option<String> = if form.smtp_password.is_empty() {
        None
    } else {
        Some(form.smtp_password)
    };
    let body = serde_json::json!({
        "smtp_host": form.smtp_host,
        "smtp_port": port,
        "smtp_username": form.smtp_username,
        "smtp_password": password,
        "smtp_from_address": form.smtp_from_address,
        "smtp_use_tls": form.smtp_use_tls.is_some(),
        // Same rule as the SMTP password: empty means "do not change" (drop the key).
        "sms_gateway_url": form.sms_gateway_url,
        "sms_auth_header": form.sms_auth_header,
        "sms_auth_token": if form.sms_auth_token.is_empty() { None } else { Some(form.sms_auth_token) },
        "sms_sender_id": form.sms_sender_id,
    });
    match state
        .api
        .update_system_settings(&correlation.0, &tenant.0, &sso, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=validation")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

/// DB override of a runtime setting (`POST /{tenant_id}/admin/system-settings/runtime`).
/// An empty `value` removes the override (back to default/environment variable). A restart is needed to apply it.
pub async fn update_runtime(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminRuntimeSettingForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{SETTINGS_SEGMENT}", tenant.prefix());
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let value = form.value.trim();
    let value = (!value.is_empty()).then_some(value);
    match state
        .api
        .update_runtime_setting(&correlation.0, &tenant.0, &sso, form.key.trim(), value)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1#runtime-settings")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => {
            found(&format!("{base}?error=runtime-validation#runtime-settings"))
        }
        // 409 = the format is valid, but the next startup would fail with that value (ADR-0017).
        Err(AdminApiError::Conflict(_)) => found(&format!(
            "{base}?error=runtime-not-bootable#runtime-settings"
        )),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "validation" => Some("admin-settings-error-validation"),
        "runtime-validation" => Some("admin-settings-error-runtime-validation"),
        "tenant-value-validation" => Some("admin-settings-error-tenant-value-validation"),
        // The format is valid, but startup would fail with that value (ADR-0017). Using the same wording as a format error
        // would keep operators suspecting the URL, never reaching the secret that is actually missing.
        "runtime-not-bootable" => Some("admin-settings-error-runtime-not-bootable"),
        "restart" => Some("admin-restart-error"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn internal_error(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        heading: None,
        message: &messages.get("admin-error-internal"),
        is_error: true,
        back_href: None,
        back_label: "",
    });
    (StatusCode::INTERNAL_SERVER_ERROR, Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::tenant_smtp_password;

    /// Empty keeps the current one, "delete" deletes it. ⚠ Saving after fixing only other fields does not delete the password.
    #[test]
    fn the_tenant_smtp_password_field_keeps_clears_or_sets() {
        assert_eq!(tenant_smtp_password(String::new(), false), None);
        assert_eq!(
            tenant_smtp_password("s3cret".into(), false),
            Some("s3cret".into())
        );
        assert_eq!(
            tenant_smtp_password(String::new(), true),
            Some(String::new())
        );
        // If "delete" is checked, delete even if the field contains something.
        assert_eq!(
            tenant_smtp_password("typo".into(), true),
            Some(String::new())
        );
    }
}
