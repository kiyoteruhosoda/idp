//! Admin console screen for login identifiers (`/{tenant_id}/admin/users/{user_id}/login-identifiers`. AP16).
//!
//! AP8 added a registry letting "one user have multiple login identifiers (alias username, email, phone number,
//! employee number)", but there was no screen and it could only be touched with curl. This setting decides
//! **which values the user can sign in with**, a surface the help desk touches routinely.
//!
//! Data operations are delegated to the api's `/admin/users/{user_id}/login-identifiers` by forwarding the SSO cookie.
//! HTML forms cannot send PATCH/DELETE, so they go through dedicated POST paths (`/{id}/active`, `/{id}/delete`)
//! and are converted to the api's PATCH/DELETE.
//!
//! # Show both the registered value and the matching key
//!
//! The api returns `display_value` (as registered) and `normalized_value` (the value actually matched). The screen
//! shows both. Seeing only one hides misconfigurations of identifiers whose notation varies, like phone numbers
//! (registering `03-1234-5678` but ending up with a different normalization).

use super::locale;
use crate::api_client::AdminApiError;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_token, console_csrf_valid};
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{
    render, LoginIdentifierRow, LoginIdentifierTypeOption, LoginIdentifiersConsole,
};
use crate::tenant::WebTenant;
use assay_contracts::admin::LOGIN_IDENTIFIER_TYPE_CODES;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Default, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub notice: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddForm {
    pub identifier_type: String,
    pub value: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ActiveForm {
    /// `"true"` / `"false"`. The form carries the target state (to match what the screen shows, rather than
    /// re-reading the current value from the api and flipping it).
    pub is_active: String,
    pub csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteForm {
    pub csrf_token: String,
}

/// Promotion is decided by the target row id alone, so nothing but the CSRF token needs to be carried.
#[derive(Debug, Deserialize)]
pub struct PromotePrimaryEmailForm {
    pub csrf_token: String,
}

pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Query(query): Query<ViewQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = sso(&headers);
    let (identifiers, mut error_key) = match state
        .api
        .list_login_identifiers(&correlation.0, &tenant.0, &sso, &user_id)
        .await
    {
        Ok(v) => (v, query.error.as_deref().and_then(error_key_for)),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (Vec::new(), Some("admin-settings-error-forbidden")),
        Err(AdminApiError::NotFound) => (Vec::new(), Some("admin-members-error-user-notfound")),
        Err(e) => {
            tracing::error!(error = %e, "failed to load login identifiers");
            (Vec::new(), Some("admin-error-internal"))
        }
    };
    error_key = error_key.or(query.error.as_deref().and_then(error_key_for));

    let messages = Messages::new(locale(&headers));
    // Resolve the kind's translation in Rust (building translation keys in the template would make it
    // impossible to verify the key exists at compile time or by search).
    let type_options: Vec<LoginIdentifierTypeOption> = LOGIN_IDENTIFIER_TYPE_CODES
        .iter()
        .map(|code| LoginIdentifierTypeOption {
            code,
            label: type_label(&messages, code),
        })
        .collect();
    let rows: Vec<LoginIdentifierRow> = identifiers
        .iter()
        .map(|i| LoginIdentifierRow {
            id: i.id.as_deref(),
            identifier_type: &i.identifier_type,
            type_label: type_label(&messages, &i.identifier_type),
            display_value: &i.display_value,
            normalized_value: &i.normalized_value,
            is_active: i.is_active,
            is_primary: i.is_primary,
            is_primary_email: i.is_primary_email,
        })
        .collect();

    Html(render(&LoginIdentifiersConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_token(&sso, state.config.csrf_secret()),
        user_id: &user_id,
        identifiers: &rows,
        type_options: &type_options,
        error_key,
        notice_key: query.notice.as_deref().and_then(notice_key_for),
    }))
    .into_response()
}

pub async fn add(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Form(form): Form<AddForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = base_path(&tenant, &user_id);
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let body = json!({
        "identifier_type": form.identifier_type.trim(),
        "value": form.value.trim(),
        "is_active": true,
    });
    match state
        .api
        .add_login_identifier(&correlation.0, &tenant.0, &sso, &user_id, body)
        .await
    {
        Ok(_) => found(&format!("{base}?notice=added")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

pub async fn set_active(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, String, String)>,
    Form(form): Form<ActiveForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = base_path(&tenant, &user_id);
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let is_active = form.is_active == "true";
    match state
        .api
        .set_login_identifier_active(
            &correlation.0,
            &tenant.0,
            &sso,
            &user_id,
            &identifier_id,
            is_active,
        )
        .await
    {
        Ok(_) if is_active => found(&format!("{base}?notice=enabled")),
        Ok(_) => found(&format!("{base}?notice=disabled")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

/// Promotes an alias email to the primary email (ADR-0052).
///
/// Only email rows that are not yet primary can be pressed (the template decides). The api has the same
/// condition, so pressing from a stale screen does not swap anything.
pub async fn promote_primary_email(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, String, String)>,
    Form(form): Form<PromotePrimaryEmailForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = base_path(&tenant, &user_id);
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .promote_primary_email(&correlation.0, &tenant.0, &sso, &user_id, &identifier_id)
        .await
    {
        Ok(_) => found(&format!("{base}?notice=primary-email")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, user_id, identifier_id)): Path<(String, String, String)>,
    Form(form): Form<DeleteForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = base_path(&tenant, &user_id);
    let sso = sso(&headers);
    if !console_csrf_valid(&sso, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .delete_login_identifier(&correlation.0, &tenant.0, &sso, &user_id, &identifier_id)
        .await
    {
        Ok(()) => found(&format!("{base}?notice=deleted")),
        Err(e) => found(&format!("{base}?error={}", error_code(&e))),
    }
}

fn base_path(tenant: &WebTenant, user_id: &str) -> String {
    format!(
        "{}/admin/users/{user_id}/login-identifiers",
        tenant.prefix()
    )
}

/// Translation of a kind code. Unknown codes (e.g. right after the api adds a new kind) are shown as the code
/// — hiding a missing translation as a blank would make the kind look like it vanished from the screen.
fn type_label(messages: &Messages, code: &str) -> String {
    let key = match code {
        "username" => "admin-login-identifier-type-username",
        "email" => "admin-login-identifier-type-email",
        "phone_number" => "admin-login-identifier-type-phone-number",
        "employee_number" => "admin-login-identifier-type-employee-number",
        other => return other.to_string(),
    };
    messages.get(key)
}

fn error_code(e: &AdminApiError) -> &'static str {
    match e {
        AdminApiError::Forbidden => "forbidden",
        AdminApiError::Validation(_) => "validation",
        AdminApiError::Conflict(_) => "conflict",
        AdminApiError::NotFound => "notfound",
        _ => "internal",
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "validation" => Some("admin-login-identifiers-error-validation"),
        "conflict" => Some("admin-login-identifiers-error-conflict"),
        "notfound" => Some("admin-login-identifiers-error-not-found"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

fn notice_key_for(notice: &str) -> Option<&'static str> {
    match notice {
        "added" => Some("admin-login-identifiers-added"),
        "enabled" => Some("admin-login-identifiers-enabled-done"),
        "disabled" => Some("admin-login-identifiers-disabled-done"),
        "deleted" => Some("admin-login-identifiers-deleted"),
        "primary-email" => Some("admin-login-identifiers-primary-email-done"),
        _ => None,
    }
}

fn sso(headers: &HeaderMap) -> String {
    crate::cookies::get(headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

    /// The kind dropdown options use the contracts vocabulary (= the api's stored values) as is,
    /// and all have translations. Without a translation the code would show on screen as is.
    #[test]
    fn every_identifier_type_code_has_a_label_in_both_locales() {
        for locale in [Locale::Ja, Locale::En] {
            let messages = Messages::new(locale);
            for code in LOGIN_IDENTIFIER_TYPE_CODES {
                let label = type_label(&messages, code);
                assert_ne!(
                    &label.as_str(),
                    code,
                    "{locale:?}: no translation for identifier type {code}"
                );
                assert!(!label.is_empty());
            }
        }
    }

    /// Unknown codes are shown as the code (a missing translation is not hidden as a blank).
    #[test]
    fn an_unknown_identifier_type_falls_back_to_its_code() {
        let messages = Messages::new(Locale::Ja);
        assert_eq!(type_label(&messages, "passport_number"), "passport_number");
    }
}
