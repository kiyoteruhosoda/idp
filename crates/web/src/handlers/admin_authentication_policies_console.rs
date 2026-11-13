//! Admin console screen for authentication policies (`/{tenant_id}/admin/authentication-policies`, AP1).
//!
//! Until now authentication policies (deny / require_mfa / allow / require_specific_method, plus the network zone,
//! time window and `acr_values` conditions added in AP3) could only be set via the API. Having **settings that stop
//! logins** reachable only by curl forces operators onto curl both to check misconfigurations and to roll back.
//!
//! Data operations are delegated to the api's `/admin/authentication-policies` by forwarding the SSO cookie. HTML forms
//! cannot send PUT/DELETE, so updates and deletes go through dedicated POST paths (`/{id}/update`, `/{id}/delete`)
//! and are converted to PUT/DELETE on the api (same scheme as the SAML SP screen).
//!
//! # Implications of updates being full replacement
//!
//! An api update replaces all fields, so **fields the form could not show are lost on save**. That is why the
//! variable-length conditions (target clients, users, CIDRs, `acr_values`, time windows) round-trip through text areas;
//! formatting and parsing are collected in [`crate::authentication_policy_form`]. If even one time window line
//! cannot be parsed, the save itself is rejected (saving only the parsed lines would silently drop conditions you wrote).

use super::locale;
use crate::api_client::AdminApiError;
use crate::authentication_policy_form::{
    format_list, format_time_windows, parse_list, parse_time_windows, selected_methods,
};
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::dto::{AdminAuthenticationPolicyDeleteForm, AdminAuthenticationPolicyForm};
use crate::handlers::admin_console::{redirect_to_login, resolve_admin, AdminResolution};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, AuthenticationPoliciesConsole, AuthenticationPolicyFormValues};
use crate::tenant::WebTenant;
use assay_contracts::admin::{
    AuthenticationPolicyResponse, AuthenticationPolicyUpsertRequest, RequiredMethodsPayload,
    AUTHENTICATION_METHOD_CODES,
};
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

/// Selectable effects (the api's allowed `effect` values, in display order).
const EFFECT_OPTIONS: &[&str] = &["allow", "deny", "require_mfa", "require_specific_method"];

#[derive(Debug, Default, Deserialize)]
pub struct AuthenticationPolicyQuery {
    /// Policy ID to edit (when given, the form opens in edit mode).
    #[serde(default)]
    pub edit: Option<String>,
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub updated: Option<String>,
    #[serde(default)]
    pub deleted: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn list(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<AuthenticationPolicyQuery>,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(uid) => uid,
        AdminResolution::Reject(resp) => return resp,
    };
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    let result = state
        .api
        .list_authentication_policies(&correlation.0, &tenant.0, &sso)
        .await;
    let (policies, default_effect, mut error_key) = match result {
        Ok(response) => (
            response.policies,
            Some(response.default_effect),
            query.error.as_deref().and_then(error_key_for),
        ),
        Err(AdminApiError::Unauthorized) => return redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => (Vec::new(), None, Some("admin-settings-error-forbidden")),
        Err(_) => (Vec::new(), None, Some("admin-error-internal")),
    };

    // Edit mode: pick the target from the list as the form's initial values (no extra round trip to the api).
    let editing = query.edit.as_deref().filter(|id| !id.is_empty());
    let (editing_id, values) = match editing {
        Some(id) => match policies.iter().find(|p| p.id == id) {
            Some(policy) => (Some(policy.id.as_str()), values_from(policy)),
            None => {
                // ID not in the list (deleted, another tenant). Fall back to the create form and show the reason.
                error_key = error_key.or(Some("admin-auth-policy-error-not-found"));
                (None, AuthenticationPolicyFormValues::default())
            }
        },
        None => (None, AuthenticationPolicyFormValues::default()),
    };

    let messages = Messages::new(locale(&headers));
    Html(render(&AuthenticationPoliciesConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf: &console_csrf_from(&headers, state.config.csrf_secret()),
        // The tenant's value (from the api response). Not taken from web's settings (ADR-0058 §10).
        default_effect: default_effect.as_deref(),
        saved: query.saved.is_some(),
        updated: query.updated.is_some(),
        deleted: query.deleted.is_some(),
        error_key,
        editing: editing_id,
        form_open: editing_id.is_some() || error_key.is_some(),
        effect_options: EFFECT_OPTIONS,
        method_options: AUTHENTICATION_METHOD_CODES,
        values: &values,
        policies: &policies,
    }))
    .into_response()
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<AdminAuthenticationPolicyForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/authentication-policies", tenant.prefix());
    let values = values_from_form(&form);
    let body = match validate(&state, &headers, form) {
        Ok(body) => body,
        // **Do not discard the input.** Redirecting back would re-show a form with defaults, forcing everything to be
        // re-entered to fix one field (conditions are multi-line text areas, so rewriting is costly).
        Err(error) => return reshow(&state, &headers, &tenant, None, values, error),
    };
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state
        .api
        .create_authentication_policy(&correlation.0, &tenant.0, &sso, body)
        .await
    {
        Ok(_) => found(&format!("{base}?saved=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(e) => reshow(&state, &headers, &tenant, None, values, api_error_code(&e)),
    }
}

pub async fn update(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Path((_tenant_id, policy_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<AdminAuthenticationPolicyForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/authentication-policies", tenant.prefix());
    let values = values_from_form(&form);
    let body = match validate(&state, &headers, form) {
        // On input errors, re-show the edit form **with the input as entered** (resetting to defaults forces re-entry).
        Err(error) => return reshow(&state, &headers, &tenant, Some(&policy_id), values, error),
        Ok(body) => body,
    };
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state
        .api
        .update_authentication_policy(&correlation.0, &tenant.0, &sso, &policy_id, body)
        .await
    {
        Ok(_) => found(&format!("{base}?updated=1")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(e) => reshow(
            &state,
            &headers,
            &tenant,
            Some(&policy_id),
            values,
            api_error_code(&e),
        ),
    }
}

pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Path((_tenant_id, policy_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<AdminAuthenticationPolicyDeleteForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}/admin/authentication-policies", tenant.prefix());
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let sso = crate::cookies::get(&headers, crate::cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state
        .api
        .delete_authentication_policy(&correlation.0, &tenant.0, &sso, &policy_id)
        .await
    {
        Ok(()) => found(&format!("{base}?deleted=1")),
        Err(e) => found(&format!("{base}?error={}", api_error_code(&e))),
    }
}

/// Re-shows a rejected submission in the form **with the values as entered** (422).
///
/// Not PRG (redirect and re-show via GET) because a redirect cannot carry the input values,
/// forcing everything to be re-entered to fix one field. Reloading resubmits, but the input remains
/// — saving here is idempotent (full replacement), so the only harm of resubmission is "saving the same content again".
fn reshow(
    state: &WebState,
    headers: &HeaderMap,
    tenant: &WebTenant,
    editing: Option<&str>,
    values: AuthenticationPolicyFormValues,
    error: &'static str,
) -> Response {
    let messages = Messages::new(locale(headers));
    let html = render(&AuthenticationPoliciesConsole {
        messages: &messages,
        tenant: &tenant.prefix(),
        // Being an admin was already checked at re-display time (each handler's entry). Do not call the api again
        // just for the display label.
        admin: None,
        csrf: &console_csrf_from(headers, state.config.csrf_secret()),
        // This screen shows no list, so it does not show the default behavior either (no api call just for the value).
        default_effect: None,
        saved: false,
        updated: false,
        deleted: false,
        error_key: error_key_for(error),
        editing,
        form_open: true,
        effect_options: EFFECT_OPTIONS,
        method_options: AUTHENTICATION_METHOD_CODES,
        values: &values,
        // No list is shown (a screen for fixing rejected input; no extra round trips to the api).
        policies: &[],
    });
    (StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response()
}

/// Maps a submitted form directly to display values (for re-display on rejection).
fn values_from_form(form: &AdminAuthenticationPolicyForm) -> AuthenticationPolicyFormValues {
    AuthenticationPolicyFormValues {
        policy_code: form.policy_code.clone(),
        policy_name: form.policy_name.clone(),
        priority: form.priority.clone(),
        enabled: form.enabled.is_some(),
        effect: form.effect.clone(),
        methods: selected_methods(form),
        user_verification: form.user_verification.is_some(),
        application_ids: form.application_ids.clone(),
        user_ids: form.user_ids.clone(),
        ip_cidrs: form.ip_cidrs.clone(),
        time_windows: form.time_windows.clone(),
        requested_acr: form.requested_acr.clone(),
    }
}

/// Maps the form to the shape sent to the api. Checks CSRF and the input validity web can judge here
/// (validity of the values themselves — code characters, CIDR shape, consistency of effect and `effect_params` — is
/// decided finally by the api. Writing it twice would hide it when only one side gets loosened).
fn validate(
    state: &WebState,
    headers: &HeaderMap,
    form: AdminAuthenticationPolicyForm,
) -> Result<AuthenticationPolicyUpsertRequest, &'static str> {
    if !console_csrf_valid_in(headers, &form.csrf_token, state.config.csrf_secret()) {
        return Err("csrf");
    }
    if form.policy_code.trim().is_empty() || form.policy_name.trim().is_empty() {
        return Err("validation");
    }
    let priority: i32 = form.priority.trim().parse().map_err(|_| "priority")?;
    let time_windows = parse_time_windows(&form.time_windows).map_err(|_| "time-window")?;
    let methods = selected_methods(&form);
    let user_verification = form.user_verification.is_some();
    // The api rejects required methods sent with an effect other than `require_specific_method`. To avoid the mix-up of
    // a checkbox merely left checked after switching the effect, drop them on the sending side.
    let effect_params =
        (form.effect == "require_specific_method").then_some(RequiredMethodsPayload {
            methods,
            user_verification,
        });
    Ok(AuthenticationPolicyUpsertRequest {
        policy_code: form.policy_code.trim().to_string(),
        policy_name: form.policy_name.trim().to_string(),
        priority,
        enabled: form.enabled.is_some(),
        effect: form.effect,
        effect_params,
        application_ids: parse_list(&form.application_ids),
        user_ids: parse_list(&form.user_ids),
        ip_cidrs: parse_list(&form.ip_cidrs),
        time_windows,
        requested_acr: parse_list(&form.requested_acr),
    })
}

/// Maps the api response (`AuthenticationPolicyResponse`) back to the form's initial values.
fn values_from(policy: &AuthenticationPolicyResponse) -> AuthenticationPolicyFormValues {
    let (methods, user_verification) = match &policy.effect_params {
        Some(params) => (params.methods.clone(), params.user_verification),
        None => (Vec::new(), false),
    };
    AuthenticationPolicyFormValues {
        policy_code: policy.policy_code.clone(),
        policy_name: policy.policy_name.clone(),
        priority: policy.priority.to_string(),
        enabled: policy.enabled,
        effect: policy.effect.clone(),
        methods,
        user_verification,
        application_ids: format_list(&policy.application_ids),
        user_ids: format_list(&policy.user_ids),
        ip_cidrs: format_list(&policy.ip_cidrs),
        time_windows: format_time_windows(&policy.time_windows),
        requested_acr: format_list(&policy.requested_acr),
    }
}

fn api_error_code(error: &AdminApiError) -> &'static str {
    match error {
        AdminApiError::Unauthorized => "session",
        AdminApiError::Forbidden => "forbidden",
        AdminApiError::Validation(_) => "validation",
        AdminApiError::Conflict(_) => "conflict",
        AdminApiError::NotFound => "not-found",
        AdminApiError::Transport(_) => "internal",
    }
}

fn error_key_for(code: &str) -> Option<&'static str> {
    match code {
        "csrf" => Some("login-error-csrf-retry"),
        "validation" => Some("admin-auth-policy-error-validation"),
        "priority" => Some("admin-auth-policy-error-priority"),
        "time-window" => Some("admin-auth-policy-error-time-window"),
        "conflict" => Some("admin-auth-policy-error-conflict"),
        "not-found" => Some("admin-auth-policy-error-not-found"),
        "forbidden" => Some("admin-settings-error-forbidden"),
        "session" => Some("admin-error-session"),
        _ => Some("admin-error-internal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assay_contracts::admin::TimeWindowPayload;

    fn policy() -> AuthenticationPolicyResponse {
        AuthenticationPolicyResponse {
            id: "p1".to_string(),
            policy_code: "office-hours".to_string(),
            policy_name: "Office hours".to_string(),
            priority: 10,
            enabled: true,
            effect: "require_specific_method".to_string(),
            effect_params: Some(RequiredMethodsPayload {
                methods: vec!["webauthn".to_string()],
                user_verification: true,
            }),
            application_ids: vec![
                "01990000-0000-7000-8000-000000000001".to_string(),
                "01990000-0000-7000-8000-000000000002".to_string(),
            ],
            user_ids: Vec::new(),
            ip_cidrs: vec!["10.0.0.0/8".to_string()],
            time_windows: vec![TimeWindowPayload {
                days: vec![1, 2, 3, 4, 5],
                start_minute: 540,
                end_minute: 1080,
                utc_offset_minutes: 540,
            }],
            requested_acr: Vec::new(),
            created_at: "2026-08-10T00:00:00Z".to_string(),
            updated_at: "2026-08-10T00:00:00Z".to_string(),
        }
    }

    /// The edit form shows **all fields**. Any field it cannot show would lose that condition on a full-replacement save.
    #[test]
    fn edit_values_carry_every_condition_back_into_the_form() {
        let values = values_from(&policy());
        assert_eq!(values.policy_code, "office-hours");
        assert_eq!(values.priority, "10");
        assert!(values.enabled);
        assert_eq!(values.effect, "require_specific_method");
        assert!(values.has_method("webauthn"));
        assert!(values.user_verification);
        assert_eq!(
            values.application_ids,
            "01990000-0000-7000-8000-000000000001\n01990000-0000-7000-8000-000000000002"
        );
        assert_eq!(values.ip_cidrs, "10.0.0.0/8");
        assert_eq!(
            values.time_windows,
            "mon,tue,wed,thu,fri 09:00-18:00 +09:00"
        );
    }

    #[test]
    fn unknown_effects_are_labelled_instead_of_being_shown_untranslated() {
        let messages = Messages::new(crate::i18n::Locale::Ja);
        let console = AuthenticationPoliciesConsole {
            messages: &messages,
            tenant: "/t",
            admin: Some(crate::templates::ConsoleAdmin {
                label: "admin-1",
                tenant_name: Some("Acme"),
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
            csrf: "csrf",
            default_effect: Some("allow"),
            saved: false,
            updated: false,
            deleted: false,
            error_key: None,
            editing: None,
            form_open: false,
            effect_options: EFFECT_OPTIONS,
            method_options: AUTHENTICATION_METHOD_CODES,
            values: &AuthenticationPolicyFormValues::default(),
            policies: &[],
        };
        assert_eq!(
            console.effect_label("something_new"),
            "admin-auth-policy-effect-unknown"
        );
        assert_eq!(
            console.effect_label("deny"),
            "admin-auth-policy-effect-deny"
        );
    }

    /// A policy with no conditions **applies to everyone**. A blank would read as "not configured",
    /// so explicit wording is shown.
    #[test]
    fn a_policy_without_conditions_says_it_matches_everyone() {
        let messages = Messages::new(crate::i18n::Locale::Ja);
        let console = AuthenticationPoliciesConsole {
            messages: &messages,
            tenant: "/t",
            admin: Some(crate::templates::ConsoleAdmin {
                label: "admin-1",
                tenant_name: Some("Acme"),
                permissions: &[],
                csrf_token: "test-console-csrf",
            }),
            csrf: "csrf",
            default_effect: Some("allow"),
            saved: false,
            updated: false,
            deleted: false,
            error_key: None,
            editing: None,
            form_open: false,
            effect_options: EFFECT_OPTIONS,
            method_options: AUTHENTICATION_METHOD_CODES,
            values: &AuthenticationPolicyFormValues::default(),
            policies: &[],
        };
        let mut bare = policy();
        bare.application_ids.clear();
        bare.ip_cidrs.clear();
        bare.time_windows.clear();
        assert_eq!(
            console.condition_summary(&bare),
            messages.get("admin-auth-policy-condition-any")
        );
        assert_eq!(
            console.condition_summary(&policy()),
            "app×2 / network×1 / time×1"
        );
    }
}
