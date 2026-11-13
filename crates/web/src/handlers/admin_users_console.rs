//! Server-rendered screens for creating users and granting/revoking permissions (web. A2, ADR-0006, ADR-0009 §5,
//! ADR-0007 §4). Listing and search start from the members screen (`/admin/members`); this module handles
//! creating individual users and managing their permissions.
//!
//! Calls the api's JSON admin APIs (user create/get, permission list/grant/revoke, grantable codes) by forwarding the
//! admin's SSO cookie and renders the results as HTML. Create/grant/revoke POSTs use Post/Redirect/Get, and
//! errors are conveyed to each screen via the `error` query. CSRF uses `console_csrf_token`; HTML is auto-escaped
//! by Askama templates.

use super::locale;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::{console_csrf_from, console_csrf_valid_in};
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminContext, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, ConsoleNotice, UserCreated, UserForm, UsersPermissions};
use crate::tenant::WebTenant;
use assay_contracts::admin::UserSummaryResponse;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

const USERS_SEGMENT: &str = "/admin/users";

macro_rules! admin_or_return {
    ($state:expr, $correlation:expr, $tenant:expr, $headers:expr) => {
        match resolve_admin($state, $correlation, $tenant, $headers).await {
            AdminResolution::Ok(uid) => uid,
            AdminResolution::Reject(resp) => return resp,
        }
    };
}

// ── User creation ────────────────────────────────────────────────────────────────

pub async fn new_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    Html(render_new_form(
        &messages,
        &tenant,
        &admin,
        &csrf,
        &NewUserDraft::default(),
        None,
    ))
    .into_response()
}

/// Input when returning to the create form (the typed content is kept even when returning with an error).
#[derive(Default)]
struct NewUserDraft<'a> {
    email: &'a str,
    preferred_username: &'a str,
    name: &'a str,
    /// Admin note (ADR-0063). Attached to the HOME membership at creation.
    note: &'a str,
}

impl<'a> From<&'a NewUserForm> for NewUserDraft<'a> {
    fn from(form: &'a NewUserForm) -> Self {
        Self {
            email: &form.email,
            preferred_username: &form.preferred_username,
            name: &form.name,
            note: &form.note,
        }
    }
}

fn render_new_form_with_message(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    csrf: &str,
    draft: &NewUserDraft,
    error: &str,
) -> String {
    render(&UserForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf,
        error: Some(error),
        email: draft.email,
        preferred_username: draft.preferred_username,
        name: draft.name,
        note: draft.note,
    })
}

#[derive(Debug, Deserialize)]
pub struct NewUserForm {
    pub email: String,
    #[serde(default)]
    pub preferred_username: String,
    #[serde(default)]
    pub name: String,
    /// Admin note (optional. ADR-0063).
    #[serde(default)]
    pub note: String,
    pub csrf_token: String,
}

pub async fn create(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<NewUserForm>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);

    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = console_csrf_from(&headers, state.config.csrf_secret());
        return bad_request_form(render_new_form(
            &messages,
            &tenant,
            &admin,
            &csrf,
            &NewUserDraft::from(&form),
            Some("admin-error-csrf"),
        ));
    }

    let body = serde_json::json!({
        "email": form.email,
        "preferred_username": normalize(&form.preferred_username),
        "name": normalize(&form.name),
        // Not sent if empty (the api also treats empty as no note).
        "note": normalize(&form.note),
    });
    // Carry over the resolved language so the api's validation/conflict messages show on this screen (MT20).
    let result = state
        .api
        .for_locale(locale(&headers))
        .create_user(&correlation.0, &tenant.0, &sso(&headers), body)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(created) => Html(render(&UserCreated {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(admin.chrome()),
            email: &form.email,
            setup_url: &created.setup_url,
            setup_expires_at: &created.setup_expires_at,
        }))
        .into_response(),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => {
            let csrf = console_csrf_from(&headers, state.config.csrf_secret());
            bad_request_form(render_new_form_with_message(
                &messages,
                &tenant,
                &admin,
                &csrf,
                &NewUserDraft::from(&form),
                &m,
            ))
        }
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

fn normalize(s: &str) -> Option<&str> {
    let s = s.trim();
    (!s.is_empty()).then_some(s)
}

// ── Permissions screen ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
    /// Completion notice (Post/Redirect/Get. `profile` = profile saved. MT25).
    #[serde(default)]
    pub saved: Option<String>,
}

pub async fn view(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Query(query): Query<ViewQuery>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);

    let user = match state
        .api
        .get_user(&correlation.0, &tenant.0, &sso, &user_id)
        .await
    {
        Ok(u) => u,
        Err(AdminApiError::NotFound) => {
            let messages = Messages::new(locale(&headers));
            return not_found(&messages, &tenant, &admin);
        }
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            return map_data_error(&messages, &tenant, &admin, &headers, e);
        }
    };
    let codes = match state
        .api
        .list_user_permissions(&correlation.0, &tenant.0, &sso, &user_id)
        .await
    {
        Ok(p) => p.permission_codes,
        Err(e) => {
            let messages = Messages::new(locale(&headers));
            return map_data_error(&messages, &tenant, &admin, &headers, e);
        }
    };
    // Grantable codes (the `permissions` master) are the source of the options. Even if fetching fails, the screen
    // is still rendered (checking/revoking held permissions can continue), and only the grant field reports the failure.
    let (available, available_load_failed) = match state
        .api
        .available_permissions(&correlation.0, &tenant.0, &sso)
        .await
    {
        Ok(a) => (a.codes, false),
        Err(e) => {
            tracing::warn!(error = %e, "failed to load grantable permission codes");
            (Vec::new(), true)
        }
    };
    // Exclude already-held codes from the options (do not show operations that change nothing).
    let grantable: Vec<String> = available
        .into_iter()
        .filter(|code| !codes.contains(code))
        .collect();

    let messages = Messages::new(locale(&headers));
    let csrf = console_csrf_from(&headers, state.config.csrf_secret());
    let error_key = query.error.as_deref().and_then(error_key_for);
    Html(render_permissions(
        &messages,
        &tenant,
        &admin,
        &user,
        &codes,
        &grantable,
        available_load_failed,
        &csrf,
        error_key,
        query.saved.as_deref() == Some("profile"),
    ))
    .into_response()
}

// ── Profile editing (MT25) ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProfileForm {
    pub email: String,
    #[serde(default)]
    pub preferred_username: String,
    #[serde(default)]
    pub name: String,
    pub csrf_token: String,
}

/// Updates a user's profile (`POST /{tenant_id}/admin/users/{user_id}/profile`. MT25).
/// Delegates to the api's `PATCH /admin/users/{user_id}/profile` and returns to the details screen via Post/Redirect/Get.
/// Validation (email format, length, uniqueness) has the api as its single source; web only maps the result to an error query.
pub async fn update_profile(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<ProfileForm>,
) -> Response {
    match resolve_admin(&state, &correlation, &tenant, &headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{USERS_SEGMENT}/{user_id}/permissions", tenant.prefix());
    if !console_csrf_valid_in(&headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    match state
        .api
        .update_user_profile(
            &correlation.0,
            &tenant.0,
            &sso(&headers),
            &user_id,
            serde_json::json!({
                "email": form.email.trim(),
                "preferred_username": form.preferred_username.trim(),
                "name": form.name.trim(),
            }),
        )
        .await
    {
        Ok(_) => found(&format!("{base}?saved=profile")),
        Err(AdminApiError::Unauthorized) => redirect_to_login(&tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(&headers),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=profile-invalid")),
        Err(AdminApiError::Conflict(_)) => found(&format!("{base}?error=profile-conflict")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

// ── Executing grant/revoke (Post/Redirect/Get) ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PermissionForm {
    pub permission_code: String,
    pub csrf_token: String,
}

pub async fn grant(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<PermissionForm>,
) -> Response {
    apply_change(
        &state,
        &correlation,
        &tenant,
        &headers,
        &user_id,
        &form,
        true,
    )
    .await
}

pub async fn revoke(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_, user_id)): Path<(String, String)>,
    Form(form): Form<PermissionForm>,
) -> Response {
    apply_change(
        &state,
        &correlation,
        &tenant,
        &headers,
        &user_id,
        &form,
        false,
    )
    .await
}

async fn apply_change(
    state: &WebState,
    correlation: &CorrelationId,
    tenant: &WebTenant,
    headers: &HeaderMap,
    user_id: &str,
    form: &PermissionForm,
    grant: bool,
) -> Response {
    // Authorization (whoami). Unauthenticated/insufficient permissions are redirected/403 here.
    match resolve_admin(state, correlation, tenant, headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{USERS_SEGMENT}/{user_id}/permissions", tenant.prefix());
    if !console_csrf_valid_in(headers, &form.csrf_token, state.config.csrf_secret()) {
        return found(&format!("{base}?error=csrf"));
    }
    let sso = sso(headers);
    let result = if grant {
        state
            .api
            .grant_permission(
                &correlation.0,
                &tenant.0,
                &sso,
                user_id,
                &form.permission_code,
            )
            .await
    } else {
        state
            .api
            .revoke_permission(
                &correlation.0,
                &tenant.0,
                &sso,
                user_id,
                &form.permission_code,
            )
            .await
    };
    match result {
        Ok(_) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(tenant),
        // 403 here means not "no permission to view this screen" but "**this grant/revoke is not allowed**"
        // (the screen itself passed `resolve_admin`). Falling back to the 403 page would disguise the cause as
        // "you do not have permission to view this page", so return to the permissions screen's error field.
        Err(AdminApiError::Forbidden) => found(&format!("{base}?error=forbidden")),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=code")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "code" => Some("admin-permission-error-unknown"),
        "forbidden" => Some("admin-permission-error-forbidden"),
        "notfound" => Some("admin-user-not-found-message"),
        "profile-invalid" => Some("admin-users-profile-error-invalid"),
        "profile-conflict" => Some("admin-users-profile-error-conflict"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

// ── CSRF ─────────────────────────────────────────────────────────────────────

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

// ── Rendering ──────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn render_permissions(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    user: &UserSummaryResponse,
    codes: &[String],
    grantable: &[String],
    available_load_failed: bool,
    csrf: &str,
    error_key: Option<&str>,
    saved: bool,
) -> String {
    render(&UsersPermissions {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        user,
        codes,
        grantable,
        available_load_failed,
        csrf,
        error_key,
        saved,
    })
}

#[allow(clippy::too_many_arguments)]
fn render_new_form(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    csrf: &str,
    draft: &NewUserDraft,
    error_key: Option<&str>,
) -> String {
    let error = error_key.map(|k| messages.get(k));
    render(&UserForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf,
        error: error.as_deref(),
        email: draft.email,
        preferred_username: draft.preferred_username,
        name: draft.name,
        note: draft.note,
    })
}

// ── Shared helpers ──────────────────────────────────────────────────────────────

fn not_found(messages: &Messages, tenant: &WebTenant, admin: &AdminContext) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        heading: Some(&messages.get("admin-user-not-found-title")),
        message: &messages.get("admin-user-not-found-message"),
        is_error: false,
        back_href: Some(&format!("{}/admin/members", tenant.prefix())),
        back_label: &messages.get("admin-members-back"),
    });
    (StatusCode::NOT_FOUND, Html(body)).into_response()
}

fn map_data_error(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    headers: &HeaderMap,
    e: AdminApiError,
) -> Response {
    match e {
        AdminApiError::Unauthorized => redirect_to_login(tenant),
        AdminApiError::Forbidden => forbidden_response(headers),
        AdminApiError::NotFound => not_found(messages, tenant, admin),
        _ => {
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
    }
}

fn bad_request_form(html: String) -> Response {
    (StatusCode::BAD_REQUEST, Html(html)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

    fn tenant() -> WebTenant {
        WebTenant("00000000-0000-7000-8000-000000000000".to_string())
    }

    fn user() -> UserSummaryResponse {
        UserSummaryResponse {
            id: "11111111-1111-1111-1111-111111111111".into(),
            sub: "22222222-2222-2222-2222-222222222222".into(),
            email: "u@example.com".into(),
            email_verified: true,
            preferred_username: Some("<b>alice</b>".into()),
            name: None,
            status: "ACTIVE".into(),
        }
    }

    fn permissions_html(grantable: &[String], available_load_failed: bool) -> String {
        let messages = Messages::new(Locale::Ja);
        render_permissions(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            &user(),
            &["idp.admin".into()],
            grantable,
            available_load_failed,
            "csrf123",
            None,
            false,
        )
    }

    #[test]
    fn permissions_lists_codes_and_grant_form() {
        let html = permissions_html(&["idp.viewer".into()], false);
        assert!(html.contains("idp.admin"));
        assert!(html.contains("permissions/grant"));
        assert!(html.contains("permissions/revoke"));
        assert!(html.contains("name=\"csrf_token\" value=\"csrf123\""));
    }

    /// Granting is a selection, not free input (so typos cannot send unknown codes). Already-held codes are
    /// not offered, and when candidates run out the form itself is not shown.
    #[test]
    fn grant_offers_a_select_of_grantable_codes_only() {
        let html = permissions_html(&["idp.viewer".into()], false);
        assert!(html.contains(r#"<select class="form-select" id="permission-code" name="permission_code" required>"#), "{html}");
        assert!(
            html.contains(r#"<option value="idp.viewer">idp.viewer</option>"#),
            "{html}"
        );
        // Already held (`idp.admin`) is not offered.
        assert!(!html.contains(r#"<option value="idp.admin">"#), "{html}");
        // No free input field or datalist remains.
        assert!(!html.contains(r#"list="admin-permission-codes""#), "{html}");

        let html = permissions_html(&[], false);
        assert!(
            html.contains(&Messages::new(Locale::Ja).get("admin-permissions-grant-none-left")),
            "{html}"
        );
        assert!(!html.contains("permissions/grant"), "{html}");
    }

    /// When candidates could not be fetched, report it as a fetch failure so it is not mistaken for "no candidates".
    #[test]
    fn grant_reports_a_failed_lookup_instead_of_showing_no_candidates() {
        let messages = Messages::new(Locale::Ja);
        let html = permissions_html(&[], true);
        assert!(
            html.contains(&messages.get("admin-permissions-grant-load-failed")),
            "{html}"
        );
        assert!(
            !html.contains(&messages.get("admin-permissions-grant-none-left")),
            "{html}"
        );
    }

    #[test]
    fn new_form_renders_fields() {
        let messages = Messages::new(Locale::Ja);
        let html = render_new_form(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            "csrf1",
            &NewUserDraft::default(),
            None,
        );
        assert!(html.contains("name=\"email\""));
        assert!(html.contains("name=\"preferred_username\""));
        assert!(html.contains("name=\"csrf_token\" value=\"csrf1\""));
        assert!(
            html.contains("name=\"note\""),
            "a note can be written at creation: {html}"
        );
        assert!(html.contains("maxlength=\"2000\""), "{html}");
    }

    /// ADR-0063: when returning with an input error, the written note is kept (no need to rewrite the background).
    #[test]
    fn the_note_survives_a_rejected_submission() {
        let messages = Messages::new(Locale::Ja);
        let draft = NewUserDraft {
            email: "dup@example.com",
            note: "家族として作成 <b>",
            ..NewUserDraft::default()
        };
        let html = render_new_form_with_message(
            &messages,
            &tenant(),
            &AdminContext::for_test("admin-1", Some("Acme")),
            "csrf1",
            &draft,
            "そのメールアドレスは既に使われています。",
        );
        assert!(html.contains("家族として作成"), "{html}");
        assert!(
            !html.contains("家族として作成 <b>"),
            "the note must always be escaped: {html}"
        );
    }
}
