//! 利用者の作成・検索・権限付与/剥奪のサーバレンダリング画面（web。A2・ADR-0006・ADR-0009 §5・
//! ADR-0007 §4）。
//!
//! api の JSON 管理 API（利用者作成・検索・取得・権限一覧/付与/剥奪・付与可能コード）を管理者の SSO
//! Cookie 転送で呼び、結果を HTML に描画する。作成・付与・剥奪の POST は Post/Redirect/Get で処理し、
//! エラーは各画面へ `error` クエリで伝える。CSRF は `console_csrf_token`、HTML は Askama テンプレートが
//! 自動エスケープする。

use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
use crate::handlers::admin_console::{
    forbidden_response, redirect_to_login, resolve_admin, AdminResolution,
};
use crate::handlers::found;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, ConsoleNotice, UserCreated, UserForm, UsersPermissions, UsersSearch};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::admin::UserSummaryResponse;
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

// ── 利用者作成 ────────────────────────────────────────────────────────────────

pub async fn new_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    Html(render_new_form(
        &messages, &tenant, &admin, &csrf, "", "", "", None,
    ))
    .into_response()
}

#[allow(clippy::too_many_arguments)]
fn render_new_form_with_message(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    csrf: &str,
    email: &str,
    preferred_username: &str,
    name: &str,
    error: &str,
) -> String {
    render(&UserForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        csrf,
        error: Some(error),
        email,
        preferred_username,
        name,
    })
}

#[derive(Debug, Deserialize)]
pub struct NewUserForm {
    pub email: String,
    #[serde(default)]
    pub preferred_username: String,
    #[serde(default)]
    pub name: String,
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

    if !csrf_valid(&headers, &form.csrf_token) {
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers);
        return bad_request_form(render_new_form(
            &messages,
            &tenant,
            &admin,
            &csrf,
            &form.email,
            &form.preferred_username,
            &form.name,
            Some("admin-error-csrf"),
        ));
    }

    let body = serde_json::json!({
        "email": form.email,
        "preferred_username": normalize(&form.preferred_username),
        "name": normalize(&form.name),
    });
    let result = state
        .api
        .create_user(&correlation.0, &tenant.0, &sso(&headers), body)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(created) => Html(render(&UserCreated {
            messages: &messages,
            tenant: &tenant.prefix(),
            admin: Some(&admin),
            email: &form.email,
            generated_password: &created.generated_password,
        }))
        .into_response(),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => {
            let csrf = csrf_from(&headers);
            bad_request_form(render_new_form_with_message(
                &messages,
                &tenant,
                &admin,
                &csrf,
                &form.email,
                &form.preferred_username,
                &form.name,
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

// ── 利用者検索 ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: Option<String>,
}

pub async fn search(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let term = query.q.unwrap_or_default();

    if term.trim().is_empty() {
        let messages = Messages::new(locale(&headers));
        return Html(render_search(&messages, &tenant, &admin, &term, SearchResult::Empty))
            .into_response();
    }
    let result = state
        .api
        .search_user(&correlation.0, &tenant.0, &sso(&headers), &term)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(user) => Html(render_search(
            &messages,
            &tenant,
            &admin,
            &term,
            SearchResult::Found(&user),
        ))
        .into_response(),
        Err(AdminApiError::NotFound) => Html(render_search(
            &messages,
            &tenant,
            &admin,
            &term,
            SearchResult::NotFound,
        ))
        .into_response(),
        Err(e) => map_data_error(&messages, &tenant, &admin, &headers, e),
    }
}

// ── 権限画面 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn view(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(query): Query<ViewQuery>,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let sso = sso(&headers);

    let user = match state.api.get_user(&correlation.0, &tenant.0, &sso, &user_id).await {
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
    let available = state
        .api
        .available_permissions(&correlation.0, &tenant.0, &sso)
        .await
        .map(|a| a.codes)
        .unwrap_or_default();

    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    let error_key = query.error.as_deref().and_then(error_key_for);
    Html(render_permissions(
        &messages, &tenant, &admin, &user, &codes, &available, &csrf, error_key,
    ))
    .into_response()
}

// ── 付与・剥奪の実行（Post/Redirect/Get） ─────────────────────────────────────

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
    Path(user_id): Path<String>,
    Form(form): Form<PermissionForm>,
) -> Response {
    apply_change(&state, &correlation, &tenant, &headers, &user_id, &form, true).await
}

pub async fn revoke(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(form): Form<PermissionForm>,
) -> Response {
    apply_change(&state, &correlation, &tenant, &headers, &user_id, &form, false).await
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
    // 認可（whoami）。未認証/権限不足はここで誘導/403。
    match resolve_admin(state, correlation, tenant, headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{USERS_SEGMENT}/{user_id}/permissions", tenant.prefix());
    if !csrf_valid(headers, &form.csrf_token) {
        return found(&format!("{base}?error=csrf"));
    }
    let sso = sso(headers);
    let result = if grant {
        state
            .api
            .grant_permission(&correlation.0, &tenant.0, &sso, user_id, &form.permission_code)
            .await
    } else {
        state
            .api
            .revoke_permission(&correlation.0, &tenant.0, &sso, user_id, &form.permission_code)
            .await
    };
    match result {
        Ok(_) => found(&base),
        Err(AdminApiError::Unauthorized) => redirect_to_login(tenant),
        Err(AdminApiError::Forbidden) => forbidden_response(headers),
        Err(AdminApiError::Validation(_)) => found(&format!("{base}?error=code")),
        Err(AdminApiError::NotFound) => found(&format!("{base}?error=notfound")),
        Err(_) => found(&format!("{base}?error=internal")),
    }
}

fn error_key_for(error: &str) -> Option<&'static str> {
    match error {
        "csrf" => Some("admin-error-csrf"),
        "code" => Some("admin-permission-error-unknown"),
        "notfound" => Some("admin-user-not-found-message"),
        "internal" => Some("admin-error-internal"),
        _ => None,
    }
}

// ── CSRF ─────────────────────────────────────────────────────────────────────

fn sso(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default()
}

fn csrf_from(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s))
        .unwrap_or_default()
}

fn csrf_valid(headers: &HeaderMap, submitted: &str) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s) == submitted)
        .unwrap_or(false)
}

// ── レンダリング ──────────────────────────────────────────────────────────────

enum SearchResult<'a> {
    Empty,
    NotFound,
    Found(&'a UserSummaryResponse),
}

fn render_search(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    term: &str,
    result: SearchResult,
) -> String {
    let (user, not_found) = match result {
        SearchResult::Empty => (None, false),
        SearchResult::NotFound => (None, true),
        SearchResult::Found(user) => (Some(user), false),
    };
    render(&UsersSearch {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        term,
        user,
        not_found,
    })
}

#[allow(clippy::too_many_arguments)]
fn render_permissions(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    user: &UserSummaryResponse,
    codes: &[String],
    available: &[String],
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    render(&UsersPermissions {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        user,
        codes,
        available,
        csrf,
        error_key,
    })
}

#[allow(clippy::too_many_arguments)]
fn render_new_form(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
    csrf: &str,
    email: &str,
    preferred_username: &str,
    name: &str,
    error_key: Option<&str>,
) -> String {
    let error = error_key.map(|k| messages.get(k));
    render(&UserForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        csrf,
        error: error.as_deref(),
        email,
        preferred_username,
        name,
    })
}

// ── 共通ヘルパー ──────────────────────────────────────────────────────────────

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn not_found(messages: &Messages, tenant: &WebTenant, admin: &str) -> Response {
    let body = render(&ConsoleNotice {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin),
        heading: Some(&messages.get("admin-user-not-found-title")),
        message: &messages.get("admin-user-not-found-message"),
        is_error: false,
        back_href: Some(&format!("{}{USERS_SEGMENT}", tenant.prefix())),
        back_label: &messages.get("admin-users-back"),
    });
    (StatusCode::NOT_FOUND, Html(body)).into_response()
}

fn map_data_error(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &str,
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
                admin: Some(admin),
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

    #[test]
    fn search_result_escapes_user_fields() {
        let messages = Messages::new(Locale::En);
        let html = render_search(&messages, &tenant(), "admin-1", "alice", SearchResult::Found(&user()));
        // Askama は HTML を数値文字参照でエスケープする（`<` → `&#60;`）。生タグが残らないことを確認する。
        assert!(html.contains("&#60;b&#62;alice&#60;/b&#62;"));
        assert!(!html.contains("<b>alice"));
        assert!(html.contains("/permissions"));
    }

    #[test]
    fn permissions_lists_codes_and_grant_form() {
        let messages = Messages::new(Locale::En);
        let html = render_permissions(
            &messages,
            &tenant(),
            "admin-1",
            &user(),
            &["idp.admin".into()],
            &["idp.admin".into(), "idp.viewer".into()],
            "csrf123",
            None,
        );
        assert!(html.contains("idp.admin"));
        assert!(html.contains("permissions/grant"));
        assert!(html.contains("permissions/revoke"));
        assert!(html.contains("name=\"csrf_token\" value=\"csrf123\""));
    }

    #[test]
    fn new_form_renders_fields() {
        let messages = Messages::new(Locale::En);
        let html = render_new_form(&messages, &tenant(), "admin-1", "csrf1", "", "", "", None);
        assert!(html.contains("name=\"email\""));
        assert!(html.contains("name=\"preferred_username\""));
        assert!(html.contains("name=\"csrf_token\" value=\"csrf1\""));
    }
}
