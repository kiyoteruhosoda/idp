//! 利用者の作成・権限付与/剥奪のサーバレンダリング画面（web。A2・ADR-0006・ADR-0009 §5・
//! ADR-0007 §4）。一覧・検索の起点はメンバー画面（`/admin/members`）で、本モジュールは個別利用者の
//! 作成と権限管理を担う。
//!
//! api の JSON 管理 API（利用者作成・取得・権限一覧/付与/剥奪・付与可能コード）を管理者の SSO
//! Cookie 転送で呼び、結果を HTML に描画する。作成・付与・剥奪の POST は Post/Redirect/Get で処理し、
//! エラーは各画面へ `error` クエリで伝える。CSRF は `console_csrf_token`、HTML は Askama テンプレートが
//! 自動エスケープする。

use super::locale;
use crate::api_client::AdminApiError;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::console_csrf_token;
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

// ── 利用者作成 ────────────────────────────────────────────────────────────────

pub async fn new_form(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let admin = admin_or_return!(&state, &correlation, &tenant, &headers);
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
    Html(render_new_form(
        &messages, &tenant, &admin, &csrf, "", "", "", None,
    ))
    .into_response()
}

#[allow(clippy::too_many_arguments)]
fn render_new_form_with_message(
    messages: &Messages,
    tenant: &WebTenant,
    admin: &AdminContext,
    csrf: &str,
    email: &str,
    preferred_username: &str,
    name: &str,
    error: &str,
) -> String {
    render(&UserForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
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

    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
        let messages = Messages::new(locale(&headers));
        let csrf = csrf_from(&headers, state.config.csrf_secret());
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
    // api のバリデーション/競合メッセージをこの画面へ出すため、決定言語を引き継ぐ（MT20）。
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
            generated_password: &created.generated_password,
        }))
        .into_response(),
        Err(AdminApiError::Validation(m)) | Err(AdminApiError::Conflict(m)) => {
            let csrf = csrf_from(&headers, state.config.csrf_secret());
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

// ── 権限画面 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ViewQuery {
    #[serde(default)]
    pub error: Option<String>,
    /// 完了通知（Post/Redirect/Get。`profile` = プロフィール保存。MT25）。
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
    // 付与可能コード（`permissions` マスタ）は選択肢の出所。取得に失敗しても画面自体は描画し
    //（保有権限の確認・剥奪は続けられる）、付与欄だけ取得失敗として伝える。
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
    // 保有済みは選択肢から除く（付与しても変化しない操作を見せない）。
    let grantable: Vec<String> = available
        .into_iter()
        .filter(|code| !codes.contains(code))
        .collect();

    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers, state.config.csrf_secret());
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

// ── プロフィール編集（MT25）──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProfileForm {
    pub email: String,
    #[serde(default)]
    pub preferred_username: String,
    #[serde(default)]
    pub name: String,
    pub csrf_token: String,
}

/// 利用者プロフィールの更新（`POST /{tenant_id}/admin/users/{user_id}/profile`。MT25）。
/// api の `PATCH /admin/users/{user_id}/profile` に委ね、Post/Redirect/Get で詳細画面へ戻す。
/// 検証（メール書式・長さ・一意性）は api 側が唯一の出所で、web は結果をエラークエリへ写すだけ。
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
    if !csrf_valid(&headers, &form.csrf_token, state.config.csrf_secret()) {
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
    // 認可（whoami）。未認証/権限不足はここで誘導/403。
    match resolve_admin(state, correlation, tenant, headers).await {
        AdminResolution::Ok(_) => {}
        AdminResolution::Reject(resp) => return resp,
    }
    let base = format!("{}{USERS_SEGMENT}/{user_id}/permissions", tenant.prefix());
    if !csrf_valid(headers, &form.csrf_token, state.config.csrf_secret()) {
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
        // 403 は「この画面を見る権限が無い」ではなく「**この付与・剥奪は許されない**」である
        // （画面自体は `resolve_admin` を通っている）。403 ページへ倒すと原因が
        // 「ページを表示する権限がありません」に化けるので、権限画面のエラー欄へ戻す。
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

fn csrf_from(headers: &HeaderMap, key: &[u8]) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s, key))
        .unwrap_or_default()
}

fn csrf_valid(headers: &HeaderMap, submitted: &str, key: &[u8]) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|s| console_csrf_token(&s, key) == submitted)
        .unwrap_or(false)
}

// ── レンダリング ──────────────────────────────────────────────────────────────

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
    email: &str,
    preferred_username: &str,
    name: &str,
    error_key: Option<&str>,
) -> String {
    let error = error_key.map(|k| messages.get(k));
    render(&UserForm {
        messages,
        tenant: &tenant.prefix(),
        admin: Some(admin.chrome()),
        csrf,
        error: error.as_deref(),
        email,
        preferred_username,
        name,
    })
}

// ── 共通ヘルパー ──────────────────────────────────────────────────────────────

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

    /// 付与は自由入力ではなく選択式（打ち間違いで未知コードを送らせない）。保有済みのコードは
    /// 選択肢に出さず、候補が尽きたらフォーム自体を出さない。
    #[test]
    fn grant_offers_a_select_of_grantable_codes_only() {
        let html = permissions_html(&["idp.viewer".into()], false);
        assert!(html.contains(r#"<select class="form-select" id="permission-code" name="permission_code" required>"#), "{html}");
        assert!(
            html.contains(r#"<option value="idp.viewer">idp.viewer</option>"#),
            "{html}"
        );
        // 保有済み（`idp.admin`）は選択肢に出さない。
        assert!(!html.contains(r#"<option value="idp.admin">"#), "{html}");
        // 自由入力欄・datalist は残っていない。
        assert!(!html.contains(r#"list="admin-permission-codes""#), "{html}");

        let html = permissions_html(&[], false);
        assert!(
            html.contains(&Messages::new(Locale::Ja).get("admin-permissions-grant-none-left")),
            "{html}"
        );
        assert!(!html.contains("permissions/grant"), "{html}");
    }

    /// 候補が取得できなかったときは「候補なし」と取り違えないよう取得失敗として伝える。
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
            "",
            "",
            "",
            None,
        );
        assert!(html.contains("name=\"email\""));
        assert!(html.contains("name=\"preferred_username\""));
        assert!(html.contains("name=\"csrf_token\" value=\"csrf1\""));
    }
}
