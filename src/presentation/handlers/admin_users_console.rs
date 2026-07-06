//! 利用者権限の付与・剥奪のサーバレンダリング画面（A2、ADR-0006）。
//!
//! 既存の JSON 管理 API（`/admin/users/{user_id}/permissions`、OpenAPI の正典）とは経路を分け、
//! ブラウザ向けに `/admin/console/users*` で提供する。認可は画面用 extractor [`AdminHtmlSession`]。
//! データ操作は API と同じ [`PermissionManagementService`] を通す（検証・監査記録を二重化しない）。
//!
//! 画面構成:
//! - `GET /admin/console/users`: メール／ユーザー名で利用者を検索し、権限画面へ導線を出す。
//! - `GET /admin/console/users/{user_id}/permissions`: 保有権限の一覧・付与フォーム・剥奪ボタン。
//! - `POST /admin/console/users/{user_id}/permissions/grant`: 権限付与（成功後は詳細へ 302）。
//! - `POST /admin/console/users/{user_id}/permissions/revoke`: 権限剥奪（成功後は詳細へ 302）。
//!
//! 状態変更フォームは SSO セッション由来の同期トークンで CSRF から守る（[`console_csrf_token`]）。
//! 利用者入力を HTML へ差し込む箇所はすべて [`html::escape`] を通す。付与・剥奪の POST は
//! Post/Redirect/Get で処理し、エラーは詳細画面へ `error` クエリで伝える（二重送信の回避）。

use crate::application::permission_management::PermissionManagementError;
use crate::domain::user::User;
use crate::presentation::admin::AdminHtmlSession;
use crate::presentation::cookies;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::handlers::admin_console::{console_csrf_token, render_layout};
use crate::presentation::handlers::{found, request_context};
use crate::presentation::html::escape;
use crate::presentation::i18n::{Locale, Messages};
use crate::presentation::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use uuid::Uuid;

const USERS_PATH: &str = "/admin/console/users";

// ── 利用者検索（GET /admin/console/users） ────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: Option<String>,
}

pub async fn search(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Response {
    // `Messages`（FluentBundle）は Send でないため await をまたいで保持しない（login.rs と同じ理由）。
    let term = query.q.unwrap_or_default();
    let outcome = if term.trim().is_empty() {
        SearchOutcome::Empty
    } else {
        match state.permissions_admin.find_user_by_identifier(&term).await {
            Ok(Some(user)) => SearchOutcome::Found(Box::new(user)),
            Ok(None) => SearchOutcome::NotFound,
            Err(e) => SearchOutcome::Internal(e),
        }
    };

    let messages = Messages::new(locale(&headers));
    match outcome {
        SearchOutcome::Internal(e) => internal_error(&messages, &admin, e),
        other => Html(render_search(&messages, &admin, &term, &other)).into_response(),
    }
}

enum SearchOutcome {
    /// 未検索（検索語なし）。
    Empty,
    Found(Box<User>),
    NotFound,
    Internal(PermissionManagementError),
}

// ── 権限画面（GET /admin/console/users/{user_id}/permissions） ─────────────────

#[derive(Debug, Deserialize)]
pub struct ViewQuery {
    /// 付与／剥奪 POST から Post/Redirect/Get で渡されるエラー種別（csrf / code / internal）。
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn view(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Query(query): Query<ViewQuery>,
) -> Response {
    let outcome = load_permissions(&state, &user_id).await;
    let messages = Messages::new(locale(&headers));
    let csrf = csrf_from(&headers);
    let error_key = query.error.as_deref().and_then(error_key_for);
    match outcome {
        LoadOutcome::Ok(page) => Html(render_permissions(
            &messages, &admin, &page, &csrf, error_key,
        ))
        .into_response(),
        LoadOutcome::NotFound => not_found(&messages, &admin),
        LoadOutcome::Internal(e) => internal_error(&messages, &admin, e),
    }
}

/// 権限画面の描画に必要なデータ（利用者・保有権限・付与可能コード）。
struct PermissionsPage {
    user: User,
    codes: Vec<String>,
    available: Vec<String>,
}

enum LoadOutcome {
    Ok(Box<PermissionsPage>),
    NotFound,
    Internal(PermissionManagementError),
}

/// 権限画面のデータを読み込む（利用者取得 → 保有権限 → 付与可能コード）。
async fn load_permissions(state: &AppState, user_id: &str) -> LoadOutcome {
    let target = match Uuid::parse_str(user_id) {
        Ok(id) => id,
        // UUID でない ID は該当利用者なしとして扱う。
        Err(_) => return LoadOutcome::NotFound,
    };
    let user = match state.permissions_admin.get_user(target).await {
        Ok(user) => user,
        Err(PermissionManagementError::NotFound) => return LoadOutcome::NotFound,
        Err(e) => return LoadOutcome::Internal(e),
    };
    let codes = match state.permissions_admin.list(target).await {
        Ok(codes) => codes,
        Err(PermissionManagementError::NotFound) => return LoadOutcome::NotFound,
        Err(e) => return LoadOutcome::Internal(e),
    };
    let available = match state.permissions_admin.available_codes().await {
        Ok(available) => available,
        Err(e) => return LoadOutcome::Internal(e),
    };
    LoadOutcome::Ok(Box::new(PermissionsPage {
        user,
        codes,
        available,
    }))
}

// ── 付与・剥奪の実行（POST） ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PermissionForm {
    pub permission_code: String,
    pub csrf_token: String,
}

/// 変更（付与／剥奪）POST の結果。詳細画面へ 302 で戻す（Post/Redirect/Get）。
enum ChangeOutcome {
    /// 成功。詳細画面へ戻す。
    Done,
    /// CSRF 不一致。
    Csrf,
    /// 未知の権限コード等。
    Invalid,
    /// 対象利用者が不存在（UUID 不正含む）。
    NotFound,
    /// 内部エラー。
    Internal,
}

pub async fn grant(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(form): Form<PermissionForm>,
) -> Response {
    let outcome = apply_change(
        &state,
        &admin,
        &correlation,
        &headers,
        &user_id,
        &form,
        true,
    )
    .await;
    redirect_after_change(&user_id, outcome)
}

pub async fn revoke(
    AdminHtmlSession(admin): AdminHtmlSession,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(form): Form<PermissionForm>,
) -> Response {
    let outcome = apply_change(
        &state,
        &admin,
        &correlation,
        &headers,
        &user_id,
        &form,
        false,
    )
    .await;
    redirect_after_change(&user_id, outcome)
}

/// 付与（`grant = true`）または剥奪（`grant = false`）を共通処理する。
async fn apply_change(
    state: &AppState,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    correlation: &CorrelationId,
    headers: &HeaderMap,
    user_id: &str,
    form: &PermissionForm,
    grant: bool,
) -> ChangeOutcome {
    if !csrf_valid(headers, &form.csrf_token) {
        return ChangeOutcome::Csrf;
    }
    let target = match Uuid::parse_str(user_id) {
        Ok(id) => id,
        Err(_) => return ChangeOutcome::NotFound,
    };
    let ctx = request_context(headers, correlation);
    let result = if grant {
        state
            .permissions_admin
            .grant(target, &form.permission_code, admin.user_id, &ctx)
            .await
    } else {
        state
            .permissions_admin
            .revoke(target, &form.permission_code, admin.user_id, &ctx)
            .await
    };
    match result {
        Ok(_) => ChangeOutcome::Done,
        Err(PermissionManagementError::Validation(_)) => ChangeOutcome::Invalid,
        Err(PermissionManagementError::NotFound) => ChangeOutcome::NotFound,
        Err(PermissionManagementError::Internal(e)) => {
            tracing::error!(error = %e, "admin permission change failed");
            ChangeOutcome::Internal
        }
    }
}

/// 変更 POST の結果を Post/Redirect/Get で詳細画面へ 302 する（エラーは `error` クエリで伝える）。
fn redirect_after_change(user_id: &str, outcome: ChangeOutcome) -> Response {
    let base = format!("{USERS_PATH}/{user_id}/permissions");
    let location = match outcome {
        ChangeOutcome::Done => base,
        ChangeOutcome::Csrf => format!("{base}?error=csrf"),
        ChangeOutcome::Invalid => format!("{base}?error=code"),
        ChangeOutcome::NotFound => format!("{base}?error=notfound"),
        ChangeOutcome::Internal => format!("{base}?error=internal"),
    };
    found(&location)
}

/// `error` クエリ値を i18n キーへ写す（未知値は無視する）。
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

/// フォームへ埋め込む CSRF トークンを SSO Cookie から導出する（Cookie が無ければ空）。
fn csrf_from(headers: &HeaderMap) -> String {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|sso| console_csrf_token(&sso))
        .unwrap_or_default()
}

/// 提出された CSRF トークンが SSO Cookie 由来の期待値と一致するか。
fn csrf_valid(headers: &HeaderMap, submitted: &str) -> bool {
    cookies::get(headers, cookies::SSO_SESSION_COOKIE)
        .map(|sso| console_csrf_token(&sso) == submitted)
        .unwrap_or(false)
}

// ── レンダリング ──────────────────────────────────────────────────────────────

fn render_search(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    term: &str,
    outcome: &SearchOutcome,
) -> String {
    let result = match outcome {
        SearchOutcome::Empty => String::new(),
        SearchOutcome::NotFound => {
            format!(
                "<p>{}</p>",
                escape(&messages.get("admin-users-search-none"))
            )
        }
        SearchOutcome::Found(user) => render_user_result(messages, user),
        // Internal は呼び出し側で別ページへ写すためここには来ない。
        SearchOutcome::Internal(_) => String::new(),
    };
    let content = format!(
        "<h2>{title}</h2>\n\
         <form method=\"get\" action=\"{path}\">\n\
         <p><label>{label}<br>\n\
         <input type=\"text\" name=\"q\" value=\"{term}\" required></label><br><small>{hint}</small></p>\n\
         <p><button type=\"submit\">{button}</button></p>\n\
         </form>\n{result}",
        title = escape(&messages.get("admin-users-title")),
        path = USERS_PATH,
        label = escape(&messages.get("admin-users-search-label")),
        term = escape(term),
        hint = escape(&messages.get("admin-users-search-hint")),
        button = escape(&messages.get("admin-users-search-button")),
    );
    render_layout(messages, Some(admin), &content)
}

/// 検索でヒットした利用者の要約と権限画面への導線。
fn render_user_result(messages: &Messages, user: &User) -> String {
    format!(
        "<table>\n\
         <tbody>\n\
         <tr><th>{email_label}</th><td>{email}</td></tr>\n\
         <tr><th>{username_label}</th><td>{username}</td></tr>\n\
         <tr><th>{id_label}</th><td><code>{id}</code></td></tr>\n\
         <tr><th>{status_label}</th><td>{status}</td></tr>\n\
         </tbody></table>\n\
         <p><a href=\"{path}/{id}/permissions\">{manage}</a></p>",
        email_label = escape(&messages.get("admin-user-col-email")),
        email = escape(&user.email),
        username_label = escape(&messages.get("admin-user-col-username")),
        username = escape(user.preferred_username.as_deref().unwrap_or("-")),
        id_label = escape(&messages.get("admin-user-col-id")),
        id = escape(&user.id.to_string()),
        status_label = escape(&messages.get("admin-user-col-status")),
        status = escape(user.status.as_str()),
        path = USERS_PATH,
        manage = escape(&messages.get("admin-user-manage-permissions")),
    )
}

fn render_permissions(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    page: &PermissionsPage,
    csrf: &str,
    error_key: Option<&str>,
) -> String {
    let error_html = error_key
        .map(|k| {
            format!(
                "<p class=\"error\" role=\"alert\">{}</p>",
                escape(&messages.get(k))
            )
        })
        .unwrap_or_default();

    let user = &page.user;
    let summary = format!(
        "<dl>\n\
         <dt>{email_label}</dt><dd>{email}</dd>\n\
         <dt>{username_label}</dt><dd>{username}</dd>\n\
         <dt>{id_label}</dt><dd><code>{id}</code></dd>\n\
         <dt>{status_label}</dt><dd>{status}</dd>\n\
         </dl>",
        email_label = escape(&messages.get("admin-user-col-email")),
        email = escape(&user.email),
        username_label = escape(&messages.get("admin-user-col-username")),
        username = escape(user.preferred_username.as_deref().unwrap_or("-")),
        id_label = escape(&messages.get("admin-user-col-id")),
        id = escape(&user.id.to_string()),
        status_label = escape(&messages.get("admin-user-col-status")),
        status = escape(user.status.as_str()),
    );

    let current = if page.codes.is_empty() {
        format!("<p>{}</p>", escape(&messages.get("admin-permissions-none")))
    } else {
        let rows: String = page
            .codes
            .iter()
            .map(|code| {
                format!(
                    "<tr><td><code>{code}</code></td>\
                     <td><form method=\"post\" action=\"{path}/{id}/permissions/revoke\">\
                     <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                     <input type=\"hidden\" name=\"permission_code\" value=\"{code}\">\
                     <button type=\"submit\">{revoke}</button></form></td></tr>",
                    code = escape(code),
                    path = USERS_PATH,
                    id = escape(&user.id.to_string()),
                    csrf = escape(csrf),
                    revoke = escape(&messages.get("admin-permissions-revoke-button")),
                )
            })
            .collect();
        format!("<table>\n<tbody>{rows}</tbody></table>")
    };

    // 付与可能コードの datalist（マスタ由来。選択肢を提示しつつ自由入力も許す）。
    let options: String = page
        .available
        .iter()
        .map(|code| format!("<option value=\"{}\"></option>", escape(code)))
        .collect();

    let grant_form = format!(
        "<h3>{grant_title}</h3>\n\
         <form method=\"post\" action=\"{path}/{id}/permissions/grant\">\n\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\n\
         <p><label>{grant_label}<br>\n\
         <input type=\"text\" name=\"permission_code\" list=\"admin-permission-codes\" required></label></p>\n\
         <datalist id=\"admin-permission-codes\">{options}</datalist>\n\
         <p><button type=\"submit\">{grant_button}</button></p>\n\
         </form>",
        grant_title = escape(&messages.get("admin-permissions-grant-title")),
        path = USERS_PATH,
        id = escape(&user.id.to_string()),
        csrf = escape(csrf),
        grant_label = escape(&messages.get("admin-permissions-grant-label")),
        grant_button = escape(&messages.get("admin-permissions-grant-button")),
    );

    let content = format!(
        "<h2>{title}</h2>\n{error_html}\n{summary}\n\
         <h3>{current_title}</h3>\n{current}\n{grant_form}\n\
         <p><a href=\"{path}\">{back}</a></p>",
        title = escape(&messages.get("admin-users-title")),
        current_title = escape(&messages.get("admin-permissions-current")),
        path = USERS_PATH,
        back = escape(&messages.get("admin-users-back")),
    );
    render_layout(messages, Some(admin), &content)
}

// ── レスポンスの共通ヘルパー ──────────────────────────────────────────────────

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn not_found(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
) -> Response {
    let content = format!(
        "<h2>{title}</h2>\n<p>{msg}</p>\n<p><a href=\"{path}\">{back}</a></p>",
        title = escape(&messages.get("admin-user-not-found-title")),
        msg = escape(&messages.get("admin-user-not-found-message")),
        path = USERS_PATH,
        back = escape(&messages.get("admin-users-back")),
    );
    (
        StatusCode::NOT_FOUND,
        Html(render_layout(messages, Some(admin), &content)),
    )
        .into_response()
}

fn internal_error(
    messages: &Messages,
    admin: &crate::application::admin_access::AuthorizedAdmin,
    e: PermissionManagementError,
) -> Response {
    tracing::error!(error = %e, "admin users console failed");
    let content = format!(
        "<p class=\"error\" role=\"alert\">{}</p>",
        escape(&messages.get("admin-error-internal"))
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(render_layout(messages, Some(admin), &content)),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::UserStatus;

    fn admin() -> crate::application::admin_access::AuthorizedAdmin {
        crate::application::admin_access::AuthorizedAdmin {
            user_id: Uuid::new_v4(),
        }
    }

    fn user_with(email: &str, username: Option<&str>) -> User {
        User {
            id: Uuid::new_v4(),
            sub: Uuid::new_v4(),
            email: email.to_string(),
            email_verified: true,
            preferred_username: username.map(str::to_string),
            name: None,
            password_hash: "x".to_string(),
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn search_result_escapes_user_fields_and_links_to_permissions() {
        let messages = Messages::new(Locale::En);
        let user = user_with("<b>e@example.com</b>", Some("<i>eve</i>"));
        let uid = user.id;
        let html = render_search(
            &messages,
            &admin(),
            "eve",
            &SearchOutcome::Found(Box::new(user)),
        );
        assert!(html.contains("&lt;b&gt;e@example.com&lt;/b&gt;"));
        assert!(html.contains("&lt;i&gt;eve&lt;/i&gt;"));
        assert!(!html.contains("<b>e@example.com"));
        assert!(html.contains(&format!("{USERS_PATH}/{uid}/permissions")));
    }

    #[test]
    fn search_term_is_escaped_in_input_value() {
        let messages = Messages::new(Locale::En);
        let html = render_search(&messages, &admin(), "\"><script>", &SearchOutcome::NotFound);
        assert!(html.contains("value=\"&quot;&gt;&lt;script&gt;\""));
        assert!(html.contains("No user matches"));
    }

    #[test]
    fn permissions_page_lists_codes_with_revoke_and_grant_forms() {
        let messages = Messages::new(Locale::En);
        let user = user_with("target@example.com", Some("target"));
        let uid = user.id;
        let page = PermissionsPage {
            user,
            codes: vec!["idp.admin".to_string()],
            available: vec!["idp.admin".to_string(), "idp.audit:read".to_string()],
        };
        let html = render_permissions(&messages, &admin(), &page, "deadbeef", None);
        // 保有権限の剥奪フォーム。
        assert!(html.contains(&format!("action=\"{USERS_PATH}/{uid}/permissions/revoke\"")));
        assert!(html.contains("name=\"permission_code\" value=\"idp.admin\""));
        // 付与フォームと datalist（付与可能コード）。
        assert!(html.contains(&format!("action=\"{USERS_PATH}/{uid}/permissions/grant\"")));
        assert!(html.contains("<datalist id=\"admin-permission-codes\">"));
        assert!(html.contains("<option value=\"idp.audit:read\">"));
        assert!(html.contains("name=\"csrf_token\" value=\"deadbeef\""));
        // エラー未指定時はエラー段落を出さない。
        assert!(!html.contains("role=\"alert\""));
    }

    #[test]
    fn permissions_page_shows_error_banner_from_query() {
        let messages = Messages::new(Locale::En);
        let page = PermissionsPage {
            user: user_with("t@example.com", None),
            codes: vec![],
            available: vec![],
        };
        let key = error_key_for("code").expect("mapped");
        let html = render_permissions(&messages, &admin(), &page, "x", Some(key));
        assert!(html.contains("role=\"alert\""));
        assert!(html.contains("Unknown permission code"));
        // 権限が無いときは none 文言を出す。
        assert!(html.contains("has no permissions"));
    }

    #[test]
    fn error_key_mapping_ignores_unknown_values() {
        assert_eq!(error_key_for("csrf"), Some("admin-error-csrf"));
        assert_eq!(
            error_key_for("code"),
            Some("admin-permission-error-unknown")
        );
        assert_eq!(error_key_for("bogus"), None);
    }

    #[test]
    fn redirect_targets_carry_error_for_failures() {
        let uid = "00000000-0000-0000-0000-000000000001";
        let resp = redirect_after_change(uid, ChangeOutcome::Csrf);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            location,
            format!("{USERS_PATH}/{uid}/permissions?error=csrf")
        );

        let ok = redirect_after_change(uid, ChangeOutcome::Done);
        let location = ok
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(location, format!("{USERS_PATH}/{uid}/permissions"));
    }
}
