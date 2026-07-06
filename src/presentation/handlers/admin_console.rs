//! 管理コンソール（A2）のサーバレンダリング画面。
//!
//! ADR-0006 §6 のとおり、既存の SSO セッション背後のサーバレンダリング画面として実装し、
//! `idp.admin` 権限で保護する（画面は [`AdminHtmlSession`]、API は `RequirePerms<IdpAdmin>`）。
//! 文言は `fluent`（`Accept-Language` で en / ja を切替、ログイン画面と同じ仕組み）。
//!
//! ブラウザ向けコンソールは JSON 管理 API（`/admin/<resource>`）と分離して `/admin/console` 配下に置く。
//!
//! - `GET/POST /admin/console/login`: 管理ログイン（クライアント不要。鶏卵問題の回避）。
//! - `GET /admin/console`: 管理コンソールのホーム（各管理機能への入口。A1/A3 の画面はこのレイアウト上に追加）。
//! - `POST /admin/console/logout`: ログアウト（SSO セッション失効）。
//!
//! CSRF:
//! - ログインフォーム（未認証）は同期トークン方式。GET で推測不能な乱数を HttpOnly Cookie（`admin_csrf_id`）に
//!   発行し、その一方向ハッシュをフォームへ埋め込む（`application::admin_login::admin_csrf_token`）。
//! - ログイン後の状態変更フォームは、SSO セッション id（HttpOnly Cookie）由来の同期トークンで保護する
//!   （[`console_csrf_token`]）。

use crate::application::admin_access::AuthorizedAdmin;
use crate::application::admin_login::{admin_csrf_token, AdminLoginCommand, AdminLoginOutcome};
use crate::infrastructure::crypto;
use crate::presentation::admin::{
    redirect_to_login, AdminHtmlSession, ADMIN_LOGIN_PATH, CONSOLE_HOME_PATH, CONSOLE_LOGOUT_PATH,
};
use crate::presentation::cookies;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::LoginForm;
use crate::presentation::handlers::{found, request_context};
use crate::presentation::i18n::{Locale, Messages};
use crate::presentation::state::AppState;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::Form;

/// 管理コンソールのホーム（`GET /admin/console`）。抽出成功＝有効な SSO ＋ `idp.admin` 保有。
pub async fn home(AdminHtmlSession(admin): AdminHtmlSession, headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    let content = format!(
        "<p>{intro}</p>\n\
         <ul class=\"admin-sections\">\n\
         <li><a href=\"/admin/console/clients\">{clients}</a></li>\n\
         <li><a href=\"/admin/console/status\">{status}</a></li>\n\
         <li><a href=\"/admin/console/audit-logs\">{audit}</a></li>\n\
         <li><a href=\"/admin/console/users\">{permissions}</a></li>\n\
         </ul>",
        intro = messages.get("admin-home-intro"),
        clients = messages.get("admin-nav-clients"),
        status = messages.get("admin-nav-status"),
        audit = messages.get("admin-nav-audit"),
        permissions = messages.get("admin-nav-permissions"),
    );
    Html(render_layout(&messages, Some(&admin), &content)).into_response()
}

/// 管理ログインフォーム（`GET /admin/console/login`）。既にログイン済みならホームへ 302 する。
pub async fn login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // 既に有効な SSO ＋ 権限を持つならホームへ。
    let sso = cookies::get(&headers, cookies::SSO_SESSION_COOKIE);
    if let crate::application::admin_access::AdminAccess::Granted(_) = state
        .admin_access
        .authorize(sso.as_deref(), "idp.admin")
        .await
    {
        return found(CONSOLE_HOME_PATH);
    }

    let messages = Messages::new(locale(&headers));
    // CSRF の種（推測不能な乱数）を新規発行し、Cookie とフォーム双方へ渡す。
    let csrf_id = crypto::random_hex(32);
    let csrf = admin_csrf_token(&csrf_id);
    let csrf_cookie = cookies::build(
        cookies::ADMIN_CSRF_COOKIE,
        &csrf_id,
        // フォーム提出までの短命。SSO の idle と揃える必要はないため 1 時間。
        3600,
        state.config.cookie_secure(),
    );
    (
        AppendHeaders([(header::SET_COOKIE, csrf_cookie)]),
        Html(render_login_form(&messages, &csrf, None)),
    )
        .into_response()
}

/// 管理ログイン処理（`POST /admin/login`）。成功時に SSO Cookie を発行してホームへ 302 する。
pub async fn login(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // CSRF 検証（Cookie の種からトークンを再計算して照合）。`Messages`（FluentBundle）は Send でないため
    // await をまたいで保持せず、各分岐で生成する（login.rs と同じ理由）。
    let csrf_id = cookies::get(&headers, cookies::ADMIN_CSRF_COOKIE);
    let csrf_ok = csrf_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|id| admin_csrf_token(id) == form.csrf_token)
        .unwrap_or(false);
    if !csrf_ok {
        let messages = Messages::new(locale(&headers));
        return (
            StatusCode::BAD_REQUEST,
            Html(render_login_form(&messages, "", Some("login-error-csrf"))),
        )
            .into_response();
    }
    let csrf = admin_csrf_token(&csrf_id.unwrap_or_default());

    let ctx = request_context(&headers, &correlation);
    let outcome = state
        .admin_login
        .login(
            AdminLoginCommand {
                username: form.username,
                password: form.password,
            },
            &ctx,
        )
        .await;

    let messages = Messages::new(locale(&headers));
    let secure = state.config.cookie_secure();
    match outcome {
        AdminLoginOutcome::Success { sso_session_id } => {
            let sso_cookie = cookies::build(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                state.config.sso_absolute_ttl().as_secs(),
                secure,
            );
            let expire_csrf = cookies::expire(cookies::ADMIN_CSRF_COOKIE, secure);
            (
                AppendHeaders([
                    (header::SET_COOKIE, sso_cookie),
                    (header::SET_COOKIE, expire_csrf),
                ]),
                found(CONSOLE_HOME_PATH),
            )
                .into_response()
        }
        AdminLoginOutcome::RateLimited => reshow_login(
            &messages,
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            "login-error-rate-limited",
        ),
        AdminLoginOutcome::InvalidCredentials => reshow_login(
            &messages,
            StatusCode::UNAUTHORIZED,
            &csrf,
            "login-error-invalid-credentials",
        ),
        AdminLoginOutcome::Locked => reshow_login(
            &messages,
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-locked",
        ),
        AdminLoginOutcome::Forbidden => reshow_login(
            &messages,
            StatusCode::FORBIDDEN,
            &csrf,
            "admin-login-error-forbidden",
        ),
        AdminLoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "admin login failed with internal error");
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

/// ログアウト（`POST /admin/logout`）。SSO セッションを失効させてログイン画面へ 302 する。
pub async fn logout(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let ctx = request_context(&headers, &correlation);
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        state.admin_login.logout(&sso, &ctx).await;
    }
    let expire = cookies::expire(cookies::SSO_SESSION_COOKIE, state.config.cookie_secure());
    (
        AppendHeaders([(header::SET_COOKIE, expire)]),
        redirect_to_login(),
    )
        .into_response()
}

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

/// エラー付きでログインフォームを再表示する（CSRF の種 Cookie はそのまま有効）。
fn reshow_login(messages: &Messages, status: StatusCode, csrf: &str, error_key: &str) -> Response {
    (
        status,
        Html(render_login_form(messages, csrf, Some(error_key))),
    )
        .into_response()
}

/// 管理コンソール共通レイアウト（ヘッダ・ナビ・ログアウト）。A1/A3 の画面はこの上に `content` を差し込む。
///
/// 埋め込む値は自前生成の翻訳文言・16 進 CSRF・信頼できる内部 ID のみで、ユーザー入力は含まない。
pub fn render_layout(
    messages: &Messages,
    admin: Option<&AuthorizedAdmin>,
    content: &str,
) -> String {
    let title = messages.get("admin-console-title");
    let header = match admin {
        Some(a) => format!(
            "<header class=\"admin-header\">\n\
             <span class=\"admin-title\">{title}</span>\n\
             <span class=\"admin-user\">{signed_in}: {uid}</span>\n\
             <form method=\"post\" action=\"{logout_path}\" class=\"admin-logout\">\
             <button type=\"submit\">{logout}</button></form>\n\
             </header>",
            signed_in = messages.get("admin-signed-in-as"),
            uid = a.user_id,
            logout_path = CONSOLE_LOGOUT_PATH,
            logout = messages.get("admin-logout"),
        ),
        None => format!(
            "<header class=\"admin-header\"><span class=\"admin-title\">{title}</span></header>"
        ),
    };
    format!(
        "<!DOCTYPE html>\n\
         <html><head><meta charset=\"utf-8\"><title>{title}</title></head>\n\
         <body>\n{header}\n<main>\n{content}\n</main>\n</body></html>"
    )
}

/// ログインフォームの HTML。埋め込む値は翻訳文言と 16 進 CSRF トークンのみ（ユーザー入力なし）。
fn render_login_form(messages: &Messages, csrf: &str, error_key: Option<&str>) -> String {
    let title = messages.get("admin-login-title");
    let username = messages.get("login-username");
    let password = messages.get("login-password");
    let submit = messages.get("login-submit");
    let error_html = error_key
        .map(|key| {
            format!(
                "<p class=\"error\" role=\"alert\">{}</p>",
                messages.get(key)
            )
        })
        .unwrap_or_default();

    format!(
        "<!DOCTYPE html>\n\
         <html><head><meta charset=\"utf-8\"><title>{title}</title></head>\n\
         <body>\n\
         <h1>{title}</h1>\n\
         {error_html}\n\
         <form method=\"post\" action=\"{action}\">\n\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\n\
         <label>{username} <input type=\"text\" name=\"username\" autocomplete=\"username\" required></label>\n\
         <label>{password} <input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>\n\
         <button type=\"submit\">{submit}</button>\n\
         </form>\n\
         </body></html>",
        action = ADMIN_LOGIN_PATH,
    )
}

/// ログイン後の管理コンソール（状態変更フォーム）用の CSRF トークンを SSO セッション id から導出する。
///
/// SSO セッション id は HttpOnly Cookie（`sso_session_id`）にのみ存在する推測不能な乱数であり、その
/// 一方向ハッシュをフォームへ埋め込む。攻撃者は Cookie を読めないためトークンを再現できない
/// （同期トークン方式。`admin_csrf_token` とは名前空間で分離）。
pub fn console_csrf_token(sso_session_id: &str) -> String {
    crypto::sha256_hex(&format!("console-csrf:{sso_session_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn login_form_has_csrf_and_credential_fields() {
        let messages = Messages::new(Locale::En);
        let html = render_login_form(&messages, "deadbeef", None);
        assert!(html.contains("action=\"/admin/console/login\""));
        assert!(html.contains("name=\"csrf_token\" value=\"deadbeef\""));
        assert!(html.contains("name=\"username\""));
        assert!(html.contains("name=\"password\""));
        assert!(html.contains("Admin sign in"));
        // エラー未指定時はエラー段落を出さない。
        assert!(!html.contains("role=\"alert\""));

        let with_error = render_login_form(&messages, "x", Some("login-error-invalid-credentials"));
        assert!(with_error.contains("role=\"alert\""));
        assert!(with_error.contains("The username or password is incorrect."));
    }

    #[test]
    fn layout_shows_admin_identity_and_logout_when_signed_in() {
        let messages = Messages::new(Locale::En);
        let uid = Uuid::new_v4();
        let admin = AuthorizedAdmin { user_id: uid };
        let html = render_layout(&messages, Some(&admin), "<p>body</p>");
        assert!(html.contains("Admin console"));
        assert!(html.contains(&uid.to_string()));
        assert!(html.contains("action=\"/admin/console/logout\""));
        assert!(html.contains("<p>body</p>"));

        // 未ログイン（ログイン画面のレイアウト流用など）ではログアウトを出さない。
        let anon = render_layout(&messages, None, "x");
        assert!(!anon.contains("/admin/console/logout"));
    }

    #[test]
    fn console_csrf_token_is_deterministic_and_namespaced() {
        let a = console_csrf_token("sso-a");
        assert_eq!(a, console_csrf_token("sso-a"));
        assert_ne!(a, console_csrf_token("sso-b"));
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        // ログイン前 CSRF（admin_csrf_token）とは種が同じでも一致しない。
        assert_ne!(console_csrf_token("x"), admin_csrf_token("x"));
    }

    #[test]
    fn layout_localizes_to_japanese() {
        let messages = Messages::new(Locale::Ja);
        let html = render_layout(&messages, None, "x");
        assert!(html.contains("管理コンソール"));
    }
}
