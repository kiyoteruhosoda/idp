//! 管理コンソール（web）のログイン・ホーム・ログアウト（ADR-0006 §6・ADR-0007 §4）。
//!
//! web は画面描画のみを担い、認証・認可・セッション失効は api に委ねる:
//! - ログインは api の `POST /internal/authenticate/admin`（サービストークン保護）。
//! - 認証状態と身元は api の `GET /admin/whoami`（管理者の SSO Cookie を転送。`RequirePerms<IdpAdmin>`）。
//! - ログアウトは api の `POST /internal/logout`（SSO セッション失効）。
//!
//! Cookie 組み立て（SSO 発行・失効、CSRF 種）は web が行う。CSRF は web 内で完結する（`crate::csrf`）。

use crate::api_client::AdminSession;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::csrf::admin_csrf_token;
use crate::dto::LoginForm;
use crate::handlers::{forwarded_context, found};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, ConsoleHome, ConsoleLogin, MessagePage};
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse, InternalLogoutRequest,
};
use uuid::Uuid;

pub const CONSOLE_HOME_PATH: &str = "/admin/console";
pub const ADMIN_LOGIN_PATH: &str = "/admin/console/login";
pub const CONSOLE_LOGOUT_PATH: &str = "/admin/console/logout";

/// 管理コンソールのホーム（`GET /admin/console`）。SSO を api へ転送して認可を確認する。
pub async fn home(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let admin = match resolve_admin(&state, &correlation, &headers).await {
        AdminResolution::Ok(user_id) => user_id,
        AdminResolution::Reject(resp) => return resp,
    };
    let messages = Messages::new(locale(&headers));
    Html(render(&ConsoleHome {
        messages: &messages,
        admin: Some(&admin),
    }))
    .into_response()
}

/// 管理ログインフォーム（`GET /admin/console/login`）。既にログイン済みならホームへ 302 する。
pub async fn login_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    // 既に有効な SSO ＋ 権限を持つならホームへ。
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        if let AdminSession::Authenticated(_) = state.api.admin_whoami(&correlation.0, &sso).await {
            return found(CONSOLE_HOME_PATH);
        }
    }

    let messages = Messages::new(locale(&headers));
    // CSRF の種（推測不能な乱数）を新規発行し、Cookie とフォーム双方へ渡す。
    let csrf_id = Uuid::new_v4().simple().to_string();
    let csrf = admin_csrf_token(&csrf_id);
    let csrf_cookie = cookies::build(
        cookies::ADMIN_CSRF_COOKIE,
        &csrf_id,
        3600,
        state.config.cookie_secure(),
    );
    (
        AppendHeaders([(header::SET_COOKIE, csrf_cookie)]),
        Html(render_login_form(&messages, &csrf, None)),
    )
        .into_response()
}

/// 管理ログイン処理（`POST /admin/console/login`）。CSRF を web で検証し、資格情報は api へ委ねる。
pub async fn login(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // CSRF 検証（Cookie の種からトークンを再計算して照合）。FluentBundle は Send でないため各分岐で生成。
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

    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalAdminAuthenticateRequest {
        // 過渡期は未指定（api が既定テナント root へフォールバック）。MT13 でパス由来へ。
        tenant_id: None,
        username: form.username,
        password: form.password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .authenticate_admin(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "admin internal authenticate call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    let secure = state.config.cookie_secure();
    match outcome {
        InternalAdminAuthenticateResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let sso_cookie = cookies::build(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                sso_absolute_ttl_secs,
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
        InternalAdminAuthenticateResponse::RateLimited => reshow_login(
            &messages,
            StatusCode::TOO_MANY_REQUESTS,
            &csrf,
            "login-error-rate-limited",
        ),
        InternalAdminAuthenticateResponse::InvalidCredentials => reshow_login(
            &messages,
            StatusCode::UNAUTHORIZED,
            &csrf,
            "login-error-invalid-credentials",
        ),
        InternalAdminAuthenticateResponse::Locked => reshow_login(
            &messages,
            StatusCode::FORBIDDEN,
            &csrf,
            "login-error-locked",
        ),
        InternalAdminAuthenticateResponse::Forbidden => reshow_login(
            &messages,
            StatusCode::FORBIDDEN,
            &csrf,
            "admin-login-error-forbidden",
        ),
        InternalAdminAuthenticateResponse::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

/// ログアウト（`POST /admin/console/logout`）。api で SSO を失効させ、Cookie を失効してログインへ 302。
pub async fn logout(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation);
    if let Some(sso) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) {
        let _ = state
            .api
            .logout(
                &ctx.correlation_id,
                &InternalLogoutRequest {
                    tenant_id: None,
                    sso_session_id: sso,
                    ip_address: ctx.ip_address,
                    user_agent: ctx.user_agent,
                },
            )
            .await;
    }
    let expire = cookies::expire(cookies::SSO_SESSION_COOKIE, state.config.cookie_secure());
    (
        AppendHeaders([(header::SET_COOKIE, expire)]),
        redirect_to_login(),
    )
        .into_response()
}

/// 認可済み管理者の解決結果。`Reject` は誘導/エラーの完成済み Response を持つ。
pub(crate) enum AdminResolution {
    Ok(String),
    Reject(Response),
}

/// SSO Cookie を api へ転送して管理者を解決する（未認証→ログイン誘導、権限不足→403 HTML）。
/// 各管理コンソール画面はこれで保護する（api の `AdminHtmlSession` に相当）。
pub(crate) async fn resolve_admin(
    state: &WebState,
    correlation: &CorrelationId,
    headers: &HeaderMap,
) -> AdminResolution {
    let sso = cookies::get(headers, cookies::SSO_SESSION_COOKIE).unwrap_or_default();
    match state.api.admin_whoami(&correlation.0, &sso).await {
        AdminSession::Authenticated(user_id) => AdminResolution::Ok(user_id),
        AdminSession::Unauthenticated => AdminResolution::Reject(redirect_to_login()),
        AdminSession::Forbidden => AdminResolution::Reject(forbidden_response(headers)),
        AdminSession::Error => {
            AdminResolution::Reject((StatusCode::BAD_GATEWAY, Html(String::new())).into_response())
        }
    }
}

/// ログイン画面への 302 リダイレクト。
pub(crate) fn redirect_to_login() -> Response {
    found(ADMIN_LOGIN_PATH)
}

/// 権限不足を伝える最小限の HTML ページ（403）。管理コンソール各画面から再利用する。
pub(crate) fn forbidden_response(headers: &HeaderMap) -> Response {
    let messages = Messages::new(locale(headers));
    let body = render(&MessagePage {
        title: messages.get("admin-forbidden-title"),
        message: messages.get("admin-forbidden-message"),
    });
    (StatusCode::FORBIDDEN, Html(body)).into_response()
}

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

fn reshow_login(messages: &Messages, status: StatusCode, csrf: &str, error_key: &str) -> Response {
    (
        status,
        Html(render_login_form(messages, csrf, Some(error_key))),
    )
        .into_response()
}

/// 管理ログインフォームの HTML をテンプレートから描画する（埋め込む値は自動 HTML エスケープされる）。
fn render_login_form(messages: &Messages, csrf: &str, error_key: Option<&str>) -> String {
    render(&ConsoleLogin {
        messages,
        csrf,
        error_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_form_has_csrf_and_credential_fields() {
        let messages = Messages::new(Locale::En);
        let html = render_login_form(&messages, "deadbeef", None);
        assert!(html.contains("action=\"/admin/console/login\""));
        assert!(html.contains("name=\"csrf_token\" value=\"deadbeef\""));
        assert!(html.contains("name=\"username\""));
        assert!(html.contains("name=\"password\""));
        assert!(!html.contains("role=\"alert\""));
    }

    #[test]
    fn home_lists_sections_and_logout_for_signed_in_admin() {
        let messages = Messages::new(Locale::En);
        let html = render(&ConsoleHome {
            messages: &messages,
            admin: Some("user-123"),
        });
        assert!(html.contains("user-123"));
        assert!(html.contains("action=\"/admin/console/logout\""));
        assert!(html.contains("/admin/console/clients"));
    }
}
