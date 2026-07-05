//! ログイン画面（`GET /login`）とログイン処理（`POST /login`、設計仕様 §4.3）。
//!
//! 画面文言は `fluent` の翻訳リソースで管理する（`Accept-Language` で en / ja を切替）。
//! CSRF トークンは `auth_session_id` から導出した値をフォームへ埋め込み、POST 時に再計算して
//! 照合する（`application::login::csrf_token`）。

use crate::application::login::{csrf_token, LoginCommand, LoginOutcome};
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

/// ログインフォームを表示する。`auth_session_id` Cookie（`/authorize` が発行）が必要。
pub async fn login_page(headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        );
    };
    Html(render_form(&messages, &csrf_token(&auth_session_id), None)).into_response()
}

/// ログインを実行し、成功時は SSO Cookie を発行して `redirect_uri` へ 302 する。
pub async fn login(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ctx = request_context(&headers, &correlation);
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);

    let outcome = state
        .login
        .login(
            LoginCommand {
                auth_session_id: auth_session_id.clone(),
                username: form.username,
                password: form.password,
                csrf_token: form.csrf_token,
            },
            &ctx,
        )
        .await;

    // FluentBundle は Send でないため、await をまたがないようここで生成する。
    let messages = Messages::new(locale(&headers));
    let secure = state.config.cookie_secure();
    match outcome {
        LoginOutcome::Success {
            location,
            sso_session_id,
        } => {
            // SSO Cookie を発行し、短命の auth_session_id Cookie は失効させる。
            let sso_cookie = cookies::build(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                state.config.sso_absolute_ttl().as_secs(),
                secure,
            );
            let expire_auth = cookies::expire(cookies::AUTH_SESSION_COOKIE, secure);
            // Set-Cookie は同名ヘッダを複数返すため append する（タプル配列は insert で上書きされる）。
            (
                AppendHeaders([
                    (header::SET_COOKIE, sso_cookie),
                    (header::SET_COOKIE, expire_auth),
                ]),
                found(&location),
            )
                .into_response()
        }
        LoginOutcome::SessionExpired => error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        ),
        LoginOutcome::CsrfMismatch => {
            error_page(&messages, StatusCode::BAD_REQUEST, "login-error-csrf")
        }
        LoginOutcome::RateLimited => error_page(
            &messages,
            StatusCode::TOO_MANY_REQUESTS,
            "login-error-rate-limited",
        ),
        LoginOutcome::InvalidCredentials => reshow_form(
            &messages,
            StatusCode::UNAUTHORIZED,
            auth_session_id.as_deref(),
            "login-error-invalid-credentials",
        ),
        LoginOutcome::Locked => reshow_form(
            &messages,
            StatusCode::FORBIDDEN,
            auth_session_id.as_deref(),
            "login-error-locked",
        ),
        LoginOutcome::Internal(e) => {
            tracing::error!(error = %e, "login failed with internal error");
            (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response()
        }
    }
}

fn locale(headers: &HeaderMap) -> Locale {
    Locale::from_accept_language(
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok()),
    )
}

/// エラー付きでフォームを再表示する（AuthSession はまだ有効なため再入力できる）。
fn reshow_form(
    messages: &Messages,
    status: StatusCode,
    auth_session_id: Option<&str>,
    error_key: &str,
) -> Response {
    match auth_session_id {
        Some(id) => (
            status,
            Html(render_form(messages, &csrf_token(id), Some(error_key))),
        )
            .into_response(),
        None => error_page(
            messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        ),
    }
}

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let title = messages.get("login-title");
    let message = messages.get(error_key);
    let body = format!(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>{title}</title></head>\
         <body><h1>{title}</h1><p>{message}</p></body></html>"
    );
    (status, Html(body)).into_response()
}

/// ログインフォームの HTML。埋め込む値は自前生成の翻訳文言と 16 進 CSRF トークンのみ
/// （ユーザー入力は含まないため追加のエスケープは不要）。
fn render_form(messages: &Messages, csrf: &str, error_key: Option<&str>) -> String {
    let title = messages.get("login-title");
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
         <form method=\"post\" action=\"/login\">\n\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\n\
         <label>{username} <input type=\"text\" name=\"username\" autocomplete=\"username\" required></label>\n\
         <label>{password} <input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>\n\
         <button type=\"submit\">{submit}</button>\n\
         </form>\n\
         </body></html>"
    )
}
