//! ログイン画面（`GET /login`）とログイン処理（`POST /login`、設計仕様 §4.3）。
//!
//! ADR-0007: web はフォーム描画とリダイレクトのみを担い、資格情報検証・SSO/code 発行は api の
//! `POST /internal/authenticate` に委ねる。web は接続元情報（`X-Forwarded-For` 由来 IP・User-Agent）を
//! 転送し、成功時に api が返す `sso_session_id` を Cookie 化して `redirect_to` へ 302 する。エラーは
//! ローカライズして再描画する。CSRF は `auth_session_id` 由来の同期トークン（`idp-contracts`）で、
//! api の LoginService が検証する。
//!
//! 画面文言は `fluent` の翻訳リソースで管理する（`Accept-Language` で en / ja を切替）。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::LoginForm;
use crate::handlers::{forwarded_context, found};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, LoginTemplate, MessagePage};
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{InternalAuthenticateRequest, InternalAuthenticateResponse};
use idp_contracts::csrf::login_csrf_token;

/// ログインフォームを表示する。`auth_session_id` Cookie（api の `/authorize` が発行）が必要。
pub async fn login_page(headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    let Some(auth_session_id) = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE) else {
        return error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        );
    };
    Html(render_form(
        &messages,
        &login_csrf_token(&auth_session_id),
        None,
    ))
    .into_response()
}

/// ログインフォームの HTML をテンプレートから描画する。埋め込む値（翻訳文言・CSRF トークン）は
/// テンプレート側で自動 HTML エスケープされる。
fn render_form(messages: &Messages, csrf: &str, error_key: Option<&str>) -> String {
    render(&LoginTemplate {
        messages,
        csrf,
        error_key,
    })
}

/// ログインを実行する。api の内部認証を呼び、成功時は SSO Cookie を発行して `redirect_to` へ 302 する。
pub async fn login(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation);
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);

    let request = InternalAuthenticateRequest {
        auth_session_id: auth_session_id.clone(),
        username: form.username,
        password: form.password,
        csrf_token: form.csrf_token,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };

    let outcome = match state.api.authenticate(&ctx.correlation_id, &request).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "internal authenticate call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // FluentBundle は Send でないため、await をまたがないようここで生成する。
    let messages = Messages::new(locale(&headers));
    let secure = state.config.cookie_secure();
    match outcome {
        InternalAuthenticateResponse::Success {
            redirect_to,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            // SSO Cookie を発行し、短命の auth_session_id Cookie は失効させる。
            let sso_cookie = cookies::build(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                sso_absolute_ttl_secs,
                secure,
            );
            let expire_auth = cookies::expire(cookies::AUTH_SESSION_COOKIE, secure);
            (
                AppendHeaders([
                    (header::SET_COOKIE, sso_cookie),
                    (header::SET_COOKIE, expire_auth),
                ]),
                found(&redirect_to),
            )
                .into_response()
        }
        InternalAuthenticateResponse::MfaRequired { auth_session_id } => {
            // パスワード認証成功・MFA 必要: auth_session_id Cookie を維持して TOTP 入力画面へ。
            let auth_cookie = cookies::build(
                cookies::AUTH_SESSION_COOKIE,
                &auth_session_id,
                state.config.auth_session_ttl_secs(),
                secure,
            );
            (
                AppendHeaders([(header::SET_COOKIE, auth_cookie)]),
                found("/mfa/totp"),
            )
                .into_response()
        }
        InternalAuthenticateResponse::SessionExpired => error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        ),
        InternalAuthenticateResponse::CsrfMismatch => {
            error_page(&messages, StatusCode::BAD_REQUEST, "login-error-csrf")
        }
        InternalAuthenticateResponse::RateLimited => error_page(
            &messages,
            StatusCode::TOO_MANY_REQUESTS,
            "login-error-rate-limited",
        ),
        InternalAuthenticateResponse::InvalidCredentials => reshow_form(
            &messages,
            StatusCode::UNAUTHORIZED,
            auth_session_id.as_deref(),
            "login-error-invalid-credentials",
        ),
        InternalAuthenticateResponse::Locked => reshow_form(
            &messages,
            StatusCode::FORBIDDEN,
            auth_session_id.as_deref(),
            "login-error-locked",
        ),
        InternalAuthenticateResponse::ConsentRequired {
            auth_session_id: new_auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            // SSO Cookie を発行し、同意画面用の auth_session_id Cookie を設定する。
            let sso_cookie = cookies::build(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                sso_absolute_ttl_secs,
                secure,
            );
            // auth_session_id はまだ有効（同意画面で使う）ので期限をそのまま保持する。
            // 具体的な TTL は api 側で設定済みのため、ここでは既存の Cookie を上書きする。
            let auth_cookie = cookies::build(
                cookies::AUTH_SESSION_COOKIE,
                &new_auth_session_id,
                state.config.auth_session_ttl_secs(),
                secure,
            );
            (
                AppendHeaders([
                    (header::SET_COOKIE, sso_cookie),
                    (header::SET_COOKIE, auth_cookie),
                ]),
                found("/consent"),
            )
                .into_response()
        }
        InternalAuthenticateResponse::Internal => {
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
            Html(render_form(
                messages,
                &login_csrf_token(id),
                Some(error_key),
            )),
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
    let body = render(&MessagePage {
        title: messages.get("login-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
