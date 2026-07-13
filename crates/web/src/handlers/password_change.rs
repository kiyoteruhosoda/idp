//! 強制パスワード変更画面（`GET/POST /{tenant_id}/password-change`、ADR-0009 §5）。
//!
//! ログインフロー中（`LoginService` がパスワード検証済み・`must_change_password` を検出した状態）に
//! 表示する。api の `POST /internal/change-password` に委ね、成功時は `LoginService` と同じ
//! SSO 発行 → 同意/code 発行の結果（`redirect_to`）へ 302 する。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::dto::PasswordChangeForm;
use crate::handlers::{forwarded_context, found};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, MessagePage, PasswordChangeTemplate};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{InternalChangePasswordRequest, InternalChangePasswordResponse};
use idp_contracts::csrf::login_csrf_token;

/// パスワード変更フォームを表示する。`auth_session_id` Cookie（パスワード検証済み状態）が必要。
pub async fn page(State(state): State<WebState>, headers: HeaderMap) -> Response {
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
        &login_csrf_token(&auth_session_id, state.config.csrf_secret()),
        None,
    ))
    .into_response()
}

/// パスワード変更を実行する。成功時は `LoginService` と同じ SSO Cookie 発行 → `redirect_to` へ 302 する。
pub async fn submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<PasswordChangeForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation);
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);

    if form.new_password != form.new_password_confirm {
        let messages = Messages::new(locale(&headers));
        return reshow_form(
            &messages,
            StatusCode::UNPROCESSABLE_ENTITY,
            auth_session_id.as_deref(),
            "password-change-error-mismatch",
            state.config.csrf_secret(),
        );
    }

    let request = InternalChangePasswordRequest {
        tenant_id: Some(tenant.0.clone()),
        auth_session_id: auth_session_id.clone(),
        current_password: form.current_password,
        new_password: form.new_password,
        csrf_token: form.csrf_token,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };

    let outcome = match state
        .api
        .change_password(&ctx.correlation_id, &request)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(error = %e, "internal change-password call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let messages = Messages::new(locale(&headers));
    let secure = state.config.cookie_secure();
    match outcome {
        InternalChangePasswordResponse::Success {
            redirect_to,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
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
        InternalChangePasswordResponse::ConsentRequired {
            auth_session_id: new_auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let sso_cookie = cookies::build(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                sso_absolute_ttl_secs,
                secure,
            );
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
                found(&format!("{}/consent", tenant.prefix())),
            )
                .into_response()
        }
        InternalChangePasswordResponse::SessionExpired => error_page(
            &messages,
            StatusCode::BAD_REQUEST,
            "login-error-session-expired",
        ),
        InternalChangePasswordResponse::CsrfMismatch => {
            error_page(&messages, StatusCode::BAD_REQUEST, "login-error-csrf")
        }
        InternalChangePasswordResponse::InvalidCurrentPassword => reshow_form(
            &messages,
            StatusCode::UNAUTHORIZED,
            auth_session_id.as_deref(),
            "password-change-error-invalid-current",
            state.config.csrf_secret(),
        ),
        InternalChangePasswordResponse::WeakPassword => reshow_form(
            &messages,
            StatusCode::UNPROCESSABLE_ENTITY,
            auth_session_id.as_deref(),
            "password-change-error-weak",
            state.config.csrf_secret(),
        ),
        InternalChangePasswordResponse::Internal => {
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

fn render_form(messages: &Messages, csrf: &str, error_key: Option<&str>) -> String {
    render(&PasswordChangeTemplate {
        messages,
        csrf,
        error_key,
    })
}

/// エラー付きでフォームを再表示する（AuthSession はまだ有効なため再入力できる）。
fn reshow_form(
    messages: &Messages,
    status: StatusCode,
    auth_session_id: Option<&str>,
    error_key: &str,
    csrf_secret: &[u8],
) -> Response {
    match auth_session_id {
        Some(id) => (
            status,
            Html(render_form(
                messages,
                &login_csrf_token(id, csrf_secret),
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
        title: messages.get("password-change-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
