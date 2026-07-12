//! セルフサービス・パスワードリセット画面（web。MT18）。
//!
//! - `GET/POST /{tenant_id}/forgot-password`: メールアドレスを入力してリセットを要求する。
//!   応答はアカウントの有無を問わず同じ完了表示（列挙防止は api / Application 層の責務で、
//!   web はその応答をそのまま写す）。
//! - `GET/POST /{tenant_id}/password-reset?token=...`: リセットメールのリンクから開き、
//!   新パスワードを設定する。成功後はログイン画面へ誘導する。
//!
//! いずれも未ログイン経路（SSO 不要）。フォームはセッションを持たないため CSRF トークンは
//! 付けない（要求はメール送信のみ・実行はトークン所持が本人性の根拠であり、第三者が強制しても
//! 得られる状態変化がない）。実体は api の `/internal/password-reset/*` に委ねる。

use crate::correlation::CorrelationId;
use crate::cookies;
use crate::handlers::forwarded_context;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, ForgotPassword, PasswordReset};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalPasswordResetCompleteRequest, InternalPasswordResetCompleteResponse,
    InternalPasswordResetRequestRequest, InternalPasswordResetRequestResponse,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ForgotForm {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResetForm {
    pub token: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

/// リセット要求フォーム（`GET /{tenant_id}/forgot-password`）。
pub async fn forgot_page(headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    Html(render(&ForgotPassword {
        messages: &messages,
        accepted: false,
        error_key: None,
    }))
    .into_response()
}

/// リセット要求の送信（`POST /{tenant_id}/forgot-password`）。
pub async fn forgot_submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ForgotForm>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalPasswordResetRequestRequest {
        tenant_id: Some(tenant.0.clone()),
        email: form.email,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let result = state
        .api
        .password_reset_request(&ctx.correlation_id, &request)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(InternalPasswordResetRequestResponse::Accepted) => Html(render(&ForgotPassword {
            messages: &messages,
            accepted: true,
            error_key: None,
        }))
        .into_response(),
        Ok(InternalPasswordResetRequestResponse::Unavailable) => forgot_error(
            &messages,
            "forgot-password-error-unavailable",
            StatusCode::OK,
        ),
        Ok(InternalPasswordResetRequestResponse::RateLimited) => forgot_error(
            &messages,
            "forgot-password-error-rate-limited",
            StatusCode::TOO_MANY_REQUESTS,
        ),
        Err(e) => {
            tracing::error!(error = %e, "password reset request call to api failed");
            forgot_error(&messages, "admin-error-internal", StatusCode::BAD_GATEWAY)
        }
    }
}

/// 再設定フォーム（`GET /{tenant_id}/password-reset?token=...`）。
pub async fn reset_page(
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<ResetQuery>,
) -> Response {
    let messages = Messages::new(locale(&headers));
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        return reset_view(
            &messages,
            &tenant,
            false,
            "",
            false,
            Some("password-reset-error-missing-token"),
            StatusCode::BAD_REQUEST,
        );
    }
    reset_view(&messages, &tenant, true, &token, false, None, StatusCode::OK)
}

/// 再設定の実行（`POST /{tenant_id}/password-reset`）。
pub async fn reset_submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<ResetForm>,
) -> Response {
    if form.new_password != form.new_password_confirm {
        let messages = Messages::new(locale(&headers));
        return reset_view(
            &messages,
            &tenant,
            true,
            &form.token,
            false,
            Some("password-reset-error-mismatch"),
            StatusCode::BAD_REQUEST,
        );
    }
    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalPasswordResetCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        token: form.token.clone(),
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let result = state
        .api
        .password_reset_complete(&ctx.correlation_id, &request)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(InternalPasswordResetCompleteResponse::Ok) => {
            reset_view(&messages, &tenant, false, "", true, None, StatusCode::OK)
        }
        Ok(InternalPasswordResetCompleteResponse::InvalidOrExpired) => reset_view(
            &messages,
            &tenant,
            false,
            "",
            false,
            Some("password-reset-error-invalid"),
            StatusCode::BAD_REQUEST,
        ),
        Ok(InternalPasswordResetCompleteResponse::WeakPassword) => reset_view(
            &messages,
            &tenant,
            true,
            &form.token,
            false,
            Some("password-reset-error-weak"),
            StatusCode::BAD_REQUEST,
        ),
        Ok(InternalPasswordResetCompleteResponse::Internal) => reset_view(
            &messages,
            &tenant,
            true,
            &form.token,
            false,
            Some("admin-error-internal"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        Err(e) => {
            tracing::error!(error = %e, "password reset complete call to api failed");
            reset_view(
                &messages,
                &tenant,
                true,
                &form.token,
                false,
                Some("admin-error-internal"),
                StatusCode::BAD_GATEWAY,
            )
        }
    }
}

fn forgot_error(messages: &Messages, error_key: &str, status: StatusCode) -> Response {
    (
        status,
        Html(render(&ForgotPassword {
            messages,
            accepted: false,
            error_key: Some(error_key),
        })),
    )
        .into_response()
}

#[allow(clippy::too_many_arguments)]
fn reset_view(
    messages: &Messages,
    tenant: &WebTenant,
    show_form: bool,
    token: &str,
    success: bool,
    error_key: Option<&str>,
    status: StatusCode,
) -> Response {
    (
        status,
        Html(render(&PasswordReset {
            messages,
            tenant_prefix: &tenant.prefix(),
            show_form,
            token,
            success,
            error_key,
        })),
    )
        .into_response()
}

fn locale(headers: &HeaderMap) -> Locale {
    let cookie_lang = cookies::get(headers, cookies::LANG_COOKIE);
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    Locale::resolve(None, cookie_lang.as_deref(), accept)
}
