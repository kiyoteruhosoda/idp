//! メール検証画面（web。`/{tenant_id}/verify-email`。SEC6b）。
//!
//! 自己登録の確認メールのリンク（`?token=...`）から開く。GET は確認ボタン（POST でトークンを消費）を
//! 表示し、メールクライアントのリンクプリフェッチで単回トークンを消費しないようにする。POST の実体は
//! api の `POST /{tenant_id}/auth/verify-email` へ委ねる。未ログイン経路（SSO 不要。トークン所持が
//! 本人性の根拠）。

use crate::api_client::VerifyEmailResult;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, VerifyEmail};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyForm {
    pub token: String,
}

/// 検証ページ（`GET /{tenant_id}/verify-email?token=...`）。確認ボタンを表示する。
pub async fn page(headers: HeaderMap, Query(query): Query<VerifyQuery>) -> Response {
    let messages = Messages::new(locale(&headers));
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html(render(&VerifyEmail {
                messages: &messages,
                show_form: false,
                token: "",
                success: false,
                error_key: None,
            })),
        )
            .into_response();
    }
    Html(render(&VerifyEmail {
        messages: &messages,
        show_form: true,
        token: &token,
        success: false,
        error_key: None,
    }))
    .into_response()
}

/// 検証の実行（`POST /{tenant_id}/verify-email`）。
pub async fn submit(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<VerifyForm>,
) -> Response {
    let result = state
        .api
        .verify_email(&correlation.0, &tenant.0, &form.token)
        .await;
    let messages = Messages::new(locale(&headers));
    match result {
        Ok(VerifyEmailResult::Verified) => Html(render(&VerifyEmail {
            messages: &messages,
            show_form: false,
            token: "",
            success: true,
            error_key: None,
        }))
        .into_response(),
        Ok(VerifyEmailResult::InvalidOrExpired) => (
            StatusCode::BAD_REQUEST,
            Html(render(&VerifyEmail {
                messages: &messages,
                show_form: true,
                token: &form.token,
                success: false,
                error_key: Some("verify-email-error-invalid"),
            })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(render(&VerifyEmail {
                messages: &messages,
                show_form: true,
                token: &form.token,
                success: false,
                error_key: Some("admin-error-internal"),
            })),
        )
            .into_response(),
    }
}

fn locale(headers: &HeaderMap) -> Locale {
    let cookie_lang = cookies::get(headers, cookies::LANG_COOKIE);
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok());
    Locale::resolve(None, None, cookie_lang.as_deref(), accept)
}
