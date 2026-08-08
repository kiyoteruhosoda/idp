//! 外部 IdP ログインのブラウザ経路（web。AP10）。
//!
//! - `GET /{tenant_id}/external/{provider}/start` — api に認可 URL を作らせて外部 IdP へ 302 する。
//! - `GET /{tenant_id}/external/{provider}/callback` — 外部 IdP から戻る先。api に検証させ、
//!   成功なら SSO Cookie を発行して元の画面へ戻す。
//!
//! `state` / `nonce` / PKCE の生成・検証はすべて api 側（進行状態は DB）。web は Cookie の組み立てと
//! 画面遷移だけを担う（他のログイン経路と同じ責務分担）。**Cookie に `state` を置かない**のは、
//! ADR-0018 と同じ理由（api はブラウザ Cookie を読まない）で、`state` は外部 IdP から戻る値だけを
//! 鍵として使う設計にしているため。

use crate::cookies;
use crate::correlation::CorrelationId;
use crate::handlers::{forwarded_context, found, locale};
use crate::i18n::{Locale, Messages};
use crate::state::WebState;
use crate::templates::{render, MessagePage};
use crate::tenant::WebTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use idp_contracts::auth::{
    InternalExternalCallbackRequest, InternalExternalCallbackResponse,
    InternalExternalStartRequest, InternalExternalStartResponse,
};
use serde::Deserialize;

/// 外部 IdP から戻ってくるクエリ（成功時は `code` + `state`、失敗時は `error`）。
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// 外部 IdP 側で拒否された場合のエラーコード（利用者が同意しなかった等）。
    #[serde(default)]
    pub error: Option<String>,
}

/// 外部 IdP ログインの開始（`GET /{tenant_id}/external/{provider}/start`）。
pub async fn start(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Path((_tenant_id, provider_code)): Path<(String, String)>,
) -> Response {
    // OIDC 認可フローの途中から来た場合は `auth_session_id` を引き継ぐ（戻り先の判断に使う）。
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);
    let request = InternalExternalStartRequest {
        tenant_id: Some(tenant.0.clone()),
        provider_code,
        auth_session_id,
    };
    match state.api.external_start(&correlation.0, &request).await {
        Ok(InternalExternalStartResponse::Redirect { location }) => found(&location),
        Ok(InternalExternalStartResponse::ProviderUnavailable) => {
            let messages = Messages::new(locale(&headers));
            message_page(
                &messages,
                "external-login-error-unavailable",
                StatusCode::NOT_FOUND,
            )
        }
        Ok(InternalExternalStartResponse::Internal) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "external idp start call to api failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// 外部 IdP からのコールバック（`GET /{tenant_id}/external/{provider}/callback`）。
pub async fn callback(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let locale = locale(&headers);

    // 外部 IdP 側が拒否した場合（利用者が同意しなかった等）。エラーコードは画面へ出さない
    //（外部 IdP の語彙をそのまま出しても利用者の助けにならず、値も外部由来のため）。
    if let Some(error) = query.error.as_deref() {
        tracing::info!(
            correlation_id = %correlation.0,
            external_error = %error,
            "external idp returned an error to the callback"
        );
        let messages = Messages::new(locale);
        return message_page(
            &messages,
            "external-login-error-denied",
            StatusCode::FORBIDDEN,
        );
    }

    let (Some(code), Some(external_state)) = (query.code, query.state) else {
        let messages = Messages::new(locale);
        return message_page(
            &messages,
            "external-login-error-invalid",
            StatusCode::BAD_REQUEST,
        );
    };

    let ctx = forwarded_context(&headers, &correlation);
    let request = InternalExternalCallbackRequest {
        tenant_id: Some(tenant.0.clone()),
        state: external_state,
        code,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .external_callback(&ctx.correlation_id, &request)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "external idp callback call to api failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let messages = Messages::new(locale);
    match outcome {
        InternalExternalCallbackResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            auth_session_id,
            user_language,
        } => {
            let mut set_cookies = state.set_cookies().set_session(
                cookies::SSO_SESSION_COOKIE,
                &sso_session_id,
                sso_absolute_ttl_secs,
            );
            // ユーザーの DB 言語設定があれば lang Cookie に同期する（MT20: DB > Cookie）。
            if let Some(lang) = user_language.as_deref().and_then(Locale::from_tag) {
                set_cookies = set_cookies.set_local(
                    cookies::LANG_COOKIE,
                    lang.as_tag(),
                    cookies::LANG_COOKIE_MAX_AGE_SECS,
                );
            }
            // OIDC 認可フローの途中から来ていれば、認可の再開へ戻す（`/authorize` をやり直すと
            // 認可要求のパラメータが失われる）。そうでなければアカウント画面へ。
            let destination = if auth_session_id.is_some() {
                format!("{}/authorize/resume", tenant.prefix())
            } else {
                format!("{}/settings", tenant.prefix())
            };
            (set_cookies.into_headers(), found(&destination)).into_response()
        }
        InternalExternalCallbackResponse::StateExpired => message_page(
            &messages,
            "external-login-error-expired",
            StatusCode::BAD_REQUEST,
        ),
        InternalExternalCallbackResponse::NotLinked => message_page(
            &messages,
            "external-login-error-not-linked",
            StatusCode::FORBIDDEN,
        ),
        InternalExternalCallbackResponse::UserUnavailable => message_page(
            &messages,
            "login-error-invalid-credentials",
            StatusCode::FORBIDDEN,
        ),
        InternalExternalCallbackResponse::PolicyDenied => message_page(
            &messages,
            "login-error-policy-denied",
            StatusCode::FORBIDDEN,
        ),
        InternalExternalCallbackResponse::ExternalFailure => message_page(
            &messages,
            "external-login-error-failed",
            StatusCode::BAD_GATEWAY,
        ),
        InternalExternalCallbackResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn message_page(messages: &Messages, key: &str, status: StatusCode) -> Response {
    let body = render(&MessagePage {
        title: messages.get("external-login-title"),
        message: messages.get(key),
    });
    (status, Html(body)).into_response()
}
