//! アカウント設定リンクの画面（web。ADR-0062）。
//!
//! 管理者が利用者を作った・パスワードを再発行したときに渡すワンタイムリンクの着地点。
//! 本人はまだログインしていないので、**本人性の根拠はトークンだけ**である（未ログイン経路。
//! 忘失時のパスワード再設定と同じ立て付け）。
//!
//! - `GET /{tenant_id}/account-setup?token=...` — 何ができるかを出す。⚠ **開いただけでは
//!   消費しない**（チャットのプレビュー bot が先に取りに来ても、リンクは生きたまま）。
//! - `POST /{tenant_id}/account-setup` — パスワードを設定する（実体は再設定と同じ api）。
//! - `POST /{tenant_id}/account-setup/passkey/begin|complete` — パスキーを登録する（JS から）。
//! - `GET /{tenant_id}/account-setup/done` — 完了の表示（パスキー登録の着地点）。
//!
//! フォームに CSRF トークンを付けないのは再設定画面と同じ理由である —— セッションを持たない
//! 画面で、実行の根拠はトークンの所持そのものであり、第三者が強制しても得られる状態変化がない。

use super::locale;
use crate::client_ip::ClientIp;
use crate::correlation::CorrelationId;
use crate::handlers::forwarded_context;
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, AccountSetup};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAccountSetupDescribeRequest, InternalAccountSetupDescribeResponse,
    InternalAccountSetupPasskeyBeginRequest, InternalAccountSetupPasskeyBeginResponse,
    InternalAccountSetupPasskeyCompleteRequest, InternalAccountSetupPasskeyCompleteResponse,
    InternalPasswordResetCompleteRequest, InternalPasswordResetCompleteResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SetupQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasswordForm {
    pub token: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyBeginBody {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyCompleteBody {
    pub token: String,
    pub challenge_id: String,
    pub name: String,
    pub credential: serde_json::Value,
}

/// リンクを開いた画面（`GET /{tenant_id}/account-setup`）。
pub async fn setup_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<SetupQuery>,
) -> Response {
    // ⚠ `Messages`（fluent のバンドル）は `Send` ではないので、**api を待つ前に作らない**。
    // 作ってしまうと await を跨いで持つことになり、ハンドラが axum に載らなくなる。
    let token = query.token.unwrap_or_default();
    if token.is_empty() {
        let messages = Messages::new(locale(&headers));
        return view(&messages, &tenant, Fatal, "", None, false, None);
    }

    let request = InternalAccountSetupDescribeRequest {
        tenant_id: Some(tenant.0.clone()),
        token: token.clone(),
    };
    let described = state
        .api
        .account_setup_describe(&correlation.0, &request)
        .await;
    let messages = Messages::new(locale(&headers));
    match described {
        Ok(InternalAccountSetupDescribeResponse::Ok {
            email,
            allows_passkey,
            ..
        }) => view(
            &messages,
            &tenant,
            Open,
            &token,
            Some(&email),
            allows_passkey,
            None,
        ),
        Ok(InternalAccountSetupDescribeResponse::InvalidOrExpired) => {
            view(&messages, &tenant, Fatal, "", None, false, None)
        }
        _ => view(
            &messages,
            &tenant,
            Open,
            &token,
            None,
            false,
            Some("account-setup-error-internal"),
        ),
    }
}

/// 完了の表示（`GET /{tenant_id}/account-setup/done`）。パスキー登録の着地点。
pub async fn done_page(Extension(tenant): Extension<WebTenant>, headers: HeaderMap) -> Response {
    let messages = Messages::new(locale(&headers));
    view(&messages, &tenant, Done, "", None, false, None)
}

/// パスワードを設定する（`POST /{tenant_id}/account-setup`）。
///
/// 実体は忘失時の再設定と同じ api（同じ表のトークンなのでそのまま通る）。ポリシー検証・
/// セッション失効・監査を二重に持たないため、専用の口は作らない。
pub async fn set_password(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    if form.new_password != form.new_password_confirm {
        let messages = Messages::new(locale(&headers));
        return view(
            &messages,
            &tenant,
            Open,
            &form.token,
            None,
            true,
            Some("account-setup-error-mismatch"),
        );
    }

    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalPasswordResetCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        token: form.token.clone(),
        new_password: form.new_password,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let completed = state
        .api
        .password_reset_complete(&ctx.correlation_id, &request)
        .await;
    let messages = Messages::new(locale(&headers));
    match completed {
        Ok(InternalPasswordResetCompleteResponse::Ok) => {
            view(&messages, &tenant, Done, "", None, false, None)
        }
        Ok(InternalPasswordResetCompleteResponse::InvalidOrExpired) => {
            view(&messages, &tenant, Fatal, "", None, false, None)
        }
        Ok(InternalPasswordResetCompleteResponse::WeakPassword { reason }) => view(
            &messages,
            &tenant,
            Open,
            &form.token,
            None,
            true,
            Some(super::password_rejection_key(
                reason,
                "account-setup-error-weak",
            )),
        ),
        _ => view(
            &messages,
            &tenant,
            Open,
            &form.token,
            None,
            true,
            Some("account-setup-error-internal"),
        ),
    }
}

/// パスキー登録の開始（`POST /{tenant_id}/account-setup/passkey/begin`）。JS から呼ぶ。
pub async fn passkey_begin(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    Json(body): Json<PasskeyBeginBody>,
) -> Response {
    let request = InternalAccountSetupPasskeyBeginRequest {
        tenant_id: Some(tenant.0.clone()),
        token: body.token,
    };
    match state
        .api
        .account_setup_passkey_begin(&correlation.0, &request)
        .await
    {
        Ok(response) => {
            let status = match response {
                InternalAccountSetupPasskeyBeginResponse::Ok { .. } => StatusCode::OK,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "account setup passkey begin failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// パスキー登録の完了（`POST /{tenant_id}/account-setup/passkey/complete`）。JS から呼ぶ。
pub async fn passkey_complete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<PasskeyCompleteBody>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let request = InternalAccountSetupPasskeyCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        token: body.token,
        challenge_id: body.challenge_id,
        name: body.name,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    match state
        .api
        .account_setup_passkey_complete(&ctx.correlation_id, &request)
        .await
    {
        Ok(response) => {
            let status = match response {
                InternalAccountSetupPasskeyCompleteResponse::Ok => StatusCode::OK,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "account setup passkey complete failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// 画面の状態。**リンクが死んでいる（`Fatal`）ときは理由を言い分けない**（ADR-0062）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Open,
    Done,
    Fatal,
}
use Stage::{Done, Fatal, Open};

fn view(
    messages: &Messages,
    tenant: &WebTenant,
    stage: Stage,
    token: &str,
    email: Option<&str>,
    allows_passkey: bool,
    error_key: Option<&'static str>,
) -> Response {
    let status = match stage {
        Stage::Fatal => StatusCode::BAD_REQUEST,
        _ if error_key.is_some() => StatusCode::BAD_REQUEST,
        _ => StatusCode::OK,
    };
    let html = render(&AccountSetup {
        messages,
        tenant: &tenant.prefix(),
        token,
        email,
        allows_passkey,
        done: stage == Stage::Done,
        fatal_key: match stage {
            Stage::Fatal => Some("account-setup-error-invalid"),
            _ => None,
        },
        error_key,
    });
    (status, Html(html)).into_response()
}
