//! Passkey（WebAuthn）Web ハンドラ。
//!
//! セルフ登録（`/account/passkey/*`）とログインフロー（`/passkey/login/*`）を提供する。
//! begin/complete は JSON API として提供し、ブラウザの WebAuthn JS API から呼び出す。
//! 一覧・削除は HTML フォームで提供する。

use super::{internal_call_status, locale};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::handlers::forwarded_context;
use crate::handlers::step_up::{self, MANAGE_AUTHENTICATORS};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, MessagePage, PasskeyListTemplate, PasskeyRegisterTemplate};
use crate::tenant::WebTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::Form;
use idp_contracts::auth::{
    InternalPasskeyDeleteRequest, InternalPasskeyDeleteResponse, InternalPasskeyListRequest,
    InternalPasskeyListResponse, InternalPasskeyLoginBeginRequest,
    InternalPasskeyLoginCompleteRequest, InternalPasskeyLoginCompleteResponse,
    InternalPasskeyRegisterBeginRequest, InternalPasskeyRegisterBeginResponse,
    InternalPasskeyRegisterCompleteRequest, InternalPasskeyRegisterCompleteResponse,
};
use serde::{Deserialize, Serialize};

// ─── 登録フロー ──────────────────────────────────────────────────────────────

/// Passkey 一覧ページ（`GET /account/passkey`）。SSO Cookie が必要。
pub async fn list_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        // FluentBundle は !Send なので await の前に作成・消費する。
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "passkey-error-not-signed-in",
        );
    };
    let req = InternalPasskeyListRequest { sso_session_id };
    let result = match state.api.passkey_list(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey list call failed");
            return internal_call_status(&e).into_response();
        }
    };
    // FluentBundle は !Send なので await の後に作成する。
    let messages = Messages::new(locale(&headers));
    match result {
        InternalPasskeyListResponse::Ok { credentials } => Html(render(&PasskeyListTemplate {
            messages: &messages,
            tenant_prefix: &tenant.prefix(),
            credentials: &credentials,
        }))
        .into_response(),
        InternalPasskeyListResponse::SessionExpired => error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "passkey-error-session-expired",
        ),
        InternalPasskeyListResponse::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Passkey 登録ページ（`GET /account/passkey/register`）。SSO Cookie が必要。
pub async fn register_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
) -> Response {
    // 認証器の追加は step-up の対象（AP5。TOTP セットアップと同じ理由）。
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/passkey/register", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let messages = Messages::new(locale(&headers));
    if cookies::get(&headers, cookies::SSO_SESSION_COOKIE).is_none() {
        return error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "passkey-error-not-signed-in",
        );
    }
    Html(render(&PasskeyRegisterTemplate {
        messages: &messages,
        tenant_prefix: &tenant.prefix(),
        error_key: None,
    }))
    .into_response()
}

/// Passkey 登録開始 JSON API（`POST /passkey/register/begin`）。JS から呼ぶ。
/// 成功時: HTTP 200 `{ "result": "ok", "challenge_id": "...", "options": {...} }`
/// 失敗時: HTTP 401 / 500
#[derive(Debug, Deserialize)]
pub struct RegisterBeginBody {
    pub name: String,
}

pub async fn register_begin_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<RegisterBeginBody>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // 画面と同じく step-up の対象（AP5）。**画面のゲートだけでは守れない**: 認証器を実際に
    // 作るのはこの JSON エンドポイントで、Cookie を持つ呼び出し元は画面を経由せず直接叩ける。
    if let Err(response) = step_up::require_step_up_api(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/passkey/register", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    // user_name は認証器に表示される名前。SSO セッションからは取得できないため入力名を使う。
    let req = InternalPasskeyRegisterBeginRequest {
        sso_session_id,
        user_name: body.name.clone(),
    };
    let result = match state.api.passkey_register_begin(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey register begin failed");
            return internal_call_status(&e).into_response();
        }
    };
    match result {
        InternalPasskeyRegisterBeginResponse::Ok { .. } => Json(result).into_response(),
        InternalPasskeyRegisterBeginResponse::SessionExpired => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        InternalPasskeyRegisterBeginResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Passkey 登録完了 JSON API（`POST /passkey/register/complete`）。JS から呼ぶ。
/// 成功時: HTTP 200 `{ "result": "ok", "credential_id": "..." }`
/// 失敗時: HTTP 200 にエラー variant、または 401 / 500
#[derive(Debug, Deserialize)]
pub struct RegisterCompleteBody {
    pub challenge_id: String,
    pub name: String,
    pub credential: serde_json::Value,
}

pub async fn register_complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<RegisterCompleteBody>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // 画面と同じく step-up の対象（AP5）。**画面のゲートだけでは守れない**: 認証器を実際に
    // 作るのはこの JSON エンドポイントで、Cookie を持つ呼び出し元は画面を経由せず直接叩ける。
    if let Err(response) = step_up::require_step_up_api(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/passkey/register", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let req = InternalPasskeyRegisterCompleteRequest {
        sso_session_id,
        challenge_id: body.challenge_id,
        name: body.name,
        credential: body.credential,
    };
    let result = match state
        .api
        .passkey_register_complete(&correlation.0, &req)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey register complete failed");
            return internal_call_status(&e).into_response();
        }
    };
    match result {
        InternalPasskeyRegisterCompleteResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        InternalPasskeyRegisterCompleteResponse::SessionExpired => {
            StatusCode::UNAUTHORIZED.into_response()
        }
        _ => Json(result).into_response(),
    }
}

/// Passkey 削除（`POST /account/passkey/delete`）。HTML フォームから呼ぶ。
/// CSRF は SameSite=Lax の SSO Cookie に委ねる（TOTP 削除と同パターン）。
#[derive(Deserialize)]
pub struct DeleteForm {
    pub credential_id: String,
}

pub async fn delete(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Form(form): Form<DeleteForm>,
) -> Response {
    // 認証器の削除は step-up の対象（AP5）。
    if let Err(response) = step_up::require_step_up(
        &state,
        &correlation,
        &tenant,
        &headers,
        MANAGE_AUTHENTICATORS,
        &format!("{}/account/passkey", tenant.prefix()),
    )
    .await
    {
        return response;
    }
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        // FluentBundle は !Send なので await の前に作成・消費する。
        let messages = Messages::new(locale(&headers));
        return error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "passkey-error-not-signed-in",
        );
    };
    let req = InternalPasskeyDeleteRequest {
        sso_session_id,
        credential_id: form.credential_id,
    };
    let result = match state.api.passkey_delete(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey delete failed");
            return internal_call_status(&e).into_response();
        }
    };
    // FluentBundle は !Send なので await の後に作成する。
    let messages = Messages::new(locale(&headers));
    match result {
        InternalPasskeyDeleteResponse::Ok => Html(render(&MessagePage {
            title: messages.get("passkey-deleted-title"),
            message: messages.get("passkey-deleted-message"),
        }))
        .into_response(),
        InternalPasskeyDeleteResponse::SessionExpired => error_page(
            &messages,
            StatusCode::UNAUTHORIZED,
            "passkey-error-session-expired",
        ),
        InternalPasskeyDeleteResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ─── ログインフロー ──────────────────────────────────────────────────────────

/// Passkey 認証開始 JSON API（`POST /passkey/login/begin`）。ログイン画面の JS から呼ぶ。
/// 成功時: HTTP 200 `{ "result": "ok", "challenge_id": "...", "options": {...} }`
pub async fn login_begin_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let auth_session_id = cookies::get(&headers, cookies::AUTH_SESSION_COOKIE);
    let req = InternalPasskeyLoginBeginRequest { auth_session_id };
    let result = match state.api.passkey_login_begin(&correlation.0, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "passkey login begin failed");
            return internal_call_status(&e).into_response();
        }
    };
    Json(result).into_response()
}

/// Passkey 認証完了 JSON API（`POST /passkey/login/complete`）。JS から呼ぶ。
/// 成功時は `{ redirect_to: "..." }` を返し、JS がリダイレクトする。
/// 失敗時は `{ error: "..." }` を返す。
#[derive(Debug, Deserialize)]
pub struct LoginCompleteBody {
    pub challenge_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct LoginCompleteJsonResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    /// `response_mode=form_post` のとき、`redirect_to` へ POST する hidden フィールド（G12）。
    ///
    /// パスキーのログインだけは応答が JSON（ブラウザの JS が受ける）なので、他の経路のように
    /// サーバ側で自動送信フォームを描けない。フィールドをそのまま渡し、**JS にフォームを
    /// 組み立てて送信させる**（`assets/passkey-login.js`）。`None` のときは従来どおり
    /// `redirect_to` へ遷移する。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_post: Option<idp_contracts::auth::FormPostFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn login_complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<LoginCompleteBody>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let req = InternalPasskeyLoginCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        challenge_id: body.challenge_id,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .passkey_login_complete(&ctx.correlation_id, &req)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "passkey login complete call failed");
            return internal_call_status(&e).into_response();
        }
    };

    match outcome {
        InternalPasskeyLoginCompleteResponse::Success {
            redirect_to,
            form_post,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_session(cookies::AUTH_SESSION_COOKIE);
            (
                set_cookies.into_headers(),
                Json(LoginCompleteJsonResponse {
                    redirect_to: Some(redirect_to),
                    form_post,
                    error: None,
                }),
            )
                .into_response()
        }
        InternalPasskeyLoginCompleteResponse::ConsentRequired {
            auth_session_id,
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .set_session(
                    cookies::AUTH_SESSION_COOKIE,
                    &auth_session_id,
                    state.config.auth_session_ttl_secs(),
                );
            (
                set_cookies.into_headers(),
                Json(LoginCompleteJsonResponse {
                    redirect_to: Some(format!("{}/consent", tenant.prefix())),
                    // 同意画面は web 自身の画面なので、認可応答の form_post は付かない。
                    form_post: None,
                    error: None,
                }),
            )
                .into_response()
        }
        InternalPasskeyLoginCompleteResponse::ChallengeNotFound => {
            Json(LoginCompleteJsonResponse {
                redirect_to: None,
                form_post: None,
                error: Some("challenge_not_found".to_string()),
            })
            .into_response()
        }
        InternalPasskeyLoginCompleteResponse::SessionExpired => Json(LoginCompleteJsonResponse {
            redirect_to: None,
            form_post: None,
            error: Some("session_expired".to_string()),
        })
        .into_response(),
        InternalPasskeyLoginCompleteResponse::InvalidCredential => {
            Json(LoginCompleteJsonResponse {
                redirect_to: None,
                form_post: None,
                error: Some("invalid_credential".to_string()),
            })
            .into_response()
        }
        // 認証ポリシーによる拒否。フロント側スクリプトはこのコードを翻訳キーへ写す。
        InternalPasskeyLoginCompleteResponse::PolicyDenied => Json(LoginCompleteJsonResponse {
            redirect_to: None,
            form_post: None,
            error: Some("policy_denied".to_string()),
        })
        .into_response(),
        InternalPasskeyLoginCompleteResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ─── ヘルパー ─────────────────────────────────────────────────────────────────

fn error_page(messages: &Messages, status: StatusCode, error_key: &str) -> Response {
    let body = render(&MessagePage {
        title: messages.get("passkey-title"),
        message: messages.get(error_key),
    });
    (status, Html(body)).into_response()
}
