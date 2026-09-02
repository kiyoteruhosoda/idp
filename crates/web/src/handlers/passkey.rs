//! Passkey（WebAuthn）Web ハンドラ。
//!
//! セルフ登録（`/account/passkey/*`）とログイン（`/passkey/login/*`）を提供する。
//! begin/complete は JSON API として提供し、ブラウザの WebAuthn JS API から呼び出す。
//! 一覧・削除は HTML フォームで提供する。
//!
//! ログインは 3 画面（OIDC 認可フロー・管理コンソール・ポータル）から呼ばれる。開始は
//! 認可フロー用（`/passkey/login/begin`。`auth_session_id` Cookie を読む）と直接ログイン用
//! （`/passkey/login/direct/begin`。読まない）の 2 つ、完了は画面ごとに 3 つある
//! （発行する Cookie と遷移先が違うため）。
//!
//! # 画面の行き先
//!
//! HTML 経路（一覧・削除）は、**結果を伝える専用ページを作らず一覧へ戻す**（PRG）。結果は
//! `?saved=` / `?error=` で一覧の上のバナーに出す。認証器の管理画面
//! （`handlers::authenticators`）と同じ形である。削除の完了ページのように「戻るリンクの無い
//! 1 枚」を挟むと、利用者はブラウザの戻るしか手が無くなる。
//!
//! サインインしていない・セッションが切れたときは、同じ理由でログイン画面へ送る（設定配下の
//! 他の画面と揃える）。

use super::{found, internal_call_status, locale, see_other};
use crate::client_ip::ClientIp;
use crate::cookies;
use crate::correlation::CorrelationId;
use crate::handlers::forwarded_context;
use crate::handlers::step_up::{self, MANAGE_AUTHENTICATORS};
use crate::i18n::Messages;
use crate::state::WebState;
use crate::templates::{render, PasskeyListTemplate, PasskeyRegisterTemplate};
use crate::tenant::WebTenant;
use assay_contracts::auth::{
    InternalAdminPasskeyLoginCompleteRequest, InternalAdminPasskeyLoginCompleteResponse,
    InternalPasskeyDeleteRequest, InternalPasskeyDeleteResponse, InternalPasskeyListRequest,
    InternalPasskeyListResponse, InternalPasskeyLoginBeginRequest,
    InternalPasskeyLoginCompleteRequest, InternalPasskeyLoginCompleteResponse,
    InternalPasskeyRegisterBeginRequest, InternalPasskeyRegisterBeginResponse,
    InternalPasskeyRegisterCompleteRequest, InternalPasskeyRegisterCompleteResponse,
    InternalPortalPasskeyLoginCompleteRequest, InternalPortalPasskeyLoginCompleteResponse,
};
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::Form;
use serde::{Deserialize, Serialize};

// ─── 登録フロー ──────────────────────────────────────────────────────────────

/// 一覧のバナー表示（削除からの PRG で戻ってくる）。
#[derive(Debug, Deserialize)]
pub struct PasskeyListQuery {
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Passkey 一覧ページ（`GET /account/passkey`）。SSO Cookie が必要。
pub async fn list_page(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Query(query): Query<PasskeyListQuery>,
) -> Response {
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
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
            saved_key: query.saved.as_deref().and_then(saved_key_for),
            error_key: query.error.as_deref().and_then(error_key_for),
        }))
        .into_response(),
        InternalPasskeyListResponse::SessionExpired => found(&format!("{}/login", tenant.prefix())),
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
    // ここへ来た時点で step-up のゲートを通っている（SSO が無ければログイン画面へ送られている）。
    let messages = Messages::new(locale(&headers));
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
    let list = format!("{}/account/passkey", tenant.prefix());
    let Some(sso_session_id) = cookies::get(&headers, cookies::SSO_SESSION_COOKIE) else {
        return found(&format!("{}/login", tenant.prefix()));
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
    match result {
        // 一覧へ戻して結果はバナーで伝える（残っているパスキーをその場で確かめられる）。
        InternalPasskeyDeleteResponse::Ok => see_other(&format!("{list}?saved=deleted")),
        InternalPasskeyDeleteResponse::NotFound => see_other(&format!("{list}?error=not-found")),
        InternalPasskeyDeleteResponse::SessionExpired => {
            found(&format!("{}/login", tenant.prefix()))
        }
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
    begin(&state, &correlation, auth_session_id).await
}

/// 直接ログイン（管理コンソール・ポータル）の Passkey 認証開始 JSON API
/// （`POST /passkey/login/direct/begin`）。
///
/// **認可フロー用と分けてあるのは、`auth_session_id` Cookie を読まないためである。** 別タブで
/// 始めて放置した認可フローの Cookie が残っていると、共通の開始 API では認可フロー用の
/// チャレンジが返ってしまい、直接ログインの完了 API が用途違いとして弾く（Cookie が期限切れに
/// なるまで管理コンソールへ入れない）。「この画面は認可フローの続きではない」という事実を
/// エンドポイントで表す。
pub async fn direct_login_begin_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
) -> Response {
    begin(&state, &correlation, None).await
}

async fn begin(
    state: &WebState,
    correlation: &CorrelationId,
    auth_session_id: Option<String>,
) -> Response {
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
    pub form_post: Option<assay_contracts::auth::FormPostFields>,
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
        InternalPasskeyLoginCompleteResponse::RateLimited => Json(LoginCompleteJsonResponse {
            redirect_to: None,
            form_post: None,
            error: Some("rate_limited".to_string()),
        })
        .into_response(),
        InternalPasskeyLoginCompleteResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// 管理コンソールの Passkey ログイン完了 JSON API（`POST /{tenant_id}/passkey/login/admin/complete`）。
///
/// 認可フローの `login_complete_api` と違い、返す `redirect_to` は RP ではなく管理コンソールのホーム
/// である（`form_post` も無い。RP へ返す認可応答が存在しないため）。
pub async fn admin_login_complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<LoginCompleteBody>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let req = InternalAdminPasskeyLoginCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        challenge_id: body.challenge_id,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .passkey_login_admin_complete(&ctx.correlation_id, &req)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "admin passkey login complete call failed");
            return internal_call_status(&e).into_response();
        }
    };

    match outcome {
        InternalAdminPasskeyLoginCompleteResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
        } => {
            // パスワード経路（`admin_console::login`）と同じく、SSO を立てて CSRF の種は捨てる。
            let set_cookies = state
                .set_cookies()
                .set_session(
                    cookies::SSO_SESSION_COOKIE,
                    &sso_session_id,
                    sso_absolute_ttl_secs,
                )
                .expire_local(&state.origin_bound_cookie(cookies::ADMIN_CSRF_COOKIE));
            (
                set_cookies.into_headers(),
                Json(login_redirect(&super::admin_console::admin_home_path(
                    &tenant,
                ))),
            )
                .into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::ChallengeNotFound => {
            Json(login_error("challenge_not_found")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::InvalidCredential => {
            Json(login_error("invalid_credential")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::Forbidden => {
            Json(login_error("forbidden")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::PolicyDenied => {
            Json(login_error("policy_denied")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::RateLimited => {
            Json(login_error("rate_limited")).into_response()
        }
        InternalAdminPasskeyLoginCompleteResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// ポータルの Passkey ログイン完了 JSON API（`POST /{tenant_id}/passkey/login/portal/complete`）。
///
/// 遷移先と Cookie の組み立てはパスワード経路と同じ判断（SAML の続き・表示言語の同期）を通す
/// （`portal::sso_success_parts`）。302 を返せないので、その結果を JSON の `redirect_to` に載せる。
pub async fn portal_login_complete_api(
    State(state): State<WebState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(client_ip): Extension<ClientIp>,
    Extension(tenant): Extension<WebTenant>,
    headers: HeaderMap,
    Json(body): Json<LoginCompleteBody>,
) -> Response {
    let ctx = forwarded_context(&headers, &correlation, &client_ip);
    let req = InternalPortalPasskeyLoginCompleteRequest {
        tenant_id: Some(tenant.0.clone()),
        challenge_id: body.challenge_id,
        credential: body.credential,
        ip_address: ctx.ip_address,
        user_agent: ctx.user_agent,
    };
    let outcome = match state
        .api
        .passkey_login_portal_complete(&ctx.correlation_id, &req)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "portal passkey login complete call failed");
            return internal_call_status(&e).into_response();
        }
    };

    match outcome {
        InternalPortalPasskeyLoginCompleteResponse::Success {
            sso_session_id,
            sso_absolute_ttl_secs,
            user_language,
        } => {
            let (set_cookies, destination) = super::portal::sso_success_parts(
                &state,
                &headers,
                &sso_session_id,
                sso_absolute_ttl_secs,
                user_language.as_deref(),
                &tenant,
                &[cookies::PORTAL_CSRF_COOKIE],
            );
            (
                set_cookies.into_headers(),
                Json(login_redirect(&destination)),
            )
                .into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::ChallengeNotFound => {
            Json(login_error("challenge_not_found")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::InvalidCredential => {
            Json(login_error("invalid_credential")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::EmailVerificationRequired => {
            Json(login_error("email_verification_required")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::PolicyDenied => {
            Json(login_error("policy_denied")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::RateLimited => {
            Json(login_error("rate_limited")).into_response()
        }
        InternalPortalPasskeyLoginCompleteResponse::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ─── ヘルパー ─────────────────────────────────────────────────────────────────

/// 直接ログイン（管理コンソール・ポータル）の成功応答。JS はこの `redirect_to` へ遷移する。
fn login_redirect(destination: &str) -> LoginCompleteJsonResponse {
    LoginCompleteJsonResponse {
        redirect_to: Some(destination.to_string()),
        form_post: None,
        error: None,
    }
}

/// 直接ログインの失敗応答。`code` はフロント側スクリプトが翻訳キーへ写す（文言は web が持つ）。
fn login_error(code: &str) -> LoginCompleteJsonResponse {
    LoginCompleteJsonResponse {
        redirect_to: None,
        form_post: None,
        error: Some(code.to_string()),
    }
}

/// 一覧のバナー（成功）。値は削除の PRG が付ける `?saved=` だけ。
fn saved_key_for(value: &str) -> Option<&'static str> {
    match value {
        "deleted" => Some("passkey-deleted-message"),
        _ => None,
    }
}

/// 一覧のバナー（失敗）。未知の値は何も出さない（URL の文字列を画面へ出さない）。
fn error_key_for(value: &str) -> Option<&'static str> {
    match value {
        "not-found" => Some("passkey-error-not-found"),
        _ => None,
    }
}
