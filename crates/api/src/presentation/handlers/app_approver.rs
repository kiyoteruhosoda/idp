//! 認証アプリが呼ぶ口（`/{tenant_id}/app-approver/*`）と App Link の受け皿（task #892。ADR-0075）。
//!
//! アプリはトークンを持たず、操作のたびに Keystore の鍵で署名する（文の形は
//! `domain::app_approver::signed_message`）。判定は Application 層（`AppApprovalService`）にあり、
//! ここは DTO の詰め替えと HTTP の状態への写しだけを行う。
//!
//! 失敗の本文は `{"error": "<コード>", "reason": "<詳細>"}`（コードは言語不変。アプリが分岐に使う）。

use crate::application::app_approval::AppApproverError;
use crate::application::audit::RequestContext;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use chrono::SecondsFormat;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// 失敗の本文。
#[derive(Debug, Serialize, ToSchema)]
pub struct AppApproverErrorResponse {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

fn error_response(e: AppApproverError) -> Response {
    let (status, error, reason) = match &e {
        AppApproverError::Disabled | AppApproverError::NotFound => {
            (StatusCode::NOT_FOUND, "not_found", None)
        }
        AppApproverError::Expired => (StatusCode::GONE, "expired", None),
        AppApproverError::Conflict => (StatusCode::CONFLICT, "conflict", None),
        AppApproverError::AttestationRejected(r) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "attestation_rejected",
            Some(r.as_str()),
        ),
        AppApproverError::AlreadyRegistered => (StatusCode::CONFLICT, "already_registered", None),
        AppApproverError::SignatureInvalid => (StatusCode::FORBIDDEN, "signature_invalid", None),
        AppApproverError::KeyRevoked => (StatusCode::FORBIDDEN, "key_revoked", None),
        AppApproverError::NotAMember => (StatusCode::FORBIDDEN, "not_a_member", None),
        AppApproverError::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request", None),
        AppApproverError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", None),
        AppApproverError::Internal(m) => {
            tracing::error!(error = %m, "app approver request failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "server_error", None)
        }
    };
    (status, Json(AppApproverErrorResponse { error, reason })).into_response()
}

fn context(state: &AppState, correlation: &CorrelationId, headers: &HeaderMap) -> RequestContext {
    super::request_context(headers, correlation, state.config.trust_forwarded_headers())
}

fn rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

// ─── 登録 ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct EnrollmentStartedResponse {
    pub enrollment_id: String,
    /// Key Attestation に入れる値（base64url・32 バイト）。
    pub challenge: String,
    pub expires_at: String,
}

/// 鍵の登録の受付を始める（`POST /{tenant_id}/app-approver/enrollments`）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/app-approver/enrollments",
    tag = "app-approver",
    responses(
        (status = 201, description = "受付（10 分）", body = EnrollmentStartedResponse),
        (status = 404, description = "認証アプリの口が閉じている"),
        (status = 429, description = "接続元ごとの枠を超えた"),
    )
)]
pub async fn start_enrollment(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
) -> Response {
    let ctx = context(&state, &correlation, &headers);
    match state
        .app_approval
        .start_enrollment(tenant.context(), &ctx)
        .await
    {
        Ok(started) => (
            StatusCode::CREATED,
            Json(EnrollmentStartedResponse {
                enrollment_id: started.enrollment_id,
                challenge: started.challenge,
                expires_at: rfc3339(started.expires_at),
            }),
        )
            .into_response(),
        Err(e) => error_response(e),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SubmitKeyRequest {
    /// Keystore の証明書の鎖（標準の base64 の DER。鍵の証明書が先頭、根が最後）。
    pub certificate_chain: Vec<String>,
    /// 機種名（表示だけ）。
    pub device_name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SubmitKeyResponse {
    /// アプリが Auth Tab で開く、利用者の確認の画面。
    pub confirm_url: String,
}

/// 鍵の証明を送る（`PUT /{tenant_id}/app-approver/enrollments/{id}/key`）。
#[utoipa::path(
    put,
    path = "/{tenant_id}/app-approver/enrollments/{id}/key",
    tag = "app-approver",
    request_body = SubmitKeyRequest,
    responses(
        (status = 200, description = "鍵の証明は通った。利用者の確認を待つ", body = SubmitKeyResponse),
        (status = 422, description = "Key Attestation が合わない", body = AppApproverErrorResponse),
        (status = 404, description = "受付が無い"),
        (status = 410, description = "受付が切れた"),
    )
)]
pub async fn submit_key(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Extension(correlation): Extension<CorrelationId>,
    Path((_tenant_id, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SubmitKeyRequest>,
) -> Response {
    let ctx = context(&state, &correlation, &headers);
    match state
        .app_approval
        .submit_key(
            tenant.context(),
            &id,
            &body.certificate_chain,
            &body.device_name,
            &ctx,
        )
        .await
    {
        Ok(()) => Json(SubmitKeyResponse {
            confirm_url: format!(
                "{}/{}/settings/app-approver/confirm?enrollment={}",
                state.config.public_web_base_url().trim_end_matches('/'),
                tenant.tenant().id.as_uuid(),
                id
            ),
        })
        .into_response(),
        Err(e) => error_response(e),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ActivateRequest {
    /// 利用者の確認の後に Auth Tab の戻り先に載ったコード。
    pub code: String,
    /// `activate` の文への署名（base64url の DER）。
    pub signature: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActivateResponse {
    pub key_id: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// 鍵を有効にする（`POST /{tenant_id}/app-approver/enrollments/{id}/activate`）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/app-approver/enrollments/{id}/activate",
    tag = "app-approver",
    request_body = ActivateRequest,
    responses(
        (status = 200, description = "有効にした", body = ActivateResponse),
        (status = 403, description = "コードか署名が合わない", body = AppApproverErrorResponse),
        (status = 409, description = "まだ確認されていない・二重の送信"),
    )
)]
pub async fn activate(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Extension(correlation): Extension<CorrelationId>,
    Path((_tenant_id, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ActivateRequest>,
) -> Response {
    let ctx = context(&state, &correlation, &headers);
    match state
        .app_approval
        .activate(tenant.context(), &id, &body.code, &body.signature, &ctx)
        .await
    {
        Ok(key) => Json(ActivateResponse {
            key_id: key.key_id,
            username: key.username,
            display_name: key.display_name,
        })
        .into_response(),
        Err(e) => error_response(e),
    }
}

// ─── 承認 ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct ApprovalRequestResponse {
    pub request_id: String,
    /// 署名に入れる値。
    pub challenge: String,
    /// `pending` / `approved` / `denied` / `completed` / `refused`
    pub state: &'static str,
    pub created_at: String,
    pub expires_at: String,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    /// 認可の途中から来たなら、その RP の表示名（無ければ client_id）。
    pub client_name: Option<String>,
}

/// 依頼の中身（`GET /{tenant_id}/app-approver/requests/{id}`）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/app-approver/requests/{id}",
    tag = "app-approver",
    responses(
        (status = 200, description = "依頼", body = ApprovalRequestResponse),
        (status = 404, description = "無い"),
        (status = 410, description = "切れた"),
    )
)]
pub async fn view_request(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Path((_tenant_id, id)): Path<(String, String)>,
) -> Response {
    match state.app_approval.view_request(tenant.context(), &id).await {
        Ok(view) => Json(ApprovalRequestResponse {
            request_id: view.request_id,
            challenge: view.challenge,
            state: view.state.as_str(),
            created_at: rfc3339(view.created_at),
            expires_at: rfc3339(view.expires_at),
            ip_address: view.ip_address,
            country: view.country,
            client_name: view.client_name,
        })
        .into_response(),
        Err(e) => error_response(e),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecisionRequest {
    pub key_id: String,
    /// `approve` / `deny` の文への署名（base64url の DER）。
    pub signature: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApproveResponse {
    /// アプリが同じスマホのブラウザで開く URL（コードは 30 秒・1 回だけ）。
    pub continue_url: String,
}

/// 承認する（`POST /{tenant_id}/app-approver/requests/{id}/approve`）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/app-approver/requests/{id}/approve",
    tag = "app-approver",
    request_body = DecisionRequest,
    responses(
        (status = 200, description = "承認した", body = ApproveResponse),
        (status = 403, description = "署名が合わない・鍵が無い・組織で使えない", body = AppApproverErrorResponse),
        (status = 409, description = "待っている依頼ではない"),
        (status = 410, description = "切れた"),
    )
)]
pub async fn approve(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Extension(correlation): Extension<CorrelationId>,
    Path((_tenant_id, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<DecisionRequest>,
) -> Response {
    let ctx = context(&state, &correlation, &headers);
    match state
        .app_approval
        .approve(tenant.context(), &id, &body.key_id, &body.signature, &ctx)
        .await
    {
        Ok(approved) => Json(ApproveResponse {
            continue_url: format!(
                "{}/{}/login/app/complete?request={}&code={}",
                state.config.public_web_base_url().trim_end_matches('/'),
                tenant.tenant().id.as_uuid(),
                id,
                approved.code
            ),
        })
        .into_response(),
        Err(e) => error_response(e),
    }
}

/// 断る（`POST /{tenant_id}/app-approver/requests/{id}/deny`）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/app-approver/requests/{id}/deny",
    tag = "app-approver",
    request_body = DecisionRequest,
    responses(
        (status = 204, description = "断った"),
        (status = 403, description = "署名が合わない・鍵が無い", body = AppApproverErrorResponse),
    )
)]
pub async fn deny(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Extension(correlation): Extension<CorrelationId>,
    Path((_tenant_id, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<DecisionRequest>,
) -> Response {
    let ctx = context(&state, &correlation, &headers);
    match state
        .app_approval
        .deny(tenant.context(), &id, &body.key_id, &body.signature, &ctx)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error_response(e),
    }
}

// ─── 鍵 ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct KeyStateResponse {
    /// いつも `active`（取り消された・知らない鍵は 404）。
    pub state: &'static str,
}

/// 鍵がまだ有効か（`GET /{tenant_id}/app-approver/keys/{key_id}`）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/app-approver/keys/{key_id}",
    tag = "app-approver",
    responses(
        (status = 200, description = "有効", body = KeyStateResponse),
        (status = 404, description = "取り消された・知らない鍵"),
    )
)]
pub async fn key_state(
    State(state): State<AppState>,
    Path((_tenant_id, key_id)): Path<(String, String)>,
) -> Response {
    match state.app_approval.key_is_active(&key_id).await {
        Ok(true) => Json(KeyStateResponse { state: "active" }).into_response(),
        Ok(false) => error_response(AppApproverError::NotFound),
        Err(e) => error_response(e),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeRequest {
    /// 署名した時刻（`YYYY-MM-DDTHH:MM:SSZ`。5 分以内）。
    pub signed_at: String,
    /// `revoke` の文への署名（base64url の DER）。
    pub signature: String,
}

/// アプリから鍵を取り消す（`POST /{tenant_id}/app-approver/keys/{key_id}/revoke`）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/app-approver/keys/{key_id}/revoke",
    tag = "app-approver",
    request_body = RevokeRequest,
    responses(
        (status = 204, description = "取り消した（その鍵で承認したログイン状態も終わる）"),
        (status = 403, description = "署名が合わない・時刻が古い", body = AppApproverErrorResponse),
        (status = 404, description = "もう無い"),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Extension(correlation): Extension<CorrelationId>,
    Path((_tenant_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RevokeRequest>,
) -> Response {
    let ctx = context(&state, &correlation, &headers);
    match state
        .app_approval
        .revoke_by_app(
            tenant.context(),
            &key_id,
            &body.signed_at,
            &body.signature,
            &ctx,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error_response(e),
    }
}

// ─── App Link ─────────────────────────────────────────────────────────

/// `/.well-known/assetlinks.json`: 認証アプリにこのホストの App Link（`/app/approve`・`/app/enrolled`）を許す。
///
/// 認証アプリの口が閉じていれば 404。指紋は `APP_APPROVER_SIGNING_CERT_SHA256`。
pub async fn asset_links(State(state): State<AppState>) -> Response {
    let Some(package) = state.config.app_approver_package_name() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let fingerprints: Vec<String> = state
        .config
        .app_approver_signing_cert_sha256()
        .split(',')
        .map(|f| {
            // `AB:CD:…` の形にそろえる（Android の Digital Asset Links が求める書き方）。
            let hex: String = f
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .map(|c| c.to_ascii_uppercase())
                .collect();
            hex.as_bytes()
                .chunks(2)
                .map(|pair| String::from_utf8_lossy(pair).into_owned())
                .collect::<Vec<_>>()
                .join(":")
        })
        .filter(|f| !f.is_empty())
        .collect();
    let body = serde_json::json!([{
        "relation": [
            "delegate_permission/common.handle_all_urls",
            "delegate_permission/common.get_login_creds"
        ],
        "target": {
            "namespace": "android_app",
            "package_name": package,
            "sha256_cert_fingerprints": fingerprints,
        }
    }]);
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// App Link（`/app/approve`・`/app/enrolled`）がブラウザで開かれたときの案内。
///
/// 認証アプリが入っていて App Link が通っていれば、ここへは来ない。
pub async fn app_link_fallback() -> Response {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Html(
            "<!doctype html><html lang=\"ja\"><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <title>nolumia 認証</title>\
             <body style=\"font-family:sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem\">\
             <h1 style=\"font-size:1.25rem\">nolumia 認証アプリで開きます</h1>\
             <p>このページは nolumia 認証アプリが開くためのものです。アプリが入っていないか、\
             アプリがこのリンクを受け取れませんでした。アプリを入れてから、ログイン画面の\
             「アプリで続ける」からやり直してください。</p></body></html>",
        ),
    )
        .into_response()
}
