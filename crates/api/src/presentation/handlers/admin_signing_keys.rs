//! 署名鍵管理エンドポイント（`/admin/signing-keys`、K1）。
//!
//! すべて `idp.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。秘密鍵・暗号化鍵は返さない。
//! 生成アルゴリズムは `RS256`（RSA-2048）または `ES256`（NIST P-256）。

use crate::application::key_service::KeyManagementError;
use crate::domain::signing_key::SigningKey;
use crate::domain::values::SigningAlgorithm;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::dto::{GenerateSigningKeyRequest, SigningKeyResponse};
use crate::presentation::error::ApiError;
use crate::presentation::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

/// 全署名鍵を作成日時の降順で返す。
#[utoipa::path(
    get,
    path = "/admin/signing-keys",
    tag = "admin",
    responses(
        (status = 200, description = "署名鍵一覧", body = [SigningKeyResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.admin 必須）"),
    )
)]
pub async fn list_keys(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
) -> Result<Json<Vec<SigningKeyResponse>>, ApiError> {
    let keys = state.keys.list_keys().await.map_err(map_error)?;
    Ok(Json(keys.iter().map(key_response).collect()))
}

/// 指定アルゴリズムの新規署名鍵を生成して ACTIVE で登録する。
#[utoipa::path(
    post,
    path = "/admin/signing-keys",
    tag = "admin",
    request_body = GenerateSigningKeyRequest,
    responses(
        (status = 201, description = "生成した署名鍵", body = SigningKeyResponse),
        (status = 400, description = "不正なアルゴリズム"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.admin 必須）"),
    )
)]
pub async fn generate_key(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Json(body): Json<GenerateSigningKeyRequest>,
) -> Result<(StatusCode, Json<SigningKeyResponse>), ApiError> {
    let algorithm = SigningAlgorithm::parse(&body.algorithm)
        .map_err(|_| ApiError::BadRequest(format!("invalid algorithm: {}", body.algorithm)))?;

    let key = state.keys.generate_key(algorithm).await.map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(key_response(&key))))
}

/// 指定 kid の署名鍵を RETIRED に変更する（ACTIVE → RETIRED）。
#[utoipa::path(
    post,
    path = "/admin/signing-keys/{kid}/retire",
    tag = "admin",
    params(("kid" = String, Path, description = "署名鍵 ID（kid）")),
    responses(
        (status = 204, description = "退役完了"),
        (status = 400, description = "既に RETIRED"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.admin 必須）"),
        (status = 404, description = "不存在"),
    )
)]
pub async fn retire_key(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Path(kid): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.keys.retire_key(&kid).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// 指定 kid の署名鍵を削除する（RETIRED のみ可）。
#[utoipa::path(
    delete,
    path = "/admin/signing-keys/{kid}",
    tag = "admin",
    params(("kid" = String, Path, description = "署名鍵 ID（kid）")),
    responses(
        (status = 204, description = "削除完了"),
        (status = 400, description = "ACTIVE 鍵は削除不可（先に退役）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.admin 必須）"),
        (status = 404, description = "不存在"),
    )
)]
pub async fn delete_key(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Path(kid): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.keys.delete_key(&kid).await.map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn key_response(k: &SigningKey) -> SigningKeyResponse {
    SigningKeyResponse {
        kid: k.kid.clone(),
        algorithm: k.algorithm.clone(),
        status: k.status.as_str().to_string(),
        not_before: k.not_before.to_rfc3339(),
        not_after: k.not_after.to_rfc3339(),
        created_at: k.created_at.to_rfc3339(),
    }
}

fn map_error(e: KeyManagementError) -> ApiError {
    match e {
        KeyManagementError::NotFound(m) => ApiError::NotFound(m),
        KeyManagementError::Validation(m) => ApiError::BadRequest(m),
        KeyManagementError::Internal(m) => ApiError::Internal(m),
    }
}
