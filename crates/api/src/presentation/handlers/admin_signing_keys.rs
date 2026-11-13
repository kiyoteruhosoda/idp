//! Signing key management endpoints (`/admin/signing-keys`, K1).
//!
//! Reading needs `idp.keys:read`; generate/retire/delete need `idp.keys:write` (`RequirePerms<KeysRead>` / `<KeysWrite>`;
//! `idp.tenant.admin` implies both). Private keys and encryption keys are never returned.
//!
//! ⚠ **There is one set of signing keys for all tenants** (`signing_keys` has no tenant column), so the endpoints are
//! **limited to the root tenant** (`require_root_tenant`). With permission checks alone, a child tenant's admin (`idp.tenant.admin`
//! implies `idp.keys:write`) could cross tenants and replace or delete the global keys.
//! Generation algorithm is `RS256` (RSA-2048) or `ES256` (NIST P-256).

use crate::application::key_service::KeyManagementError;
use crate::domain::signing_key::{current_signer_at, SigningKey};
use crate::domain::values::SigningAlgorithm;
use crate::presentation::admin::{KeysRead, KeysWrite, RequirePerms};
use crate::presentation::dto::{GenerateSigningKeyRequest, SigningKeyResponse};
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::{require_root_tenant, ResolvedTenant};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};

/// Returns all signing keys in descending order of creation time.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/signing-keys",
    tag = "admin",
    responses(
        (status = 200, description = "署名鍵一覧", body = [SigningKeyResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.keys:read 必須。root テナントのみ）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_keys(
    RequirePerms(_admin, _): RequirePerms<KeysRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<Vec<SigningKeyResponse>>, ApiError> {
    require_root_tenant(&tenant, locale)?;
    let keys = state
        .keys
        .list_keys()
        .await
        .map_err(|e| map_error(e, locale))?;
    // "Which one is signing" cannot be read from `status` (there may be several ACTIVE). It is decided by
    // `current_signer_at` -- the same rule used to pick the signing key, so the screen never diverges from reality.
    let now = state.clock.now();
    let signer = current_signer_at(&keys, now).map(|key| key.kid.clone());
    Ok(Json(
        keys.iter()
            .map(|key| key_response(key, signer.as_deref(), now))
            .collect(),
    ))
}

/// Generates a new signing key with the given algorithm and registers it as ACTIVE.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/signing-keys",
    tag = "admin",
    request_body = GenerateSigningKeyRequest,
    responses(
        (status = 201, description = "生成した署名鍵", body = SigningKeyResponse),
        (status = 400, description = "不正なアルゴリズム"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.keys:write 必須。root テナントのみ）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn generate_key(
    RequirePerms(_admin, _): RequirePerms<KeysWrite>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Json(body): Json<GenerateSigningKeyRequest>,
) -> Result<(StatusCode, Json<SigningKeyResponse>), ApiError> {
    require_root_tenant(&tenant, locale)?;
    let algorithm = SigningAlgorithm::parse(&body.algorithm)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;

    // The default is "publish first, sign only after a grace period". `activate_immediately` discards
    // that grace period; use it only when you can't wait, e.g. key compromise.
    let publish_lead = if body.activate_immediately {
        chrono::Duration::zero()
    } else {
        chrono::Duration::hours(state.config.key_rotation_publish_lead_hours() as i64)
    };
    let key = state
        .keys
        .generate_key(algorithm, publish_lead)
        .await
        .map_err(|e| map_error(e, locale))?;
    // Signs right after generation only when no grace period was set. By default it is only published and the old key still signs.
    let now = state.clock.now();
    let signer_kid = key.is_usable_for_signing_at(now).then(|| key.kid.clone());
    Ok((
        StatusCode::CREATED,
        Json(key_response(&key, signer_kid.as_deref(), now)),
    ))
}

/// Changes the signing key with the given kid to RETIRED (ACTIVE -> RETIRED).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/signing-keys/{kid}/retire",
    tag = "admin",
    params(("kid" = String, Path, description = "署名鍵 ID（kid）")),
    responses(
        (status = 204, description = "退役完了"),
        (status = 400, description = "既に RETIRED、または最後の署名可能な鍵"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.keys:write 必須。root テナントのみ）"),
        (status = 404, description = "不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn retire_key(
    RequirePerms(_admin, _): RequirePerms<KeysWrite>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // The first path segment is `{tenant_id}`. Signing keys are cross-tenant (global), so
    // admin routes sit uniformly under `/{tenant_id}/admin/...` for all tenants and are then limited to root.
    Path((_tenant_id, kid)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_root_tenant(&tenant, locale)?;
    state
        .keys
        .retire_key(&kid)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes the signing key with the given kid (RETIRED only).
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/signing-keys/{kid}",
    tag = "admin",
    params(("kid" = String, Path, description = "署名鍵 ID（kid）")),
    responses(
        (status = 204, description = "削除完了"),
        (status = 400, description = "ACTIVE 鍵は削除不可（先に退役）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.keys:write 必須。root テナントのみ）"),
        (status = 404, description = "不存在"),
    ),
    security(("bearer_token" = []))
)]
pub async fn delete_key(
    RequirePerms(_admin, _): RequirePerms<KeysWrite>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, kid)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_root_tenant(&tenant, locale)?;
    state
        .keys
        .delete_key(&kid)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

fn key_response(
    k: &SigningKey,
    signer_kid: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> SigningKeyResponse {
    SigningKeyResponse {
        kid: k.kid.clone(),
        algorithm: k.algorithm.clone(),
        status: k.status.as_str().to_string(),
        not_before: k.not_before.to_rfc3339(),
        not_after: k.not_after.to_rfc3339(),
        created_at: k.created_at.to_rfc3339(),
        is_current_signer: signer_kid == Some(k.kid.as_str()),
        is_pending: k.is_pending_at(now),
    }
}

fn map_error(e: KeyManagementError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        KeyManagementError::NotFound(_) => {
            ApiError::NotFound(msgs.get("api-signing-key-not-found"))
        }
        KeyManagementError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        KeyManagementError::Internal(m) => ApiError::Internal(m),
    }
}
