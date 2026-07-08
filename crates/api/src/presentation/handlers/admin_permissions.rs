//! 利用者権限の付与・剥奪・参照エンドポイント（`/admin/users/{user_id}/permissions`、
//! A2・ADR-0006・設計仕様 §7）。
//!
//! すべて `idp.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。付与・剥奪は `audit_log` に記録する
//! （`user_permission.granted` / `.revoked`）。判定は Application 層（`PermissionManagementService`）
//! が行い、本ハンドラは HTTP への写像のみを担う。

use crate::application::permission_management::PermissionManagementError;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{GrantPermissionRequest, UserPermissionsResponse};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use uuid::Uuid;

/// 付与可能な権限コード（`permissions` マスタ）を一覧する（`GET /admin/permissions`）。
/// 管理コンソール（web）の付与フォームの選択肢に使う支援 API。
pub async fn list_available_permissions(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
) -> Result<Json<idp_contracts::admin::AvailablePermissionsResponse>, ApiError> {
    let codes = state
        .permissions_admin
        .available_codes()
        .await
        .map_err(map_error)?;
    Ok(Json(idp_contracts::admin::AvailablePermissionsResponse {
        codes,
    }))
}

/// 対象利用者が保有する権限コードを一覧する。
#[utoipa::path(
    get,
    path = "/admin/users/{user_id}/permissions",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "保有する権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "user_id が UUID でない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.admin 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    )
)]
pub async fn list_permissions(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id)?;
    let codes = state
        .permissions_admin
        .list(target)
        .await
        .map_err(map_error)?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

/// 対象利用者へ権限コードを付与する（冪等）。付与後の保有コード一覧を返す。
#[utoipa::path(
    post,
    path = "/admin/users/{user_id}/permissions",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = GrantPermissionRequest,
    responses(
        (status = 200, description = "付与後の権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "バリデーションエラー（未知の権限コード等）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.admin 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    )
)]
pub async fn grant_permission(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(body): Json<GrantPermissionRequest>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id)?;
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());
    let codes = state
        .permissions_admin
        .grant(target, &body.permission_code, admin.user_id, &ctx)
        .await
        .map_err(map_error)?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

/// 対象利用者から権限コードを剥奪する（未保有でもエラーにしない）。剥奪後の保有コード一覧を返す。
#[utoipa::path(
    delete,
    path = "/admin/users/{user_id}/permissions/{permission_code}",
    tag = "admin",
    params(
        ("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）"),
        ("permission_code" = String, Path, description = "剥奪する権限コード"),
    ),
    responses(
        (status = 200, description = "剥奪後の権限コード一覧", body = UserPermissionsResponse),
        (status = 400, description = "user_id が UUID でない・権限コードが空"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.admin 必須）"),
        (status = 404, description = "対象利用者が不存在"),
    )
)]
pub async fn revoke_permission(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    headers: HeaderMap,
    Path((user_id, permission_code)): Path<(String, String)>,
) -> Result<Json<UserPermissionsResponse>, ApiError> {
    let target = parse_user_id(&user_id)?;
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());
    let codes = state
        .permissions_admin
        .revoke(target, &permission_code, admin.user_id, &ctx)
        .await
        .map_err(map_error)?;
    Ok(Json(UserPermissionsResponse {
        user_id: target.to_string(),
        permission_codes: codes,
    }))
}

fn parse_user_id(raw: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw).map_err(|_| ApiError::BadRequest(format!("invalid user_id: {raw}")))
}

fn map_error(e: PermissionManagementError) -> ApiError {
    match e {
        PermissionManagementError::Validation(m) => ApiError::BadRequest(m),
        PermissionManagementError::NotFound => ApiError::NotFound("user not found".to_string()),
        PermissionManagementError::Internal(m) => ApiError::Internal(m),
    }
}
