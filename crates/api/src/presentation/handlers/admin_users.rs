//! 利用者検索・取得の管理 API（`/admin/users`）。管理コンソール（web）の権限画面が用いる支援 API。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。パスワードハッシュ等の機微情報は返さない。
//! 権限の一覧・付与・剥奪は `admin_permissions` にある。

use crate::application::permission_management::PermissionManagementError;
use crate::domain::user::User;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::error::ApiError;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::Json;
use idp_contracts::admin::UserSummaryResponse;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct UserSearchQuery {
    #[serde(default)]
    pub q: Option<String>,
}

/// メール／ユーザー名で利用者を検索する（`GET /admin/users?q=`）。該当なしは 404。
pub async fn search_user(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Query(query): Query<UserSearchQuery>,
) -> Result<Json<UserSummaryResponse>, ApiError> {
    let term = query.q.unwrap_or_default();
    if term.trim().is_empty() {
        return Err(ApiError::NotFound("user not found".to_string()));
    }
    match state
        .permissions_admin
        .find_user_by_identifier(tenant.context(), &term)
        .await
        .map_err(map_error)?
    {
        Some(user) => Ok(Json(summary(&user))),
        None => Err(ApiError::NotFound("user not found".to_string())),
    }
}

/// 内部 ID（UUID）で利用者を取得する（`GET /admin/users/{user_id}`）。
pub async fn get_user(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserSummaryResponse>, ApiError> {
    let target =
        Uuid::parse_str(&user_id).map_err(|_| ApiError::NotFound("user not found".to_string()))?;
    let user = state
        .permissions_admin
        .get_user(tenant.context(), target)
        .await
        .map_err(map_error)?;
    Ok(Json(summary(&user)))
}

fn summary(u: &User) -> UserSummaryResponse {
    UserSummaryResponse {
        id: u.id.to_string(),
        sub: u.sub.to_string(),
        email: u.email.clone(),
        email_verified: u.email_verified,
        preferred_username: u.preferred_username.clone(),
        name: u.name.clone(),
        status: u.status.as_str().to_string(),
    }
}

fn map_error(e: PermissionManagementError) -> ApiError {
    match e {
        PermissionManagementError::Validation(m) => ApiError::BadRequest(m),
        PermissionManagementError::NotFound => ApiError::NotFound("user not found".to_string()),
        PermissionManagementError::Forbidden(m) => ApiError::Forbidden(m),
        PermissionManagementError::Internal(m) => ApiError::Internal(m),
    }
}
