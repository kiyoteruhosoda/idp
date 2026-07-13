//! 利用者検索・取得の管理 API（`/admin/users`）。管理コンソール（web）の権限画面が用いる支援 API。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。パスワードハッシュ等の機微情報は返さない。
//! 権限の一覧・付与・剥奪は `admin_permissions` にある。

use crate::application::user_management::{CreateUserCommand, UserManagementError};
use crate::domain::user::User;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{CreateUserRequest, UserCreatedResponse};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::{map_permission_management_error, request_context};
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use idp_contracts::admin::UserSummaryResponse;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct UserSearchQuery {
    #[serde(default)]
    pub q: Option<String>,
}

/// 所属元が当該テナントの利用者を作成する（`POST /{tenant_id}/admin/users`）。パスワードは自動生成し、
/// `must_change_password` を付与する。`generated_password` を**その応答でのみ**平文で返す。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users",
    tag = "admin",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "作成成功（generated_password を含む）", body = UserCreatedResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 409, description = "email / preferred_username の重複"),
    )
)]
pub async fn create_user(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserCreatedResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let created = state
        .users_admin
        .create_user(
            tenant.context(),
            CreateUserCommand {
                email: body.email,
                preferred_username: body.preferred_username,
                name: body.name,
            },
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_user_management_error(e, locale))?;
    Ok((
        StatusCode::CREATED,
        Json(UserCreatedResponse {
            user_id: created.user_id.to_string(),
            sub: created.sub.to_string(),
            generated_password: created.generated_password,
        }),
    ))
}

/// メール／ユーザー名で利用者を検索する（`GET /admin/users?q=`）。該当なしは 404。
pub async fn search_user(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(query): Query<UserSearchQuery>,
) -> Result<Json<UserSummaryResponse>, ApiError> {
    let term = query.q.unwrap_or_default();
    if term.trim().is_empty() {
        return Err(ApiError::NotFound(
            ApiMessages::new(locale).get("api-user-not-found"),
        ));
    }
    match state
        .permissions_admin
        .find_user_by_identifier(tenant.context(), &term)
        .await
        .map_err(|e| map_permission_management_error(e, locale))?
    {
        Some(user) => Ok(Json(summary(&user))),
        None => Err(ApiError::NotFound(
            ApiMessages::new(locale).get("api-user-not-found"),
        )),
    }
}

/// 内部 ID（UUID）で利用者を取得する（`GET /admin/users/{user_id}`）。
pub async fn get_user(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserSummaryResponse>, ApiError> {
    let target = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::NotFound(ApiMessages::new(locale).get("api-user-not-found")))?;
    let user = state
        .permissions_admin
        .get_user(tenant.context(), target)
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
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

fn map_user_management_error(e: UserManagementError, _locale: ApiLocale) -> ApiError {
    match e {
        UserManagementError::Validation(m) => ApiError::BadRequest(m),
        UserManagementError::Conflict(m) => ApiError::Conflict(m),
        UserManagementError::Internal(m) => ApiError::Internal(m),
    }
}
