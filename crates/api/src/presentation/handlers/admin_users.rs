//! 利用者検索・取得の管理 API（`/admin/users`）。管理コンソール（web）の権限画面が用いる支援 API。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。パスワードハッシュ等の機微情報は返さない。
//! 権限の一覧・付与・剥奪は `admin_permissions` にある。

use crate::application::user_lifecycle::{UpdateUserProfileCommand, UserLifecycleError};
use crate::application::user_management::{CreateUserCommand, UserManagementError};
use crate::domain::user::User;
use crate::domain::values::UserStatus;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    CreateUserRequest, UpdateUserProfileRequest, UpdateUserStatusRequest, UserCreatedResponse,
    UserMfaResetResponse, UserPasswordResetResponse,
};
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

/// 利用者の状態を変更する（`PATCH /{tenant_id}/admin/users/{user_id}`）。所属元が当該テナントの
/// 利用者のみ。自分自身は変更できない。無効化時は全セッション・トークンを失効させる。
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/users/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = UpdateUserStatusRequest,
    responses(
        (status = 200, description = "更新後の利用者"),
        (status = 400, description = "status が不正（ACTIVE / DISABLED 以外）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足・自分自身は変更不可"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_user_status(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdateUserStatusRequest>,
) -> Result<Json<UserSummaryResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let status = UserStatus::parse(&body.status).map_err(|_| {
        ApiError::BadRequest(ApiMessages::new(locale).get("api-user-status-invalid"))
    })?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .users_lifecycle
        .set_status(tenant.context(), target, status, admin.user_id, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    let user = state
        .permissions_admin
        .get_user(tenant.context(), target)
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    Ok(Json(summary(&user)))
}

/// 利用者のプロフィール（メール・表示名・ログイン識別子）を編集する
/// （`PATCH /{tenant_id}/admin/users/{user_id}/profile`。MT25）。所属元が当該テナントの利用者のみ。
///
/// 状態変更（`PATCH /admin/users/{user_id}`）と分けているのは認可の粒度が違うため:
/// プロフィール編集はロックアウトを招かないので**自分自身も対象にできる**（状態変更・削除・
/// パスワード再発行・MFA 解除は自己操作禁止）。
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/users/{user_id}/profile",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = UpdateUserProfileRequest,
    responses(
        (status = 200, description = "更新後の利用者"),
        (status = 400, description = "バリデーションエラー（メール書式・長さ・ログイン識別子の解除）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
        (status = 409, description = "email / preferred_username がテナント内で重複"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_user_profile(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdateUserProfileRequest>,
) -> Result<Json<UserSummaryResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let updated = state
        .users_lifecycle
        .update_profile(
            tenant.context(),
            target,
            UpdateUserProfileCommand {
                email: body.email,
                preferred_username: body.preferred_username,
                name: body.name,
            },
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(summary(&updated)))
}

/// 利用者を削除する（`DELETE /{tenant_id}/admin/users/{user_id}`）。所属元が当該テナントの
/// 利用者のみ。自分自身は削除できない。関連行は DB の FK CASCADE / SET NULL で後始末される。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/users/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 204, description = "削除成功"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足・自分自身は削除不可"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    )
)]
pub async fn delete_user(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .users_lifecycle
        .delete_user(tenant.context(), target, admin.user_id, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// 利用者のパスワードを再発行する（`POST /{tenant_id}/admin/users/{user_id}/password-reset`）。
/// 32 文字以上のランダムパスワードを自動生成して `must_change_password` を設定し、
/// `generated_password` を**この応答でのみ**平文で返す（作成時と同じパターン。ADR-0009 §5）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/password-reset",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "再発行成功（generated_password を含む）", body = UserPasswordResetResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足・自分自身は再発行不可"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    )
)]
pub async fn reset_user_password(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserPasswordResetResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let reset = state
        .users_lifecycle
        .reset_password(tenant.context(), target, admin.user_id, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(UserPasswordResetResponse {
        user_id: reset.user_id.to_string(),
        generated_password: reset.generated_password,
    }))
}

/// 利用者の MFA（TOTP・Passkey）を解除する（`POST /{tenant_id}/admin/users/{user_id}/mfa-reset`。MT21）。
/// 端末を失って本人では解除できない状態からの復旧手段。TOTP と Passkey を両方外し、当該利用者の
/// セッション・トークンも失効させる（紛失端末が生きたセッションを保持している可能性があるため）。
/// MFA 未設定でも成功する（何も外さなかったことが応答で分かる）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/mfa-reset",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "解除成功（外した要素の内訳を含む）", body = UserMfaResetResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足・自分自身は解除不可（セルフサービスを使う）"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    )
)]
pub async fn reset_user_mfa(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserMfaResetResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let reset = state
        .users_lifecycle
        .reset_mfa(tenant.context(), target, admin.user_id, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(UserMfaResetResponse {
        user_id: reset.user_id.to_string(),
        totp_removed: reset.totp_removed,
        passkeys_removed: reset.passkeys_removed,
    }))
}

fn parse_user_id(raw: &str, locale: ApiLocale) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw)
        .map_err(|_| ApiError::NotFound(ApiMessages::new(locale).get("api-user-not-found")))
}

fn map_user_lifecycle_error(e: UserLifecycleError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        UserLifecycleError::NotFound => ApiError::NotFound(msgs.get("api-user-not-found")),
        UserLifecycleError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        UserLifecycleError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        UserLifecycleError::Conflict(m) => ApiError::Conflict(msgs.get_message(&m)),
        UserLifecycleError::Internal(m) => ApiError::Internal(m),
    }
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

fn map_user_management_error(e: UserManagementError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        UserManagementError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        UserManagementError::Conflict(m) => ApiError::Conflict(msgs.get_message(&m)),
        UserManagementError::Internal(m) => ApiError::Internal(m),
    }
}
