//! Admin API for searching and getting users (`/admin/users`). A support API used by the admin console (web) permission screens.
//!
//! Permissions are split finely per operation (ADR-0037). Search, get and the count of active tokens need user read
//! (`idp.users:read`, `RequirePerms<UsersRead>`); create, status change, profile update, delete, password
//! reissue, MFA reset, token reissue and unlock need write (`idp.users:write`, `RequirePerms<UsersWrite>`).
//! `idp.tenant.admin` implies both, so tenant admins can do everything. Sensitive information such as password hashes
//! is never returned.
//! Listing, granting and revoking permissions live in `admin_permissions`.

use crate::application::user_lifecycle::{UpdateUserProfileCommand, UserLifecycleError};
use crate::application::user_management::{CreateUserCommand, UserManagementError};
use crate::domain::user::User;
use crate::domain::values::UserStatus;
use crate::presentation::admin::{RequirePerms, UsersRead, UsersWrite};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    CreateUserRequest, UpdateUserProfileRequest, UpdateUserStatusRequest, UserActiveTokensResponse,
    UserCreatedResponse, UserMfaResetResponse, UserPasswordResetResponse, UserSummaryResponse,
    UserTokenReissueResponse, UserUnlockResponse,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::{
    map_admin_account_guard_error, map_permission_management_error, request_context,
};
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

/// Query of `GET /admin/users`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct UserSearchQuery {
    /// Email address (when it contains `@`) or username. Resolves to one person (not a partial-match search). 404 if empty.
    #[serde(default)]
    pub q: Option<String>,
}

/// Creates a user whose home is this tenant (`POST /{tenant_id}/admin/users`). The password is auto-generated and
/// `must_change_password` is set. The **account setup link** (`setup_url`) to hand to the user is
/// returned only in this response (ADR-0062; the generated password is not returned).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users",
    tag = "admin",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "作成成功（setup_url を含む）", body = UserCreatedResponse),
        (status = 400, description = "バリデーションエラー"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）"),
        (status = 409, description = "email / preferred_username の重複"),
    ),
    security(("bearer_token" = []))
)]
pub async fn create_user(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
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
                note: body.note,
            },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_user_management_error(e, locale))?;
    Ok((
        StatusCode::CREATED,
        Json(UserCreatedResponse {
            user_id: created.user_id.to_string(),
            sub: created.sub.to_string(),
            setup_url: created.setup_link.url,
            setup_expires_at: created.setup_link.expires_at.to_rfc3339(),
        }),
    ))
}

/// Searches for a user by email / username (`GET /admin/users?q=`). 404 if none.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/users",
    tag = "admin",
    params(UserSearchQuery),
    responses(
        (status = 200, description = "該当した利用者の要約", body = UserSummaryResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:read 必須）"),
        (status = 404, description = "該当なし（q が空の場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn search_user(
    RequirePerms(_admin, _): RequirePerms<UsersRead>,
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

/// Gets a user by internal ID (UUID) (`GET /admin/users/{user_id}`).
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/users/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "利用者の要約", body = UserSummaryResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:read 必須）"),
        (status = 404, description = "不存在（user_id が UUID でない場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn get_user(
    RequirePerms(_admin, _): RequirePerms<UsersRead>,
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

/// Changes a user's status (`PATCH /{tenant_id}/admin/users/{user_id}`). Only users whose home is this
/// tenant. Cannot change oneself. Disabling revokes all sessions and tokens.
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/users/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = UpdateUserStatusRequest,
    responses(
        (status = 200, description = "更新後の利用者", body = UserSummaryResponse),
        (status = 400, description = "status が不正（ACTIVE / DISABLED 以外）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）・自分自身は変更不可"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_user_status(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdateUserStatusRequest>,
) -> Result<Json<UserSummaryResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
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
        .set_status(tenant.context(), target, status, &admin.actor, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    let user = state
        .permissions_admin
        .get_user(tenant.context(), target)
        .await
        .map_err(|e| map_permission_management_error(e, locale))?;
    Ok(Json(summary(&user)))
}

/// Edits a user's profile (email, display name, login identifier)
/// (`PATCH /{tenant_id}/admin/users/{user_id}/profile`, MT25). Only users whose home is this tenant.
///
/// It is separate from the status change (`PATCH /admin/users/{user_id}`) because the authorization granularity differs:
/// profile editing can't cause a lockout, so **oneself can be a target too** (status change, delete,
/// password reissue and MFA reset forbid self-operation).
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/users/{user_id}/profile",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = UpdateUserProfileRequest,
    responses(
        (status = 200, description = "更新後の利用者", body = UserSummaryResponse),
        (status = 400, description = "バリデーションエラー（メール書式・長さ・ログイン識別子の解除）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
        (status = 409, description = "email / preferred_username がテナント内で重複"),
    ),
    security(("bearer_token" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_user_profile(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdateUserProfileRequest>,
) -> Result<Json<UserSummaryResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
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
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(summary(&updated)))
}

/// Deletes a user (`DELETE /{tenant_id}/admin/users/{user_id}`). Only users whose home is this
/// tenant. Cannot delete oneself. Related rows are cleaned up by the DB's FK CASCADE / SET NULL.
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/users/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 204, description = "削除成功"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）・自分自身は削除不可"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn delete_user(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .users_lifecycle
        .delete_user(tenant.context(), target, &admin.actor, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reissues a user's password (`POST /{tenant_id}/admin/users/{user_id}/password-reset`).
/// Auto-generates a random password of 32+ characters, sets `must_change_password`, and
/// returns the **account setup link** (`setup_url`) to hand to the user only in this response (ADR-0062).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/password-reset",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "再発行成功（setup_url を含む）", body = UserPasswordResetResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）・自分自身は再発行不可"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn reset_user_password(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserPasswordResetResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let reset = state
        .users_lifecycle
        .reset_password(tenant.context(), target, &admin.actor, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(UserPasswordResetResponse {
        user_id: reset.user_id.to_string(),
        setup_url: reset.setup_link.url,
        setup_expires_at: reset.setup_link.expires_at.to_rfc3339(),
    }))
}

/// Resets a user's MFA (TOTP, passkeys) (`POST /{tenant_id}/admin/users/{user_id}/mfa-reset`, MT21).
/// A recovery path when the user lost their device and can't reset it themselves. Removes both TOTP and passkeys and also
/// revokes the user's sessions and tokens (the lost device may hold a live session).
/// Succeeds even without MFA configured (the response shows that nothing was removed).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/mfa-reset",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "解除成功（外した要素の内訳を含む）", body = UserMfaResetResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）・自分自身は解除不可（セルフサービスを使う）"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn reset_user_mfa(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserMfaResetResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let reset = state
        .users_lifecycle
        .reset_mfa(tenant.context(), target, &admin.actor, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(UserMfaResetResponse {
        user_id: reset.user_id.to_string(),
        totp_removed: reset.totp_removed,
        passkeys_removed: reset.passkeys_removed,
    }))
}

/// Revokes all refresh tokens issued to a user
/// (`POST /{tenant_id}/admin/users/{user_id}/token-reissue`, ADR-0047).
///
/// The same operation the user can press on their security screen, done by an admin on a specified target. Only
/// tokens are dropped; sessions, authenticators and passwords are untouched. Apps re-obtain them through SSO on
/// the next refresh, so for most users nothing happens. Can be run on oneself too (no lockout).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/token-reissue",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "失効成功（対象が 0 件の場合を含む）", body = UserTokenReissueResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn reissue_user_tokens(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserTokenReissueResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let reissue = state
        .users_lifecycle
        .reissue_tokens(tenant.context(), target, &admin.actor, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(UserTokenReissueResponse {
        user_id: reissue.user_id.to_string(),
        revoked: reissue.revoked,
    }))
}

/// Returns the number of the user's currently active refresh tokens
/// (`GET /{tenant_id}/admin/users/{user_id}/active-tokens`, task #83).
///
/// Shows admins "how many are alive for this person now" before pressing reissue (`token-reissue`).
/// The permission matches user read (`idp.users:read`). As with reissue, targets are only users whose home is this
/// tenant; users of other tenants get the same 404 as nonexistent ones. Access tokens
/// have no DB rows, so they are not counted.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/users/{user_id}/active-tokens",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "有効な refresh token の本数（0 を含む。アクセストークンは数えない）", body = UserActiveTokensResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:read 必須）"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn count_user_active_tokens(
    RequirePerms(_admin, _): RequirePerms<UsersRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserActiveTokensResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    let count = state
        .users_lifecycle
        .count_active_tokens(tenant.context(), target)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(UserActiveTokensResponse {
        user_id: count.user_id.to_string(),
        active_refresh_tokens: count.refresh_tokens,
    }))
}

/// Unlocks an account immediately (`POST /{tenant_id}/admin/users/{user_id}/unlock`, AP6).
///
/// Clears the lock expiry and resets the failure count together (with only one, the next attempt would lock again).
/// Succeeds for users that aren't locked too (idempotent; distinguishable via `was_locked`).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/users/{user_id}/unlock",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "解除成功（元からロックされていない場合を含む）", body = UserUnlockResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.users:write 必須）"),
        (status = 404, description = "不存在（所属元が他テナントの場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn unlock_user(
    RequirePerms(admin, _): RequirePerms<UsersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<UserUnlockResponse>, ApiError> {
    let target = parse_user_id(&user_id, locale)?;
    state
        .admin_account_guard
        .ensure_may_manage_account(
            tenant.context(),
            tenant.tenant().is_root(),
            &admin.permission_codes,
            target,
        )
        .await
        .map_err(|e| map_admin_account_guard_error(e, locale))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let was_locked = state
        .users_lifecycle
        .unlock_account(tenant.context(), target, &admin.actor, &ctx)
        .await
        .map_err(|e| map_user_lifecycle_error(e, locale))?;
    Ok(Json(UserUnlockResponse {
        user_id: target.to_string(),
        was_locked,
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
