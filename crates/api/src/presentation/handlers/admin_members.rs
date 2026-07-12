//! テナントメンバー管理エンドポイント（`/{tenant_id}/admin/members`。ADR-0009 §3・§6）。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。参加先テナントの管理者が行えるのは
//! メンバー一覧の閲覧と**ゲストメンバーシップの解除**のみで、HOME は解除できない。ゲストの `users`
//! レコード（パスワード・状態・MFA・プロフィール）は操作できない（所属元テナントの管理者と本人のみ。§3）。

use crate::application::invitation::InvitationError;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::MemberResponse;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use uuid::Uuid;

/// 当該テナントのメンバー（HOME / GUEST）を一覧する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/members",
    tag = "admin",
    responses(
        (status = 200, description = "メンバー一覧", body = [MemberResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn list_members(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<Vec<MemberResponse>>, ApiError> {
    let members = state
        .invitations
        .list_members(tenant.context())
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(
        members
            .into_iter()
            .map(|m| MemberResponse {
                user_id: m.user_id.to_string(),
                email: m.email,
                name: m.name,
                membership_type: m.membership_type.as_str().to_string(),
                status: m.status.as_str().to_string(),
            })
            .collect(),
    ))
}

/// ゲストメンバーシップを解除する（ゲストの追放）。HOME は解除できない（403）。解除時、当該テナントを
/// scope とするそのユーザーの権限行も削除する（§3）。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/members/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "解除する利用者の内部 ID（UUID）")),
    responses(
        (status = 204, description = "解除成功"),
        (status = 400, description = "user_id が UUID でない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足・HOME は解除不可"),
        (status = 404, description = "メンバーシップが不存在"),
    )
)]
pub async fn revoke_member(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let target = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());
    state
        .invitations
        .revoke_membership(tenant.context(), target, admin.user_id, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_error(e: InvitationError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        InvitationError::NotFound => ApiError::NotFound(msgs.get("api-member-not-found")),
        InvitationError::AlreadyMember => {
            ApiError::Conflict("already a member".to_string())
        }
        InvitationError::Forbidden(m) => ApiError::Forbidden(m),
        InvitationError::InvalidOrExpired => {
            ApiError::BadRequest(msgs.get("api-invalid-request"))
        }
        InvitationError::Internal(m) => ApiError::Internal(m),
    }
}
