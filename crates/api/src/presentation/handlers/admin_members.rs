//! テナントメンバー管理エンドポイント（`/{tenant_id}/admin/members`。ADR-0009 §3・§6）。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。参加先テナントの管理者が行えるのは
//! メンバー一覧の閲覧と**ゲストメンバーシップの解除・一時停止/再開**（MT24）のみで、HOME は解除も停止も
//! できない。ゲストの `users` レコード（パスワード・状態・MFA・プロフィール）は操作できない
//! （所属元テナントの管理者と本人のみ。§3）。

use crate::application::invitation::InvitationError;
use crate::application::member_directory::MemberSearchParams;
use crate::domain::values::MembershipStatus;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    MemberListQueryParams, MemberListResponse, MemberResponse, UpdateMemberStatusRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use uuid::Uuid;

/// 当該テナントのメンバー（HOME / GUEST）を一覧する（MT22 でページング・絞り込みを追加）。
///
/// 絞り込み・並び替え・ページングはすべて DB 側で行う。全件を返して呼び出し側で絞る方式は、
/// テナントの規模に比例して応答が膨らむため採らない。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/members",
    tag = "admin",
    params(MemberListQueryParams),
    responses(
        (status = 200, description = "メンバー一覧（1 ページ分と総件数）", body = MemberListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn list_members(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Query(params): Query<MemberListQueryParams>,
) -> Result<Json<MemberListResponse>, ApiError> {
    let search = MemberSearchParams {
        search: params.q,
        limit: params.limit,
        offset: params.offset,
    };
    let result = state
        .member_directory
        .search(tenant.context(), search)
        .await
        .map_err(|e| map_error(InvitationError::Internal(e.to_string()), locale))?;
    Ok(Json(MemberListResponse {
        members: result
            .page
            .members
            .into_iter()
            .map(|m| MemberResponse {
                user_id: m.user_id.to_string(),
                email: m.email,
                name: m.name,
                membership_type: m.membership_type.as_str().to_string(),
                status: m.status.as_str().to_string(),
                user_status: m.user_status.map(|s| s.as_str().to_string()),
            })
            .collect(),
        total: result.page.total,
        limit: result.limit,
        offset: result.offset,
    }))
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
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .invitations
        .revoke_membership(tenant.context(), target, admin.user_id, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// ゲストメンバーシップの一時停止・再開（`PATCH /{tenant_id}/admin/members/{user_id}`。MT24）。
///
/// `status` に `SUSPENDED` を指定すると停止、`ACTIVE` を指定すると再開する。停止できるのは GUEST の
/// `ACTIVE` のみ、再開できるのは `SUSPENDED` のみ（それ以外は 403）。解除（`DELETE`）と違い
/// メンバーシップ行と当該テナント scope の権限行は残るため、再開すれば停止前の状態に戻る。
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/members/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = UpdateMemberStatusRequest,
    responses(
        (status = 204, description = "更新成功"),
        (status = 400, description = "user_id が UUID でない・status が不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足・HOME は停止不可・遷移できない状態"),
        (status = 404, description = "メンバーシップが不存在"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_member_status(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdateMemberStatusRequest>,
) -> Result<StatusCode, ApiError> {
    // `ApiMessages`（fluent バンドル）は `Send` ではないため、`.await` を跨いで保持しない
    // （保持するとハンドラの future が `Send` でなくなり axum の `Handler` を満たさない）。
    let target = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    // 受け付けるのは停止・再開の 2 遷移のみ。`INVITED` は招待フローが管理する状態のため、
    // ここから直接は設定させない。
    let status = MembershipStatus::parse(body.status.trim())
        .ok()
        .filter(|s| matches!(s, MembershipStatus::Active | MembershipStatus::Suspended))
        .ok_or_else(|| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let result = match status {
        MembershipStatus::Suspended => {
            state
                .invitations
                .suspend_membership(tenant.context(), target, admin.user_id, &ctx)
                .await
        }
        _ => {
            state
                .invitations
                .resume_membership(tenant.context(), target, admin.user_id, &ctx)
                .await
        }
    };
    result.map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_error(e: InvitationError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        InvitationError::NotFound => ApiError::NotFound(msgs.get("api-member-not-found")),
        InvitationError::AlreadyMember => ApiError::Conflict(msgs.get("api-member-already")),
        InvitationError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        InvitationError::InvalidOrExpired => ApiError::BadRequest(msgs.get("api-invalid-request")),
        InvitationError::Internal(m) => ApiError::Internal(m),
    }
}
