//! テナントメンバー管理エンドポイント（`/{tenant_id}/admin/members`。ADR-0009 §3・§6）。
//!
//! すべて `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。参加先テナントの管理者が行えるのは
//! メンバー一覧の閲覧と**ゲストメンバーシップの解除・一時停止/再開**（MT24）のみで、HOME は解除も停止も
//! できない。ゲストの `users` レコード（パスワード・状態・MFA・プロフィール）は操作できない
//! （所属元テナントの管理者と本人のみ。§3）。

use crate::application::account_note::AccountNoteError;
use crate::application::invitation::InvitationError;
use crate::application::member_directory::MemberSearchParams;
use crate::domain::account::AccountLocator;
use crate::domain::account_note::AccountNote;
use crate::domain::tenant_membership::TenantMember;
use crate::domain::values::MembershipStatus;
use crate::presentation::admin::{MembersRead, MembersWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{
    AccountNoteResponse, MemberListQueryParams, MemberListResponse, MemberResponse,
    UpdateAccountNoteRequest, UpdateMemberStatusRequest,
};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// メンバー 1 人を名指しで引く（`GET /{tenant_id}/admin/members/{user_id}`）。
///
/// メンバーの詳細画面のためにある。⚠ **一覧を引いて呼び出し側で探させない** ——一覧は
/// ページングされているので、目的の 1 人が何ページ目に居るかは呼び出し側には分からない。
///
/// 要求テナントに所属していなければ 404（他テナントのメンバーの存在を推測させない）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/members/{user_id}",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    responses(
        (status = 200, description = "メンバー 1 人", body = MemberResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.members:read 必須）"),
        (status = 404, description = "このテナントのメンバーではない"),
    )
)]
pub async fn get_member(
    RequirePerms(_admin, _): RequirePerms<MembersRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    // ⚠ **経路には `{tenant_id}` と `{user_id}` の 2 つがある。** `Path<Uuid>` の 1 つだけで
    //   受けると**先頭のテナント ID を取ってしまい**、必ず「メンバーではない」になる
    //   （同じ経路の `revoke_member` / `update_member_status` も 2 つで受けている）。
    Path((_tenant_id, user_id)): Path<(String, Uuid)>,
) -> Result<Json<MemberResponse>, ApiError> {
    let found = state
        .member_directory
        .find(tenant.context(), user_id)
        .await
        .map_err(|e| map_error(InvitationError::Internal(e.to_string()), locale))?;
    let now = state.clock.now();
    match found {
        Some(m) => Ok(Json(member_response(m, now))),
        None => Err(ApiError::NotFound(
            ApiMessages::new(locale).get("api-user-not-found"),
        )),
    }
}

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
    RequirePerms(_admin, _): RequirePerms<MembersRead>,
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
    let now = state.clock.now();
    Ok(Json(MemberListResponse {
        members: result
            .page
            .members
            .into_iter()
            .map(|m| member_response(m, now))
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
    RequirePerms(admin, _): RequirePerms<MembersWrite>,
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
        .revoke_membership(tenant.context(), target, &admin.actor, &ctx)
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
    RequirePerms(admin, _): RequirePerms<MembersWrite>,
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
                .suspend_membership(tenant.context(), target, &admin.actor, &ctx)
                .await
        }
        _ => {
            state
                .invitations
                .resume_membership(tenant.context(), target, &admin.actor, &ctx)
                .await
        }
    };
    result.map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// 管理者メモを書く・消す（`PUT /{tenant_id}/admin/members/{user_id}/note`。ADR-0063）。
///
/// HOME / GUEST を問わず書ける（メモはこのテナントの管理者の覚え書きで、ゲストの利用者そのものは
/// 変えない）。空（空白だけ）を送るとメモを消す。
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/members/{user_id}/note",
    tag = "admin",
    params(("user_id" = String, Path, description = "対象利用者の内部 ID（UUID）")),
    request_body = UpdateAccountNoteRequest,
    responses(
        (status = 204, description = "保存した（空なら消した）"),
        (status = 400, description = "user_id が UUID でない・メモが長すぎる"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.members:write 必須）"),
        (status = 404, description = "このテナントのメンバーではない"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn update_member_note(
    RequirePerms(admin, _): RequirePerms<MembersWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Path((_tenant_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdateAccountNoteRequest>,
) -> Result<StatusCode, ApiError> {
    let target = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .account_notes
        .write(
            tenant.context(),
            AccountLocator::User { user_id: target },
            &body.note,
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(|e| {
            let msgs = ApiMessages::new(locale);
            match e {
                AccountNoteError::NotFound => ApiError::NotFound(msgs.get("api-member-not-found")),
                AccountNoteError::Invalid(m) => ApiError::BadRequest(msgs.get_message(&m)),
                AccountNoteError::Internal(m) => ApiError::Internal(m),
            }
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// メンバー 1 人の応答（一覧・名指し・アカウント一覧の人の行が共有する）。
pub(crate) fn member_response(m: TenantMember, now: DateTime<Utc>) -> MemberResponse {
    MemberResponse {
        user_id: m.user_id.to_string(),
        email: m.email,
        preferred_username: m.preferred_username,
        name: m.name,
        membership_type: m.membership_type.as_str().to_string(),
        status: m.status.as_str().to_string(),
        user_status: m.user_status.map(|s| s.as_str().to_string()),
        // 期限切れのロックは「掛かっていない」として返す（読んだ時点で判定する）。
        locked: m.locked_until.is_some_and(|until| until > now),
        pending_setup: m.pending_setup,
        // 期限は仮登録の人にだけ意味がある（設定を終えた人のリンクは使い道が無い）。
        setup_link_expires_at: m
            .setup_link_expires_at
            .filter(|_| m.pending_setup)
            .map(|t| t.to_rfc3339()),
        setup_link_expired: m.pending_setup
            && !m.setup_link_expires_at.is_some_and(|until| until > now),
        note: note_response(m.note),
    }
}

/// 管理者メモの応答（人・サービスアカウントで同じ形。ADR-0065）。
pub(crate) fn note_response(note: Option<AccountNote>) -> Option<AccountNoteResponse> {
    note.map(|n| AccountNoteResponse {
        text: n.text,
        updated_at: n.updated_at.to_rfc3339(),
    })
}

fn map_error(e: InvitationError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        InvitationError::NotFound => ApiError::NotFound(msgs.get("api-member-not-found")),
        InvitationError::AlreadyMember => ApiError::Conflict(msgs.get("api-member-already")),
        InvitationError::Validation(m) => ApiError::BadRequest(msgs.get_message(&m)),
        InvitationError::Forbidden(m) => ApiError::Forbidden(msgs.get_message(&m)),
        InvitationError::InvalidOrExpired => ApiError::BadRequest(msgs.get("api-invalid-request")),
        InvitationError::Internal(m) => ApiError::Internal(m),
    }
}
