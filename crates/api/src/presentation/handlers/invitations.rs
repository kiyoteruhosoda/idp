//! 招待承諾エンドポイント（`/{tenant_id}/invitations/accept`。ADR-0009 §3・§6）。
//!
//! 管理 API（`/admin/*`）ではなく、**ログイン済み利用者本人**が用いる（権限は不要）。被招待者は所属元
//! テナントでログイン済みのセッションで、参加先テナント（`{tenant_id}`）の承諾エンドポイントに招待
//! トークンを提示する。本人性はトークンの所持 + ログイン済みセッションで確認する（`AuthenticatedUser`
//! extractor が SSO セッションから利用者を解決し、ユースケースがトークンと突き合わせる。§3）。

use crate::application::invitation::InvitationError;
use crate::presentation::admin::AuthenticatedUser;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::AcceptInvitationRequest;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

/// 招待を承諾し、メンバーシップを `ACTIVE` にする。承諾者は被招待者本人（ログイン済み）でなければ
/// ならない。トークンが当該テナントの招待でない・期限切れ・不存在は 400、本人でなければ 403。
#[utoipa::path(
    post,
    path = "/{tenant_id}/invitations/accept",
    tag = "auth",
    request_body = AcceptInvitationRequest,
    responses(
        (status = 204, description = "承諾成功"),
        (status = 400, description = "トークンが無効・期限切れ・別テナントの招待"),
        (status = 401, description = "未認証（ログインが必要）"),
        (status = 403, description = "被招待者本人でない"),
    )
)]
pub async fn accept_invitation(
    AuthenticatedUser(user_id): AuthenticatedUser,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Json(body): Json<AcceptInvitationRequest>,
) -> Result<StatusCode, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    state
        .invitations
        .accept_invitation(tenant.context(), user_id, &body.token, &ctx)
        .await
        .map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_error(e: InvitationError) -> ApiError {
    match e {
        InvitationError::NotFound => ApiError::NotFound("not found".to_string()),
        InvitationError::AlreadyMember => ApiError::Conflict("already a member".to_string()),
        InvitationError::Forbidden(m) => ApiError::Forbidden(m),
        InvitationError::InvalidOrExpired => {
            ApiError::BadRequest("invalid or expired invitation".to_string())
        }
        InvitationError::Internal(m) => ApiError::Internal(m),
    }
}
