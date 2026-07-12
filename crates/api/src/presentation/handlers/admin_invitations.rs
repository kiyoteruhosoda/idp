//! ゲスト招待作成エンドポイント（`/{tenant_id}/admin/invitations`。ADR-0009 §3・§6）。
//!
//! `idp.tenant.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。参加先テナントの管理者が既存利用者
//! （所属元は他テナント）を招待すると、一度限りの**招待トークン**を返す。トークンはハッシュのみ保存し、
//! ログ・監査ログには出さない（`generated_password` と同じパターン。§3）。管理者がトークンを被招待者へ
//! 別途通知し、被招待者は所属元テナントでログイン済みのセッションで `/invitations/accept` に提示する。

use crate::application::invitation::InvitationError;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{CreateInvitationRequest, InvitationCreatedResponse};
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use uuid::Uuid;

/// ゲスト招待を作成し、招待トークンを**この応答でのみ**返す。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/invitations",
    tag = "admin",
    request_body = CreateInvitationRequest,
    responses(
        (status = 201, description = "招待作成（招待トークンを含む）", body = InvitationCreatedResponse),
        (status = 400, description = "user_id が UUID でない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
        (status = 404, description = "被招待利用者が不存在"),
        (status = 409, description = "既に当該テナントのメンバー"),
    )
)]
pub async fn create_invitation(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    headers: HeaderMap,
    Json(body): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationCreatedResponse>), ApiError> {
    let target = Uuid::parse_str(&body.user_id)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    let ctx = request_context(&headers, &correlation, state.config.trust_forwarded_headers());
    let created = state
        .invitations
        .create_invitation(tenant.context(), target, admin.user_id, &ctx)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((
        StatusCode::CREATED,
        Json(InvitationCreatedResponse {
            token: created.token,
            expires_at: created.expires_at.to_rfc3339(),
            email_sent: created.email_sent,
            invitee_email: created.invitee_email,
        }),
    ))
}

fn map_error(e: InvitationError, locale: ApiLocale) -> ApiError {
    let msgs = ApiMessages::new(locale);
    match e {
        InvitationError::NotFound => ApiError::NotFound(msgs.get("api-invitation-user-not-found")),
        InvitationError::AlreadyMember => ApiError::Conflict("already a member".to_string()),
        InvitationError::Forbidden(m) => ApiError::Forbidden(m),
        InvitationError::InvalidOrExpired => {
            ApiError::BadRequest(msgs.get("api-invalid-request"))
        }
        InvitationError::Internal(m) => ApiError::Internal(m),
    }
}
