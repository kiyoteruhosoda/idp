//! api の再起動エンドポイント（`POST /{tenant_id}/admin/restart`。ADR-0017）。
//!
//! `idp.system.admin` 必須（ランタイム設定と同じ権限。実質 root テナントの system 管理者のみ）。
//!
//! **応答を返してから終了する。** 先に graceful shutdown を起こすと、この要求自身が接続ごと切れて
//! 「押したが何も起きなかった」ように見える。要求元へ受理を返し、少し待ってから停止することで、
//! web は再起動中の画面を描いてから自分の停止へ進める。
//!
//! 停止するだけで、新しいプロセスを起こすのは配置側の再起動ポリシーである（`service_restart`
//! のモジュールドキュメント参照）。ポリシーが無い環境では**サービスが停止したままになる**ため、
//! 画面には必ずその前提を書く。

use crate::presentation::admin::{IdpSystemAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::RestartServiceResponse;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;

/// api を再起動する（graceful shutdown → 配置側の再起動ポリシーが新プロセスを起こす）。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/restart",
    tag = "admin",
    responses(
        (status = 202, description = "再起動を受理した（応答後に停止する）", body = RestartServiceResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    )
)]
pub async fn restart_service(
    RequirePerms(admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<RestartServiceResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    tracing::warn!("restart requested from the admin console");
    state
        .service_restart
        .request(tenant.context(), &admin.actor, "api", &ctx)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok((
        StatusCode::ACCEPTED,
        Json(RestartServiceResponse {
            service: "api".to_string(),
            restarting: true,
        }),
    ))
}
