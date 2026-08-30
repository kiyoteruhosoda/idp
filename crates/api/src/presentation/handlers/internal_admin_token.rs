//! 管理トークン交換 API（`POST /internal/admin/token`。ADR-0037）。
//!
//! 管理コンソール（web）はブラウザの SSO セッション Cookie を持っているが、api の管理 API は
//! **Bearer トークンしか受け付けない**。その橋渡しがここである。web はリクエストの度にこの
//! エンドポイントで交換してから `/{tenant_id}/admin/*` を呼ぶ。
//!
//! 交換結果をキャッシュしないのは、**セッション失効・権限剥奪・ゲスト一時停止を即座に効かせる**
//! ためである。キャッシュするとトークンの寿命だけ古い判断が残る。管理コンソールの流量は少なく、
//! 1 往復増える代わりに「無効化したのにまだ操作できる」窓が無くなる方が価値が高い。
//!
//! 保護は `/internal/*` 共通のサービス認証トークン（`X-Internal-Auth-Token`）。SSO セッション値を
//! 受け取る以上、外部公開面には出さない。

use crate::application::management_token::ManagementTokenError;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::admin::{ManagementTokenRequest, ManagementTokenResponse};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// SSO セッションを管理トークンへ交換する。
///
/// 権限を 1 つも持たない利用者にも 200 を返す（`permission_codes` が空のトークン）。ここで 403 に
/// 倒すと、web は「未ログイン（ログイン画面へ）」と「権限不足（その旨を表示）」を区別できない。
pub async fn issue_management_token(
    State(state): State<AppState>,
    Json(body): Json<ManagementTokenRequest>,
) -> Result<Json<ManagementTokenResponse>, Response> {
    let tenant = require_internal_tenant(&state.tenant_resolution, Some(&body.tenant_id)).await?;
    match state
        .management_tokens
        .issue_for_session(tenant, Some(body.sso_session_id.as_str()))
        .await
    {
        Ok(issued) => Ok(Json(ManagementTokenResponse {
            access_token: issued.access_token,
            token_type: "Bearer".to_string(),
            expires_in: issued.expires_in,
            permission_codes: issued.permission_codes,
            name: issued.name,
            preferred_username: issued.preferred_username,
        })),
        Err(ManagementTokenError::Unauthenticated) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response()),
        Err(ManagementTokenError::Internal(e)) => {
            tracing::error!(error = %e, "failed to issue a management token");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server_error" })),
            )
                .into_response())
        }
    }
}
