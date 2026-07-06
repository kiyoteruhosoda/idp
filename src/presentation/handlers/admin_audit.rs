//! 監査ログ参照エンドポイント（`GET /admin/audit-logs`、状況確認画面 A3、設計仕様 §7）。
//!
//! `idp.admin` 権限が必要（`RequirePerms<IdpAdmin>`）。`result=failure` などで**エラー絞り込み**でき、
//! `correlation_id` でリクエスト〜監査イベントを追跡できる。

use crate::application::audit_query::AuditQueryParams;
use crate::domain::audit::AuditLogEntry;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::dto::{AuditLogEntryResponse, AuditLogQueryParams};
use crate::presentation::error::ApiError;
use crate::presentation::state::AppState;
use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};

/// 監査ログを条件で絞り込み、新しい順に返す。
#[utoipa::path(
    get,
    path = "/admin/audit-logs",
    tag = "admin",
    params(AuditLogQueryParams),
    responses(
        (status = 200, description = "監査ログ一覧（新しい順）", body = [AuditLogEntryResponse]),
        (status = 400, description = "from / to の日時形式が不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.admin 必須）"),
    )
)]
pub async fn list_audit_logs(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Query(params): Query<AuditLogQueryParams>,
) -> Result<Json<Vec<AuditLogEntryResponse>>, ApiError> {
    let query = AuditQueryParams {
        event_type: params.event_type,
        result: params.result,
        client_id: params.client_id,
        correlation_id: params.correlation_id,
        from: parse_datetime(params.from.as_deref(), "from")?,
        to: parse_datetime(params.to.as_deref(), "to")?,
        limit: params.limit,
        offset: params.offset,
    };

    let entries = state
        .audit_query
        .search(query)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(entries.iter().map(entry_response).collect()))
}

/// RFC3339 の日時をパースする。未指定は `None`、形式不正は 400。
fn parse_datetime(value: Option<&str>, field: &str) -> Result<Option<DateTime<Utc>>, ApiError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .map(|dt| Some(dt.with_timezone(&Utc)))
        .map_err(|_| ApiError::BadRequest(format!("invalid RFC3339 datetime in `{field}`")))
}

fn entry_response(e: &AuditLogEntry) -> AuditLogEntryResponse {
    AuditLogEntryResponse {
        id: e.id,
        event_type: e.event_type.clone(),
        occurred_at: e.occurred_at.to_rfc3339(),
        user_id: e.user_id.map(|u| u.to_string()),
        client_id: e.client_id.clone(),
        ip_address: e.ip_address.clone(),
        user_agent: e.user_agent.clone(),
        result: e.result.clone(),
        reason: e.reason.clone(),
        correlation_id: e.correlation_id.clone(),
    }
}
