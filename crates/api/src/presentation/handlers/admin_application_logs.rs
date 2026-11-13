//! Error/warning log query / ingestion endpoints (`log` table, CLAUDE.md "ログ").
//!
//! - `GET /{tenant_id}/admin/logs`: query from the admin console. Filterable by `level` / `service` / `target` /
//!   `correlation_id` / period. `correlation_id` lets you match the audit log (`/admin/audit-logs`)
//!   with records of the same request.
//! - `POST /internal/logs`: ingestion from web (web has no DB, so the api writes for it).
//!
//! **Querying is limited to `idp.system.admin` (root)**. Application logs are cross-tenant operational data,
//! and errors from other tenants' processing land in the same table, so tenant admins cannot open them
//! (per-tenant tracing is covered by the audit log `/admin/audit-logs`).

use crate::application::application_log::ApplicationLogQueryParams;
use crate::domain::application_log::ApplicationLogEntry;
use crate::domain::message::MessageKey;
use crate::presentation::admin::{IdpSystemAdmin, RequirePerms};
use crate::presentation::dto::ApplicationLogQueryString;
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use assay_contracts::application_log::{
    ApplicationLogEntryResponse, ApplicationLogIngestRequest, ApplicationLogIngestResponse,
};
use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};

/// Filters error/warning logs by conditions and returns them newest first.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/logs",
    tag = "admin",
    params(ApplicationLogQueryString),
    responses(
        (status = 200, description = "エラー・警告ログ一覧（新しい順）"),
        (status = 400, description = "from / to の日時形式が不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.system.admin 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_application_logs(
    RequirePerms(_admin, _): RequirePerms<IdpSystemAdmin>,
    State(state): State<AppState>,
    locale: ApiLocale,
    Query(params): Query<ApplicationLogQueryString>,
) -> Result<Json<Vec<ApplicationLogEntryResponse>>, ApiError> {
    let query = ApplicationLogQueryParams {
        level: params.level,
        service: params.service,
        target: params.target,
        correlation_id: params.correlation_id,
        from: parse_datetime(params.from.as_deref(), "from", locale)?,
        to: parse_datetime(params.to.as_deref(), "to", locale)?,
        limit: params.limit,
        offset: params.offset,
    };

    let entries = state
        .application_logs
        .search(query)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(entries.iter().map(entry_response).collect()))
}

/// Max entries accepted per request. A limit with headroom over web's send batch (64 entries) that
/// keeps an unexpectedly huge batch from bloating a single INSERT. The excess is dropped.
const MAX_INGEST_RECORDS: usize = 256;

/// Writes WARN / ERROR sent by web into the `log` table (protected by the `/internal/*` service token).
///
/// Unparseable rows (unknown level/service, malformed timestamp) are silently dropped; returns the count written.
/// So that ingestion trouble never fails the log sender (web), write failures also return 200 + `accepted: 0`.
pub async fn ingest_application_logs(
    State(state): State<AppState>,
    Json(body): Json<ApplicationLogIngestRequest>,
) -> Json<ApplicationLogIngestResponse> {
    let records = &body.records[..body.records.len().min(MAX_INGEST_RECORDS)];
    // Failures are not logged here (a log about a failed log write would trigger another write).
    let accepted = state.application_logs.ingest(records).await.unwrap_or(0);
    Json(ApplicationLogIngestResponse { accepted })
}

/// Parses an RFC3339 timestamp. `None` if absent, 400 if malformed.
/// Which field (`from` / `to`) is invalid is conveyed via the translated message's placeholder.
fn parse_datetime(
    value: Option<&str>,
    field: &str,
    locale: ApiLocale,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .map(|dt| Some(dt.with_timezone(&Utc)))
        .map_err(|_| {
            ApiError::BadRequest(
                ApiMessages::new(locale)
                    .get_message(&MessageKey::with_value("api-audit-invalid-datetime", field)),
            )
        })
}

fn entry_response(e: &ApplicationLogEntry) -> ApplicationLogEntryResponse {
    ApplicationLogEntryResponse {
        id: e.id,
        occurred_at: e.occurred_at.to_rfc3339(),
        level: e.level.clone(),
        service: e.service.clone(),
        target: e.target.clone(),
        message: e.message.clone(),
        correlation_id: e.correlation_id.clone(),
        tenant_id: e.tenant_id.map(|t| t.to_string()),
        traceback: e.traceback.clone(),
    }
}
