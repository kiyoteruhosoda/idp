//! エラー・警告ログ参照／取り込みエンドポイント（`log` テーブル。CLAUDE.md「ログ」）。
//!
//! - `GET /{tenant_id}/admin/logs`: 管理コンソールからの参照。`level` / `service` / `target` /
//!   `correlation_id` / 期間で絞り込める。`correlation_id` で監査ログ（`/admin/audit-logs`）と
//!   同じリクエストの記録を突き合わせられる。
//! - `POST /internal/logs`: web からの取り込み（web は DB を持たないため api に書いてもらう）。
//!
//! **参照は `idp.system.admin`（root）に限る**。アプリケーションログはテナント横断の運用情報で、
//! 他テナントの処理で出たエラーも同じテーブルに載るため、テナント管理者には開けない
//! （テナント単位の追跡は監査ログ `/admin/audit-logs` が担う）。

use crate::application::application_log::ApplicationLogQueryParams;
use crate::domain::application_log::ApplicationLogEntry;
use crate::domain::message::MessageKey;
use crate::presentation::admin::{IdpSystemAdmin, RequirePerms};
use crate::presentation::dto::ApplicationLogQueryString;
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use idp_contracts::application_log::{
    ApplicationLogEntryResponse, ApplicationLogIngestRequest, ApplicationLogIngestResponse,
};

/// エラー・警告ログを条件で絞り込み、新しい順に返す。
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
    )
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

/// 1 リクエストで受け取る最大件数。web の送信バッチ（64 件）に余裕を持たせた上限で、
/// 想定外の巨大なバッチで 1 文の INSERT が膨らむのを防ぐ。超過分は捨てる。
const MAX_INGEST_RECORDS: usize = 256;

/// web が送ってきた WARN / ERROR を `log` テーブルへ書く（`/internal/*` のサービストークンで保護）。
///
/// 解釈できない行（未知のレベル・サービス、日時形式不正）は黙って捨て、書けた件数を返す。
/// 取り込み側の不調でログ送出元（web）を失敗させないため、書き込み失敗も 200 + `accepted: 0` で返す。
pub async fn ingest_application_logs(
    State(state): State<AppState>,
    Json(body): Json<ApplicationLogIngestRequest>,
) -> Json<ApplicationLogIngestResponse> {
    let records = &body.records[..body.records.len().min(MAX_INGEST_RECORDS)];
    // 失敗はここでログに出さない（ログ書き込み失敗のログがまた書き込みを誘発するため）。
    let accepted = state.application_logs.ingest(records).await.unwrap_or(0);
    Json(ApplicationLogIngestResponse { accepted })
}

/// RFC3339 の日時をパースする。未指定は `None`、形式不正は 400。
/// どの項目（`from` / `to`）が不正かは翻訳文の差し込み値で伝える。
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
