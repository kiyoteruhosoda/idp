//! アプリケーションログ（`log`）の取り込み・参照・掃除のユースケース（CLAUDE.md「ログ」）。
//!
//! 取り込み元は 2 つある。どちらも同じ [`ApplicationLogPayload`] で届き、ここで唯一の変換を通る。
//!
//! - api 自身: `tracing` 取り込み層 → チャネル → 書き込みタスク
//! - web: `tracing` 取り込み層 → `POST /internal/logs`（web は DB を持たないため api に書いてもらう）
//!
//! 参照は管理コンソールのエラー・警告ログ画面から。テナント横断の運用情報のため、閲覧は
//! `idp.system.admin`（root）に限る（呼び出し側 = Presentation の extractor が強制する）。

use crate::domain::application_log::{
    ApplicationLogEntry, ApplicationLogFilter, ApplicationLogRecord, LogLevel, LogService,
};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::repositories::{ApplicationLogQuery, ApplicationLogSink};
use chrono::{DateTime, Utc};
use idp_contracts::application_log::ApplicationLogPayload;
use std::sync::Arc;
use uuid::Uuid;

/// 1 ページの既定件数。
pub const DEFAULT_LIMIT: i64 = 50;
/// 1 ページの上限件数（過大な取得を防ぐ）。
pub const MAX_LIMIT: i64 = 200;

/// 検索パラメータ（Presentation から受け取る素の値。`limit`/`offset` は未クランプ）。
#[derive(Debug, Clone, Default)]
pub struct ApplicationLogQueryParams {
    pub level: Option<String>,
    pub service: Option<String>,
    pub target: Option<String>,
    pub correlation_id: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub struct ApplicationLogService {
    sink: Arc<dyn ApplicationLogSink>,
    logs: Arc<dyn ApplicationLogQuery>,
    clock: Arc<dyn Clock>,
}

impl ApplicationLogService {
    pub fn new(
        sink: Arc<dyn ApplicationLogSink>,
        logs: Arc<dyn ApplicationLogQuery>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self { sink, logs, clock }
    }

    /// 取り込み。解釈できない行（未知のレベル・サービス・日時）は捨てて残りを書く。
    /// 書き込めた件数を返す。
    ///
    /// **ここでは失敗をログに出さない**。ログ書き込みの失敗ログがまた書き込みを誘発するため、
    /// 呼び出し側（書き込みタスク・`/internal/logs` ハンドラ）が扱う。
    pub async fn ingest(&self, payloads: &[ApplicationLogPayload]) -> Result<usize, DomainError> {
        let records: Vec<ApplicationLogRecord> = payloads
            .iter()
            .filter_map(to_record)
            .map(|r| r.truncated())
            .collect();
        if records.is_empty() {
            return Ok(0);
        }
        self.sink.record_batch(&records).await?;
        Ok(records.len())
    }

    /// 検索（新しい順）。
    pub async fn search(
        &self,
        params: ApplicationLogQueryParams,
    ) -> Result<Vec<ApplicationLogEntry>, DomainError> {
        let filter = ApplicationLogFilter {
            level: normalize(params.level).and_then(|v| LogLevel::parse(&v)),
            service: normalize(params.service).and_then(|v| LogService::parse(&v)),
            target_prefix: normalize(params.target),
            correlation_id: normalize(params.correlation_id),
            from: params.from,
            to: params.to,
            limit: clamp_limit(params.limit),
            offset: params.offset.unwrap_or(0).max(0),
        };
        self.logs.search(&filter).await
    }

    /// 保持期間を過ぎた行を削除し、削除件数を返す。`retention_days` が 0 のときは無効（何もしない）。
    pub async fn purge_expired(&self, retention_days: u32) -> Result<u64, DomainError> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = self.clock.now() - chrono::Duration::days(i64::from(retention_days));
        self.sink.purge_older_than(cutoff).await
    }
}

/// 受信した 1 件を保存形へ変換する。必須項目が解釈できなければ `None`（その行だけ捨てる）。
fn to_record(payload: &ApplicationLogPayload) -> Option<ApplicationLogRecord> {
    Some(ApplicationLogRecord {
        occurred_at: DateTime::parse_from_rfc3339(&payload.occurred_at)
            .ok()?
            .with_timezone(&Utc),
        level: LogLevel::parse(&payload.level)?,
        service: LogService::parse(&payload.service)?,
        target: payload.target.clone(),
        message: payload.message.clone(),
        correlation_id: normalize(payload.correlation_id.clone()),
        tenant_id: payload
            .tenant_id
            .as_deref()
            .and_then(|v| Uuid::parse_str(v.trim()).ok()),
        traceback: normalize(payload.traceback.clone()),
    })
}

/// `limit` を 1..=MAX_LIMIT に収める。未指定・非正値は既定値。
fn clamp_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(l) if l > 0 => l.min(MAX_LIMIT),
        _ => DEFAULT_LIMIT,
    }
}

/// 空文字列を `None` に正規化する（クエリ未指定の `?level=` を無視するため）。
fn normalize(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(level: &str, service: &str, occurred_at: &str) -> ApplicationLogPayload {
        ApplicationLogPayload {
            occurred_at: occurred_at.to_string(),
            level: level.to_string(),
            service: service.to_string(),
            target: "idp_api::token".to_string(),
            message: "boom".to_string(),
            correlation_id: Some("  ".to_string()),
            tenant_id: Some("0192f0c0-0000-7000-8000-000000000001".to_string()),
            traceback: None,
        }
    }

    #[test]
    fn converts_valid_payload() {
        let record = to_record(&payload("error", "web", "2026-07-27T01:02:03Z")).expect("record");
        assert_eq!(record.level, LogLevel::Error);
        assert_eq!(record.service, LogService::Web);
        assert_eq!(record.occurred_at.to_rfc3339(), "2026-07-27T01:02:03+00:00");
        // 空白だけの correlation_id は未指定として扱う。
        assert_eq!(record.correlation_id, None);
        assert!(record.tenant_id.is_some());
    }

    #[test]
    fn rejects_unparseable_payloads() {
        assert!(to_record(&payload("info", "api", "2026-07-27T00:00:00Z")).is_none());
        assert!(to_record(&payload("error", "worker", "2026-07-27T00:00:00Z")).is_none());
        assert!(to_record(&payload("error", "api", "not-a-timestamp")).is_none());
    }

    #[test]
    fn clamps_limit_to_bounds_and_defaults() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(MAX_LIMIT + 100)), MAX_LIMIT);
    }

    #[test]
    fn normalizes_blank_to_none() {
        assert_eq!(normalize(Some(" ".to_string())), None);
        assert_eq!(
            normalize(Some(" WARN ".to_string())),
            Some("WARN".to_string())
        );
    }
}
