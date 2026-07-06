//! 監査ログ参照のユースケース（状況確認画面 A3、設計仕様 §7）。
//!
//! `audit_log` を `event_type` / `result`（`failure` 等のエラー絞り込みを主眼）／期間 /
//! `client_id` / `correlation_id` で絞り込み、新しい順に返す。`correlation_id` により
//! 「リクエスト → 処理 → 監査イベント」を一気通貫で追跡できる。

use crate::domain::audit::{AuditLogEntry, AuditLogFilter};
use crate::domain::error::DomainError;
use crate::domain::repositories::AuditLogQuery;
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// 1 ページの既定件数。
pub const DEFAULT_LIMIT: i64 = 50;
/// 1 ページの上限件数（過大な取得を防ぐ）。
pub const MAX_LIMIT: i64 = 200;

/// 検索パラメータ（Presentation から受け取る素の値。`limit`/`offset` は未クランプ）。
#[derive(Debug, Clone, Default)]
pub struct AuditQueryParams {
    pub event_type: Option<String>,
    pub result: Option<String>,
    pub client_id: Option<String>,
    pub correlation_id: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub struct AuditQueryService {
    logs: Arc<dyn AuditLogQuery>,
}

impl AuditQueryService {
    pub fn new(logs: Arc<dyn AuditLogQuery>) -> Self {
        Self { logs }
    }

    pub async fn search(
        &self,
        params: AuditQueryParams,
    ) -> Result<Vec<AuditLogEntry>, DomainError> {
        let filter = AuditLogFilter {
            event_type: normalize(params.event_type),
            result: normalize(params.result),
            client_id: normalize(params.client_id),
            correlation_id: normalize(params.correlation_id),
            from: params.from,
            to: params.to,
            limit: clamp_limit(params.limit),
            offset: params.offset.unwrap_or(0).max(0),
        };
        self.logs.search(&filter).await
    }
}

/// `limit` を 1..=MAX_LIMIT に収める。未指定・非正値は既定値。
fn clamp_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(l) if l > 0 => l.min(MAX_LIMIT),
        _ => DEFAULT_LIMIT,
    }
}

/// 空文字列を `None` に正規化する（クエリ未指定の `?event_type=` を無視するため）。
fn normalize(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_limit_to_bounds_and_defaults() {
        assert_eq!(clamp_limit(None), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(-5)), DEFAULT_LIMIT);
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(MAX_LIMIT + 100)), MAX_LIMIT);
    }

    #[test]
    fn normalizes_blank_to_none() {
        assert_eq!(normalize(Some("  ".to_string())), None);
        assert_eq!(
            normalize(Some(" failure ".to_string())),
            Some("failure".to_string())
        );
        assert_eq!(normalize(None), None);
    }
}
