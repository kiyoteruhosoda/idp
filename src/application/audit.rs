//! 監査ログのユースケース（設計仕様 §7）。
//!
//! すべての監査イベントを構造化ログ（`tracing`、JSON）へ出力し、同時に `audit_log` テーブルへ
//! 書き込む。DB 書き込みの失敗で元の処理を失敗させない（エラーログのみ残す）。

use crate::domain::audit::{AuditEvent, AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::repositories::AuditLogSink;
use std::sync::Arc;
use uuid::Uuid;

/// リクエスト由来の監査コンテキスト（追跡キーと接続元情報）。
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub correlation_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub struct AuditService {
    sink: Arc<dyn AuditLogSink>,
    clock: Arc<dyn Clock>,
}

impl AuditService {
    pub fn new(sink: Arc<dyn AuditLogSink>, clock: Arc<dyn Clock>) -> Self {
        Self { sink, clock }
    }

    /// 監査イベントを 1 件記録する。PII は渡さない（ユーザー識別は内部 UUID のみ）。
    pub async fn record(
        &self,
        event_type: AuditEventType,
        result: AuditResult,
        user_id: Option<Uuid>,
        client_id: Option<&str>,
        reason: Option<&str>,
        ctx: &RequestContext,
    ) {
        let event = AuditEvent {
            event_type,
            occurred_at: self.clock.now(),
            user_id,
            client_id: client_id.map(str::to_string),
            ip_address: ctx.ip_address.clone(),
            user_agent: ctx.user_agent.clone(),
            result,
            reason: reason.map(str::to_string),
            correlation_id: ctx.correlation_id.clone(),
        };

        tracing::info!(
            target: "audit",
            event_type = event.event_type.as_str(),
            result = event.result.as_str(),
            user_id = event.user_id.map(|u| u.to_string()),
            client_id = event.client_id.as_deref(),
            reason = event.reason.as_deref(),
            correlation_id = %event.correlation_id,
            "audit event"
        );

        if let Err(e) = self.sink.record(&event).await {
            tracing::error!(
                error = %e,
                event_type = event.event_type.as_str(),
                "failed to persist audit event"
            );
        }
    }
}
