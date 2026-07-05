//! `AuditLogSink` の sqlx 実装（`audit_log` テーブルへの書き込み）。

use crate::domain::audit::AuditEvent;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::AuditLogSink;
use crate::infrastructure::db::Db;
use async_trait::async_trait;

pub struct SqlxAuditLogSink {
    pool: Db,
}

impl SqlxAuditLogSink {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditLogSink for SqlxAuditLogSink {
    async fn record(&self, event: &AuditEvent) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log \
             (event_type, occurred_at, user_id, client_id, ip_address, user_agent, \
              result, reason, correlation_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.event_type.as_str())
        .bind(event.occurred_at.naive_utc())
        .bind(event.user_id.map(|u| u.to_string()))
        .bind(&event.client_id)
        .bind(&event.ip_address)
        .bind(&event.user_agent)
        .bind(event.result.as_str())
        .bind(&event.reason)
        .bind(&event.correlation_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::Repository(e.to_string()))?;
        Ok(())
    }
}
