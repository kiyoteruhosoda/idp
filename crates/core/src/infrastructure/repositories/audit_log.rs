//! sqlx implementation of the `audit_log` table. Writing (`AuditLogSink`) and reading (`AuditLogQuery`).

use crate::domain::audit::{AuditEvent, AuditLogEntry, AuditLogFilter};
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::{AuditLogQuery, AuditLogSink};
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};
use uuid::Uuid;

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
             (event_type, occurred_at, tenant_id, user_id, client_id, ip_address, user_agent, \
              result, reason, correlation_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.event_type.as_str())
        .bind(event.occurred_at.naive_utc())
        .bind(event.tenant_id.map(|t| t.to_string()))
        .bind(event.user_id.map(|u| u.to_string()))
        .bind(&event.client_id)
        .bind(&event.ip_address)
        .bind(&event.user_agent)
        .bind(event.result.as_str())
        .bind(event.reason.as_deref().map(truncate_reason))
        .bind(&event.correlation_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::Repository(e.to_string()))?;
        Ok(())
    }

    async fn purge_older_than(&self, older_than: DateTime<Utc>) -> Result<u64> {
        // Cap the number of rows deleted by one DELETE. The audit log is expected to run for a long time with
        // `AUDIT_LOG_RETENTION_DAYS = 0` (no deletion) before being enabled, so the first deletion may cover millions of rows.
        // An unbounded DELETE would hold locks the whole time and stall the authorization flow's INSERTs.
        // The rest is picked up by the next cycle (callers can tell "some remain" from the deleted count).
        let deleted = sqlx::query("DELETE FROM audit_log WHERE occurred_at < ? LIMIT ?")
            .bind(older_than.naive_utc())
            .bind(PURGE_BATCH_SIZE)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?
            .rows_affected();
        Ok(deleted)
    }
}

/// Maximum rows deleted in one retention deletion (G8). It is a range delete using `audit_log_occurred_idx`,
/// so one batch's duration is roughly proportional to the row count.
const PURGE_BATCH_SIZE: i64 = 10_000;

pub struct SqlxAuditLogQuery {
    pool: Db,
}

impl SqlxAuditLogQuery {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

/// Column limit for `reason` (`VARCHAR(255)`). Anything beyond is truncated.
///
/// `reason` holds variable-length values (a tenant domain is up to 253 characters; ADR-0029). Binding an overflowing value
/// makes strict-mode MariaDB fail the whole INSERT, and **the audit event is lost entirely** --
/// the caller (`AuditService::record`) only logs an error while the operation itself succeeded,
/// leaving "it happened but there is no record". Keep the record even if the tail is cut.
const REASON_MAX_LEN: usize = 255;

/// Cuts by `char` so character boundaries aren't broken (the `VARCHAR` limit is in characters too).
fn truncate_reason(reason: &str) -> String {
    reason.chars().take(REASON_MAX_LEN).collect()
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<AuditLogEntry> {
    let tenant_id: Option<String> = row.try_get("tenant_id").map_err(repo_err)?;
    let tenant_id = tenant_id
        .map(|s| {
            Uuid::parse_str(&s)
                .map_err(|e| DomainError::Repository(format!("invalid UUID `{s}`: {e}")))
        })
        .transpose()?;
    let user_id: Option<String> = row.try_get("user_id").map_err(repo_err)?;
    let user_id = user_id
        .map(|s| {
            Uuid::parse_str(&s)
                .map_err(|e| DomainError::Repository(format!("invalid UUID `{s}`: {e}")))
        })
        .transpose()?;
    Ok(AuditLogEntry {
        id: row.try_get("id").map_err(repo_err)?,
        event_type: row.try_get("event_type").map_err(repo_err)?,
        occurred_at: to_utc(row.try_get("occurred_at").map_err(repo_err)?),
        tenant_id,
        user_id,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        ip_address: row.try_get("ip_address").map_err(repo_err)?,
        user_agent: row.try_get("user_agent").map_err(repo_err)?,
        result: row.try_get("result").map_err(repo_err)?,
        reason: row.try_get("reason").map_err(repo_err)?,
        correlation_id: row.try_get("correlation_id").map_err(repo_err)?,
    })
}

#[async_trait]
impl AuditLogQuery for SqlxAuditLogQuery {
    async fn search(&self, filter: &AuditLogFilter) -> Result<Vec<AuditLogEntry>> {
        // Only the specified conditions are ANDed. All values are bound (SQL injection protection).
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT id, event_type, occurred_at, tenant_id, user_id, client_id, ip_address, \
             user_agent, result, reason, correlation_id FROM audit_log WHERE 1 = 1",
        );
        if let Some(tenant_id) = filter.tenant_id {
            qb.push(" AND tenant_id = ")
                .push_bind(tenant_id.to_string());
        }
        if let Some(event_type) = &filter.event_type {
            qb.push(" AND event_type = ").push_bind(event_type);
        }
        if let Some(result) = &filter.result {
            qb.push(" AND result = ").push_bind(result);
        }
        if let Some(client_id) = &filter.client_id {
            qb.push(" AND client_id = ").push_bind(client_id);
        }
        if let Some(correlation_id) = &filter.correlation_id {
            qb.push(" AND correlation_id = ").push_bind(correlation_id);
        }
        if let Some(from) = filter.from {
            qb.push(" AND occurred_at >= ").push_bind(from.naive_utc());
        }
        if let Some(to) = filter.to {
            qb.push(" AND occurred_at <= ").push_bind(to.naive_utc());
        }
        qb.push(" ORDER BY occurred_at DESC, id DESC LIMIT ")
            .push_bind(filter.limit)
            .push(" OFFSET ")
            .push_bind(filter.offset);

        let rows = qb.build().fetch_all(&self.pool).await.map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn last_used_per_client(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<(String, DateTime<Utc>)>> {
        // "Usage" = successful token issuance and authorization code issuance. Gets the latest time per client_id in one aggregation.
        let rows = sqlx::query(
            "SELECT client_id, MAX(occurred_at) AS last_used_at FROM audit_log \
             WHERE tenant_id = ? AND client_id IS NOT NULL AND result = 'success' \
             AND event_type IN ('token.issued', 'authorization_code.issued') \
             GROUP BY client_id",
        )
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter()
            .map(|row| {
                let client_id: String = row.try_get("client_id").map_err(repo_err)?;
                let last_used: NaiveDateTime = row.try_get("last_used_at").map_err(repo_err)?;
                Ok((client_id, to_utc(last_used)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `reason` over the limit is truncated (binding it overflowing would lose the whole audit event).
    #[test]
    fn reason_is_truncated_to_the_column_limit() {
        let long = "domain=".to_string() + &"a".repeat(300);
        assert_eq!(truncate_reason(&long).chars().count(), REASON_MAX_LEN);
        assert_eq!(
            truncate_reason("domain=corp.example"),
            "domain=corp.example"
        );
        // Don't break character boundaries (no panic even with multibyte characters).
        assert_eq!(
            truncate_reason(&"あ".repeat(300)).chars().count(),
            REASON_MAX_LEN
        );
    }
}
