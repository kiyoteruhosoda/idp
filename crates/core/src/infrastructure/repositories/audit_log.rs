//! `audit_log` テーブルの sqlx 実装。書き込み（`AuditLogSink`）と読み取り（`AuditLogQuery`）。

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
        .bind(&event.reason)
        .bind(&event.correlation_id)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::Repository(e.to_string()))?;
        Ok(())
    }
}

pub struct SqlxAuditLogQuery {
    pool: Db,
}

impl SqlxAuditLogQuery {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
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
        // 条件は指定された項目のみ AND で積む。値はすべてバインドする（SQL インジェクション対策）。
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
        // 「利用」= 成功したトークン発行・認可コード発行。client_id ごとの最新時刻を 1 回の集計で取る。
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
