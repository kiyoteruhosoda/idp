//! `log` テーブルの sqlx 実装。書き込み（`ApplicationLogSink`）と読み取り（`ApplicationLogQuery`）。

use crate::domain::application_log::{
    ApplicationLogEntry, ApplicationLogFilter, ApplicationLogRecord,
};
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::{ApplicationLogQuery, ApplicationLogSink};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};
use uuid::Uuid;

pub struct SqlxApplicationLogSink {
    pool: Db,
}

impl SqlxApplicationLogSink {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApplicationLogSink for SqlxApplicationLogSink {
    async fn record_batch(&self, records: &[ApplicationLogRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "INSERT INTO log \
             (occurred_at, level, service, target, message, correlation_id, tenant_id, traceback) ",
        );
        qb.push_values(records, |mut row, record| {
            row.push_bind(record.occurred_at.naive_utc())
                .push_bind(record.level.as_str())
                .push_bind(record.service.as_str())
                .push_bind(record.target.as_str())
                .push_bind(record.message.as_str())
                .push_bind(record.correlation_id.as_deref())
                .push_bind(record.tenant_id.map(|t| t.to_string()))
                .push_bind(record.traceback.as_deref());
        });
        qb.build()
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::Repository(e.to_string()))?;
        Ok(())
    }

    async fn purge_older_than(&self, older_than: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query("DELETE FROM log WHERE occurred_at < ?")
            .bind(older_than.naive_utc())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}

pub struct SqlxApplicationLogQuery {
    pool: Db,
}

impl SqlxApplicationLogQuery {
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

fn map_row(row: &MySqlRow) -> Result<ApplicationLogEntry> {
    let tenant_id: Option<String> = row.try_get("tenant_id").map_err(repo_err)?;
    let tenant_id = tenant_id
        .map(|s| {
            Uuid::parse_str(&s)
                .map_err(|e| DomainError::Repository(format!("invalid UUID `{s}`: {e}")))
        })
        .transpose()?;
    Ok(ApplicationLogEntry {
        id: row.try_get("id").map_err(repo_err)?,
        occurred_at: to_utc(row.try_get("occurred_at").map_err(repo_err)?),
        level: row.try_get("level").map_err(repo_err)?,
        service: row.try_get("service").map_err(repo_err)?,
        target: row.try_get("target").map_err(repo_err)?,
        message: row.try_get("message").map_err(repo_err)?,
        correlation_id: row.try_get("correlation_id").map_err(repo_err)?,
        tenant_id,
        traceback: row.try_get("traceback").map_err(repo_err)?,
    })
}

#[async_trait]
impl ApplicationLogQuery for SqlxApplicationLogQuery {
    async fn search(&self, filter: &ApplicationLogFilter) -> Result<Vec<ApplicationLogEntry>> {
        // 条件は指定された項目のみ AND で積む。値はすべてバインドする（SQL インジェクション対策）。
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT id, occurred_at, level, service, target, message, correlation_id, \
             tenant_id, traceback FROM log WHERE 1 = 1",
        );
        if let Some(level) = filter.level {
            qb.push(" AND level = ").push_bind(level.as_str());
        }
        if let Some(service) = filter.service {
            qb.push(" AND service = ").push_bind(service.as_str());
        }
        if let Some(prefix) = &filter.target_prefix {
            // 前方一致。LIKE のメタ文字はエスケープしてから連結する（利用者入力をパターンにしない）。
            qb.push(" AND target LIKE ")
                .push_bind(format!("{}%", escape_like(prefix)))
                .push(" ESCAPE '\\\\'");
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
}

/// LIKE パターンのメタ文字（`%` / `_` / `\`）を無効化する。前方一致検索の入力は「文字列」であり
/// パターンではないため、利用者が `%` を書いても全件一致にならないようにする。
fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_metacharacters() {
        assert_eq!(escape_like("idp_api"), "idp\\_api");
        assert_eq!(escape_like("100%"), "100\\%");
        assert_eq!(escape_like("a\\b"), "a\\\\b");
        assert_eq!(escape_like("idp::handlers"), "idp::handlers");
    }
}
