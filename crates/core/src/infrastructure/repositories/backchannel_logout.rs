//! sqlx implementation of `BackchannelLogoutDeliveryRepository` (G5).

use crate::domain::backchannel_logout::BackchannelLogoutDelivery;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::BackchannelLogoutDeliveryRepository;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxBackchannelLogoutDeliveryRepository {
    pool: Db,
}

impl SqlxBackchannelLogoutDeliveryRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, tenant_id, client_id, target_uri, subject, sid, jti, attempts, \
     next_attempt_at, last_error, delivered_at, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(value: &str, column: &str) -> Result<Uuid> {
    Uuid::parse_str(value)
        .map_err(|e| DomainError::Repository(format!("invalid UUID in `{column}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<BackchannelLogoutDelivery> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let jti: String = row.try_get("jti").map_err(repo_err)?;
    Ok(BackchannelLogoutDelivery {
        id: parse_uuid(&id, "id")?,
        tenant_id: parse_uuid(&tenant_id, "tenant_id")?.into(),
        client_id: row.try_get("client_id").map_err(repo_err)?,
        target_uri: row.try_get("target_uri").map_err(repo_err)?,
        subject: row.try_get("subject").map_err(repo_err)?,
        sid: row.try_get("sid").map_err(repo_err)?,
        jti: parse_uuid(&jti, "jti")?,
        attempts: row.try_get("attempts").map_err(repo_err)?,
        next_attempt_at: to_utc(row.try_get("next_attempt_at").map_err(repo_err)?),
        last_error: row.try_get("last_error").map_err(repo_err)?,
        delivered_at: row
            .try_get::<Option<NaiveDateTime>, _>("delivered_at")
            .map_err(repo_err)?
            .map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

/// Column limit for `last_error` (`VARCHAR(1000)`). Anything beyond is truncated.
const LAST_ERROR_MAX_LEN: usize = 1_000;

fn truncate_error(error: &str) -> String {
    error.chars().take(LAST_ERROR_MAX_LEN).collect()
}

#[async_trait]
impl BackchannelLogoutDeliveryRepository for SqlxBackchannelLogoutDeliveryRepository {
    async fn enqueue(&self, deliveries: &[BackchannelLogoutDelivery]) -> Result<()> {
        if deliveries.is_empty() {
            return Ok(());
        }
        // One logout notifies multiple RPs. Push them in one statement rather than row by row
        // (it is within the synchronous part of the logout response, so don't add round trips).
        let placeholders = std::iter::repeat_n("(?, ?, ?, ?, ?, ?, ?, 0, ?)", deliveries.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "INSERT INTO backchannel_logout_deliveries \
             (id, tenant_id, client_id, target_uri, subject, sid, jti, attempts, next_attempt_at) \
             VALUES {placeholders}"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for d in deliveries {
            query = query
                .bind(d.id.to_string())
                .bind(d.tenant_id.to_string())
                .bind(&d.client_id)
                .bind(&d.target_uri)
                .bind(&d.subject)
                .bind(&d.sid)
                .bind(d.jti.to_string())
                .bind(d.next_attempt_at.naive_utc());
        }
        query.execute(&self.pool).await.map_err(repo_err)?;
        Ok(())
    }

    async fn claim_due(
        &self,
        now: DateTime<Utc>,
        max_attempts: i32,
        limit: u32,
    ) -> Result<Vec<BackchannelLogoutDelivery>> {
        // Read candidates, then claim them one by one with compare-and-swap. Since `attempts` is part of the condition,
        // even if two runners read the same row only one succeeds in updating, so there is no double delivery
        // (marking in bulk with an UPDATE with `ORDER BY ... LIMIT` risks the mark value colliding with other rows).
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM backchannel_logout_deliveries \
             WHERE delivered_at IS NULL AND next_attempt_at <= ? AND attempts < ? \
             ORDER BY next_attempt_at ASC LIMIT ?"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(now.naive_utc())
            .bind(max_attempts)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;

        // Push back the next attempt time of claimed rows so "others don't take them until the next attempt finishes".
        // The send result is overwritten by `mark_delivered` / `mark_failed`.
        let hold_until = now + crate::domain::backchannel_logout::retry_backoff(1);
        let mut claimed = Vec::new();
        for row in rows.iter() {
            let mut delivery = map_row(row)?;
            let updated = sqlx::query(
                "UPDATE backchannel_logout_deliveries \
                 SET attempts = attempts + 1, next_attempt_at = ? \
                 WHERE id = ? AND attempts = ? AND delivered_at IS NULL",
            )
            .bind(hold_until.naive_utc())
            .bind(delivery.id.to_string())
            .bind(delivery.attempts)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
            if updated.rows_affected() == 1 {
                delivery.attempts += 1;
                delivery.next_attempt_at = hold_until;
                claimed.push(delivery);
            }
        }
        Ok(claimed)
    }

    async fn mark_delivered(&self, id: Uuid, delivered_at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "UPDATE backchannel_logout_deliveries SET delivered_at = ?, last_error = NULL \
             WHERE id = ?",
        )
        .bind(delivered_at.naive_utc())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn mark_failed(
        &self,
        id: Uuid,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE backchannel_logout_deliveries SET next_attempt_at = ?, last_error = ? \
             WHERE id = ?",
        )
        .bind(next_attempt_at.naive_utc())
        .bind(truncate_error(error))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn purge_settled(&self, older_than: DateTime<Utc>, max_attempts: i32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM backchannel_logout_deliveries \
             WHERE updated_at < ? AND (delivered_at IS NOT NULL OR attempts >= ?)",
        )
        .bind(older_than.naive_utc())
        .bind(max_attempts)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `last_error` is truncated to the column length (persistence doesn't fail even if the RP returns a huge error).
    #[test]
    fn last_error_is_truncated_to_the_column_limit() {
        let long = "e".repeat(LAST_ERROR_MAX_LEN + 500);
        assert_eq!(truncate_error(&long).chars().count(), LAST_ERROR_MAX_LEN);
        assert_eq!(truncate_error("short"), "short");
    }
}
