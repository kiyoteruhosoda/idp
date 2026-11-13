//! sqlx implementation of `PasswordResetTokenRepository` (MT18).
//!
//! Consumption is done in two steps, "UPDATE (unused and unexpired only) -> SELECT", and `rows_affected == 0`
//! is treated as used, expired or nonexistent (the same one-time pattern as authorization codes).

use crate::domain::error::{DomainError, Result};
use crate::domain::password_reset::{PasswordResetToken, ResetPurpose};
use crate::domain::repositories::PasswordResetTokenRepository;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxPasswordResetTokenRepository {
    pool: Db,
}

impl SqlxPasswordResetTokenRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    /// Used by expired-row cleanup (the `ExpiringRecordStore` implementation in `expired_records`).
    pub(super) fn pool(&self) -> &Db {
        &self.pool
    }
}

const SELECT_COLUMNS: &str = "token_hash, user_id, purpose, expires_at, used_at, created_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<PasswordResetToken> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let used_at: Option<NaiveDateTime> = row.try_get("used_at").map_err(repo_err)?;
    let purpose: String = row.try_get("purpose").map_err(repo_err)?;
    Ok(PasswordResetToken {
        token_hash: row.try_get("token_hash").map_err(repo_err)?,
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        // ⚠ Don't round unknown purposes to a default (rounding would silently allow operations permitted only for that purpose).
        purpose: ResetPurpose::parse(&purpose).ok_or_else(|| {
            DomainError::Repository(format!("unknown password reset purpose `{purpose}`"))
        })?,
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        used_at: used_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl PasswordResetTokenRepository for SqlxPasswordResetTokenRepository {
    async fn create(&self, token: &PasswordResetToken) -> Result<()> {
        sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_id, purpose, expires_at, used_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&token.token_hash)
        .bind(token.user_id.to_string())
        .bind(token.purpose.as_str())
        .bind(token.expires_at.naive_utc())
        .bind(token.used_at.map(|t| t.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn consume(
        &self,
        token_hash: &str,
        used_at: DateTime<Utc>,
    ) -> Result<Option<PasswordResetToken>> {
        let result = sqlx::query(
            "UPDATE password_reset_tokens SET used_at = ? \
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        )
        .bind(used_at.naive_utc())
        .bind(token_hash)
        .bind(used_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        let sql =
            format!("SELECT {SELECT_COLUMNS} FROM password_reset_tokens WHERE token_hash = ?");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    /// Looks up without consuming (unused and unexpired only). Used by the screen opened from the link to show its contents.
    async fn find_active(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<PasswordResetToken>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM password_reset_tokens \
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(token_hash)
            .bind(now.naive_utc())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn invalidate_all_for_user(&self, user_id: Uuid, now: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL",
        )
        .bind(now.naive_utc())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }
}
