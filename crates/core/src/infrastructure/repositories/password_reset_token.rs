//! `PasswordResetTokenRepository` の sqlx 実装（MT18）。
//!
//! 消費は「UPDATE（未使用・期限内のみ）→ SELECT」の 2 段で行い、`rows_affected == 0` を
//! 使用済み・期限切れ・不存在として扱う（authorization code と同じ one-time パターン）。

use crate::domain::error::{DomainError, Result};
use crate::domain::password_reset::PasswordResetToken;
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
}

const SELECT_COLUMNS: &str = "token_hash, user_id, expires_at, used_at, created_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<PasswordResetToken> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let used_at: Option<NaiveDateTime> = row.try_get("used_at").map_err(repo_err)?;
    Ok(PasswordResetToken {
        token_hash: row.try_get("token_hash").map_err(repo_err)?,
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        used_at: used_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl PasswordResetTokenRepository for SqlxPasswordResetTokenRepository {
    async fn create(&self, token: &PasswordResetToken) -> Result<()> {
        sqlx::query(
            "INSERT INTO password_reset_tokens (token_hash, user_id, expires_at, used_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&token.token_hash)
        .bind(token.user_id.to_string())
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

        let sql = format!("SELECT {SELECT_COLUMNS} FROM password_reset_tokens WHERE token_hash = ?");
        let row = sqlx::query(&sql)
            .bind(token_hash)
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
