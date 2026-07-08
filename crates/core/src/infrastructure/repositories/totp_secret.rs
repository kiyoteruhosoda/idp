//! `TotpSecretRepository` の sqlx 実装。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TotpSecretRepository;
use crate::domain::totp_secret::TotpSecret;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxTotpSecretRepository {
    pool: Db,
}

impl SqlxTotpSecretRepository {
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

fn map_row(row: &MySqlRow) -> Result<TotpSecret> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let confirmed_at: Option<NaiveDateTime> = row.try_get("confirmed_at").map_err(repo_err)?;
    Ok(TotpSecret {
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))?,
        secret_encrypted: row.try_get("secret_encrypted").map_err(repo_err)?,
        confirmed_at: confirmed_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl TotpSecretRepository for SqlxTotpSecretRepository {
    async fn upsert(&self, secret: &TotpSecret) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_totp_secrets (user_id, secret_encrypted, confirmed_at) \
             VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE secret_encrypted = VALUES(secret_encrypted), \
                                     confirmed_at = VALUES(confirmed_at)",
        )
        .bind(secret.user_id.to_string())
        .bind(&secret.secret_encrypted)
        .bind(secret.confirmed_at.map(|d| d.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TotpSecret>> {
        let row = sqlx::query(
            "SELECT user_id, secret_encrypted, confirmed_at, created_at, updated_at \
             FROM user_totp_secrets WHERE user_id = ?",
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn confirm(&self, user_id: Uuid, confirmed_at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "UPDATE user_totp_secrets SET confirmed_at = ? WHERE user_id = ? AND confirmed_at IS NULL",
        )
        .bind(confirmed_at.naive_utc())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM user_totp_secrets WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
