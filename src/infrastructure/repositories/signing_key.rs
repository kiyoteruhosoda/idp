//! `SigningKeyRepository` の sqlx 実装。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SigningKeyRepository;
use crate::domain::signing_key::SigningKey;
use crate::domain::values::SigningKeyStatus;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;

pub struct SqlxSigningKeyRepository {
    pool: Db,
}

impl SqlxSigningKeyRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "kid, algorithm, public_key, private_key_encrypted, status, \
     not_before, not_after, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<SigningKey> {
    let status: String = row.try_get("status").map_err(repo_err)?;
    Ok(SigningKey {
        kid: row.try_get("kid").map_err(repo_err)?,
        algorithm: row.try_get("algorithm").map_err(repo_err)?,
        public_key: row.try_get("public_key").map_err(repo_err)?,
        private_key_encrypted: row.try_get("private_key_encrypted").map_err(repo_err)?,
        status: SigningKeyStatus::parse(&status)?,
        not_before: to_utc(row.try_get("not_before").map_err(repo_err)?),
        not_after: to_utc(row.try_get("not_after").map_err(repo_err)?),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl SigningKeyRepository for SqlxSigningKeyRepository {
    async fn insert(&self, key: &SigningKey) -> Result<()> {
        sqlx::query(
            "INSERT INTO signing_keys \
             (kid, algorithm, public_key, private_key_encrypted, status, not_before, not_after) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&key.kid)
        .bind(&key.algorithm)
        .bind(&key.public_key)
        .bind(&key.private_key_encrypted)
        .bind(key.status.as_str())
        .bind(key.not_before.naive_utc())
        .bind(key.not_after.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_active(&self) -> Result<Option<SigningKey>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM signing_keys \
             WHERE status = 'ACTIVE' AND not_before <= UTC_TIMESTAMP(6) AND not_after > UTC_TIMESTAMP(6) \
             ORDER BY not_before DESC LIMIT 1"
        );
        let row = sqlx::query(&sql)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_published(&self) -> Result<Vec<SigningKey>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM signing_keys \
             WHERE status IN ('ACTIVE', 'RETIRED') ORDER BY created_at DESC"
        );
        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn find_by_kid(&self, kid: &str) -> Result<Option<SigningKey>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM signing_keys WHERE kid = ?");
        let row = sqlx::query(&sql)
            .bind(kid)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }
}
