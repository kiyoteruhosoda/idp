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

    async fn insert_if_no_active(&self, key: &SigningKey) -> Result<bool> {
        // MariaDB の advisory lock（GET_LOCK）で「存在確認 → 挿入」を直列化する（SEC5）。
        // GET_LOCK は接続スコープのため、確認・挿入・解放まで同一接続で行う。
        // 接続が切れた場合はサーバ側でロックが自動解放される。
        let mut conn = self.pool.acquire().await.map_err(repo_err)?;
        let locked: i64 = sqlx::query_scalar("SELECT GET_LOCK('idp.signing_key_bootstrap', 10)")
            .fetch_one(&mut *conn)
            .await
            .map_err(repo_err)?;
        if locked != 1 {
            return Err(DomainError::Repository(
                "failed to acquire signing key bootstrap lock".to_string(),
            ));
        }
        // ロック保持中に再確認 → 無ければ挿入。エラーでも必ず RELEASE_LOCK を試みる。
        let result: Result<bool> = async {
            let active: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM signing_keys WHERE status = 'ACTIVE' LIMIT 1")
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(repo_err)?;
            if active.is_some() {
                return Ok(false);
            }
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
            .execute(&mut *conn)
            .await
            .map_err(repo_err)?;
            Ok(true)
        }
        .await;
        let release = sqlx::query("SELECT RELEASE_LOCK('idp.signing_key_bootstrap')")
            .execute(&mut *conn)
            .await;
        if let Err(e) = release {
            tracing::warn!(error = %e, "failed to release signing key bootstrap lock (released on disconnect)");
        }
        result
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
        // ACTIVE + RETIRED のうち not_after が未来のものだけを公開する（期限切れ RETIRED は非公開）。
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM signing_keys \
             WHERE status IN ('ACTIVE', 'RETIRED') AND not_after > UTC_TIMESTAMP(6) \
             ORDER BY created_at DESC"
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

    async fn list_all(&self) -> Result<Vec<SigningKey>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM signing_keys ORDER BY created_at DESC");
        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn update_status(&self, kid: &str, status: SigningKeyStatus) -> Result<()> {
        let result = sqlx::query(
            "UPDATE signing_keys SET status = ?, updated_at = UTC_TIMESTAMP(6) WHERE kid = ?",
        )
        .bind(status.as_str())
        .bind(kid)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    async fn delete(&self, kid: &str) -> Result<()> {
        sqlx::query("DELETE FROM signing_keys WHERE kid = ?")
            .bind(kid)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
