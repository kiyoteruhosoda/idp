//! `RefreshTokenRepository` の sqlx 実装（設計仕様 §9.1）。

use crate::domain::error::{DomainError, Result};
use crate::domain::refresh_token::RefreshToken;
use crate::domain::repositories::RefreshTokenRepository;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxRefreshTokenRepository {
    pool: Db,
}

impl SqlxRefreshTokenRepository {
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

fn map_row(row: &MySqlRow) -> Result<RefreshToken> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let scope: Vec<u8> = row.try_get("scope").map_err(repo_err)?;
    let revoked_at: Option<NaiveDateTime> = row.try_get("revoked_at").map_err(repo_err)?;
    Ok(RefreshToken {
        token_hash: row.try_get("token_hash").map_err(repo_err)?,
        parent_hash: row.try_get("parent_hash").map_err(repo_err)?,
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        scope: serde_json::from_slice(&scope)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `scope`: {e}")))?,
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        revoked_at: revoked_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl RefreshTokenRepository for SqlxRefreshTokenRepository {
    async fn create(&self, token: &RefreshToken) -> Result<()> {
        sqlx::query(
            "INSERT INTO refresh_tokens \
             (token_hash, parent_hash, user_id, client_id, scope, expires_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.token_hash)
        .bind(&token.parent_hash)
        .bind(token.user_id.to_string())
        .bind(&token.client_id)
        .bind(serde_json::to_string(&token.scope).map_err(repo_err)?)
        .bind(token.expires_at.naive_utc())
        .bind(token.revoked_at.map(|d| d.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<RefreshToken>> {
        let row = sqlx::query(
            "SELECT token_hash, parent_hash, user_id, client_id, scope, \
             expires_at, revoked_at, created_at \
             FROM refresh_tokens WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn revoke(&self, token_hash: &str, revoked_at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? \
             WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(revoked_at.naive_utc())
        .bind(token_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn exists_by_parent_hash(&self, parent_hash: &str) -> Result<bool> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM refresh_tokens WHERE parent_hash = ? LIMIT 1",
        )
        .bind(parent_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(row.0 > 0)
    }

    async fn revoke_all_for_user(&self, user_id: Uuid, revoked_at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = ? \
             WHERE user_id = ? AND revoked_at IS NULL",
        )
        .bind(revoked_at.naive_utc())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }
}
