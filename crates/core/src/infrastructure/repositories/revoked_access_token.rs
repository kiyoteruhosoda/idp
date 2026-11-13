//! sqlx implementation of `RevokedAccessTokenRepository` (F5: token management).

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::RevokedAccessTokenRepository;
use crate::domain::revoked_access_token::RevokedAccessToken;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{NaiveDateTime, TimeZone, Utc};

pub struct SqlxRevokedAccessTokenRepository {
    pool: Db,
}

impl SqlxRevokedAccessTokenRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    /// Used by the expired-row cleanup (the `ExpiringRecordStore` impl in `expired_records`).
    pub(super) fn pool(&self) -> &Db {
        &self.pool
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl RevokedAccessTokenRepository for SqlxRevokedAccessTokenRepository {
    async fn revoke(&self, token: &RevokedAccessToken) -> Result<()> {
        // INSERT IGNORE: an existing jti is ignored idempotently.
        sqlx::query(
            "INSERT IGNORE INTO revoked_access_tokens (jti, revoked_at, expires_at) \
             VALUES (?, ?, ?)",
        )
        .bind(&token.jti)
        .bind(token.revoked_at.naive_utc())
        .bind(token.expires_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn is_revoked(&self, jti: &str) -> Result<bool> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM revoked_access_tokens WHERE jti = ? LIMIT 1")
                .bind(jti)
                .fetch_one(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(row.0 > 0)
    }
}

#[allow(dead_code)]
fn to_utc(naive: NaiveDateTime) -> chrono::DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}
