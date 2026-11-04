//! `SessionKeyBindingRepository` の sqlx 実装（task #887。ADR-0074）。置き場は `sso_session_contexts`。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SessionKeyBindingRepository;
use crate::domain::session_key::{SessionKeyAlgorithm, SessionKeyBinding, SessionPublicKey};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::Row;

pub struct SqlxSessionKeyBindingRepository {
    pool: Db,
}

impl SqlxSessionKeyBindingRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl SessionKeyBindingRepository for SqlxSessionKeyBindingRepository {
    async fn find(&self, session_hash: &str) -> Result<Option<SessionKeyBinding>> {
        let row = sqlx::query(
            "SELECT key_session_identifier, key_algorithm, key_public_jwk, key_thumbprint, \
             key_bound_at FROM sso_session_contexts \
             WHERE session_hash = ? AND key_bound_at IS NOT NULL",
        )
        .bind(session_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let algorithm: String = row.try_get("key_algorithm").map_err(repo_err)?;
        let algorithm = SessionKeyAlgorithm::parse(&algorithm).ok_or_else(|| {
            DomainError::Repository(format!("unknown key algorithm `{algorithm}`"))
        })?;
        let bound_at: NaiveDateTime = row.try_get("key_bound_at").map_err(repo_err)?;
        Ok(Some(SessionKeyBinding {
            session_identifier: row.try_get("key_session_identifier").map_err(repo_err)?,
            key: SessionPublicKey {
                algorithm,
                jwk_json: row.try_get("key_public_jwk").map_err(repo_err)?,
                thumbprint: row.try_get("key_thumbprint").map_err(repo_err)?,
            },
            bound_at: Utc.from_utc_datetime(&bound_at),
        }))
    }

    async fn bind(&self, session_hash: &str, binding: &SessionKeyBinding) -> Result<bool> {
        // 行が無ければ作る（端末の印の無いブラウザでは、ログインのときに行ができていない）。
        sqlx::query("INSERT IGNORE INTO sso_session_contexts (session_hash) VALUES (?)")
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        // ⚠ 既に結び付いた行は書き換えない（盗んだ Cookie で別の鍵へ結び直させない）。
        let updated = sqlx::query(
            "UPDATE sso_session_contexts SET key_session_identifier = ?, key_algorithm = ?, \
             key_public_jwk = ?, key_thumbprint = ?, key_bound_at = ?, key_refreshed_at = ? \
             WHERE session_hash = ? AND key_bound_at IS NULL",
        )
        .bind(&binding.session_identifier)
        .bind(binding.key.algorithm.as_str())
        .bind(&binding.key.jwk_json)
        .bind(&binding.key.thumbprint)
        .bind(binding.bound_at.naive_utc())
        .bind(binding.bound_at.naive_utc())
        .bind(session_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(updated.rows_affected() > 0)
    }

    async fn record_refresh(&self, session_hash: &str, at: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE sso_session_contexts SET key_refreshed_at = ? WHERE session_hash = ?")
            .bind(at.naive_utc())
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
