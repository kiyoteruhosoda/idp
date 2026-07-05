//! `SsoSessionRepository` の sqlx 実装。DB には `session_hash = SHA-256(session_id)` のみ保存する。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SsoSessionRepository;
use crate::domain::sso_session::SsoSession;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxSsoSessionRepository {
    pool: Db,
}

impl SqlxSsoSessionRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "session_hash, user_id, auth_time, idle_expires_at, \
     absolute_expires_at, user_agent, ip_address, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<SsoSession> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    Ok(SsoSession {
        session_hash: row.try_get("session_hash").map_err(repo_err)?,
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        auth_time: to_utc(row.try_get("auth_time").map_err(repo_err)?),
        idle_expires_at: to_utc(row.try_get("idle_expires_at").map_err(repo_err)?),
        absolute_expires_at: to_utc(row.try_get("absolute_expires_at").map_err(repo_err)?),
        user_agent: row.try_get("user_agent").map_err(repo_err)?,
        ip_address: row.try_get("ip_address").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl SsoSessionRepository for SqlxSsoSessionRepository {
    async fn create(&self, session: &SsoSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO sso_sessions \
             (session_hash, user_id, auth_time, idle_expires_at, absolute_expires_at, \
              user_agent, ip_address) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session.session_hash)
        .bind(session.user_id.to_string())
        .bind(session.auth_time.naive_utc())
        .bind(session.idle_expires_at.naive_utc())
        .bind(session.absolute_expires_at.naive_utc())
        .bind(&session.user_agent)
        .bind(&session.ip_address)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_hash(&self, session_hash: &str) -> Result<Option<SsoSession>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM sso_sessions WHERE session_hash = ?");
        let row = sqlx::query(&sql)
            .bind(session_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn extend_idle(&self, session_hash: &str, idle_expires_at: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE sso_sessions SET idle_expires_at = ? WHERE session_hash = ?")
            .bind(idle_expires_at.naive_utc())
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, session_hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM sso_sessions WHERE session_hash = ?")
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
