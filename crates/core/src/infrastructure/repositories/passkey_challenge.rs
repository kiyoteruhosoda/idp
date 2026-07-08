//! `PasskeyChallengeRepository` の sqlx 実装。

use crate::domain::error::{DomainError, Result};
use crate::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use crate::domain::repositories::PasskeyChallengeRepository;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxPasskeyChallengeRepository {
    pool: Db,
}

impl SqlxPasskeyChallengeRepository {
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

fn map_row(row: &MySqlRow) -> Result<PasskeyChallenge> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let user_id_str: Option<String> = row.try_get("user_id").map_err(repo_err)?;
    let challenge_type_str: String = row.try_get("challenge_type").map_err(repo_err)?;
    let challenge_type = challenge_type_str
        .parse::<PasskeyChallengeType>()
        .map_err(|e| DomainError::Repository(e))?;
    let user_id = user_id_str
        .map(|s| {
            Uuid::parse_str(&s)
                .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))
        })
        .transpose()?;
    Ok(PasskeyChallenge {
        id: Uuid::parse_str(&id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))?,
        user_id,
        challenge_type,
        state_json: row.try_get("state_json").map_err(repo_err)?,
        auth_session_id: row.try_get("auth_session_id").map_err(repo_err)?,
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl PasskeyChallengeRepository for SqlxPasskeyChallengeRepository {
    async fn create(&self, challenge: &PasskeyChallenge) -> Result<()> {
        sqlx::query(
            "INSERT INTO passkey_challenges \
             (id, user_id, challenge_type, state_json, auth_session_id, expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(challenge.id.to_string())
        .bind(challenge.user_id.map(|u| u.to_string()))
        .bind(challenge.challenge_type.as_str())
        .bind(&challenge.state_json)
        .bind(&challenge.auth_session_id)
        .bind(challenge.expires_at.naive_utc())
        .bind(challenge.created_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<PasskeyChallenge>> {
        let row = sqlx::query(
            "SELECT id, user_id, challenge_type, state_json, auth_session_id, expires_at, created_at \
             FROM passkey_challenges WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM passkey_challenges WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<()> {
        sqlx::query("DELETE FROM passkey_challenges WHERE expires_at <= ?")
            .bind(now.naive_utc())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
