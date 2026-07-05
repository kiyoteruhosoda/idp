//! `AuthSessionRepository` の sqlx 実装。

use crate::domain::auth_session::AuthSession;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::AuthSessionRepository;
use crate::domain::values::CodeChallengeMethod;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxAuthSessionRepository {
    pool: Db,
}

impl SqlxAuthSessionRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, client_id, redirect_uri, scope, state, nonce, \
     code_challenge, code_challenge_method, authenticated_user_id, auth_time, \
     expires_at, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<AuthSession> {
    // MariaDB の JSON カラムは sqlx では BLOB として返るため、バイト列で受けて parse する。
    let scope: Vec<u8> = row.try_get("scope").map_err(repo_err)?;
    let ccm: String = row.try_get("code_challenge_method").map_err(repo_err)?;
    let user_id: Option<String> = row.try_get("authenticated_user_id").map_err(repo_err)?;
    let auth_time: Option<NaiveDateTime> = row.try_get("auth_time").map_err(repo_err)?;
    Ok(AuthSession {
        id: row.try_get("id").map_err(repo_err)?,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        redirect_uri: row.try_get("redirect_uri").map_err(repo_err)?,
        scope: serde_json::from_slice(&scope)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `scope`: {e}")))?,
        state: row.try_get("state").map_err(repo_err)?,
        nonce: row.try_get("nonce").map_err(repo_err)?,
        code_challenge: row.try_get("code_challenge").map_err(repo_err)?,
        code_challenge_method: CodeChallengeMethod::parse(&ccm)?,
        authenticated_user_id: user_id
            .map(|s| {
                Uuid::parse_str(&s)
                    .map_err(|e| DomainError::Repository(format!("invalid UUID `{s}`: {e}")))
            })
            .transpose()?,
        auth_time: auth_time.map(to_utc),
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl AuthSessionRepository for SqlxAuthSessionRepository {
    async fn create(&self, session: &AuthSession) -> Result<()> {
        sqlx::query(
            "INSERT INTO auth_sessions \
             (id, client_id, redirect_uri, scope, state, nonce, code_challenge, \
              code_challenge_method, authenticated_user_id, auth_time, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session.id)
        .bind(&session.client_id)
        .bind(&session.redirect_uri)
        .bind(serde_json::to_string(&session.scope).map_err(repo_err)?)
        .bind(&session.state)
        .bind(&session.nonce)
        .bind(&session.code_challenge)
        .bind(session.code_challenge_method.as_str())
        .bind(session.authenticated_user_id.map(|u| u.to_string()))
        .bind(session.auth_time.map(|d| d.naive_utc()))
        .bind(session.expires_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<AuthSession>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM auth_sessions WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn set_authenticated_user(
        &self,
        id: &str,
        user_id: Uuid,
        auth_time: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE auth_sessions SET authenticated_user_id = ?, auth_time = ? WHERE id = ?",
        )
        .bind(user_id.to_string())
        .bind(auth_time.naive_utc())
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM auth_sessions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
