//! `AuthorizationCodeRepository` の sqlx 実装。
//!
//! one-time 消費は `UPDATE ... WHERE used_at IS NULL AND expires_at > ?` の affected rows で
//! 原子的に判定する（設計仕様 §3.5。MariaDB 10.11 は UPDATE ... RETURNING 非対応のため、
//! 消費成功時のみ続けて SELECT する）。

use crate::domain::authorization_code::AuthorizationCode;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::AuthorizationCodeRepository;
use crate::domain::values::CodeChallengeMethod;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxAuthorizationCodeRepository {
    pool: Db,
}

impl SqlxAuthorizationCodeRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "code_hash, user_id, client_id, redirect_uri, scope, nonce, \
     auth_time, code_challenge, code_challenge_method, expires_at, used_at, \
     created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<AuthorizationCode> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    // MariaDB の JSON カラムは sqlx では BLOB として返るため、バイト列で受けて parse する。
    let scope: Vec<u8> = row.try_get("scope").map_err(repo_err)?;
    let ccm: String = row.try_get("code_challenge_method").map_err(repo_err)?;
    let used_at: Option<NaiveDateTime> = row.try_get("used_at").map_err(repo_err)?;
    Ok(AuthorizationCode {
        code_hash: row.try_get("code_hash").map_err(repo_err)?,
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        redirect_uri: row.try_get("redirect_uri").map_err(repo_err)?,
        scope: serde_json::from_slice(&scope)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `scope`: {e}")))?,
        nonce: row.try_get("nonce").map_err(repo_err)?,
        auth_time: to_utc(row.try_get("auth_time").map_err(repo_err)?),
        code_challenge: row.try_get("code_challenge").map_err(repo_err)?,
        code_challenge_method: CodeChallengeMethod::parse(&ccm)?,
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        used_at: used_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl AuthorizationCodeRepository for SqlxAuthorizationCodeRepository {
    async fn create(&self, code: &AuthorizationCode) -> Result<()> {
        sqlx::query(
            "INSERT INTO authorization_codes \
             (code_hash, user_id, client_id, redirect_uri, scope, nonce, auth_time, \
              code_challenge, code_challenge_method, expires_at, used_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&code.code_hash)
        .bind(code.user_id.to_string())
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(serde_json::to_string(&code.scope).map_err(repo_err)?)
        .bind(&code.nonce)
        .bind(code.auth_time.naive_utc())
        .bind(&code.code_challenge)
        .bind(code.code_challenge_method.as_str())
        .bind(code.expires_at.naive_utc())
        .bind(code.used_at.map(|d| d.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn consume(
        &self,
        code_hash: &str,
        used_at: DateTime<Utc>,
    ) -> Result<Option<AuthorizationCode>> {
        let result = sqlx::query(
            "UPDATE authorization_codes SET used_at = ? \
             WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?",
        )
        .bind(used_at.naive_utc())
        .bind(code_hash)
        .bind(used_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        let sql = format!("SELECT {SELECT_COLUMNS} FROM authorization_codes WHERE code_hash = ?");
        let row = sqlx::query(&sql)
            .bind(code_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }
}
