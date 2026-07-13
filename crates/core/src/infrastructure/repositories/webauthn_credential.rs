//! `WebAuthnCredentialRepository` の sqlx 実装。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::WebAuthnCredentialRepository;
use crate::domain::webauthn_credential::WebAuthnCredential;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxWebAuthnCredentialRepository {
    pool: Db,
}

impl SqlxWebAuthnCredentialRepository {
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

fn map_row(row: &MySqlRow) -> Result<WebAuthnCredential> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let last_used_at: Option<NaiveDateTime> = row.try_get("last_used_at").map_err(repo_err)?;
    Ok(WebAuthnCredential {
        id: Uuid::parse_str(&id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))?,
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))?,
        credential_id: row.try_get("credential_id").map_err(repo_err)?,
        passkey_json: row.try_get("passkey_json").map_err(repo_err)?,
        name: row.try_get("name").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        last_used_at: last_used_at.map(to_utc),
    })
}

#[async_trait]
impl WebAuthnCredentialRepository for SqlxWebAuthnCredentialRepository {
    async fn create(&self, cred: &WebAuthnCredential) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_webauthn_credentials \
             (id, user_id, credential_id, passkey_json, name, created_at, last_used_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(cred.id.to_string())
        .bind(cred.user_id.to_string())
        .bind(&cred.credential_id)
        .bind(&cred.passkey_json)
        .bind(&cred.name)
        .bind(cred.created_at.naive_utc())
        .bind(cred.last_used_at.map(|d| d.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<WebAuthnCredential>> {
        let row = sqlx::query(
            "SELECT id, user_id, credential_id, passkey_json, name, created_at, last_used_at \
             FROM user_webauthn_credentials WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebAuthnCredential>> {
        let row = sqlx::query(
            "SELECT id, user_id, credential_id, passkey_json, name, created_at, last_used_at \
             FROM user_webauthn_credentials WHERE credential_id = ?",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_by_user_id(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>> {
        let rows = sqlx::query(
            "SELECT id, user_id, credential_id, passkey_json, name, created_at, last_used_at \
             FROM user_webauthn_credentials WHERE user_id = ? ORDER BY created_at ASC",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn update_passkey(
        &self,
        id: Uuid,
        passkey_json: &str,
        last_used_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE user_webauthn_credentials \
             SET passkey_json = ?, last_used_at = ? WHERE id = ?",
        )
        .bind(passkey_json)
        .bind(last_used_at.naive_utc())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM user_webauthn_credentials WHERE id = ? AND user_id = ?")
            .bind(id.to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
