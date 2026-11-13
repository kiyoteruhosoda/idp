//! sqlx implementation of `WebAuthnCredentialRepository`.
//!
//! # Where the secret lives
//!
//! Public keys and signature counters (the whole `passkey_json`) live only in **the authenticator registry**
//! (`user_authenticators.secret_encrypted`) (AP11b; the original table
//! `user_webauthn_credentials` was dropped in migration 0038).
//!
//! **One passkey = one registry row**. `WebAuthnCredential::id` is the registry row id, and
//! the ambiguity during the migration of "original table id or registry id" is gone
//! (`credential_ref` was also dropped in 0038).
//!
//! This repository creates the rows, and
//! [`crate::application::authenticator_management`] moves the state (`status`). If the side holding the secret did not create the row,
//! there would be a moment of "the row exists but has no key".

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

/// Aliases aligning registry columns to the vocabulary of `WebAuthnCredential`.
const COLUMNS: &str = "id, user_id, credential_id, secret_encrypted AS passkey_json, \
     label AS name, created_at, last_used_at";

/// Condition narrowing to "usable passkey rows". Revoked rows and rows without a key are ignored.
const USABLE: &str =
    "authenticator_type = 'webauthn' AND status <> 'revoked' AND secret_encrypted IS NOT NULL";

#[async_trait]
impl WebAuthnCredentialRepository for SqlxWebAuthnCredentialRepository {
    /// Creates a passkey row in the registry. **It is usable from the moment of registration**, so it is created `active` with
    /// `confirmed_at` (WebAuthn registration has already verified the attestation, with no confirmation step like TOTP).
    async fn create(&self, cred: &WebAuthnCredential) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_authenticators \
             (id, user_id, authenticator_type, status, label, secret_encrypted, credential_id, \
              confirmed_at, last_used_at, created_at) \
             VALUES (?, ?, 'webauthn', 'active', ?, ?, ?, ?, ?, ?)",
        )
        .bind(cred.id.to_string())
        .bind(cred.user_id.to_string())
        .bind(&cred.name)
        .bind(&cred.passkey_json)
        .bind(&cred.credential_id)
        .bind(cred.created_at.naive_utc())
        .bind(cred.last_used_at.map(|d| d.naive_utc()))
        .bind(cred.created_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // Unique constraint on credential ID. Hit when trying to register the same authenticator twice.
            if matches!(&e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23000")) {
                DomainError::Conflict("credential is already registered".to_string())
            } else {
                repo_err(e)
            }
        })?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<WebAuthnCredential>> {
        let sql =
            format!("SELECT {COLUMNS} FROM user_authenticators WHERE id = ? AND {USABLE} LIMIT 1");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
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
        let sql = format!(
            "SELECT {COLUMNS} FROM user_authenticators \
             WHERE credential_id = ? AND {USABLE} LIMIT 1"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_by_user_id(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>> {
        let sql = format!(
            "SELECT {COLUMNS} FROM user_authenticators \
             WHERE user_id = ? AND {USABLE} ORDER BY created_at ASC"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    /// Advances the signature counter. **It must always advance** (otherwise clone detection doesn't work).
    async fn update_passkey(
        &self,
        id: Uuid,
        passkey_json: &str,
        last_used_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = ?, last_used_at = ? \
             WHERE id = ? AND authenticator_type = 'webauthn'",
        )
        .bind(passkey_json)
        .bind(last_used_at.naive_utc())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    /// Removes one passkey. **The row is kept** (revocation is expressed by
    /// `AuthenticatorManagementService::revoke_webauthn` via `status`). The credential ID is
    /// also cleared: otherwise the deleted passkey keeps matching reverse lookups.
    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = NULL, credential_id = NULL \
             WHERE id = ? AND user_id = ? AND authenticator_type = 'webauthn'",
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    /// MFA reset by an admin (MT21). Leftovers would make recovery fail, so all keys are dropped together.
    /// Returns **the number removed** (shown by the caller).
    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = NULL, credential_id = NULL \
             WHERE user_id = ? AND authenticator_type = 'webauthn' \
               AND secret_encrypted IS NOT NULL",
        )
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}
