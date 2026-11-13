//! sqlx implementation of `TotpSecretRepository`.
//!
//! # Where the secret lives
//!
//! The shared key lives only in **the authenticator registry** (`user_authenticators.secret_encrypted`) (AP11b;
//! the original table `user_totp_secrets` was dropped in migration 0038).
//!
//! The target is "non-revoked TOTP rows". Re-registering makes the old row `revoked`, so
//! looking at revoked rows too would **let authentication pass with a shared key that should have been revoked**.
//!
//! The trait (DIP boundary) did not change across the migration. Which table holds the secret is an infrastructure
//! concern; callers (login, step-up, registration) need not know.

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TotpSecretRepository;
use crate::domain::totp_secret::TotpSecret;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxTotpSecretRepository {
    pool: Db,
}

impl SqlxTotpSecretRepository {
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

fn map_row(row: &MySqlRow) -> Result<TotpSecret> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let confirmed_at: Option<NaiveDateTime> = row.try_get("confirmed_at").map_err(repo_err)?;
    Ok(TotpSecret {
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID: {e}")))?,
        secret_encrypted: row.try_get("secret_encrypted").map_err(repo_err)?,
        confirmed_at: confirmed_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl TotpSecretRepository for SqlxTotpSecretRepository {
    /// Puts the shared key on the registry row.
    ///
    /// The row itself is created first by `AuthenticatorManagementService::register_totp_pending`.
    /// **Fails if not a single row was updated** -- now that the registry is the only place for the secret,
    /// silently doing nothing would create users who "registered but are not set up".
    async fn upsert(&self, secret: &TotpSecret) -> Result<()> {
        let result = sqlx::query(
            "UPDATE user_authenticators \
             SET secret_encrypted = ?, confirmed_at = COALESCE(confirmed_at, ?) \
             WHERE user_id = ? AND authenticator_type = 'totp' AND status <> 'revoked'",
        )
        .bind(&secret.secret_encrypted)
        .bind(secret.confirmed_at.map(|d| d.naive_utc()))
        .bind(secret.user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::Repository(
                "no active totp authenticator row to store the shared secret on".to_string(),
            ));
        }
        Ok(())
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TotpSecret>> {
        let row = sqlx::query(
            "SELECT user_id, secret_encrypted, confirmed_at, created_at, updated_at \
             FROM user_authenticators \
             WHERE user_id = ? AND authenticator_type = 'totp' AND status <> 'revoked' \
               AND secret_encrypted IS NOT NULL \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    /// Records the confirmation time. The `status` transition (`pending` -> `active`) is done by
    /// `AuthenticatorManagementService::activate_totp`.
    async fn confirm(&self, user_id: Uuid, confirmed_at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "UPDATE user_authenticators SET confirmed_at = ? \
             WHERE user_id = ? AND authenticator_type = 'totp' AND status <> 'revoked' \
               AND confirmed_at IS NULL",
        )
        .bind(confirmed_at.naive_utc())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    /// Clears the shared key. **The row is kept** (revocation is expressed by `AuthenticatorManagementService::revoke_totp`
    /// via `status`). Forgetting to clear it would leave a shared key that should have been revoked in the DB.
    async fn delete(&self, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE user_authenticators SET secret_encrypted = NULL \
             WHERE user_id = ? AND authenticator_type = 'totp'",
        )
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    /// Records an accepted time-step. Updates **only if newer than the recorded one**, returning `true` if updated.
    ///
    /// Including `totp_last_used_step < ?` in the WHERE makes the check and the write one atomic statement.
    /// Of 2 requests racing with the same code (same step), only the one that UPDATEs first gets
    /// `rows_affected == 1`; the other gets `0` (= replay). NULL (not recorded) is treated as -1
    /// via `COALESCE`, so the first one can always be recorded.
    async fn record_totp_step_if_newer(
        &self,
        user_id: Uuid,
        step: i64,
        at: DateTime<Utc>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE user_authenticators \
             SET totp_last_used_step = ?, last_used_at = ? \
             WHERE user_id = ? AND authenticator_type = 'totp' AND status <> 'revoked' \
               AND COALESCE(totp_last_used_step, -1) < ?",
        )
        .bind(step)
        .bind(at.naive_utc())
        .bind(user_id.to_string())
        .bind(step)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }
}
