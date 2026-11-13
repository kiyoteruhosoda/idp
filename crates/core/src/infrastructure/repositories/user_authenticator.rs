//! sqlx implementation of `UserAuthenticatorRepository` (AP9).

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::UserAuthenticatorRepository;
use crate::domain::user_authenticator::{
    AuthenticatorStatus, AuthenticatorType, UserAuthenticator, OTP_SEND_WINDOW_SECS,
};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxUserAuthenticatorRepository {
    pool: Db,
}

impl SqlxUserAuthenticatorRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, user_id, authenticator_type, status, label, secret_encrypted, \
     target, confirmed_at, last_used_at, expires_at, revoked_at, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(value: &str, column: &str) -> Result<Uuid> {
    Uuid::parse_str(value)
        .map_err(|e| DomainError::Repository(format!("invalid UUID in `{column}`: {e}")))
}

fn opt_time(row: &MySqlRow, column: &str) -> Result<Option<DateTime<Utc>>> {
    Ok(row
        .try_get::<Option<NaiveDateTime>, _>(column)
        .map_err(repo_err)?
        .map(to_utc))
}

fn map_row(row: &MySqlRow) -> Result<UserAuthenticator> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let authenticator_type: String = row.try_get("authenticator_type").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    Ok(UserAuthenticator {
        id: parse_uuid(&id, "id")?,
        user_id: parse_uuid(&user_id, "user_id")?,
        authenticator_type: AuthenticatorType::parse(&authenticator_type)?,
        status: AuthenticatorStatus::parse(&status)?,
        label: row.try_get("label").map_err(repo_err)?,
        secret_encrypted: row.try_get("secret_encrypted").map_err(repo_err)?,
        target: row.try_get("target").map_err(repo_err)?,
        confirmed_at: opt_time(row, "confirmed_at")?,
        last_used_at: opt_time(row, "last_used_at")?,
        expires_at: opt_time(row, "expires_at")?,
        revoked_at: opt_time(row, "revoked_at")?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl UserAuthenticatorRepository for SqlxUserAuthenticatorRepository {
    async fn create(&self, authenticator: &UserAuthenticator) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_authenticators \
             (id, user_id, authenticator_type, status, label, secret_encrypted, \
              target, confirmed_at, last_used_at, expires_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(authenticator.id.to_string())
        .bind(authenticator.user_id.to_string())
        .bind(authenticator.authenticator_type.as_str())
        .bind(authenticator.status.as_str())
        .bind(&authenticator.label)
        .bind(&authenticator.secret_encrypted)
        .bind(&authenticator.target)
        .bind(authenticator.confirmed_at.map(|t| t.naive_utc()))
        .bind(authenticator.last_used_at.map(|t| t.naive_utc()))
        .bind(authenticator.expires_at.map(|t| t.naive_utc()))
        .bind(authenticator.revoked_at.map(|t| t.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // Registering the same WebAuthn credential ID twice is rejected by the unique constraint.
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation())
            {
                DomainError::Conflict("authenticator already registered".to_string())
            } else {
                repo_err(e)
            }
        })?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<UserAuthenticator>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM user_authenticators WHERE id = ?");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<UserAuthenticator>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_authenticators WHERE user_id = ? \
             ORDER BY created_at DESC"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn list_usable_for_user(
        &self,
        user_id: Uuid,
        authenticator_type: Option<AuthenticatorType>,
        now: DateTime<Utc>,
    ) -> Result<Vec<UserAuthenticator>> {
        // Type filtering is split by presence of the clause, not by value (`? IS NULL OR type = ?` can't use the index).
        let type_clause = if authenticator_type.is_some() {
            " AND authenticator_type = ?"
        } else {
            ""
        };
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_authenticators \
             WHERE user_id = ? AND status = 'active' \
               AND (expires_at IS NULL OR expires_at > ?){type_clause} \
             ORDER BY created_at DESC"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(user_id.to_string())
            .bind(now.naive_utc());
        if let Some(t) = authenticator_type {
            query = query.bind(t.as_str());
        }
        let rows = query.fetch_all(&self.pool).await.map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn update_status(
        &self,
        id: Uuid,
        user_id: Uuid,
        status: AuthenticatorStatus,
        at: DateTime<Utc>,
    ) -> Result<bool> {
        // Including `user_id` in the condition is the owner check (bringing in someone else's authenticator id changes nothing).
        let revoked_at = (status == AuthenticatorStatus::Revoked).then(|| at.naive_utc());
        let confirmed_clause = if status == AuthenticatorStatus::Active {
            // Set the confirmation time only on rows activated from unconfirmed (pending) (not overwritten on resume).
            ", confirmed_at = COALESCE(confirmed_at, ?)"
        } else {
            ""
        };
        let sql = format!(
            "UPDATE user_authenticators SET status = ?, revoked_at = ?{confirmed_clause} \
             WHERE id = ? AND user_id = ?"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(status.as_str())
            .bind(revoked_at);
        if status == AuthenticatorStatus::Active {
            query = query.bind(at.naive_utc());
        }
        let result = query
            .bind(id.to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn update_label(&self, id: Uuid, user_id: Uuid, label: &str) -> Result<bool> {
        let result =
            sqlx::query("UPDATE user_authenticators SET label = ? WHERE id = ? AND user_id = ?")
                .bind(label)
                .bind(id.to_string())
                .bind(user_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn touch_last_used(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE user_authenticators SET last_used_at = ? WHERE id = ?")
            .bind(at.naive_utc())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn consume_single_use(
        &self,
        user_id: Uuid,
        authenticator_type: AuthenticatorType,
        secret_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<UserAuthenticator>> {
        // "Revoke a usable row" in one statement and re-read only if the update succeeded (same approach as the
        // one-time consumption of authorization codes). Reading then updating would let concurrent presentations of the same code both pass.
        let claimed = sqlx::query(
            "UPDATE user_authenticators \
             SET status = 'revoked', revoked_at = ?, last_used_at = ? \
             WHERE user_id = ? AND authenticator_type = ? AND secret_encrypted = ? \
               AND status = 'active' AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(now.naive_utc())
        .bind(now.naive_utc())
        .bind(user_id.to_string())
        .bind(authenticator_type.as_str())
        .bind(secret_hash)
        .bind(now.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        if claimed.rows_affected() == 0 {
            return Ok(None);
        }

        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_authenticators \
             WHERE user_id = ? AND authenticator_type = ? AND secret_encrypted = ? \
             ORDER BY revoked_at DESC LIMIT 1"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(user_id.to_string())
            .bind(authenticator_type.as_str())
            .bind(secret_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn revoke_all_of_type(
        &self,
        user_id: Uuid,
        authenticator_type: AuthenticatorType,
        at: DateTime<Utc>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE user_authenticators SET status = 'revoked', revoked_at = ? \
             WHERE user_id = ? AND authenticator_type = ? AND status <> 'revoked'",
        )
        .bind(at.naive_utc())
        .bind(user_id.to_string())
        .bind(authenticator_type.as_str())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }

    async fn revoke_issued_codes_of_type(
        &self,
        user_id: Uuid,
        authenticator_type: AuthenticatorType,
        at: DateTime<Utc>,
    ) -> Result<u64> {
        // Only rows with an expiry (= issued one-time codes). Registration rows without a lifetime (the SMS OTP
        // registered phone number) are kept.
        let result = sqlx::query(
            "UPDATE user_authenticators SET status = 'revoked', revoked_at = ? \
             WHERE user_id = ? AND authenticator_type = ? AND status <> 'revoked' \
               AND expires_at IS NOT NULL",
        )
        .bind(at.naive_utc())
        .bind(user_id.to_string())
        .bind(authenticator_type.as_str())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }

    async fn confirm_pending(
        &self,
        user_id: Uuid,
        authenticator_type: AuthenticatorType,
        secret_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<UserAuthenticator>> {
        // Re-read only if the update succeeded (same approach as `consume_single_use`). Drop the code and expiry
        // from rows being confirmed: if an expiry remains, GC deletes the row and the confirmed registration vanishes.
        let claimed = sqlx::query(
            "UPDATE user_authenticators \
             SET status = 'active', confirmed_at = ?, secret_encrypted = NULL, expires_at = NULL \
             WHERE user_id = ? AND authenticator_type = ? AND secret_encrypted = ? \
               AND status = 'pending' AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(now.naive_utc())
        .bind(user_id.to_string())
        .bind(authenticator_type.as_str())
        .bind(secret_hash)
        .bind(now.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        if claimed.rows_affected() == 0 {
            return Ok(None);
        }

        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_authenticators \
             WHERE user_id = ? AND authenticator_type = ? AND status = 'active' \
             ORDER BY confirmed_at DESC LIMIT 1"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(user_id.to_string())
            .bind(authenticator_type.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        // Only single-use codes have an expiry. TOTP and WebAuthn rows have `expires_at IS NULL`, so
        // they don't match this condition (the registry isn't wiped).
        // ⚠ Even after expiry, rows are kept for the window. The number of OTPs sent is counted from these rows (task #749).
        //   Expired codes can't be used because the verifying side checks `expires_at`.
        let keep_until = now - chrono::Duration::seconds(OTP_SEND_WINDOW_SECS);
        let result = sqlx::query(
            "DELETE FROM user_authenticators WHERE expires_at IS NOT NULL AND expires_at <= ?",
        )
        .bind(keep_until.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}
