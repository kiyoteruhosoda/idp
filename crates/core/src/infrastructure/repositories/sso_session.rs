//! sqlx implementation of `SsoSessionRepository`. Only `session_hash = SHA-256(session_id)` is stored in the DB.

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SsoSessionRepository;
use crate::domain::sso_session::SsoSession;
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength};
use crate::infrastructure::db::Db;
use crate::infrastructure::repositories::authentication_methods_json;
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
     absolute_expires_at, authentication_methods, authentication_strength, mfa_completed_at, \
     step_up_at, user_agent, ip_address, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<SsoSession> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let strength: String = row.try_get("authentication_strength").map_err(repo_err)?;
    Ok(SsoSession {
        session_hash: row.try_get("session_hash").map_err(repo_err)?,
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        auth_time: to_utc(row.try_get("auth_time").map_err(repo_err)?),
        idle_expires_at: to_utc(row.try_get("idle_expires_at").map_err(repo_err)?),
        absolute_expires_at: to_utc(row.try_get("absolute_expires_at").map_err(repo_err)?),
        authentication_methods: authentication_methods_json::from_json(
            row.try_get("authentication_methods").map_err(repo_err)?,
        ),
        authentication_strength: AuthenticationStrength::parse(&strength)?,
        mfa_completed_at: row
            .try_get::<Option<NaiveDateTime>, _>("mfa_completed_at")
            .map_err(repo_err)?
            .map(to_utc),
        step_up_at: row
            .try_get::<Option<NaiveDateTime>, _>("step_up_at")
            .map_err(repo_err)?
            .map(to_utc),
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
              authentication_methods, authentication_strength, mfa_completed_at, step_up_at, \
              user_agent, ip_address) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session.session_hash)
        .bind(session.user_id.to_string())
        .bind(session.auth_time.naive_utc())
        .bind(session.idle_expires_at.naive_utc())
        .bind(session.absolute_expires_at.naive_utc())
        .bind(authentication_methods_json::to_json(
            &session.authentication_methods,
        ))
        .bind(session.authentication_strength.as_str())
        .bind(session.mfa_completed_at.map(|t| t.naive_utc()))
        .bind(session.step_up_at.map(|t| t.naive_utc()))
        .bind(&session.user_agent)
        .bind(&session.ip_address)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_hash(&self, session_hash: &str) -> Result<Option<SsoSession>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM sso_sessions WHERE session_hash = ?");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(session_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<SsoSession>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM sso_sessions WHERE user_id = ? \
             ORDER BY created_at DESC"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn extend_idle(&self, session_hash: &str, idle_expires_at: DateTime<Utc>) -> Result<()> {
        // ⚠ Not shortened (login states bound to a device key have idle extended up to absolute; ADR-0074).
        sqlx::query(
            "UPDATE sso_sessions SET idle_expires_at = GREATEST(idle_expires_at, ?) \
             WHERE session_hash = ?",
        )
        .bind(idle_expires_at.naive_utc())
        .bind(session_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn set_lifetime(
        &self,
        session_hash: &str,
        idle_expires_at: DateTime<Utc>,
        absolute_expires_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE sso_sessions SET idle_expires_at = ?, absolute_expires_at = ? \
             WHERE session_hash = ?",
        )
        .bind(idle_expires_at.naive_utc())
        .bind(absolute_expires_at.naive_utc())
        .bind(session_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn record_second_factor(
        &self,
        session_hash: &str,
        methods: &[AuthenticationMethod],
        completed_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE sso_sessions \
             SET authentication_methods = ?, authentication_strength = ?, mfa_completed_at = ? \
             WHERE session_hash = ?",
        )
        .bind(authentication_methods_json::to_json(methods))
        .bind(AuthenticationStrength::from_methods(methods).as_str())
        .bind(completed_at.naive_utc())
        .bind(session_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn record_step_up(
        &self,
        session_hash: &str,
        methods: &[AuthenticationMethod],
        verified_at: DateTime<Utc>,
    ) -> Result<()> {
        let strength = AuthenticationStrength::from_methods(methods);
        // Only a step-up through a second factor advances `mfa_completed_at`. Restoring MFA freshness through
        // single-factor re-verification would let an attacker who knows the password bypass the second factor.
        // To keep the existing value, `mfa_completed_at` is not touched for single factor (it is left out of the
        // update targets rather than using COALESCE).
        if strength == AuthenticationStrength::MultiFactor {
            sqlx::query(
                "UPDATE sso_sessions \
                 SET authentication_methods = ?, authentication_strength = ?, \
                     mfa_completed_at = ?, step_up_at = ? \
                 WHERE session_hash = ?",
            )
            .bind(authentication_methods_json::to_json(methods))
            .bind(strength.as_str())
            .bind(verified_at.naive_utc())
            .bind(verified_at.naive_utc())
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        } else {
            // Single-factor re-verification doesn't lower the strength either (a session established with multiple factors must not be
            // downgraded to single factor by re-entering the password). Only the step-up time is updated.
            sqlx::query("UPDATE sso_sessions SET step_up_at = ? WHERE session_hash = ?")
                .bind(verified_at.naive_utc())
                .bind(session_hash)
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        }
        // Keep the passkey verification time separately for the device registration condition (task #872). `step_up_at`
        // also advances on password re-verification, so it can't tell "was it verified with a passkey".
        if methods.contains(&AuthenticationMethod::WebAuthn) {
            sqlx::query(
                "INSERT INTO sso_session_contexts (session_hash, passkey_verified_at) \
                 VALUES (?, ?) \
                 ON DUPLICATE KEY UPDATE passkey_verified_at = VALUES(passkey_verified_at)",
            )
            .bind(session_hash)
            .bind(verified_at.naive_utc())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        }
        Ok(())
    }

    async fn passkey_verified_at(&self, session_hash: &str) -> Result<Option<DateTime<Utc>>> {
        let row: Option<Option<NaiveDateTime>> = sqlx::query_scalar(
            "SELECT passkey_verified_at FROM sso_session_contexts WHERE session_hash = ?",
        )
        .bind(session_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(row.flatten().map(to_utc))
    }

    async fn delete(&self, session_hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM sso_sessions WHERE session_hash = ?")
            .bind(session_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM sso_sessions WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete_all_for_user_except(
        &self,
        user_id: Uuid,
        keep_session_hash: &str,
    ) -> Result<u64> {
        let result =
            sqlx::query("DELETE FROM sso_sessions WHERE user_id = ? AND session_hash <> ?")
                .bind(user_id.to_string())
                .bind(keep_session_hash)
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(result.rows_affected())
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM sso_sessions WHERE idle_expires_at <= ? OR absolute_expires_at <= ?",
        )
        .bind(now.naive_utc())
        .bind(now.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods_round_trip_through_json() {
        let methods = vec![AuthenticationMethod::Password, AuthenticationMethod::Totp];
        let json = authentication_methods_json::to_json(&methods);
        assert_eq!(json, r#"["password","totp"]"#);
        assert_eq!(
            authentication_methods_json::from_json(Some(json.into_bytes())),
            methods
        );
    }

    /// Sessions established before AP4 (NULL) are read as "no record" = empty array.
    #[test]
    fn null_methods_read_as_no_record() {
        assert!(authentication_methods_json::from_json(None).is_empty());
    }

    /// Even rows containing unknown methods are read without breaking, picking up only what is readable (forward compatibility).
    #[test]
    fn unknown_methods_are_skipped() {
        let raw = br#"["password","quantum_handshake","totp"]"#.to_vec();
        assert_eq!(
            authentication_methods_json::from_json(Some(raw)),
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp]
        );
    }
}
