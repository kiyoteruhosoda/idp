//! `SsoSessionRepository` の sqlx 実装。DB には `session_hash = SHA-256(session_id)` のみ保存する。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SsoSessionRepository;
use crate::domain::sso_session::SsoSession;
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength};
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
     absolute_expires_at, authentication_methods, authentication_strength, mfa_completed_at, \
     user_agent, ip_address, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

/// 認証方式の配列を JSON 文字列へ落とす（保存形式は許可値の文字列配列）。
fn methods_to_json(methods: &[AuthenticationMethod]) -> String {
    let values: Vec<&str> = methods.iter().map(|m| m.as_str()).collect();
    serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_string())
}

/// 保存済み JSON から認証方式の配列を復元する。
///
/// NULL（AP4 導入前に確立したセッション）は空配列＝「記録なし」として扱う。未知の値は無視する
/// （将来の版で追加された方式を持つ行を、古い版のプロセスが読んでも壊れないようにする）。
fn methods_from_json(raw: Option<Vec<u8>>) -> Vec<AuthenticationMethod> {
    let Some(bytes) = raw else {
        return Vec::new();
    };
    let values: Vec<String> = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "invalid JSON in sso_sessions.authentication_methods");
            return Vec::new();
        }
    };
    values
        .iter()
        .filter_map(|v| AuthenticationMethod::parse(v).ok())
        .collect()
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
        authentication_methods: methods_from_json(
            row.try_get("authentication_methods").map_err(repo_err)?,
        ),
        authentication_strength: AuthenticationStrength::parse(&strength)?,
        mfa_completed_at: row
            .try_get::<Option<NaiveDateTime>, _>("mfa_completed_at")
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
              authentication_methods, authentication_strength, mfa_completed_at, \
              user_agent, ip_address) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session.session_hash)
        .bind(session.user_id.to_string())
        .bind(session.auth_time.naive_utc())
        .bind(session.idle_expires_at.naive_utc())
        .bind(session.absolute_expires_at.naive_utc())
        .bind(methods_to_json(&session.authentication_methods))
        .bind(session.authentication_strength.as_str())
        .bind(session.mfa_completed_at.map(|t| t.naive_utc()))
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

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<SsoSession>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM sso_sessions WHERE user_id = ? \
             ORDER BY created_at DESC"
        );
        let rows = sqlx::query(&sql)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
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
        .bind(methods_to_json(methods))
        .bind(AuthenticationStrength::from_methods(methods).as_str())
        .bind(completed_at.naive_utc())
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

    async fn delete_all_for_user(&self, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM sso_sessions WHERE user_id = ?")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
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
        let json = methods_to_json(&methods);
        assert_eq!(json, r#"["password","totp"]"#);
        assert_eq!(methods_from_json(Some(json.into_bytes())), methods);
    }

    /// AP4 導入前に確立したセッション（NULL）は「記録なし」＝空配列として読む。
    #[test]
    fn null_methods_read_as_no_record() {
        assert!(methods_from_json(None).is_empty());
    }

    /// 未知の方式を含む行でも、読めるものだけを拾って壊れない（前方互換）。
    #[test]
    fn unknown_methods_are_skipped() {
        let raw = br#"["password","quantum_handshake","totp"]"#.to_vec();
        assert_eq!(
            methods_from_json(Some(raw)),
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp]
        );
    }
}
