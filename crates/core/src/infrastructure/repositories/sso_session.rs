//! `SsoSessionRepository` の sqlx 実装。DB には `session_hash = SHA-256(session_id)` のみ保存する。

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
        // 第二要素を通した step-up だけが `mfa_completed_at` を進める。単一要素の再確認で
        // MFA の鮮度まで回復させると、パスワードを知る攻撃者が第二要素を迂回できてしまう。
        // 既存値を残すため、単一要素のときは `mfa_completed_at` を触らない（COALESCE ではなく
        // 更新対象から外す）。
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
            // 単一要素の再確認では強度も下げない（多要素で確立したセッションを、パスワードの
            // 再入力で単一要素へ格下げしてはいけない）。更新するのは step-up の時刻だけ。
            sqlx::query("UPDATE sso_sessions SET step_up_at = ? WHERE session_hash = ?")
                .bind(verified_at.naive_utc())
                .bind(session_hash)
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        }
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
        let json = authentication_methods_json::to_json(&methods);
        assert_eq!(json, r#"["password","totp"]"#);
        assert_eq!(
            authentication_methods_json::from_json(Some(json.into_bytes())),
            methods
        );
    }

    /// AP4 導入前に確立したセッション（NULL）は「記録なし」＝空配列として読む。
    #[test]
    fn null_methods_read_as_no_record() {
        assert!(authentication_methods_json::from_json(None).is_empty());
    }

    /// 未知の方式を含む行でも、読めるものだけを拾って壊れない（前方互換）。
    #[test]
    fn unknown_methods_are_skipped() {
        let raw = br#"["password","quantum_handshake","totp"]"#.to_vec();
        assert_eq!(
            authentication_methods_json::from_json(Some(raw)),
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp]
        );
    }
}
