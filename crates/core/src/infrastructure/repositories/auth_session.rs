//! `AuthSessionRepository` の sqlx 実装。

use crate::domain::auth_session::AuthSession;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::AuthSessionRepository;
use crate::domain::tenant::TenantId;
use crate::domain::values::{CodeChallengeMethod, PromptSet};
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

const SELECT_COLUMNS: &str = "id_hash, tenant_id, client_id, redirect_uri, scope, state, nonce, \
     code_challenge, code_challenge_method, prompt, max_age, acr_values, login_hint, \
     ui_locales, handle_hash, handle_expires_at, \
     authenticated_user_id, auth_time, password_verified_at, sso_sid, expires_at, created_at, \
     updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<AuthSession> {
    // MariaDB の JSON カラムは sqlx では BLOB として返るため、バイト列で受けて parse する。
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let scope: Vec<u8> = row.try_get("scope").map_err(repo_err)?;
    let ccm: String = row.try_get("code_challenge_method").map_err(repo_err)?;
    let prompt: Option<String> = row.try_get("prompt").map_err(repo_err)?;
    let max_age: Option<i64> = row.try_get("max_age").map_err(repo_err)?;
    let handle_expires_at: Option<NaiveDateTime> =
        row.try_get("handle_expires_at").map_err(repo_err)?;
    let user_id: Option<String> = row.try_get("authenticated_user_id").map_err(repo_err)?;
    let auth_time: Option<NaiveDateTime> = row.try_get("auth_time").map_err(repo_err)?;
    let password_verified_at: Option<NaiveDateTime> =
        row.try_get("password_verified_at").map_err(repo_err)?;
    Ok(AuthSession {
        id_hash: row.try_get("id_hash").map_err(repo_err)?,
        tenant_id: Uuid::parse_str(&tenant_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{tenant_id}`: {e}")))?
            .into(),
        client_id: row.try_get("client_id").map_err(repo_err)?,
        redirect_uri: row.try_get("redirect_uri").map_err(repo_err)?,
        scope: serde_json::from_slice(&scope)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `scope`: {e}")))?,
        state: row.try_get("state").map_err(repo_err)?,
        nonce: row.try_get("nonce").map_err(repo_err)?,
        code_challenge: row.try_get("code_challenge").map_err(repo_err)?,
        code_challenge_method: CodeChallengeMethod::parse(&ccm)?,
        prompt: PromptSet::parse(prompt.as_deref().unwrap_or_default()),
        max_age: max_age.map(|v| v.max(0) as u64),
        acr_values: row.try_get("acr_values").map_err(repo_err)?,
        login_hint: row.try_get("login_hint").map_err(repo_err)?,
        ui_locales: row.try_get("ui_locales").map_err(repo_err)?,
        handle_hash: row.try_get("handle_hash").map_err(repo_err)?,
        handle_expires_at: handle_expires_at.map(to_utc),
        authenticated_user_id: user_id
            .map(|s| {
                Uuid::parse_str(&s)
                    .map_err(|e| DomainError::Repository(format!("invalid UUID `{s}`: {e}")))
            })
            .transpose()?,
        auth_time: auth_time.map(to_utc),
        password_verified_at: password_verified_at.map(to_utc),
        sso_sid: row.try_get("sso_sid").map_err(repo_err)?,
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
             (id_hash, tenant_id, client_id, redirect_uri, scope, state, nonce, code_challenge, \
              code_challenge_method, prompt, max_age, acr_values, login_hint, ui_locales, \
              handle_hash, handle_expires_at, \
              authenticated_user_id, auth_time, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&session.id_hash)
        .bind(session.tenant_id.to_string())
        .bind(&session.client_id)
        .bind(&session.redirect_uri)
        .bind(serde_json::to_string(&session.scope).map_err(repo_err)?)
        .bind(&session.state)
        .bind(&session.nonce)
        .bind(&session.code_challenge)
        .bind(session.code_challenge_method.as_str())
        .bind(session.prompt.to_storage())
        .bind(session.max_age.map(|v| v as i64))
        .bind(&session.acr_values)
        .bind(&session.login_hint)
        .bind(&session.ui_locales)
        .bind(&session.handle_hash)
        .bind(session.handle_expires_at.map(|d| d.naive_utc()))
        .bind(session.authenticated_user_id.map(|u| u.to_string()))
        .bind(session.auth_time.map(|d| d.naive_utc()))
        .bind(session.expires_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id_hash(
        &self,
        tenant_id: TenantId,
        id_hash: &str,
    ) -> Result<Option<AuthSession>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM auth_sessions WHERE id_hash = ? AND tenant_id = ?"
        );
        let row = sqlx::query(&sql)
            .bind(id_hash)
            .bind(tenant_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_handle(
        &self,
        tenant_id: TenantId,
        handle_hash: &str,
    ) -> Result<Option<AuthSession>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM auth_sessions WHERE handle_hash = ? AND tenant_id = ?"
        );
        let row = sqlx::query(&sql)
            .bind(handle_hash)
            .bind(tenant_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn consume_handle(
        &self,
        id_hash: &str,
        handle_hash: &str,
        new_id_hash: &str,
    ) -> Result<bool> {
        // WHERE に handle_hash を含めることで単回使用を原子的に強制する。並行する交換は
        // 片方だけが 1 行更新に成功し、負けた側（および再利用）は 0 行 = false になる。
        // 同じ文で id_hash も差し替える（勝った側だけが新しい id を得る）。
        let result = sqlx::query(
            "UPDATE auth_sessions \
             SET handle_hash = NULL, handle_expires_at = NULL, id_hash = ? \
             WHERE id_hash = ? AND handle_hash = ?",
        )
        .bind(new_id_hash)
        .bind(id_hash)
        .bind(handle_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn set_authenticated_user(
        &self,
        id_hash: &str,
        new_id_hash: &str,
        user_id: Uuid,
        auth_time: DateTime<Utc>,
        sso_sid: Option<&str>,
    ) -> Result<()> {
        // id の再生成を同じ UPDATE に含める（SEC7）。別文に分けると、認証済みフラグは立っているのに
        // 旧 id がまだ引ける瞬間ができる。
        sqlx::query(
            "UPDATE auth_sessions \
             SET id_hash = ?, authenticated_user_id = ?, auth_time = ?, sso_sid = ? \
             WHERE id_hash = ?",
        )
        .bind(new_id_hash)
        .bind(user_id.to_string())
        .bind(auth_time.naive_utc())
        .bind(sso_sid)
        .bind(id_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn set_password_verified(
        &self,
        id_hash: &str,
        new_id_hash: &str,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE auth_sessions \
             SET id_hash = ?, authenticated_user_id = ?, password_verified_at = ? \
             WHERE id_hash = ?",
        )
        .bind(new_id_hash)
        .bind(user_id.to_string())
        .bind(verified_at.naive_utc())
        .bind(id_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id_hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM auth_sessions WHERE id_hash = ?")
            .bind(id_hash)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query("DELETE FROM auth_sessions WHERE expires_at <= ?")
            .bind(now.naive_utc())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}
