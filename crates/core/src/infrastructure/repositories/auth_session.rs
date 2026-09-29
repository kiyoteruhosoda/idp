//! `AuthSessionRepository` の sqlx 実装。

use crate::domain::auth_session::{
    AuthSession, AuthSessionIdHash, AuthSessionParts, AuthenticationCompletion, HandoffExchange,
    HandoffHandleHash, PasswordVerification,
};
use crate::domain::authorization_request::{AuthorizationRequest, AuthorizationRequestParts};
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::AuthSessionRepository;
use crate::domain::response_mode::ResponseMode;
use crate::domain::tenant::TenantId;
use crate::domain::values::{CodeChallengeMethod, PromptSet};
use crate::infrastructure::db::Db;
use crate::infrastructure::repositories::authentication_methods_json;
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
     code_challenge, code_challenge_method, prompt, response_mode, max_age, acr_values, login_hint, \
     ui_locales, handle_hash, handle_expires_at, \
     authenticated_user_id, auth_time, password_verified_at, sso_sid, authentication_methods, \
     expires_at, created_at, updated_at";

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
    let response_mode: Option<String> = row.try_get("response_mode").map_err(repo_err)?;
    let max_age: Option<i64> = row.try_get("max_age").map_err(repo_err)?;
    let handle_hash: Option<String> = row.try_get("handle_hash").map_err(repo_err)?;
    let handle_expires_at: Option<NaiveDateTime> =
        row.try_get("handle_expires_at").map_err(repo_err)?;
    let user_id: Option<String> = row.try_get("authenticated_user_id").map_err(repo_err)?;
    let auth_time: Option<NaiveDateTime> = row.try_get("auth_time").map_err(repo_err)?;
    let password_verified_at: Option<NaiveDateTime> =
        row.try_get("password_verified_at").map_err(repo_err)?;
    let request = AuthorizationRequest::reconstitute(AuthorizationRequestParts {
        client_id: row.try_get("client_id").map_err(repo_err)?,
        redirect_uri: row.try_get("redirect_uri").map_err(repo_err)?,
        scope: serde_json::from_slice(&scope)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `scope`: {e}")))?,
        state: row.try_get("state").map_err(repo_err)?,
        nonce: row.try_get("nonce").map_err(repo_err)?,
        code_challenge: row.try_get("code_challenge").map_err(repo_err)?,
        code_challenge_method: CodeChallengeMethod::parse(&ccm)?,
        prompt: PromptSet::parse(prompt.as_deref().unwrap_or_default()),
        response_mode: ResponseMode::from_stored(response_mode.as_deref()),
        max_age: max_age.map(|v| v.max(0) as u64),
        acr_values: row.try_get("acr_values").map_err(repo_err)?,
        login_hint: row.try_get("login_hint").map_err(repo_err)?,
        ui_locales: row.try_get("ui_locales").map_err(repo_err)?,
    });
    Ok(AuthSession::reconstitute(AuthSessionParts {
        id_hash: AuthSessionIdHash::from_stored(row.try_get("id_hash").map_err(repo_err)?),
        tenant_id: Uuid::parse_str(&tenant_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{tenant_id}`: {e}")))?
            .into(),
        request,
        handle_hash: handle_hash.map(HandoffHandleHash::from_stored),
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
        authentication_methods: authentication_methods_json::from_json_opt(
            row.try_get("authentication_methods").map_err(repo_err)?,
        ),
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    }))
}

#[async_trait]
impl AuthSessionRepository for SqlxAuthSessionRepository {
    async fn create(&self, session: &AuthSession) -> Result<()> {
        let request = session.request();
        let handoff = session.handoff();
        let authentication = session.completed_authentication();
        sqlx::query(
            "INSERT INTO auth_sessions \
             (id_hash, tenant_id, client_id, redirect_uri, scope, state, nonce, code_challenge, \
              code_challenge_method, prompt, response_mode, max_age, acr_values, login_hint, ui_locales, \
              handle_hash, handle_expires_at, \
              authenticated_user_id, auth_time, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id_hash().as_str())
        .bind(session.tenant_id().to_string())
        .bind(request.client_id())
        .bind(request.redirect_uri())
        .bind(serde_json::to_string(request.scope()).map_err(repo_err)?)
        .bind(request.state())
        .bind(request.nonce())
        .bind(request.pkce().challenge())
        .bind(request.pkce().method().as_str())
        .bind(request.prompt().to_storage())
        .bind(request.response_mode().to_stored())
        .bind(request.max_age().map(|v| v as i64))
        .bind(request.acr_values())
        .bind(request.login_hint())
        .bind(request.ui_locales())
        .bind(handoff.map(|h| h.handle_hash().as_str()))
        .bind(handoff.map(|h| h.expires_at().naive_utc()))
        .bind(session.identified_user().map(|u| u.to_string()))
        .bind(authentication.map(|a| a.auth_time().naive_utc()))
        .bind(session.expires_at().naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find(
        &self,
        tenant_id: TenantId,
        id: &AuthSessionIdHash,
    ) -> Result<Option<AuthSession>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM auth_sessions WHERE id_hash = ? AND tenant_id = ?"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(id.as_str())
            .bind(tenant_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_handoff(
        &self,
        tenant_id: TenantId,
        handle: &HandoffHandleHash,
    ) -> Result<Option<AuthSession>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM auth_sessions WHERE handle_hash = ? AND tenant_id = ?"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(handle.as_str())
            .bind(tenant_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn save_handoff_exchange(&self, exchange: &HandoffExchange) -> Result<bool> {
        // WHERE に handle_hash を含めることで単回使用を原子的に強制する。並行する交換は
        // 片方だけが 1 行更新に成功し、負けた側（および再利用）は 0 行 = false になる。
        // 同じ文で id_hash も差し替える（勝った側だけが新しい id を得る）。
        let rotation = exchange.rotation();
        let result = sqlx::query(
            "UPDATE auth_sessions \
             SET handle_hash = NULL, handle_expires_at = NULL, id_hash = ? \
             WHERE id_hash = ? AND handle_hash = ?",
        )
        .bind(rotation.issued_hash().as_str())
        .bind(rotation.previous().as_str())
        .bind(exchange.consumed().as_str())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn save_password_verification(&self, verification: &PasswordVerification) -> Result<()> {
        // 前の認証（auth_time・sid・方式）は同じ文で消す。残すと、第二段を済ませていない利用者の
        // 行が「認証済み」に読める。
        let rotation = verification.rotation();
        sqlx::query(
            "UPDATE auth_sessions \
             SET id_hash = ?, authenticated_user_id = ?, password_verified_at = ?, \
                 auth_time = NULL, sso_sid = NULL, authentication_methods = NULL \
             WHERE id_hash = ?",
        )
        .bind(rotation.issued_hash().as_str())
        .bind(verification.user_id().to_string())
        .bind(verification.verified_at().naive_utc())
        .bind(rotation.previous().as_str())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn save_authentication(&self, completion: &AuthenticationCompletion) -> Result<()> {
        // id の再生成を同じ UPDATE に含める（SEC7）。別文に分けると、認証済みフラグは立っているのに
        // 旧 id がまだ引ける瞬間ができる。
        let rotation = completion.rotation();
        let authentication = completion.authentication();
        sqlx::query(
            "UPDATE auth_sessions \
             SET id_hash = ?, authenticated_user_id = ?, auth_time = ?, sso_sid = ?, \
                 authentication_methods = ? \
             WHERE id_hash = ?",
        )
        .bind(rotation.issued_hash().as_str())
        .bind(authentication.user_id().to_string())
        .bind(authentication.auth_time().naive_utc())
        .bind(authentication.sso_sid())
        .bind(
            authentication
                .methods()
                .map(authentication_methods_json::to_json),
        )
        .bind(rotation.previous().as_str())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: &AuthSessionIdHash) -> Result<()> {
        sqlx::query("DELETE FROM auth_sessions WHERE id_hash = ?")
            .bind(id.as_str())
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
