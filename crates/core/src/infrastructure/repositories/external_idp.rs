//! 外部 IdP 連携（AP10）の sqlx 実装。プロバイダ設定・利用者との対応・進行状態の 3 表を扱う。

use crate::domain::error::{DomainError, Result};
use crate::domain::external_idp::{
    ExternalIdentity, ExternalIdentityProvider, ExternalLoginRequest,
};
use crate::domain::repositories::{
    ExternalIdentityProviderRepository, ExternalIdentityRepository, ExternalLoginRequestRepository,
};
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

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

// ── プロバイダ設定 ───────────────────────────────────────────────────────────

pub struct SqlxExternalIdentityProviderRepository {
    pool: Db,
}

impl SqlxExternalIdentityProviderRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const PROVIDER_COLUMNS: &str = "id, tenant_id, provider_code, display_name, issuer, \
     authorization_endpoint, token_endpoint, jwks_uri, client_id, client_secret_encrypted, \
     scopes, enabled, allow_auto_link, created_at, updated_at";

fn map_provider(row: &MySqlRow) -> Result<ExternalIdentityProvider> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    // MariaDB の JSON カラムは sqlx では BLOB として返るため、バイト列で受けて parse する。
    let scopes: Vec<u8> = row.try_get("scopes").map_err(repo_err)?;
    Ok(ExternalIdentityProvider {
        id: parse_uuid(&id, "id")?,
        tenant_id: parse_uuid(&tenant_id, "tenant_id")?.into(),
        provider_code: row.try_get("provider_code").map_err(repo_err)?,
        display_name: row.try_get("display_name").map_err(repo_err)?,
        issuer: row.try_get("issuer").map_err(repo_err)?,
        authorization_endpoint: row.try_get("authorization_endpoint").map_err(repo_err)?,
        token_endpoint: row.try_get("token_endpoint").map_err(repo_err)?,
        jwks_uri: row.try_get("jwks_uri").map_err(repo_err)?,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        client_secret_encrypted: row.try_get("client_secret_encrypted").map_err(repo_err)?,
        scopes: serde_json::from_slice(&scopes)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `scopes`: {e}")))?,
        enabled: row.try_get::<i8, _>("enabled").map_err(repo_err)? != 0,
        allow_auto_link: row.try_get::<i8, _>("allow_auto_link").map_err(repo_err)? != 0,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl ExternalIdentityProviderRepository for SqlxExternalIdentityProviderRepository {
    async fn create(&self, provider: &ExternalIdentityProvider) -> Result<()> {
        sqlx::query(
            "INSERT INTO external_identity_providers \
             (id, tenant_id, provider_code, display_name, issuer, authorization_endpoint, \
              token_endpoint, jwks_uri, client_id, client_secret_encrypted, scopes, enabled, \
              allow_auto_link) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(provider.id.to_string())
        .bind(provider.tenant_id.to_string())
        .bind(&provider.provider_code)
        .bind(&provider.display_name)
        .bind(&provider.issuer)
        .bind(&provider.authorization_endpoint)
        .bind(&provider.token_endpoint)
        .bind(&provider.jwks_uri)
        .bind(&provider.client_id)
        .bind(&provider.client_secret_encrypted)
        .bind(serde_json::to_string(&provider.scopes).map_err(repo_err)?)
        .bind(provider.enabled)
        .bind(provider.allow_auto_link)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation())
            {
                DomainError::Conflict("provider code already exists".to_string())
            } else {
                repo_err(e)
            }
        })?;
        Ok(())
    }

    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<ExternalIdentityProvider>> {
        let sql = format!(
            "SELECT {PROVIDER_COLUMNS} FROM external_identity_providers \
             WHERE tenant_id = ? ORDER BY provider_code ASC"
        );
        let rows = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_provider).collect()
    }

    async fn list_enabled_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<ExternalIdentityProvider>> {
        let sql = format!(
            "SELECT {PROVIDER_COLUMNS} FROM external_identity_providers \
             WHERE tenant_id = ? AND enabled = TRUE ORDER BY provider_code ASC"
        );
        let rows = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_provider).collect()
    }

    async fn find_by_code(
        &self,
        tenant_id: TenantId,
        provider_code: &str,
    ) -> Result<Option<ExternalIdentityProvider>> {
        let sql = format!(
            "SELECT {PROVIDER_COLUMNS} FROM external_identity_providers \
             WHERE tenant_id = ? AND provider_code = ?"
        );
        let row = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .bind(provider_code)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_provider).transpose()
    }

    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<ExternalIdentityProvider>> {
        let sql = format!(
            "SELECT {PROVIDER_COLUMNS} FROM external_identity_providers \
             WHERE tenant_id = ? AND id = ?"
        );
        let row = sqlx::query(&sql)
            .bind(tenant_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_provider).transpose()
    }

    async fn update(&self, provider: &ExternalIdentityProvider) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE external_identity_providers SET \
             provider_code = ?, display_name = ?, issuer = ?, authorization_endpoint = ?, \
             token_endpoint = ?, jwks_uri = ?, client_id = ?, client_secret_encrypted = ?, \
             scopes = ?, enabled = ?, allow_auto_link = ? \
             WHERE id = ? AND tenant_id = ?",
        )
        .bind(&provider.provider_code)
        .bind(&provider.display_name)
        .bind(&provider.issuer)
        .bind(&provider.authorization_endpoint)
        .bind(&provider.token_endpoint)
        .bind(&provider.jwks_uri)
        .bind(&provider.client_id)
        .bind(&provider.client_secret_encrypted)
        .bind(serde_json::to_string(&provider.scopes).map_err(repo_err)?)
        .bind(provider.enabled)
        .bind(provider.allow_auto_link)
        .bind(provider.id.to_string())
        .bind(provider.tenant_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation())
            {
                DomainError::Conflict("provider code already exists".to_string())
            } else {
                repo_err(e)
            }
        })?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM external_identity_providers WHERE id = ? AND tenant_id = ?")
                .bind(id.to_string())
                .bind(tenant_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }
}

// ── 利用者との対応 ───────────────────────────────────────────────────────────

pub struct SqlxExternalIdentityRepository {
    pool: Db,
}

impl SqlxExternalIdentityRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const IDENTITY_COLUMNS: &str =
    "id, user_id, provider_id, external_issuer, external_subject, created_at, last_used_at";

fn map_identity(row: &MySqlRow) -> Result<ExternalIdentity> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let provider_id: String = row.try_get("provider_id").map_err(repo_err)?;
    Ok(ExternalIdentity {
        id: parse_uuid(&id, "id")?,
        user_id: parse_uuid(&user_id, "user_id")?,
        provider_id: parse_uuid(&provider_id, "provider_id")?,
        external_issuer: row.try_get("external_issuer").map_err(repo_err)?,
        external_subject: row.try_get("external_subject").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        last_used_at: row
            .try_get::<Option<NaiveDateTime>, _>("last_used_at")
            .map_err(repo_err)?
            .map(to_utc),
    })
}

#[async_trait]
impl ExternalIdentityRepository for SqlxExternalIdentityRepository {
    async fn create(&self, identity: &ExternalIdentity) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_external_identities \
             (id, user_id, provider_id, external_issuer, external_subject, last_used_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(identity.id.to_string())
        .bind(identity.user_id.to_string())
        .bind(identity.provider_id.to_string())
        .bind(&identity.external_issuer)
        .bind(&identity.external_subject)
        .bind(identity.last_used_at.map(|t| t.naive_utc()))
        .execute(&self.pool)
        .await
        .map_err(|e| {
            // 同じ外部アカウントの二重連携・同じプロバイダの重複連携はどちらも一意制約違反。
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation())
            {
                DomainError::Conflict("external identity is already linked".to_string())
            } else {
                repo_err(e)
            }
        })?;
        Ok(())
    }

    async fn find_by_subject(
        &self,
        provider_id: Uuid,
        external_issuer: &str,
        external_subject: &str,
    ) -> Result<Option<ExternalIdentity>> {
        let sql = format!(
            "SELECT {IDENTITY_COLUMNS} FROM user_external_identities \
             WHERE provider_id = ? AND external_issuer = ? AND external_subject = ?"
        );
        let row = sqlx::query(&sql)
            .bind(provider_id.to_string())
            .bind(external_issuer)
            .bind(external_subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_identity).transpose()
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>> {
        let sql = format!(
            "SELECT {IDENTITY_COLUMNS} FROM user_external_identities \
             WHERE user_id = ? ORDER BY created_at DESC"
        );
        let rows = sqlx::query(&sql)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_identity).collect()
    }

    async fn touch_last_used(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE user_external_identities SET last_used_at = ? WHERE id = ?")
            .bind(at.naive_utc())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM user_external_identities WHERE id = ? AND user_id = ?")
                .bind(id.to_string())
                .bind(user_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }
}

// ── 進行状態 ─────────────────────────────────────────────────────────────────

pub struct SqlxExternalLoginRequestRepository {
    pool: Db,
}

impl SqlxExternalLoginRequestRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const REQUEST_COLUMNS: &str = "id, tenant_id, provider_id, state_hash, nonce, \
     code_verifier_encrypted, auth_session_id_hash, expires_at, created_at";

fn map_request(row: &MySqlRow) -> Result<ExternalLoginRequest> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let provider_id: String = row.try_get("provider_id").map_err(repo_err)?;
    Ok(ExternalLoginRequest {
        id: parse_uuid(&id, "id")?,
        tenant_id: parse_uuid(&tenant_id, "tenant_id")?.into(),
        provider_id: parse_uuid(&provider_id, "provider_id")?,
        state_hash: row.try_get("state_hash").map_err(repo_err)?,
        nonce: row.try_get("nonce").map_err(repo_err)?,
        code_verifier_encrypted: row.try_get("code_verifier_encrypted").map_err(repo_err)?,
        auth_session_id_hash: row.try_get("auth_session_id_hash").map_err(repo_err)?,
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl ExternalLoginRequestRepository for SqlxExternalLoginRequestRepository {
    async fn create(&self, request: &ExternalLoginRequest) -> Result<()> {
        sqlx::query(
            "INSERT INTO external_login_requests \
             (id, tenant_id, provider_id, state_hash, nonce, code_verifier_encrypted, \
              auth_session_id_hash, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(request.id.to_string())
        .bind(request.tenant_id.to_string())
        .bind(request.provider_id.to_string())
        .bind(&request.state_hash)
        .bind(&request.nonce)
        .bind(&request.code_verifier_encrypted)
        .bind(&request.auth_session_id_hash)
        .bind(request.expires_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_state(
        &self,
        tenant_id: TenantId,
        state_hash: &str,
    ) -> Result<Option<ExternalLoginRequest>> {
        let sql = format!(
            "SELECT {REQUEST_COLUMNS} FROM external_login_requests \
             WHERE state_hash = ? AND tenant_id = ?"
        );
        let row = sqlx::query(&sql)
            .bind(state_hash)
            .bind(tenant_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_request).transpose()
    }

    async fn consume(&self, id: Uuid) -> Result<bool> {
        // 削除できた側だけが処理を続けられる（単回使用の原子的クレーム）。
        let result = sqlx::query("DELETE FROM external_login_requests WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query("DELETE FROM external_login_requests WHERE expires_at <= ?")
            .bind(now.naive_utc())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected())
    }
}
