//! `SamlSsoRequestRepository` の sqlx 実装。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SamlSsoRequestRepository;
use crate::domain::saml_sso_request::SamlSsoRequest;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxSamlSsoRequestRepository {
    pool: Db,
}

impl SqlxSamlSsoRequestRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, tenant_id, service_provider_id, sp_entity_id, acs_url, \
     request_id, relay_state, handle_hash, handle_expires_at, expires_at, created_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value)
        .map_err(|e| DomainError::Repository(format!("invalid UUID `{value}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<SamlSsoRequest> {
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let service_provider_id: String = row.try_get("service_provider_id").map_err(repo_err)?;
    let handle_expires_at: Option<NaiveDateTime> =
        row.try_get("handle_expires_at").map_err(repo_err)?;
    Ok(SamlSsoRequest {
        id: row.try_get("id").map_err(repo_err)?,
        tenant_id: parse_uuid(&tenant_id)?.into(),
        service_provider_id: parse_uuid(&service_provider_id)?,
        sp_entity_id: row.try_get("sp_entity_id").map_err(repo_err)?,
        acs_url: row.try_get("acs_url").map_err(repo_err)?,
        request_id: row.try_get("request_id").map_err(repo_err)?,
        relay_state: row.try_get("relay_state").map_err(repo_err)?,
        handle_hash: row.try_get("handle_hash").map_err(repo_err)?,
        handle_expires_at: handle_expires_at.map(to_utc),
        expires_at: to_utc(row.try_get("expires_at").map_err(repo_err)?),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl SamlSsoRequestRepository for SqlxSamlSsoRequestRepository {
    async fn create(&self, request: &SamlSsoRequest) -> Result<()> {
        sqlx::query(
            "INSERT INTO saml_sso_requests \
             (id, tenant_id, service_provider_id, sp_entity_id, acs_url, request_id, \
              relay_state, handle_hash, handle_expires_at, expires_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&request.id)
        .bind(request.tenant_id.to_string())
        .bind(request.service_provider_id.to_string())
        .bind(&request.sp_entity_id)
        .bind(&request.acs_url)
        .bind(&request.request_id)
        .bind(&request.relay_state)
        .bind(&request.handle_hash)
        .bind(request.handle_expires_at.map(|d| d.naive_utc()))
        .bind(request.expires_at.naive_utc())
        .bind(request.created_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(&self, tenant_id: TenantId, id: &str) -> Result<Option<SamlSsoRequest>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM saml_sso_requests WHERE id = ? AND tenant_id = ?"
        );
        let row = sqlx::query(&sql)
            .bind(id)
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
    ) -> Result<Option<SamlSsoRequest>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM saml_sso_requests WHERE handle_hash = ? AND tenant_id = ?"
        );
        let row = sqlx::query(&sql)
            .bind(handle_hash)
            .bind(tenant_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn consume_handle(&self, id: &str, handle_hash: &str) -> Result<bool> {
        // WHERE に handle_hash を含めることで単回使用を原子的に強制する（auth_sessions と同方式）。
        let result = sqlx::query(
            "UPDATE saml_sso_requests \
             SET handle_hash = NULL, handle_expires_at = NULL \
             WHERE id = ? AND handle_hash = ?",
        )
        .bind(id)
        .bind(handle_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM saml_sso_requests WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
