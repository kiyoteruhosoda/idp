//! `ProtectedResourceRepository` / `ClientResourceRepository` の sqlx 実装（ADR-0042）。
//! UUID は CHAR(36) 正準文字列で入出力する。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::{ClientResourceRepository, ProtectedResourceRepository};
use crate::domain::resource::ProtectedResource;
use crate::domain::tenant::TenantId;
use crate::domain::values::ResourceStatus;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxProtectedResourceRepository {
    pool: Db,
}

impl SqlxProtectedResourceRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

pub struct SqlxClientResourceRepository {
    pool: Db,
}

impl SqlxClientResourceRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str =
    "id, tenant_id, resource_uri, display_name, status, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(raw: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| DomainError::Repository(format!("invalid UUID `{raw}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<ProtectedResource> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    Ok(ProtectedResource {
        id: parse_uuid(&id)?,
        tenant_id: TenantId::from(parse_uuid(&tenant_id)?),
        resource_uri: row.try_get("resource_uri").map_err(repo_err)?,
        display_name: row.try_get("display_name").map_err(repo_err)?,
        status: ResourceStatus::parse(&status)
            .map_err(|_| DomainError::Repository(format!("invalid resource status `{status}`")))?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl ProtectedResourceRepository for SqlxProtectedResourceRepository {
    async fn create(&self, resource: &ProtectedResource) -> Result<()> {
        sqlx::query(
            "INSERT INTO resources \
             (id, tenant_id, resource_uri, display_name, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(resource.id.to_string())
        .bind(resource.tenant_id.to_string())
        .bind(&resource.resource_uri)
        .bind(&resource.display_name)
        .bind(resource.status.as_str())
        .bind(resource.created_at)
        .bind(resource.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("resource is already registered".to_string())
            }
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }

    async fn find_by_id(&self, tenant_id: TenantId, id: Uuid) -> Result<Option<ProtectedResource>> {
        let row = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM resources WHERE id = ? AND tenant_id = ?"
        ))
        .bind(id.to_string())
        .bind(tenant_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    /// 照合は**完全一致**。`https://x` と `https://x/` を同じ宛名として扱わないのは、
    /// リソースサーバ側も受け取った `aud` を文字列で比べるためである（片方だけを正規化すると外れる）。
    async fn find_by_uri(
        &self,
        tenant_id: TenantId,
        uri: &str,
    ) -> Result<Option<ProtectedResource>> {
        let row = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM resources WHERE tenant_id = ? AND resource_uri = ?"
        ))
        .bind(tenant_id.to_string())
        .bind(uri)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list(&self, tenant_id: TenantId) -> Result<Vec<ProtectedResource>> {
        let rows = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM resources WHERE tenant_id = ? ORDER BY resource_uri"
        ))
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    /// `tenant_id` も条件に入れる（id だけで更新できると、root の管理者が他テナントの宛名を
    /// 止められる）。
    async fn set_status(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        status: ResourceStatus,
        updated_at: DateTime<Utc>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE resources SET status = ?, updated_at = ? WHERE id = ? AND tenant_id = ?",
        )
        .bind(status.as_str())
        .bind(updated_at)
        .bind(id.to_string())
        .bind(tenant_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM resources WHERE id = ? AND tenant_id = ?")
            .bind(id.to_string())
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }
}

#[async_trait]
impl ClientResourceRepository for SqlxClientResourceRepository {
    async fn list_for_client(&self, client_row_id: Uuid) -> Result<Vec<ProtectedResource>> {
        let rows = sqlx::query(&format!(
            "SELECT {} FROM resources r \
             JOIN client_resources cr ON cr.resource_id = r.id \
             WHERE cr.client_id = ? ORDER BY r.resource_uri",
            SELECT_COLUMNS
                .split(", ")
                .map(|c| format!("r.{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .bind(client_row_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn grant(
        &self,
        client_row_id: Uuid,
        resource_id: Uuid,
        granted_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO client_resources (client_id, resource_id, granted_at) \
             VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE client_id = client_id",
        )
        .bind(client_row_id.to_string())
        .bind(resource_id.to_string())
        .bind(granted_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            // 存在しないクライアント・宛名（FK 違反）は入力の誤り。
            sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                DomainError::InvalidValue("unknown client or resource".to_string())
            }
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }

    async fn revoke(&self, client_row_id: Uuid, resource_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM client_resources WHERE client_id = ? AND resource_id = ?")
            .bind(client_row_id.to_string())
            .bind(resource_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn is_granted(&self, client_row_id: Uuid, resource_id: Uuid) -> Result<bool> {
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM client_resources WHERE client_id = ? AND resource_id = ?",
        )
        .bind(client_row_id.to_string())
        .bind(resource_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(found.is_some())
    }
}
