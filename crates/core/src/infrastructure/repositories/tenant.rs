//! `TenantRepository` の sqlx 実装（ADR-0009 §1）。`is_root` は生成列のため入出力しない。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TenantRepository;
use crate::domain::tenant::{Tenant, TenantId};
use crate::domain::values::TenantStatus;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;

pub struct SqlxTenantRepository {
    pool: Db,
}

impl SqlxTenantRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str =
    "id, parent_tenant_id, name, status, self_registration_enabled, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_id(raw: &str) -> Result<TenantId> {
    uuid::Uuid::parse_str(raw)
        .map(TenantId::from)
        .map_err(|e| DomainError::Repository(format!("invalid UUID `{raw}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<Tenant> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let parent: Option<String> = row.try_get("parent_tenant_id").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    Ok(Tenant {
        id: parse_id(&id)?,
        parent_tenant_id: parent.map(|p| parse_id(&p)).transpose()?,
        name: row.try_get("name").map_err(repo_err)?,
        status: TenantStatus::parse(&status)?,
        self_registration_enabled: row.try_get("self_registration_enabled").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

/// tenants への INSERT（プール直接実行と provisioning トランザクションで共用する）。
pub(crate) async fn insert_tenant<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::MySql>,
    tenant: &Tenant,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status, self_registration_enabled) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenant.id.as_uuid().to_string())
    .bind(tenant.parent_tenant_id.map(|p| p.as_uuid().to_string()))
    .bind(&tenant.name)
    .bind(tenant.status.as_str())
    .bind(tenant.self_registration_enabled)
    .execute(executor)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DomainError::Conflict("a root tenant already exists".to_string())
        }
        _ => DomainError::Repository(e.to_string()),
    })?;
    Ok(())
}

#[async_trait]
impl TenantRepository for SqlxTenantRepository {
    async fn create(&self, tenant: &Tenant) -> Result<()> {
        insert_tenant(&self.pool, tenant).await
    }

    async fn find_by_id(&self, id: TenantId) -> Result<Option<Tenant>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM tenants WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id.as_uuid().to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_root(&self) -> Result<Option<Tenant>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM tenants WHERE parent_tenant_id IS NULL");
        let row = sqlx::query(&sql)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_children(&self, parent_id: TenantId) -> Result<Vec<Tenant>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM tenants WHERE parent_tenant_id = ? ORDER BY created_at"
        );
        let rows = sqlx::query(&sql)
            .bind(parent_id.as_uuid().to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn update(&self, tenant: &Tenant) -> Result<()> {
        sqlx::query(
            "UPDATE tenants SET name = ?, status = ?, self_registration_enabled = ? WHERE id = ?",
        )
        .bind(&tenant.name)
        .bind(tenant.status.as_str())
        .bind(tenant.self_registration_enabled)
        .bind(tenant.id.as_uuid().to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: TenantId) -> Result<()> {
        sqlx::query("DELETE FROM tenants WHERE id = ?")
            .bind(id.as_uuid().to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                    DomainError::Conflict("tenant has child tenants, users, or clients".to_string())
                }
                _ => DomainError::Repository(e.to_string()),
            })?;
        Ok(())
    }
}
