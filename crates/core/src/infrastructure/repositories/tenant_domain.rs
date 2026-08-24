//! `TenantDomainRepository` の sqlx 実装（ADR-0029）。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TenantDomainRepository;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_domain::TenantDomain;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxTenantDomainRepository {
    pool: Db,
}

impl SqlxTenantDomainRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, tenant_id, domain, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(raw: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| DomainError::Repository(format!("invalid UUID `{raw}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<TenantDomain> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    Ok(TenantDomain {
        id: parse_uuid(&id)?,
        tenant_id: TenantId::from(parse_uuid(&tenant_id)?),
        domain: row.try_get("domain").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl TenantDomainRepository for SqlxTenantDomainRepository {
    /// 一意キー `tenant_domains_domain_uk` の等値検索 1 本。**テナントの状態はここでは見ない** ——
    /// 所属元テナントが `ACTIVE` かは解決の後段（`is_active_member`）が見ており、そちらに寄せると
    /// 「ドメインは引けたがメンバーではない」と「所属元が止まっている」を 1 か所で扱える。
    async fn find_tenant_by_domain(&self, domain: &str) -> Result<Option<TenantId>> {
        let found: Option<String> =
            sqlx::query_scalar("SELECT tenant_id FROM tenant_domains WHERE domain = ?")
                .bind(domain)
                .fetch_optional(&self.pool)
                .await
                .map_err(repo_err)?;
        found
            .map(|raw| parse_uuid(&raw).map(TenantId::from))
            .transpose()
    }

    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantDomain>> {
        let rows = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM tenant_domains WHERE tenant_id = ? ORDER BY domain"
        ))
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn create(&self, domain: &TenantDomain) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_domains (id, tenant_id, domain, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(domain.id.to_string())
        .bind(domain.tenant_id.to_string())
        .bind(&domain.domain)
        .bind(domain.created_at)
        .bind(domain.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            // 一意キーはテナントを含まないので、他テナントが押さえている場合もここへ来る
            // （値そのものは秘密ではないが、どのテナントが持っているかは返さない）。
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("domain is already assigned to a tenant".to_string())
            }
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }

    /// `tenant_id` も条件に入れる。id だけで消せると、root の管理者が誤って（あるいは id を
    /// 取り違えて）他テナントのドメインを解除できてしまう。
    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM tenant_domains WHERE id = ? AND tenant_id = ?")
            .bind(id.to_string())
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }
}
