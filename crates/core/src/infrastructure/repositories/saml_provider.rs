//! `SamlIdentityProviderRepository` の sqlx 実装。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SamlIdentityProviderRepository;
use crate::domain::saml_provider::SamlIdentityProvider;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxSamlIdentityProviderRepository {
    pool: Db,
}

impl SqlxSamlIdentityProviderRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn map_row(row: &MySqlRow) -> Result<SamlIdentityProvider> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    Ok(SamlIdentityProvider {
        id: Uuid::parse_str(&id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{id}`: {e}")))?,
        tenant_id: Uuid::parse_str(&tenant_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{tenant_id}`: {e}")))?
            .into(),
        display_name: row.try_get("display_name").map_err(repo_err)?,
        entity_id: row.try_get("entity_id").map_err(repo_err)?,
        sso_url: row.try_get("sso_url").map_err(repo_err)?,
        x509_certificate: row.try_get("x509_certificate").map_err(repo_err)?,
        enabled: row.try_get("enabled").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl SamlIdentityProviderRepository for SqlxSamlIdentityProviderRepository {
    async fn create(&self, provider: &SamlIdentityProvider) -> Result<()> {
        let result = sqlx::query(
            "INSERT INTO saml_identity_providers \
             (id, tenant_id, display_name, entity_id, sso_url, x509_certificate, enabled, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(provider.id.to_string())
        .bind(provider.tenant_id.as_uuid().to_string())
        .bind(&provider.display_name)
        .bind(&provider.entity_id)
        .bind(&provider.sso_url)
        .bind(&provider.x509_certificate)
        .bind(provider.enabled)
        .bind(provider.created_at.naive_utc())
        .bind(provider.updated_at.naive_utc())
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
                Err(DomainError::Conflict(
                    "SAML provider entity_id already exists in this tenant".to_string(),
                ))
            }
            Err(e) => Err(repo_err(e)),
        }
    }

    async fn latest_for_tenant(&self, tenant_id: TenantId) -> Result<Option<SamlIdentityProvider>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, display_name, entity_id, sso_url, x509_certificate, enabled, created_at, updated_at \
             FROM saml_identity_providers WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id.as_uuid().to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<SamlIdentityProvider>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, display_name, entity_id, sso_url, x509_certificate, enabled, created_at, updated_at \
             FROM saml_identity_providers WHERE tenant_id = ? ORDER BY created_at DESC",
        )
        .bind(tenant_id.as_uuid().to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }
}
