//! `ClientConsentRepository` の sqlx 実装（F3: Consent）。

use crate::domain::consent::ClientConsent;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::ClientConsentRepository;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxClientConsentRepository {
    pool: Db,
}

impl SqlxClientConsentRepository {
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

fn map_row(row: &MySqlRow) -> Result<ClientConsent> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let scopes_raw: Vec<u8> = row.try_get("scopes").map_err(repo_err)?;
    Ok(ClientConsent {
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        tenant_id: Uuid::parse_str(&tenant_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{tenant_id}`: {e}")))?
            .into(),
        client_id: row.try_get("client_id").map_err(repo_err)?,
        scopes: serde_json::from_slice(&scopes_raw)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `scopes`: {e}")))?,
        granted_at: to_utc(row.try_get("granted_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl ClientConsentRepository for SqlxClientConsentRepository {
    async fn find(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<Option<ClientConsent>> {
        let row = sqlx::query(
            "SELECT user_id, tenant_id, client_id, scopes, granted_at, updated_at \
             FROM client_consents WHERE user_id = ? AND tenant_id = ? AND client_id = ?",
        )
        .bind(user_id.to_string())
        .bind(tenant_id.to_string())
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;

        row.map(|r| map_row(&r)).transpose()
    }

    async fn upsert(&self, consent: &ClientConsent) -> Result<()> {
        let scopes_json =
            serde_json::to_string(&consent.scopes).map_err(|e| repo_err(format!("{e}")))?;
        sqlx::query(
            "INSERT INTO client_consents \
             (user_id, tenant_id, client_id, scopes, granted_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE scopes = VALUES(scopes), updated_at = VALUES(updated_at)",
        )
        .bind(consent.user_id.to_string())
        .bind(consent.tenant_id.to_string())
        .bind(&consent.client_id)
        .bind(scopes_json)
        .bind(consent.granted_at)
        .bind(consent.updated_at)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, client_id: &str) -> Result<()> {
        sqlx::query(
            "DELETE FROM client_consents WHERE user_id = ? AND tenant_id = ? AND client_id = ?",
        )
        .bind(user_id.to_string())
        .bind(tenant_id.to_string())
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> Result<Vec<ClientConsent>> {
        let rows = sqlx::query(
            "SELECT user_id, tenant_id, client_id, scopes, granted_at, updated_at \
             FROM client_consents WHERE user_id = ? AND tenant_id = ? ORDER BY updated_at DESC",
        )
        .bind(user_id.to_string())
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;

        rows.iter().map(map_row).collect()
    }
}
