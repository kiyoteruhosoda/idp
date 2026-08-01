//! `AuthenticationPolicyRepository` の sqlx 実装（ユーザー認証・認証ポリシー仕様書 §7）。

use crate::domain::authentication_policy::{AuthenticationPolicy, PolicyConditions, PolicyEffect};
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::AuthenticationPolicyRepository;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxAuthenticationPolicyRepository {
    pool: Db,
}

impl SqlxAuthenticationPolicyRepository {
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

/// `(tenant_id, policy_code)` 一意制約違反を `Conflict` へ写像する。
fn map_write_err(e: sqlx::Error) -> DomainError {
    if let Some(db_err) = e.as_database_error() {
        if db_err.is_unique_violation() {
            return DomainError::Conflict("policy code already exists in this tenant".to_string());
        }
    }
    repo_err(e)
}

fn map_row(row: &MySqlRow) -> Result<AuthenticationPolicy> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let effect: String = row.try_get("effect").map_err(repo_err)?;
    let conditions_raw: Vec<u8> = row.try_get("conditions").map_err(repo_err)?;
    Ok(AuthenticationPolicy {
        id: Uuid::parse_str(&id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{id}`: {e}")))?,
        tenant_id: Uuid::parse_str(&tenant_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{tenant_id}`: {e}")))?
            .into(),
        policy_code: row.try_get("policy_code").map_err(repo_err)?,
        policy_name: row.try_get("policy_name").map_err(repo_err)?,
        priority: row.try_get("priority").map_err(repo_err)?,
        enabled: row.try_get::<bool, _>("enabled").map_err(repo_err)?,
        effect: PolicyEffect::parse(&effect)?,
        conditions: serde_json::from_slice::<PolicyConditions>(&conditions_raw)
            .map_err(|e| DomainError::Repository(format!("invalid JSON in `conditions`: {e}")))?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

const SELECT_COLUMNS: &str = "id, tenant_id, policy_code, policy_name, priority, enabled, \
     effect, conditions, created_at, updated_at";

#[async_trait]
impl AuthenticationPolicyRepository for SqlxAuthenticationPolicyRepository {
    async fn create(&self, policy: &AuthenticationPolicy) -> Result<()> {
        let conditions_json = serde_json::to_string(&policy.conditions).map_err(repo_err)?;
        sqlx::query(
            "INSERT INTO authentication_policies \
             (id, tenant_id, policy_code, policy_name, priority, enabled, effect, conditions, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(policy.id.to_string())
        .bind(policy.tenant_id.to_string())
        .bind(&policy.policy_code)
        .bind(&policy.policy_name)
        .bind(policy.priority)
        .bind(policy.enabled)
        .bind(policy.effect.as_str())
        .bind(conditions_json)
        .bind(policy.created_at)
        .bind(policy.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_write_err)?;
        Ok(())
    }

    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<AuthenticationPolicy>> {
        let rows = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM authentication_policies \
             WHERE tenant_id = ? ORDER BY priority ASC, policy_code ASC"
        ))
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn list_enabled_for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<AuthenticationPolicy>> {
        let rows = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM authentication_policies \
             WHERE tenant_id = ? AND enabled = TRUE ORDER BY priority ASC, policy_code ASC"
        ))
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<AuthenticationPolicy>> {
        let row = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM authentication_policies WHERE tenant_id = ? AND id = ?"
        ))
        .bind(tenant_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.map(|r| map_row(&r)).transpose()
    }

    async fn update(&self, policy: &AuthenticationPolicy) -> Result<bool> {
        let conditions_json = serde_json::to_string(&policy.conditions).map_err(repo_err)?;
        let result = sqlx::query(
            "UPDATE authentication_policies SET \
             policy_code = ?, policy_name = ?, priority = ?, enabled = ?, effect = ?, \
             conditions = ?, updated_at = ? \
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(&policy.policy_code)
        .bind(&policy.policy_name)
        .bind(policy.priority)
        .bind(policy.enabled)
        .bind(policy.effect.as_str())
        .bind(conditions_json)
        .bind(policy.updated_at)
        .bind(policy.tenant_id.to_string())
        .bind(policy.id.to_string())
        .execute(&self.pool)
        .await
        .map_err(map_write_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM authentication_policies WHERE tenant_id = ? AND id = ?")
                .bind(tenant_id.to_string())
                .bind(id.to_string())
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }
}
