//! `TenantMembershipRepository` の sqlx 実装（ADR-0009 §3）。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TenantMembershipRepository;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::values::{MembershipStatus, MembershipType};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxTenantMembershipRepository {
    pool: Db,
}

impl SqlxTenantMembershipRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "tenant_id, user_id, membership_type, status, invited_by, \
     invitation_token_hash, invitation_expires_at, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(raw: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| DomainError::Repository(format!("invalid UUID `{raw}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<TenantMembership> {
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let membership_type: String = row.try_get("membership_type").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    let invited_by: Option<String> = row.try_get("invited_by").map_err(repo_err)?;
    let invitation_expires_at: Option<NaiveDateTime> =
        row.try_get("invitation_expires_at").map_err(repo_err)?;
    Ok(TenantMembership {
        tenant_id: TenantId::from(parse_uuid(&tenant_id)?),
        user_id: parse_uuid(&user_id)?,
        membership_type: MembershipType::parse(&membership_type)?,
        status: MembershipStatus::parse(&status)?,
        invited_by: invited_by.map(|s| parse_uuid(&s)).transpose()?,
        invitation_token_hash: row.try_get("invitation_token_hash").map_err(repo_err)?,
        invitation_expires_at: invitation_expires_at.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

/// tenant_memberships への INSERT（プール直接実行と provisioning トランザクションで共用する）。
pub(crate) async fn insert_membership<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::MySql>,
    membership: &TenantMembership,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO tenant_memberships \
         (tenant_id, user_id, membership_type, status, invited_by, \
          invitation_token_hash, invitation_expires_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(membership.tenant_id.as_uuid().to_string())
    .bind(membership.user_id.to_string())
    .bind(membership.membership_type.as_str())
    .bind(membership.status.as_str())
    .bind(membership.invited_by.map(|u| u.to_string()))
    .bind(&membership.invitation_token_hash)
    .bind(membership.invitation_expires_at.map(|t| t.naive_utc()))
    .execute(executor)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DomainError::Conflict("membership already exists".to_string())
        }
        _ => DomainError::Repository(e.to_string()),
    })?;
    Ok(())
}

#[async_trait]
impl TenantMembershipRepository for SqlxTenantMembershipRepository {
    async fn create(&self, membership: &TenantMembership) -> Result<()> {
        insert_membership(&self.pool, membership).await
    }

    async fn find(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Option<TenantMembership>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?"
        );
        let row = sqlx::query(&sql)
            .bind(tenant_id.as_uuid().to_string())
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantMembership>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM tenant_memberships WHERE tenant_id = ? ORDER BY created_at"
        );
        let rows = sqlx::query(&sql)
            .bind(tenant_id.as_uuid().to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn list_active_for_user(&self, user_id: Uuid) -> Result<Vec<TenantMembership>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM tenant_memberships \
             WHERE user_id = ? AND status = 'ACTIVE' ORDER BY membership_type, created_at"
        );
        let rows = sqlx::query(&sql)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn is_active_member(&self, tenant_id: TenantId, user_id: Uuid) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM tenant_memberships WHERE tenant_id = ? AND user_id = ? AND status = 'ACTIVE'",
        )
        .bind(tenant_id.as_uuid().to_string())
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(row.is_some())
    }

    async fn find_by_invitation_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<TenantMembership>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM tenant_memberships \
             WHERE invitation_token_hash = ? AND status = 'INVITED'"
        );
        let row = sqlx::query(&sql)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn activate(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE tenant_memberships \
             SET status = 'ACTIVE', invitation_token_hash = NULL, invitation_expires_at = NULL \
             WHERE tenant_id = ? AND user_id = ?",
        )
        .bind(tenant_id.as_uuid().to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?")
            .bind(tenant_id.as_uuid().to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
