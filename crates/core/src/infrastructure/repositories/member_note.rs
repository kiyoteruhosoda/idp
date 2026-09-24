//! `MemberNoteRepository` の sqlx 実装（ADR-0063）。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::MemberNoteRepository;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct SqlxMemberNoteRepository {
    pool: Db,
}

impl SqlxMemberNoteRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl MemberNoteRepository for SqlxMemberNoteRepository {
    async fn save(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        text: &str,
        updated_by: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_member_notes (tenant_id, user_id, note, updated_at, updated_by) \
             VALUES (?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE note = VALUES(note), updated_at = VALUES(updated_at), \
             updated_by = VALUES(updated_by)",
        )
        .bind(tenant_id.as_uuid().to_string())
        .bind(user_id.to_string())
        .bind(text)
        .bind(now.naive_utc())
        .bind(updated_by.map(|id| id.to_string()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn clear(&self, tenant_id: TenantId, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM tenant_member_notes WHERE tenant_id = ? AND user_id = ?")
            .bind(tenant_id.as_uuid().to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
