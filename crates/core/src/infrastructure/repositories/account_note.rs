//! `AccountNoteRepository` の sqlx 実装（ADR-0063 / ADR-0065）。

use crate::domain::account::AccountRef;
use crate::domain::error::{DomainError, Result};
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::AccountNoteRepository;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

pub struct SqlxAccountNoteRepository {
    pool: Db,
    ids: Arc<dyn IdGenerator>,
}

impl SqlxAccountNoteRepository {
    pub fn new(pool: Db, ids: Arc<dyn IdGenerator>) -> Self {
        Self { pool, ids }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl AccountNoteRepository for SqlxAccountNoteRepository {
    async fn save(
        &self,
        tenant_id: TenantId,
        account: AccountRef,
        text: &str,
        updated_by: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        // 種類ごとの UNIQUE（`(tenant_id, user_id)` / `(tenant_id, client_id)`）に当たれば置き換える。
        // `id` は最初に書いたときのものを残す。
        sqlx::query(
            "INSERT INTO account_notes \
             (id, tenant_id, kind, user_id, client_id, note, updated_at, updated_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE note = VALUES(note), updated_at = VALUES(updated_at), \
             updated_by = VALUES(updated_by)",
        )
        .bind(self.ids.new_id().to_string())
        .bind(tenant_id.as_uuid().to_string())
        .bind(account.kind())
        .bind(account.user_id().map(|id| id.to_string()))
        .bind(account.client_row_id().map(|id| id.to_string()))
        .bind(text)
        .bind(now.naive_utc())
        .bind(updated_by.map(|id| id.to_string()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn clear(&self, tenant_id: TenantId, account: AccountRef) -> Result<()> {
        let (column, id) = match account {
            AccountRef::User { user_id } => ("user_id", user_id),
            AccountRef::ServiceAccount { client_row_id } => ("client_id", client_row_id),
        };
        sqlx::query(&format!(
            "DELETE FROM account_notes WHERE tenant_id = ? AND {column} = ?"
        ))
        .bind(tenant_id.as_uuid().to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }
}
