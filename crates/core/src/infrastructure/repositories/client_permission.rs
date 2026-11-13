//! sqlx implementation of `ClientPermissionRepository` (ADR-0037). UUIDs are read and written as canonical CHAR(36) strings.

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::ClientPermissionRepository;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxClientPermissionRepository {
    pool: Db,
}

impl SqlxClientPermissionRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl ClientPermissionRepository for SqlxClientPermissionRepository {
    async fn list_codes_for_client(&self, client_row_id: Uuid) -> Result<Vec<String>> {
        let rows =
            sqlx::query("SELECT permission_code FROM client_permissions WHERE client_id = ?")
                .bind(client_row_id.to_string())
                .fetch_all(&self.pool)
                .await
                .map_err(repo_err)?;
        rows.iter()
            .map(|row| {
                row.try_get::<String, _>("permission_code")
                    .map_err(repo_err)
            })
            .collect()
    }

    async fn grant(
        &self,
        client_row_id: Uuid,
        code: &str,
        granted_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO client_permissions (client_id, permission_code, granted_at) \
             VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE client_id = client_id",
        )
        .bind(client_row_id.to_string())
        .bind(code)
        .bind(granted_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            // A code missing from the permissions master or a nonexistent client (FK violation) is treated as a bad request.
            sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                DomainError::InvalidValue(format!("unknown permission code or client: {code}"))
            }
            // Blanket admin permissions are rejected by a CHECK constraint (the app layer checks the same; defense in depth).
            sqlx::Error::Database(db) if db.is_check_violation() => DomainError::InvalidValue(
                format!("permission code cannot be granted to a client: {code}"),
            ),
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }

    async fn revoke(&self, client_row_id: Uuid, code: &str) -> Result<()> {
        sqlx::query("DELETE FROM client_permissions WHERE client_id = ? AND permission_code = ?")
            .bind(client_row_id.to_string())
            .bind(code)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
