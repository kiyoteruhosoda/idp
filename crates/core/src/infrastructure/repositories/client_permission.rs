//! `ClientPermissionRepository` の sqlx 実装（ADR-0037）。UUID は CHAR(36) 正準文字列で入出力する。

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
            // permissions マスタに無いコード・存在しないクライアント（FK 違反）は不正リクエスト扱い。
            sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                DomainError::InvalidValue(format!("unknown permission code or client: {code}"))
            }
            // 包括的な管理権限は CHECK 制約が拒む（アプリ層でも同じ判定を行う。二重防御）。
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
