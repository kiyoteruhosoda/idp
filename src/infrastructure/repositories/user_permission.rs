//! `UserPermissionRepository` の sqlx 実装（ADR-0006）。UUID は CHAR(36) 正準文字列で入出力する。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::UserPermissionRepository;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxUserPermissionRepository {
    pool: Db,
}

impl SqlxUserPermissionRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

#[async_trait]
impl UserPermissionRepository for SqlxUserPermissionRepository {
    async fn list_available_codes(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT code FROM permissions ORDER BY code")
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter()
            .map(|row| row.try_get::<String, _>("code").map_err(repo_err))
            .collect()
    }

    async fn list_codes_for_user(&self, user_id: Uuid) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT permission_code FROM user_permissions WHERE user_id = ?")
            .bind(user_id.to_string())
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

    async fn has_permission(&self, user_id: Uuid, code: &str) -> Result<bool> {
        let row =
            sqlx::query("SELECT 1 FROM user_permissions WHERE user_id = ? AND permission_code = ?")
                .bind(user_id.to_string())
                .bind(code)
                .fetch_optional(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(row.is_some())
    }

    async fn grant(&self, user_id: Uuid, code: &str, granted_at: DateTime<Utc>) -> Result<()> {
        // 冪等: 既存付与は granted_at を保持する（ON DUPLICATE KEY UPDATE user_id = user_id）。
        sqlx::query(
            "INSERT INTO user_permissions (user_id, permission_code, granted_at) \
             VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE user_id = user_id",
        )
        .bind(user_id.to_string())
        .bind(code)
        .bind(granted_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            // permission_code が permissions マスタに無い（FK 違反）等は不正リクエスト扱い。
            sqlx::Error::Database(db) if db.is_foreign_key_violation() => {
                DomainError::InvalidValue(format!("unknown permission code or user: {code}"))
            }
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }

    async fn revoke(&self, user_id: Uuid, code: &str) -> Result<()> {
        sqlx::query("DELETE FROM user_permissions WHERE user_id = ? AND permission_code = ?")
            .bind(user_id.to_string())
            .bind(code)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
