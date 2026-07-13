//! `UserPermissionRepository` の sqlx 実装（ADR-0006）。UUID は CHAR(36) 正準文字列で入出力する。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::UserPermissionRepository;
use crate::domain::tenant::TenantId;
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

/// user_permissions への付与 INSERT（プール直接実行と provisioning トランザクションで共用する）。
/// 冪等: 既存付与は granted_at を保持する（ON DUPLICATE KEY UPDATE user_id = user_id）。
pub(crate) async fn insert_grant<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::MySql>,
    tenant_id: TenantId,
    user_id: Uuid,
    code: &str,
    granted_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id, granted_at) \
         VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE user_id = user_id",
    )
    .bind(user_id.to_string())
    .bind(code)
    .bind(tenant_id.to_string())
    .bind(granted_at.naive_utc())
    .execute(executor)
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

    async fn list_codes_for_user(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT permission_code FROM user_permissions WHERE user_id = ? AND tenant_id = ?",
        )
        .bind(user_id.to_string())
        .bind(tenant_id.to_string())
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

    async fn has_permission(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM user_permissions \
             WHERE user_id = ? AND permission_code = ? AND tenant_id = ?",
        )
        .bind(user_id.to_string())
        .bind(code)
        .bind(tenant_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(row.is_some())
    }

    async fn has_any_permission(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        codes: &[&str],
    ) -> Result<bool> {
        if codes.is_empty() {
            return Ok(false);
        }
        let placeholders = codes.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT 1 FROM user_permissions \
             WHERE user_id = ? AND tenant_id = ? AND permission_code IN ({placeholders})"
        );
        let mut q = sqlx::query(&sql)
            .bind(user_id.to_string())
            .bind(tenant_id.to_string());
        for code in codes {
            q = q.bind(*code);
        }
        let row = q.fetch_optional(&self.pool).await.map_err(repo_err)?;
        Ok(row.is_some())
    }

    async fn grant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        code: &str,
        granted_at: DateTime<Utc>,
    ) -> Result<()> {
        insert_grant(&self.pool, tenant_id, user_id, code, granted_at).await
    }

    async fn revoke(&self, tenant_id: TenantId, user_id: Uuid, code: &str) -> Result<()> {
        sqlx::query(
            "DELETE FROM user_permissions \
             WHERE user_id = ? AND permission_code = ? AND tenant_id = ?",
        )
        .bind(user_id.to_string())
        .bind(code)
        .bind(tenant_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn revoke_all_for_user_in_tenant(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> Result<Vec<String>> {
        // 剥奪対象コードの読み取りと削除を同一トランザクションで行い、返す一覧と削除行を一致させる。
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        let rows = sqlx::query(
            "SELECT permission_code FROM user_permissions \
             WHERE user_id = ? AND tenant_id = ? FOR UPDATE",
        )
        .bind(user_id.to_string())
        .bind(tenant_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(repo_err)?;
        let codes: Vec<String> = rows
            .iter()
            .map(|row| {
                row.try_get::<String, _>("permission_code")
                    .map_err(repo_err)
            })
            .collect::<Result<_>>()?;
        if !codes.is_empty() {
            sqlx::query("DELETE FROM user_permissions WHERE user_id = ? AND tenant_id = ?")
                .bind(user_id.to_string())
                .bind(tenant_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(repo_err)?;
        }
        tx.commit().await.map_err(repo_err)?;
        Ok(codes)
    }
}
