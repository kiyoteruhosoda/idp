//! `TenantSettingsRepository` の sqlx 実装（ADR-0058）。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TenantSettingsRepository;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_setting::{
    TenantOverrideEntry, TenantOverridesAcrossTenants, TenantSetting,
};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use sqlx::mysql::MySqlRow;
use sqlx::Row;

pub struct SqlxTenantSettingsRepository {
    pool: Db,
}

impl SqlxTenantSettingsRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn map_row(tenant_id: TenantId, row: &MySqlRow) -> Result<TenantSetting> {
    let is_secret: i8 = row.try_get("is_secret").map_err(repo_err)?;
    Ok(TenantSetting {
        tenant_id,
        key: row.try_get("setting_key").map_err(repo_err)?,
        value: row.try_get("setting_value").map_err(repo_err)?,
        is_secret: is_secret != 0,
    })
}

#[async_trait]
impl TenantSettingsRepository for SqlxTenantSettingsRepository {
    /// 主キー `(tenant_id, setting_key)` の前方一致 1 本。⚠ **テナントをまたいで読まない**
    /// ——テナント分離はアプリ層が唯一の防御線であり（ADR-0009 §8）、設定の読みは
    /// リクエストごとのホットパスなので、ここを緩めると気付けない。
    async fn load_for_tenant(&self, tenant_id: TenantId) -> Result<Vec<TenantSetting>> {
        let rows = sqlx::query(
            "SELECT setting_key, setting_value, is_secret FROM tenant_settings \
             WHERE tenant_id = ?",
        )
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(|row| map_row(tenant_id, row)).collect()
    }

    async fn upsert(&self, setting: &TenantSetting) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
             VALUES (?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), \
                                     is_secret = VALUES(is_secret)",
        )
        .bind(setting.tenant_id.to_string())
        .bind(&setting.key)
        .bind(&setting.value)
        .bind(if setting.is_secret { 1i8 } else { 0i8 })
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    /// 上書きを消す（＝そのキーは全体に従う状態へ戻る）。不存在は冪等に無視する。
    async fn delete(&self, tenant_id: TenantId, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM tenant_settings WHERE tenant_id = ? AND setting_key = ?")
            .bind(tenant_id.to_string())
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn list_overrides_across_tenants(&self) -> Result<TenantOverridesAcrossTenants> {
        let tenant_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
            .fetch_one(&self.pool)
            .await
            .map_err(repo_err)?;
        // 秘匿値は SQL の時点で落とす（暗号文を全体の画面へ運ばない）。
        let rows = sqlx::query(
            "SELECT s.tenant_id, t.name, s.setting_key, s.setting_value \
             FROM tenant_settings s JOIN tenants t ON t.id = s.tenant_id \
             WHERE s.is_secret = 0 AND s.setting_value <> '' \
             ORDER BY s.setting_key, t.name, s.tenant_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        let overrides = rows
            .iter()
            .map(|row| {
                let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
                Ok(TenantOverrideEntry {
                    tenant_id: tenant_id.parse::<uuid::Uuid>().map_err(repo_err)?.into(),
                    tenant_name: row.try_get("name").map_err(repo_err)?,
                    key: row.try_get("setting_key").map_err(repo_err)?,
                    value: row.try_get("setting_value").map_err(repo_err)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(TenantOverridesAcrossTenants {
            tenant_count: u64::try_from(tenant_count).unwrap_or(0),
            overrides,
        })
    }
}
