//! `SystemSettingsRepository` の sqlx 実装（MT14）。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::SystemSettingsRepository;
use crate::domain::system_setting::SystemSetting;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use sqlx::mysql::MySqlRow;
use sqlx::Row;

pub struct SqlxSystemSettingsRepository {
    pool: Db,
}

impl SqlxSystemSettingsRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn map_row(row: &MySqlRow) -> Result<SystemSetting> {
    let is_secret: i8 = row.try_get("is_secret").map_err(repo_err)?;
    Ok(SystemSetting {
        key: row.try_get("setting_key").map_err(repo_err)?,
        value: row.try_get("setting_value").map_err(repo_err)?,
        is_secret: is_secret != 0,
    })
}

#[async_trait]
impl SystemSettingsRepository for SqlxSystemSettingsRepository {
    async fn load_all(&self) -> Result<Vec<SystemSetting>> {
        let rows = sqlx::query("SELECT setting_key, setting_value, is_secret FROM system_settings")
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn upsert(&self, setting: &SystemSetting) -> Result<()> {
        sqlx::query(
            "INSERT INTO system_settings (setting_key, setting_value, is_secret) \
             VALUES (?, ?, ?) \
             ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), \
                                     is_secret = VALUES(is_secret)",
        )
        .bind(&setting.key)
        .bind(&setting.value)
        .bind(if setting.is_secret { 1i8 } else { 0i8 })
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }
}
