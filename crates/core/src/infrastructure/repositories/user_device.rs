//! `UserDeviceRepository` の sqlx 実装（task #872。ADR-0071）。
//!
//! DB に置くのは端末の印の SHA-256 だけ（[`DeviceRef`]）。印の平文は持たない。

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::UserDeviceRepository;
use crate::domain::user_device::{CountryCode, DeviceRef, UserDevice};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxUserDeviceRepository {
    pool: Db,
}

impl SqlxUserDeviceRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, user_id, device_hash, name, user_agent, registered_at, \
     last_used_at, last_country, last_ip";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(raw: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| DomainError::Repository(format!("invalid UUID `{raw}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<UserDevice> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let country: Option<String> = row.try_get("last_country").map_err(repo_err)?;
    Ok(UserDevice {
        id: parse_uuid(&id)?,
        user_id: parse_uuid(&user_id)?,
        device: DeviceRef::from_hash(row.try_get("device_hash").map_err(repo_err)?),
        name: row.try_get("name").map_err(repo_err)?,
        user_agent: row.try_get("user_agent").map_err(repo_err)?,
        registered_at: to_utc(row.try_get("registered_at").map_err(repo_err)?),
        last_used_at: to_utc(row.try_get("last_used_at").map_err(repo_err)?),
        last_country: country.as_deref().and_then(CountryCode::parse),
        last_ip: row.try_get("last_ip").map_err(repo_err)?,
    })
}

/// ブラウザの名乗りは列の長さに切り詰める（長い値で INSERT を落とさない）。
fn clip(value: Option<&str>, max_chars: usize) -> Option<String> {
    value.map(|v| v.chars().take(max_chars).collect())
}

#[async_trait]
impl UserDeviceRepository for SqlxUserDeviceRepository {
    async fn home_members_without_trusted_device(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
    ) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT COALESCE(NULLIF(u.preferred_username, ''), u.email) AS label FROM users u \
             WHERE u.tenant_id = ? AND u.status = 'ACTIVE' AND u.pending_setup = FALSE \
             AND NOT EXISTS (SELECT 1 FROM user_devices d WHERE d.user_id = u.id) \
             AND NOT EXISTS (SELECT 1 FROM app_approver_keys k WHERE k.user_id = u.id) \
             ORDER BY label LIMIT 50",
        )
        .bind(tenant_id.as_uuid().to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter()
            .map(|row| row.try_get::<String, _>("label").map_err(repo_err))
            .collect()
    }

    async fn find(&self, user_id: Uuid, device: &DeviceRef) -> Result<Option<UserDevice>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_devices WHERE user_id = ? AND device_hash = ?"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(user_id.to_string())
            .bind(device.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<UserDevice>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_devices WHERE user_id = ? \
             ORDER BY last_used_at DESC, id DESC"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn insert(&self, device: &UserDevice) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_devices \
             (id, user_id, device_hash, name, user_agent, registered_at, last_used_at, \
              last_country, last_ip) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(device.id.to_string())
        .bind(device.user_id.to_string())
        .bind(device.device.as_str())
        .bind(&device.name)
        .bind(clip(device.user_agent.as_deref(), 512))
        .bind(device.registered_at.naive_utc())
        .bind(device.last_used_at.naive_utc())
        .bind(device.last_country.as_ref().map(CountryCode::as_str))
        .bind(clip(device.last_ip.as_deref(), 45))
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("device is already registered".to_string())
            }
            other => repo_err(other),
        })?;
        Ok(())
    }

    async fn delete(&self, user_id: Uuid, device_id: Uuid) -> Result<Option<UserDevice>> {
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_devices WHERE id = ? AND user_id = ? FOR UPDATE"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(device_id.to_string())
            .bind(user_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(repo_err)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let device = map_row(&row)?;
        sqlx::query("DELETE FROM user_devices WHERE id = ?")
            .bind(device_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        Ok(Some(device))
    }

    async fn touch(
        &self,
        device_id: Uuid,
        used_at: DateTime<Utc>,
        country: Option<&CountryCode>,
        ip: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE user_devices SET last_used_at = ?, last_country = ?, last_ip = ? WHERE id = ?",
        )
        .bind(used_at.naive_utc())
        .bind(country.map(CountryCode::as_str))
        .bind(clip(ip, 45))
        .bind(device_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn delete_unused_before(&self, cutoff: DateTime<Utc>) -> Result<Vec<UserDevice>> {
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        let sql =
            format!("SELECT {SELECT_COLUMNS} FROM user_devices WHERE last_used_at < ? FOR UPDATE");
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(cutoff.naive_utc())
            .fetch_all(&mut *tx)
            .await
            .map_err(repo_err)?;
        let devices = rows.iter().map(map_row).collect::<Result<Vec<_>>>()?;
        for device in &devices {
            sqlx::query("DELETE FROM user_devices WHERE id = ?")
                .bind(device.id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(repo_err)?;
        }
        tx.commit().await.map_err(repo_err)?;
        Ok(devices)
    }

    async fn link_session(
        &self,
        session_hash: &str,
        device: &DeviceRef,
        country: Option<&CountryCode>,
        observed_at: DateTime<Utc>,
    ) -> Result<bool> {
        // 行が無ければ作り、あっても端末が未設定のときだけ書く（パスキーの時刻の行が先にできていることがある）。
        // ⚠ 既に端末が結び付いた行は上書きしない（他人のセッション id を知った者が自分の印で塗り替えない）。
        let inserted = sqlx::query(
            "INSERT IGNORE INTO sso_session_contexts \
             (session_hash, device_hash, country, observed_at) VALUES (?, ?, ?, ?)",
        )
        .bind(session_hash)
        .bind(device.as_str())
        .bind(country.map(CountryCode::as_str))
        .bind(observed_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        if inserted.rows_affected() > 0 {
            return Ok(true);
        }
        let updated = sqlx::query(
            "UPDATE sso_session_contexts SET device_hash = ?, country = ?, observed_at = ? \
             WHERE session_hash = ? AND device_hash IS NULL",
        )
        .bind(device.as_str())
        .bind(country.map(CountryCode::as_str))
        .bind(observed_at.naive_utc())
        .bind(session_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(updated.rows_affected() > 0)
    }

    async fn session_device(&self, session_hash: &str) -> Result<Option<DeviceRef>> {
        let row: Option<Option<String>> = sqlx::query_scalar(
            "SELECT device_hash FROM sso_session_contexts WHERE session_hash = ?",
        )
        .bind(session_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(row.flatten().map(DeviceRef::from_hash))
    }

    async fn seen_before(
        &self,
        user_id: Uuid,
        device: &DeviceRef,
        except_session_hash: &str,
    ) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sso_session_contexts c \
             JOIN sso_sessions s ON s.session_hash = c.session_hash \
             WHERE s.user_id = ? AND c.device_hash = ? AND c.session_hash <> ?",
        )
        .bind(user_id.to_string())
        .bind(device.as_str())
        .bind(except_session_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(count > 0)
    }

    async fn sessions_for_device(&self, user_id: Uuid, device: &DeviceRef) -> Result<Vec<String>> {
        let hashes: Vec<String> = sqlx::query_scalar(
            "SELECT s.session_hash FROM sso_sessions s \
             JOIN sso_session_contexts c ON c.session_hash = s.session_hash \
             WHERE s.user_id = ? AND c.device_hash = ?",
        )
        .bind(user_id.to_string())
        .bind(device.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_values_are_clipped_by_characters() {
        assert_eq!(clip(Some("あいう"), 2).as_deref(), Some("あい"));
        assert_eq!(clip(None, 2), None);
    }
}
