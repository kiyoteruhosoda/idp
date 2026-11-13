//! sqlx implementation of `UserSshKeyRepository` (task #885, ADR-0072).
//!
//! Only the public key is stored (type, body, fingerprint). The comment of the pasted line is not stored.

use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::UserSshKeyRepository;
use crate::domain::ssh_key::{DistributedSshKey, SshKeyType, SshPublicKey, UserSshKey};
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxUserSshKeyRepository {
    pool: Db,
}

impl SqlxUserSshKeyRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str =
    "id, tenant_id, user_id, name, key_type, key_blob, fingerprint, created_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(raw: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| DomainError::Repository(format!("invalid UUID `{raw}`: {e}")))
}

fn map_key(row: &MySqlRow) -> Result<SshPublicKey> {
    let key_type: String = row.try_get("key_type").map_err(repo_err)?;
    let key_type = SshKeyType::parse(&key_type).ok_or_else(|| {
        DomainError::Repository(format!(
            "unknown SSH key type `{key_type}` in user_ssh_keys"
        ))
    })?;
    Ok(SshPublicKey::from_stored(
        key_type,
        row.try_get("key_blob").map_err(repo_err)?,
        row.try_get("fingerprint").map_err(repo_err)?,
    ))
}

fn map_row(row: &MySqlRow) -> Result<UserSshKey> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    Ok(UserSshKey {
        id: parse_uuid(&id)?,
        tenant_id: TenantId::from(parse_uuid(&tenant_id)?),
        user_id: parse_uuid(&user_id)?,
        name: row.try_get("name").map_err(repo_err)?,
        key: map_key(row)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl UserSshKeyRepository for SqlxUserSshKeyRepository {
    async fn list_for_user(&self, tenant_id: TenantId, user_id: Uuid) -> Result<Vec<UserSshKey>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_ssh_keys WHERE tenant_id = ? AND user_id = ? \
             ORDER BY created_at DESC, id DESC"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(tenant_id.to_string())
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn insert(&self, key: &UserSshKey) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_ssh_keys \
             (id, tenant_id, user_id, name, key_type, key_blob, fingerprint, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(key.id.to_string())
        .bind(key.tenant_id.to_string())
        .bind(key.user_id.to_string())
        .bind(&key.name)
        .bind(key.key.key_type().as_str())
        .bind(key.key.blob())
        .bind(key.key.fingerprint())
        .bind(key.created_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("SSH key is already registered".to_string())
            }
            other => repo_err(other),
        })?;
        Ok(())
    }

    async fn delete(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        key_id: Uuid,
    ) -> Result<Option<UserSshKey>> {
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_ssh_keys \
             WHERE id = ? AND tenant_id = ? AND user_id = ? FOR UPDATE"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(key_id.to_string())
            .bind(tenant_id.to_string())
            .bind(user_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(repo_err)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let key = map_row(&row)?;
        sqlx::query("DELETE FROM user_ssh_keys WHERE id = ?")
            .bind(key_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        Ok(Some(key))
    }

    async fn list_distributable(&self, tenant_id: TenantId) -> Result<Vec<DistributedSshKey>> {
        // Only keys of active users (not provisional) who are active members of the org (the home tenant also has a HOME row)
        // and who have a username. Without a username, the distributor cannot map them to a machine user.
        // The username is the registry's primary identifier (`user_login_identifiers.primary_of_user`; `users` has no column).
        let rows = sqlx::query(
            "SELECT p.display_value AS username, k.name, k.key_type, k.key_blob, \
                    k.fingerprint, k.created_at \
             FROM user_ssh_keys k \
             JOIN users u ON u.id = k.user_id \
                 AND u.status = 'ACTIVE' AND u.pending_setup = 0 \
             JOIN user_login_identifiers p ON p.primary_of_user = k.user_id \
                 AND p.display_value <> '' \
             JOIN tenant_memberships m ON m.tenant_id = k.tenant_id AND m.user_id = k.user_id \
                 AND m.status = 'ACTIVE' \
             WHERE k.tenant_id = ? \
             ORDER BY p.display_value, k.created_at, k.id",
        )
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter()
            .map(|row| {
                Ok(DistributedSshKey {
                    username: row.try_get("username").map_err(repo_err)?,
                    name: row.try_get("name").map_err(repo_err)?,
                    key: map_key(row)?,
                    created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
                })
            })
            .collect()
    }
}
