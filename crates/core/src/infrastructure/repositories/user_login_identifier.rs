//! `UserLoginIdentifierRepository` の sqlx 実装（AP8）。

use crate::domain::error::{DomainError, Result};
use crate::domain::login_identifier::{LoginIdentifierType, UserLoginIdentifier};
use crate::domain::repositories::UserLoginIdentifierRepository;
use crate::domain::tenant::TenantId;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxUserLoginIdentifierRepository {
    pool: Db,
}

impl SqlxUserLoginIdentifierRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str = "id, tenant_id, user_id, identifier_type, display_value, \
     normalized_value, is_active, created_at, updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(value: &str, column: &str) -> Result<Uuid> {
    Uuid::parse_str(value)
        .map_err(|e| DomainError::Repository(format!("invalid UUID in `{column}`: {e}")))
}

pub(crate) fn map_row(row: &MySqlRow) -> Result<UserLoginIdentifier> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let identifier_type: String = row.try_get("identifier_type").map_err(repo_err)?;
    Ok(UserLoginIdentifier {
        id: parse_uuid(&id, "id")?,
        tenant_id: parse_uuid(&tenant_id, "tenant_id")?.into(),
        user_id: parse_uuid(&user_id, "user_id")?,
        identifier_type: LoginIdentifierType::parse(&identifier_type)?,
        display_value: row.try_get("display_value").map_err(repo_err)?,
        normalized_value: row.try_get("normalized_value").map_err(repo_err)?,
        is_active: row.try_get("is_active").map_err(repo_err)?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl UserLoginIdentifierRepository for SqlxUserLoginIdentifierRepository {
    async fn create(&self, identifier: &UserLoginIdentifier) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_login_identifiers \
             (id, tenant_id, user_id, identifier_type, display_value, normalized_value, is_active) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(identifier.id.to_string())
        .bind(identifier.tenant_id.to_string())
        .bind(identifier.user_id.to_string())
        .bind(identifier.identifier_type.as_str())
        .bind(&identifier.display_value)
        .bind(&identifier.normalized_value)
        .bind(identifier.is_active)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("login identifier already exists".to_string())
            }
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<UserLoginIdentifier>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM user_login_identifiers \
             WHERE user_id = ? ORDER BY identifier_type, created_at, id"
        );
        let rows = sqlx::query(&sql)
            .bind(user_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(map_row).collect()
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<UserLoginIdentifier>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM user_login_identifiers WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn set_active(&self, id: Uuid, user_id: Uuid, is_active: bool) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE user_login_identifiers SET is_active = ? WHERE id = ? AND user_id = ?",
        )
        .bind(is_active)
        .bind(id.to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM user_login_identifiers WHERE id = ? AND user_id = ?")
            .bind(id.to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn sync_derived(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        identifier_type: LoginIdentifierType,
        value: Option<&str>,
        id: Uuid,
    ) -> Result<()> {
        let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
            sqlx::query(
                "DELETE FROM user_login_identifiers WHERE user_id = ? AND identifier_type = ?",
            )
            .bind(user_id.to_string())
            .bind(identifier_type.as_str())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
            return Ok(());
        };
        let normalized = identifier_type.normalize(raw);

        // 「消してから入れる」ではなく「更新して、無ければ入れる」にする。消してから入れる間に
        // ログインが来ると、その一瞬だけ登録簿に行が無くなる（フォールバック先の
        // `users.preferred_username` は既に新しい値なので実害は無いが、無効化していた行の
        // `is_active` まで復活してしまうのを避けたい）。
        let updated = sqlx::query(
            "UPDATE user_login_identifiers SET display_value = ?, normalized_value = ? \
             WHERE user_id = ? AND identifier_type = ?",
        )
        .bind(raw)
        .bind(&normalized)
        .bind(user_id.to_string())
        .bind(identifier_type.as_str())
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("login identifier already exists".to_string())
            }
            _ => DomainError::Repository(e.to_string()),
        })?;
        if updated.rows_affected() > 0 {
            return Ok(());
        }

        sqlx::query(
            "INSERT INTO user_login_identifiers \
             (id, tenant_id, user_id, identifier_type, display_value, normalized_value, is_active) \
             VALUES (?, ?, ?, ?, ?, ?, 1)",
        )
        .bind(id.to_string())
        .bind(tenant_id.to_string())
        .bind(user_id.to_string())
        .bind(identifier_type.as_str())
        .bind(raw)
        .bind(&normalized)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("login identifier already exists".to_string())
            }
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }
}
