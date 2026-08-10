//! `UserLoginIdentifierRepository` の sqlx 実装（AP8）。

use crate::domain::error::{DomainError, Result};
use crate::domain::login_identifier::{LoginIdentifierType, UserLoginIdentifier};
use crate::domain::repositories::UserLoginIdentifierRepository;
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

/// `is_primary` は列ではなく `primary_of_user`（主なら自分の user_id、そうでなければ NULL）から
/// 導く。同じ事実を 2 列に持つと片方だけ更新される余地が生まれるため、DB 側の単一の出所は
/// `primary_of_user`（UNIQUE が「1 利用者 1 行」を守る）だけにしてある。
const SELECT_COLUMNS: &str = "id, tenant_id, user_id, identifier_type, display_value, \
     normalized_value, is_active, primary_of_user IS NOT NULL AS is_primary, \
     created_at, updated_at";

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
        // MariaDB の真偽式は 1/0 の整数で返る。
        is_primary: row.try_get::<i64, _>("is_primary").map_err(repo_err)? != 0,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

#[async_trait]
impl UserLoginIdentifierRepository for SqlxUserLoginIdentifierRepository {
    async fn create(&self, identifier: &UserLoginIdentifier) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_login_identifiers \
             (id, tenant_id, user_id, identifier_type, display_value, normalized_value, \
              is_active, primary_of_user) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(identifier.id.to_string())
        .bind(identifier.tenant_id.to_string())
        .bind(identifier.user_id.to_string())
        .bind(identifier.identifier_type.as_str())
        .bind(&identifier.display_value)
        .bind(&identifier.normalized_value)
        .bind(identifier.is_active)
        .bind(
            identifier
                .is_primary
                .then(|| identifier.user_id.to_string()),
        )
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
        // 主識別子は識別子単位で止められない（止めるとログインできなくなる。止めるなら
        // アカウントの無効化を使う）。条件に含めて DB 側で弾く。
        let result = sqlx::query(
            "UPDATE user_login_identifiers SET is_active = ? \
             WHERE id = ? AND user_id = ? AND primary_of_user IS NULL",
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
        // 主識別子は識別子単位で消せない（消すとログインできなくなる。変えるならプロフィール編集）。
        let result = sqlx::query(
            "DELETE FROM user_login_identifiers WHERE id = ? AND user_id = ? \
             AND primary_of_user IS NULL",
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }
}
