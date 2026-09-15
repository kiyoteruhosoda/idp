//! `ApplicationRepository` の sqlx 実装（ADR-0054）。
//! UUID は CHAR(36) 正準文字列で入出力する。

use crate::domain::application::{
    Application, ApplicationAssignment, ApplicationBinding, BindingTarget,
};
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::ApplicationRepository;
use crate::domain::tenant::TenantId;
use crate::domain::values::{ApplicationStatus, AssignmentMode};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use uuid::Uuid;

pub struct SqlxApplicationRepository {
    pool: Db,
}

impl SqlxApplicationRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

const SELECT_COLUMNS: &str =
    "id, tenant_id, display_name, status, assignment_mode, created_at, updated_at";

/// 別名（`a.`）付きの SELECT 句。join する問い合わせで列名が曖昧にならないようにする。
fn aliased_columns(alias: &str) -> String {
    SELECT_COLUMNS
        .split(", ")
        .map(|c| format!("{alias}.{c}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(raw: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| DomainError::Repository(format!("invalid UUID `{raw}`: {e}")))
}

fn map_application(row: &MySqlRow) -> Result<Application> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    let assignment_mode: String = row.try_get("assignment_mode").map_err(repo_err)?;
    Ok(Application {
        id: parse_uuid(&id)?,
        tenant_id: TenantId::from(parse_uuid(&tenant_id)?),
        display_name: row.try_get("display_name").map_err(repo_err)?,
        status: ApplicationStatus::parse(&status).map_err(|_| {
            DomainError::Repository(format!("invalid application status `{status}`"))
        })?,
        assignment_mode: AssignmentMode::parse(&assignment_mode).map_err(|_| {
            DomainError::Repository(format!("invalid assignment mode `{assignment_mode}`"))
        })?,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

fn map_binding(row: &MySqlRow) -> Result<ApplicationBinding> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let application_id: String = row.try_get("application_id").map_err(repo_err)?;
    let protocol: String = row.try_get("protocol").map_err(repo_err)?;
    let client_id: Option<String> = row.try_get("client_id").map_err(repo_err)?;
    let service_provider_id: Option<String> =
        row.try_get("service_provider_id").map_err(repo_err)?;
    // DB 側の CHECK 制約と同じことをここでも言う。片方だけが埋まっている前提が崩れた行は、
    // 黙って片方を使うのではなくリポジトリエラーにする（表せてはいけない状態をドメインへ通さない）。
    let target = match (protocol.as_str(), client_id, service_provider_id) {
        ("oidc", Some(client), None) => BindingTarget::Oidc {
            client_row_id: parse_uuid(&client)?,
        },
        ("saml", None, Some(provider)) => BindingTarget::Saml {
            service_provider_id: parse_uuid(&provider)?,
        },
        (other, _, _) => {
            return Err(DomainError::Repository(format!(
                "application binding `{id}` has an inconsistent target for protocol `{other}`"
            )))
        }
    };
    Ok(ApplicationBinding {
        id: parse_uuid(&id)?,
        application_id: parse_uuid(&application_id)?,
        target,
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
    })
}

fn map_assignment(row: &MySqlRow) -> Result<ApplicationAssignment> {
    let application_id: String = row.try_get("application_id").map_err(repo_err)?;
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let assigned_by: Option<String> = row.try_get("assigned_by").map_err(repo_err)?;
    Ok(ApplicationAssignment {
        application_id: parse_uuid(&application_id)?,
        user_id: parse_uuid(&user_id)?,
        assigned_at: to_utc(row.try_get("assigned_at").map_err(repo_err)?),
        assigned_by: assigned_by.as_deref().map(parse_uuid).transpose()?,
    })
}

#[async_trait]
impl ApplicationRepository for SqlxApplicationRepository {
    async fn create(&self, application: &Application) -> Result<()> {
        sqlx::query(&format!(
            "INSERT INTO applications ({SELECT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ))
        .bind(application.id.to_string())
        .bind(application.tenant_id.to_string())
        .bind(&application.display_name)
        .bind(application.status.as_str())
        .bind(application.assignment_mode.as_str())
        .bind(application.created_at)
        .bind(application.updated_at)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(&self, tenant_id: TenantId, id: Uuid) -> Result<Option<Application>> {
        let row = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM applications WHERE id = ? AND tenant_id = ?"
        ))
        .bind(id.to_string())
        .bind(tenant_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_application).transpose()
    }

    /// `clients.client_id`（テナント内一意の文字列）→ binding → アプリ、を 1 往復で解く。
    /// 認可のたびに引くため、client を読んでからアプリを読む 2 往復にはしない。
    async fn find_by_oidc_client_id(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Application>> {
        let row = sqlx::query(&format!(
            "SELECT {} FROM applications a \
             JOIN application_bindings b ON b.application_id = a.id \
             JOIN clients c ON c.id = b.client_id \
             WHERE a.tenant_id = ? AND c.tenant_id = ? AND c.client_id = ?",
            aliased_columns("a")
        ))
        .bind(tenant_id.to_string())
        .bind(tenant_id.to_string())
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_application).transpose()
    }

    async fn find_by_saml_entity_id(
        &self,
        tenant_id: TenantId,
        entity_id: &str,
    ) -> Result<Option<Application>> {
        let row = sqlx::query(&format!(
            "SELECT {} FROM applications a \
             JOIN application_bindings b ON b.application_id = a.id \
             JOIN saml_service_providers s ON s.id = b.service_provider_id \
             WHERE a.tenant_id = ? AND s.tenant_id = ? AND s.entity_id = ?",
            aliased_columns("a")
        ))
        .bind(tenant_id.to_string())
        .bind(tenant_id.to_string())
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        row.as_ref().map(map_application).transpose()
    }

    async fn list(&self, tenant_id: TenantId) -> Result<Vec<Application>> {
        let rows = sqlx::query(&format!(
            "SELECT {SELECT_COLUMNS} FROM applications WHERE tenant_id = ? ORDER BY display_name, id"
        ))
        .bind(tenant_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_application).collect()
    }

    /// `tenant_id` も条件に入れる（id だけで更新できると、root の管理者が他テナントのアプリを
    /// 止められる）。
    async fn update(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        display_name: &str,
        status: ApplicationStatus,
        assignment_mode: AssignmentMode,
        updated_at: DateTime<Utc>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE applications \
             SET display_name = ?, status = ?, assignment_mode = ?, updated_at = ? \
             WHERE id = ? AND tenant_id = ?",
        )
        .bind(display_name)
        .bind(status.as_str())
        .bind(assignment_mode.as_str())
        .bind(updated_at)
        .bind(id.to_string())
        .bind(tenant_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, tenant_id: TenantId, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM applications WHERE id = ? AND tenant_id = ?")
            .bind(id.to_string())
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_bindings(&self, application_id: Uuid) -> Result<Vec<ApplicationBinding>> {
        let rows = sqlx::query(
            "SELECT id, application_id, protocol, client_id, service_provider_id, created_at \
             FROM application_bindings WHERE application_id = ? ORDER BY created_at, id",
        )
        .bind(application_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_binding).collect()
    }

    /// 一意制約違反は `Conflict`。「その client は既に別のアプリに繋がっている」であって、
    /// 呼び出し側の不具合ではない（管理画面がそのまま出せる失敗）。
    async fn add_binding(&self, binding: &ApplicationBinding) -> Result<()> {
        let (client_id, service_provider_id) = match binding.target {
            BindingTarget::Oidc { client_row_id } => (Some(client_row_id.to_string()), None),
            BindingTarget::Saml {
                service_provider_id,
            } => (None, Some(service_provider_id.to_string())),
        };
        sqlx::query(
            "INSERT INTO application_bindings \
             (id, application_id, protocol, client_id, service_provider_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(binding.id.to_string())
        .bind(binding.application_id.to_string())
        .bind(binding.target.protocol())
        .bind(client_id)
        .bind(service_provider_id)
        .bind(binding.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => DomainError::Conflict(
                "the protocol configuration is already bound to an application".to_string(),
            ),
            _ => DomainError::Repository(e.to_string()),
        })?;
        Ok(())
    }

    async fn remove_binding(&self, application_id: Uuid, binding_id: Uuid) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM application_bindings WHERE id = ? AND application_id = ?")
                .bind(binding_id.to_string())
                .bind(application_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(repo_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn is_assigned(&self, application_id: Uuid, user_id: Uuid) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM application_assignments WHERE application_id = ? AND user_id = ?",
        )
        .bind(application_id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(row.is_some())
    }

    async fn list_assignments(&self, application_id: Uuid) -> Result<Vec<ApplicationAssignment>> {
        let rows = sqlx::query(
            "SELECT application_id, user_id, assigned_at, assigned_by \
             FROM application_assignments WHERE application_id = ? ORDER BY assigned_at, user_id",
        )
        .bind(application_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;
        rows.iter().map(map_assignment).collect()
    }

    async fn count_assignments(&self, application_id: Uuid) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS assigned FROM application_assignments WHERE application_id = ?",
        )
        .bind(application_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(repo_err)?;
        row.try_get("assigned").map_err(repo_err)
    }

    /// 冪等（既存の割り当ては `assigned_at` も `assigned_by` も保持する）。割り当て直しで
    /// 「いつから使えるのか」が書き換わると、監査でさかのぼれなくなる。
    async fn assign(&self, assignment: &ApplicationAssignment) -> Result<()> {
        sqlx::query(
            "INSERT INTO application_assignments \
             (application_id, user_id, assigned_at, assigned_by) VALUES (?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE application_id = application_id",
        )
        .bind(assignment.application_id.to_string())
        .bind(assignment.user_id.to_string())
        .bind(assignment.assigned_at)
        .bind(assignment.assigned_by.map(|id| id.to_string()))
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(())
    }

    async fn unassign(&self, application_id: Uuid, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM application_assignments WHERE application_id = ? AND user_id = ?")
            .bind(application_id.to_string())
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
}
