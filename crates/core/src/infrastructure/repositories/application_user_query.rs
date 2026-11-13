//! sqlx implementation of the roster lookup ([`ApplicationUserQuery`]) (ADR-0057).
//!
//! ⚠ **This only reads facts.** What decides "may use" is
//! [`Application::roster_state`](crate::domain::application::Application::roster_state),
//! whose content is the same [`Application::admits`] as the decision (at code issuance). Writing the allow condition
//! in SQL too would put the rule in 2 places, and ⚠ **the roster and the entrance would disagree** ("on the roster but can't get in").
//!
//! The order is fixed to `sub` ascending. `users.sub` is unique across all tenants, so rows are neither duplicated nor
//! missing across pages (unlike email order, it doesn't move when display names change).

use crate::domain::application::ApplicationUserFacts;
use crate::domain::error::{DomainError, Result};
use crate::domain::paging::{Page, PageRequest};
use crate::domain::repositories::{ApplicationUserQuery, SubjectFacts};
use crate::domain::tenant::TenantId;
use crate::domain::values::{MembershipStatus, UserStatus};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};
use uuid::Uuid;

pub struct SqlxApplicationUserQuery {
    pool: Db,
}

impl SqlxApplicationUserQuery {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

/// Maps one row to facts. `assigned` depends on the query (whether the assignment table was consulted), so it is passed as an argument.
fn map_facts(row: &MySqlRow, assigned: Option<bool>) -> Result<SubjectFacts> {
    let sub: String = row.try_get("sub").map_err(repo_err)?;
    let user_status: String = row.try_get("user_status").map_err(repo_err)?;
    let membership_status: Option<String> = row.try_get("membership_status").map_err(repo_err)?;
    let assigned = match assigned {
        Some(fixed) => fixed,
        // MariaDB boolean expressions come back as 0 / 1 integers.
        None => row.try_get::<i64, _>("assigned").map_err(repo_err)? != 0,
    };
    let membership_status = membership_status
        .map(|s| MembershipStatus::parse(&s))
        .transpose()?;
    Ok(SubjectFacts {
        sub: Uuid::parse_str(&sub)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{sub}`: {e}")))?,
        facts: ApplicationUserFacts {
            user_status: UserStatus::parse(&user_status).map_err(|_| {
                DomainError::Repository(format!("invalid user status `{user_status}`"))
            })?,
            pending_setup: row.try_get("pending_setup").map_err(repo_err)?,
            active_member: membership_status == Some(MembershipStatus::Active),
            assigned,
        },
    })
}

#[async_trait]
impl ApplicationUserQuery for SqlxApplicationUserQuery {
    async fn list_tenant_members(
        &self,
        tenant_id: TenantId,
        page: PageRequest,
    ) -> Result<Page<SubjectFacts>> {
        let total: i64 =
            sqlx::query("SELECT COUNT(*) AS total FROM tenant_memberships WHERE tenant_id = ?")
                .bind(tenant_id.to_string())
                .fetch_one(&self.pool)
                .await
                .map_err(repo_err)?
                .try_get("total")
                .map_err(repo_err)?;

        let rows = sqlx::query(
            "SELECT u.sub, u.status AS user_status, u.pending_setup AS pending_setup, \
             m.status AS membership_status \
             FROM tenant_memberships m JOIN users u ON u.id = m.user_id \
             WHERE m.tenant_id = ? ORDER BY u.sub ASC LIMIT ? OFFSET ?",
        )
        .bind(tenant_id.to_string())
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;

        // For "everyone" apps the assignment rows are not consulted (the decision doesn't either; ADR-0054).
        let items = rows
            .iter()
            .map(|row| map_facts(row, Some(false)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Page::new(items, total))
    }

    async fn list_assigned(
        &self,
        tenant_id: TenantId,
        application_id: Uuid,
        page: PageRequest,
    ) -> Result<Page<SubjectFacts>> {
        let total: i64 = sqlx::query(
            // ⚠ Only people appear on the roster (decision 5 of ADR-0059). Service account assignments are not counted.
            "SELECT COUNT(*) AS total FROM application_assignments \
             WHERE application_id = ? AND kind = 'USER'",
        )
        .bind(application_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(repo_err)?
        .try_get("total")
        .map_err(repo_err)?;

        // Membership is a **LEFT JOIN**. The assignment's foreign key is `users`, so assignments may remain for users who are
        // not members of the tenant (the decision doesn't look at membership, so dropping them here
        // would make the roster and the entrance disagree).
        let rows = sqlx::query(
            "SELECT u.sub, u.status AS user_status, u.pending_setup AS pending_setup, \
             m.status AS membership_status \
             FROM application_assignments a JOIN users u ON u.id = a.user_id \
             LEFT JOIN tenant_memberships m ON m.user_id = u.id AND m.tenant_id = ? \
             WHERE a.application_id = ? AND a.kind = 'USER' ORDER BY u.sub ASC LIMIT ? OFFSET ?",
        )
        .bind(tenant_id.to_string())
        .bind(application_id.to_string())
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await
        .map_err(repo_err)?;

        let items = rows
            .iter()
            .map(|row| map_facts(row, Some(true)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Page::new(items, total))
    }

    async fn facts_for_subs(
        &self,
        tenant_id: TenantId,
        application_id: Uuid,
        subs: &[Uuid],
    ) -> Result<Vec<SubjectFacts>> {
        if subs.is_empty() {
            return Ok(Vec::new());
        }
        // The membership side is an **INNER JOIN**. A `sub` not in the requested tenant returns no row, and the caller
        // treats it as `unknown` (= gone). ⚠ This shape also avoids revealing the existence of other tenants' users.
        let mut builder = QueryBuilder::<MySql>::new(
            "SELECT u.sub, u.status AS user_status, u.pending_setup AS pending_setup, \
             m.status AS membership_status, \
             (a.application_id IS NOT NULL) AS assigned \
             FROM users u JOIN tenant_memberships m ON m.user_id = u.id AND m.tenant_id = ",
        );
        builder.push_bind(tenant_id.to_string());
        builder.push(
            " LEFT JOIN application_assignments a ON a.kind = 'USER' AND a.user_id = u.id \
             AND a.application_id = ",
        );
        builder.push_bind(application_id.to_string());
        builder.push(" WHERE u.sub IN (");
        let mut separated = builder.separated(", ");
        for sub in subs {
            separated.push_bind(sub.to_string());
        }
        separated.push_unseparated(")");

        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        rows.iter().map(|row| map_facts(row, None)).collect()
    }
}
