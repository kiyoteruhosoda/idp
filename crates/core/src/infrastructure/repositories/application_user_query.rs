//! 名簿の照会（[`ApplicationUserQuery`]）の sqlx 実装（ADR-0057）。
//!
//! ⚠ **ここは事実しか読まない。** 「使ってよいか」を決めるのは
//! [`Application::roster_state`](crate::domain::application::Application::roster_state) であり、
//! その中身は判定（code 発行地点）と同じ [`Application::admits`] である。SQL 側にも可否の条件を
//! 書くと規則が 2 か所になり、⚠ **名簿と入口が食い違う**（「名簿に居るのに入れない」）。
//!
//! 並びは `sub` の昇順に固定する。`users.sub` は全テナントで一意なので、ページ間で行が重複・欠落
//! しない安定な並びになる（メール順と違い、表示名の変更でも動かない）。

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

/// 1 行を事実へ写す。`assigned` は問い合わせごとに決まる（割り当ての表を引いたか）ので引数で渡す。
fn map_facts(row: &MySqlRow, assigned: Option<bool>) -> Result<SubjectFacts> {
    let sub: String = row.try_get("sub").map_err(repo_err)?;
    let user_status: String = row.try_get("user_status").map_err(repo_err)?;
    let membership_status: Option<String> = row.try_get("membership_status").map_err(repo_err)?;
    let assigned = match assigned {
        Some(fixed) => fixed,
        // MariaDB の真偽式は 0 / 1 の整数で返る。
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

        // 「全員」のアプリでは割り当ての行を引かない（判定も引かない。ADR-0054）。
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
            // ⚠ 名簿に載るのは人だけ（ADR-0059 の決定 5）。サービスアカウントの割り当てを数えない。
            "SELECT COUNT(*) AS total FROM application_assignments \
             WHERE application_id = ? AND kind = 'USER'",
        )
        .bind(application_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(repo_err)?
        .try_get("total")
        .map_err(repo_err)?;

        // メンバーシップは **LEFT JOIN**。割り当ての外部キーは `users` なので、テナントのメンバー
        // でない利用者に割り当てが残っていることがある（判定はメンバーシップを見ないので、ここで
        // 落とすと名簿と入口が食い違う）。
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
        // メンバーシップ側は **INNER JOIN**。要求テナントに居ない `sub` は行を返さず、呼び出し側が
        // `unknown`（＝消えた）として扱う。⚠ 他テナントの利用者の存在を答えないための形でもある。
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
