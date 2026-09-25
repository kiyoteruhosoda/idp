//! アカウント一覧（人とサービスアカウント。読み取りモデル）の sqlx 実装（`AccountQuery`。ADR-0065）。
//!
//! 2 種類を `UNION ALL` した 1 クエリで、絞り込み・並び替え・ページングまで DB 側で行う。片方ずつ
//! 引いて web で混ぜると、総件数もページの境目も合わない。
//!
//! 2 つの枝は**同じ列を同じ順に同じ名前で**出す（`UNION` の列名は最初の枝から付くので、どちらの枝が
//! 先に来ても読めるよう、両方の枝で名前を付ける）。その種別に無い列は `NULL`。
//!
//! 人の側の `FROM … WHERE …`（絞り込みの規則）はメンバー一覧と共有する
//! （[`super::tenant_member_query::push_member_source`]）。

use super::tenant_member_query::{escape_like, map_note, map_row, push_member_source};
use crate::domain::account::{
    Account, AccountFilter, AccountKind, AccountPage, IdentityApplication, ServiceAccount,
};
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::AccountQuery;
use crate::domain::tenant::TenantId;
use crate::domain::values::ClientStatus;
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::TimeZone;
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};
use uuid::Uuid;

pub struct SqlxAccountQuery {
    pool: Db,
}

impl SqlxAccountQuery {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

fn parse_uuid(raw: &str) -> Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| DomainError::Repository(format!("invalid UUID `{raw}`: {e}")))
}

/// 人の枝の列。見出し（`sort_key`）は一覧の見出しと同じ規則（メール → ユーザー名）。
const USER_COLUMNS: &str = "'USER' AS kind, \
     COALESCE(u.email, (SELECT p.display_value FROM user_login_identifiers p \
        WHERE p.primary_of_user = u.id), '') AS sort_key, \
     m.user_id AS account_id, \
     m.user_id AS user_id, m.membership_type AS membership_type, m.status AS status, \
     u.email AS email, u.name AS name, u.status AS user_status, \
     u.locked_until AS locked_until, u.pending_setup AS pending_setup, \
     (SELECT MAX(t.expires_at) FROM password_reset_tokens t \
        WHERE t.user_id = u.id AND t.purpose = 'setup' AND t.used_at IS NULL) AS setup_link_expires_at, \
     (SELECT p.display_value FROM user_login_identifiers p \
        WHERE p.primary_of_user = u.id) AS preferred_username, \
     NULL AS client_row_id, NULL AS client_id, NULL AS app_name, NULL AS client_status, \
     NULL AS client_created_at, NULL AS identity_application_id, NULL AS identity_display_name, \
     n.note AS note, n.updated_at AS note_updated_at, n.updated_by AS note_updated_by";

/// サービスアカウントの枝の列。見出しは登録名。
const SERVICE_ACCOUNT_COLUMNS: &str = "'SERVICE_ACCOUNT' AS kind, \
     c.app_name AS sort_key, \
     c.id AS account_id, \
     NULL AS user_id, NULL AS membership_type, NULL AS status, \
     NULL AS email, NULL AS name, NULL AS user_status, \
     NULL AS locked_until, NULL AS pending_setup, NULL AS setup_link_expires_at, \
     NULL AS preferred_username, \
     c.id AS client_row_id, c.client_id AS client_id, c.app_name AS app_name, \
     c.client_status AS client_status, \
     c.created_at AS client_created_at, a.id AS identity_application_id, \
     a.display_name AS identity_display_name, \
     n.note AS note, n.updated_at AS note_updated_at, n.updated_by AS note_updated_by";

/// サービスアカウントの `FROM … WHERE …`。
///
/// サービスアカウントの定義は [`crate::domain::client::Client::is_service_account`] と同じ
/// （confidential・`client_credentials` あり・`authorization_code` なし）。論理削除（ADR-0035）は並べない。
fn push_service_account_source<'a>(
    builder: &mut QueryBuilder<'a, MySql>,
    tenant_id: String,
    search: Option<&'a str>,
) {
    builder.push(
        " FROM clients c \
          LEFT JOIN application_bindings b ON b.kind = 'service_account' AND b.client_id = c.id \
          LEFT JOIN applications a ON a.id = b.application_id \
          LEFT JOIN account_notes n ON n.tenant_id = c.tenant_id AND n.client_id = c.id \
          WHERE c.tenant_id = ",
    );
    builder.push_bind(tenant_id);
    builder.push(
        " AND c.client_status <> 'DELETED' AND c.client_type = 'confidential' \
          AND JSON_CONTAINS(c.grant_types, JSON_QUOTE('client_credentials')) \
          AND NOT JSON_CONTAINS(c.grant_types, JSON_QUOTE('authorization_code'))",
    );
    if let Some(search) = search {
        let pattern = format!("%{}%", escape_like(search));
        builder.push(" AND (c.app_name LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" ESCAPE '!' OR c.client_id LIKE ");
        builder.push_bind(pattern.clone());
        // メモも探す（人の側と同じ。ADR-0065）。
        builder.push(" ESCAPE '!' OR n.note LIKE ");
        builder.push_bind(pattern);
        builder.push(" ESCAPE '!')");
    }
}

/// 種別ごとの枝を `UNION ALL` で繋ぐ。`rows` が偽なら件数用（`SELECT 1`）。
fn push_union<'a>(builder: &mut QueryBuilder<'a, MySql>, filter: &'a AccountFilter, rows: bool) {
    for (i, kind) in filter.kinds.iter().enumerate() {
        if i > 0 {
            builder.push(" UNION ALL ");
        }
        match kind {
            AccountKind::User => {
                builder.push("SELECT ");
                builder.push(if rows { USER_COLUMNS } else { "1 AS one" });
                push_member_source(
                    builder,
                    filter.tenant_id.to_string(),
                    filter.search.as_deref(),
                );
            }
            AccountKind::ServiceAccount => {
                builder.push("SELECT ");
                builder.push(if rows {
                    SERVICE_ACCOUNT_COLUMNS
                } else {
                    "1 AS one"
                });
                push_service_account_source(
                    builder,
                    filter.tenant_id.to_string(),
                    filter.search.as_deref(),
                );
            }
        }
    }
}

fn map_service_account(row: &MySqlRow) -> Result<ServiceAccount> {
    let client_row_id: String = row.try_get("client_row_id").map_err(repo_err)?;
    let status: String = row.try_get("client_status").map_err(repo_err)?;
    let created_at: chrono::NaiveDateTime = row.try_get("client_created_at").map_err(repo_err)?;
    let identity_id: Option<String> = row.try_get("identity_application_id").map_err(repo_err)?;
    let identity_name: Option<String> = row.try_get("identity_display_name").map_err(repo_err)?;
    Ok(ServiceAccount {
        client_row_id: parse_uuid(&client_row_id)?,
        client_id: row.try_get("client_id").map_err(repo_err)?,
        app_name: row.try_get("app_name").map_err(repo_err)?,
        status: ClientStatus::parse(&status)?,
        created_at: chrono::Utc.from_utc_datetime(&created_at),
        identity_of: match (identity_id, identity_name) {
            (Some(id), Some(display_name)) => Some(IdentityApplication {
                application_id: parse_uuid(&id)?,
                display_name,
            }),
            _ => None,
        },
        note: map_note(row)?,
    })
}

fn map_account(row: &MySqlRow) -> Result<Account> {
    let kind: String = row.try_get("kind").map_err(repo_err)?;
    match AccountKind::from_db(&kind)? {
        AccountKind::User => Ok(Account::User(map_row(row)?)),
        AccountKind::ServiceAccount => Ok(Account::ServiceAccount(map_service_account(row)?)),
    }
}

#[async_trait]
impl AccountQuery for SqlxAccountQuery {
    async fn search(&self, filter: &AccountFilter) -> Result<AccountPage> {
        if filter.kinds.is_empty() {
            // 呼び出し側が 403 にする約束。ここへ来たら配線ミスで、空の UNION は SQL として成り立たない。
            return Err(DomainError::Repository(
                "account search needs at least one kind".to_string(),
            ));
        }
        let mut count = QueryBuilder::<MySql>::new("SELECT COUNT(*) AS total FROM (");
        push_union(&mut count, filter, false);
        count.push(") AS accounts");
        let total: i64 = count
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(repo_err)?
            .try_get("total")
            .map_err(repo_err)?;

        let mut page = QueryBuilder::<MySql>::new("SELECT * FROM (");
        push_union(&mut page, filter, true);
        // 並びはページ間で安定していなければならない（重複・欠落を防ぐ）。見出しが同じ行は種別・ID で決める。
        page.push(") AS accounts ORDER BY sort_key ASC, kind ASC, account_id ASC LIMIT ");
        page.push_bind(filter.limit);
        page.push(" OFFSET ");
        page.push_bind(filter.offset);
        let rows = page.build().fetch_all(&self.pool).await.map_err(repo_err)?;

        Ok(AccountPage {
            accounts: rows.iter().map(map_account).collect::<Result<Vec<_>>>()?,
            total,
        })
    }

    async fn find_service_account(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<ServiceAccount>> {
        let mut query = QueryBuilder::<MySql>::new(format!("SELECT {SERVICE_ACCOUNT_COLUMNS}"));
        push_service_account_source(&mut query, tenant_id.to_string(), None);
        query.push(" AND c.client_id = ");
        query.push_bind(client_id);
        let row = query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_service_account).transpose()
    }
}
