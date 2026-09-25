//! メンバー一覧（読み取りモデル）の sqlx 実装（`TenantMemberQuery`。MT22）。
//!
//! `tenant_memberships` と `users` を結合し、絞り込み・並び替え・ページングをすべて DB 側で行う。
//! 総件数は同じ絞り込み条件で `COUNT(*)` を取り、画面が「全 N 件」と次ページの有無を確定できるようにする。

use crate::domain::account_note::AccountNote;
use crate::domain::error::{DomainError, Result};
use crate::domain::repositories::TenantMemberQuery;
use crate::domain::tenant_membership::{TenantMember, TenantMemberFilter, TenantMemberPage};
use crate::domain::values::{MembershipStatus, MembershipType, UserStatus};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::TimeZone;
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};
use uuid::Uuid;

pub struct SqlxTenantMemberQuery {
    pool: Db,
}

impl SqlxTenantMemberQuery {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }
}

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

/// `LIKE` のワイルドカードを無効化する。エスケープしないと、検索語の `%` が「全件一致」、
/// `_` が「任意の 1 文字」として働き、利用者の入力が意図しない広い一致になる。
/// エスケープ文字自体（`!`）も対象に含める（順序も重要で、`!` を最初に置き換える）。
pub(crate) fn escape_like(term: &str) -> String {
    term.replace('!', "!!")
        .replace('%', "!%")
        .replace('_', "!_")
}

/// メンバー 1 行の列（一覧・名指しが共有する。[`map_row`] が読む名前）。
const MEMBER_COLUMNS: &str = "m.user_id, m.membership_type, m.status, \
     u.email, u.name, u.status AS user_status, u.locked_until AS locked_until, \
     u.pending_setup AS pending_setup, \
     n.note AS note, n.updated_at AS note_updated_at, n.updated_by AS note_updated_by, \
     (SELECT p.display_value FROM user_login_identifiers p \
        WHERE p.primary_of_user = u.id) AS preferred_username";

/// 絞り込み条件（`FROM` 以降）を組み立てる。一覧本体と `COUNT(*)` の双方が同じ条件を使う。
fn push_conditions<'a>(builder: &mut QueryBuilder<'a, MySql>, filter: &'a TenantMemberFilter) {
    push_member_source(
        builder,
        filter.tenant_id.to_string(),
        filter.search.as_deref(),
    );
    // 名指し（詳細画面）。完全一致なので `search` の部分一致とは併用しない。
    if let Some(user_id) = filter.user_id {
        builder.push(" AND m.user_id = ");
        builder.push_bind(user_id.to_string());
    }
}

/// メンバーの `FROM … WHERE …`（テナントと絞り込み語）。アカウント一覧（ADR-0065）の人の側も
/// これを使う ——⚠ 絞り込みの規則を 2 か所に書かない。
///
/// `users` の照合順序（`utf8mb4_unicode_ci`）が大文字小文字を無視するため、`LOWER()` は使わない
/// （関数を挟むと索引が使えなくなる）。
pub(crate) fn push_member_source<'a>(
    builder: &mut QueryBuilder<'a, MySql>,
    tenant_id: String,
    search: Option<&'a str>,
) {
    builder.push(
        " FROM tenant_memberships m JOIN users u ON u.id = m.user_id \
               LEFT JOIN account_notes n ON n.tenant_id = m.tenant_id AND n.user_id = m.user_id \
               WHERE m.tenant_id = ",
    );
    builder.push_bind(tenant_id);
    if let Some(search) = search {
        let pattern = format!("%{}%", escape_like(search));
        builder.push(" AND (u.email LIKE ");
        builder.push_bind(pattern.clone());
        builder.push(" ESCAPE '!' OR u.name LIKE ");
        builder.push_bind(pattern.clone());
        // ユーザー名は `users` に無い（AP15b で撤去済み）。一覧に出す値と同じ経路で引く。
        builder.push(
            " ESCAPE '!' OR EXISTS (SELECT 1 FROM user_login_identifiers p \
                       WHERE p.primary_of_user = u.id AND p.display_value LIKE ",
        );
        builder.push_bind(pattern.clone());
        // 管理者メモも探す（「〇〇経由で招いた人」を経緯から引けるように。ADR-0063）。
        builder.push(" ESCAPE '!') OR n.note LIKE ");
        builder.push_bind(pattern);
        builder.push(" ESCAPE '!')");
    }
}

pub(crate) fn map_row(row: &MySqlRow) -> Result<TenantMember> {
    let user_id: String = row.try_get("user_id").map_err(repo_err)?;
    let membership_type: String = row.try_get("membership_type").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    let user_status: String = row.try_get("user_status").map_err(repo_err)?;
    let locked_until: Option<chrono::NaiveDateTime> =
        row.try_get("locked_until").map_err(repo_err)?;
    Ok(TenantMember {
        user_id: Uuid::parse_str(&user_id)
            .map_err(|e| DomainError::Repository(format!("invalid UUID `{user_id}`: {e}")))?,
        email: row.try_get("email").map_err(repo_err)?,
        preferred_username: row.try_get("preferred_username").map_err(repo_err)?,
        name: row.try_get("name").map_err(repo_err)?,
        membership_type: MembershipType::parse(&membership_type)?,
        status: MembershipStatus::parse(&status)?,
        // 結合は外部キー（`tenant_memberships.user_id` → `users.id`）越しのため利用者は必ず存在する。
        user_status: Some(UserStatus::parse(&user_status)?),
        locked_until: locked_until.map(|naive| chrono::Utc.from_utc_datetime(&naive)),
        pending_setup: row.try_get("pending_setup").map_err(repo_err)?,
        note: map_note(row)?,
    })
}

/// 管理者メモ（`LEFT JOIN` なので、書かれていなければ全列 NULL）。
pub(crate) fn map_note(row: &MySqlRow) -> Result<Option<AccountNote>> {
    let text: Option<String> = row.try_get("note").map_err(repo_err)?;
    let Some(text) = text else {
        return Ok(None);
    };
    let updated_at: chrono::NaiveDateTime = row.try_get("note_updated_at").map_err(repo_err)?;
    let updated_by: Option<String> = row.try_get("note_updated_by").map_err(repo_err)?;
    Ok(Some(AccountNote {
        text,
        updated_at: chrono::Utc.from_utc_datetime(&updated_at),
        updated_by: updated_by
            .map(|id| {
                Uuid::parse_str(&id)
                    .map_err(|e| DomainError::Repository(format!("invalid UUID `{id}`: {e}")))
            })
            .transpose()?,
    }))
}

#[async_trait]
impl TenantMemberQuery for SqlxTenantMemberQuery {
    async fn search(&self, filter: &TenantMemberFilter) -> Result<TenantMemberPage> {
        let mut count = QueryBuilder::<MySql>::new("SELECT COUNT(*) AS total");
        push_conditions(&mut count, filter);
        let total: i64 = count
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(repo_err)?
            .try_get("total")
            .map_err(repo_err)?;

        let mut page = QueryBuilder::<MySql>::new(format!("SELECT {MEMBER_COLUMNS}"));
        push_conditions(&mut page, filter);
        // 並びはページ間で安定していなければならない（重複・欠落を防ぐ）。email は
        // `(tenant_id, email)` が一意なので実質決定的だが、意図を明示して user_id を副キーに置く。
        page.push(" ORDER BY u.email ASC, m.user_id ASC LIMIT ");
        page.push_bind(filter.limit);
        page.push(" OFFSET ");
        page.push_bind(filter.offset);
        let rows = page.build().fetch_all(&self.pool).await.map_err(repo_err)?;

        Ok(TenantMemberPage {
            members: rows.iter().map(map_row).collect::<Result<Vec<_>>>()?,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// エスケープしないと `%` が「全件一致」、`_` が「任意の 1 文字」になる。
    #[test]
    fn escapes_like_wildcards_and_the_escape_character_itself() {
        assert_eq!(escape_like("100%"), "100!%");
        assert_eq!(escape_like("a_b"), "a!_b");
        assert_eq!(escape_like("a!b"), "a!!b");
        // `!` を先に置換するので、置換で生まれた `!` が二重にエスケープされない。
        assert_eq!(escape_like("!%"), "!!!%");
        assert_eq!(escape_like("plain"), "plain");
    }
}
