//! sqlx implementation of the member list (a read model) (`TenantMemberQuery`, MT22).
//!
//! Joins `tenant_memberships` and `users`, doing filtering, sorting and paging all in the DB.
//! The total is a `COUNT(*)` with the same filters, so the screen can determine "N in total" and whether there is a next page.

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

/// Neutralizes `LIKE` wildcards. Without escaping, a `%` in the search term acts as "match all" and
/// `_` as "any single character", making the user's input match unintentionally broadly.
/// The escape character itself (`!`) is included too (order matters: `!` is replaced first).
pub(crate) fn escape_like(term: &str) -> String {
    term.replace('!', "!!")
        .replace('%', "!%")
        .replace('_', "!_")
}

/// Columns of one member row (shared by the list and direct lookup; names read by [`map_row`]).
const MEMBER_COLUMNS: &str = "m.user_id, m.membership_type, m.status, \
     u.email, u.name, u.status AS user_status, u.locked_until AS locked_until, \
     u.pending_setup AS pending_setup, \
     (SELECT MAX(t.expires_at) FROM password_reset_tokens t \
        WHERE t.user_id = u.id AND t.purpose = 'setup' AND t.used_at IS NULL) AS setup_link_expires_at, \
     n.note AS note, n.updated_at AS note_updated_at, n.updated_by AS note_updated_by, \
     (SELECT p.display_value FROM user_login_identifiers p \
        WHERE p.primary_of_user = u.id) AS preferred_username";

/// Builds the filter condition (`FROM` onwards). Both the list itself and `COUNT(*)` use the same condition.
fn push_conditions(builder: &mut QueryBuilder<MySql>, filter: &TenantMemberFilter) {
    push_member_source(
        builder,
        filter.tenant_id.to_string(),
        filter.search.as_deref(),
    );
    // Direct lookup (detail screen). It is an exact match, so it is not combined with `search`'s partial match.
    if let Some(user_id) = filter.user_id {
        builder.push(" AND m.user_id = ");
        builder.push_bind(user_id.to_string());
    }
}

/// The members' `FROM … WHERE …` (tenant and filter term). The people side of the account list (ADR-0065) also
/// uses this -- ⚠ don't write the filtering rules in 2 places.
///
/// The `users` collation (`utf8mb4_unicode_ci`) is case-insensitive, so `LOWER()` is not used
/// (wrapping in a function would prevent index use).
pub(crate) fn push_member_source(
    builder: &mut QueryBuilder<MySql>,
    tenant_id: String,
    search: Option<&str>,
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
        // The username is not in `users` (removed in AP15b). Looked up through the same path as the value shown in the list.
        builder.push(
            " ESCAPE '!' OR EXISTS (SELECT 1 FROM user_login_identifiers p \
                       WHERE p.primary_of_user = u.id AND p.display_value LIKE ",
        );
        builder.push_bind(pattern.clone());
        // Admin notes are searched too (so "people invited via X" can be found by history; ADR-0063).
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
        // The join goes through a foreign key (`tenant_memberships.user_id` -> `users.id`), so the user always exists.
        user_status: Some(UserStatus::parse(&user_status)?),
        locked_until: locked_until.map(|naive| chrono::Utc.from_utc_datetime(&naive)),
        pending_setup: row.try_get("pending_setup").map_err(repo_err)?,
        setup_link_expires_at: row
            .try_get::<Option<chrono::NaiveDateTime>, _>("setup_link_expires_at")
            .map_err(repo_err)?
            .map(|naive| chrono::Utc.from_utc_datetime(&naive)),
        note: map_note(row)?,
    })
}

/// Admin note (`LEFT JOIN`, so all columns are NULL if none is written).
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
        // The order must be stable across pages (prevents duplicates/gaps). email is effectively deterministic since
        // `(tenant_id, email)` is unique, but user_id is made the secondary key to state the intent.
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

    /// Without escaping, `%` becomes "match all" and `_` "any single character".
    #[test]
    fn escapes_like_wildcards_and_the_escape_character_itself() {
        assert_eq!(escape_like("100%"), "100!%");
        assert_eq!(escape_like("a_b"), "a!_b");
        assert_eq!(escape_like("a!b"), "a!!b");
        // `!` is replaced first, so `!`s produced by replacement are not escaped twice.
        assert_eq!(escape_like("!%"), "!!!%");
        assert_eq!(escape_like("plain"), "plain");
    }
}
