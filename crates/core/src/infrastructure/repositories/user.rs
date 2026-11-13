//! sqlx implementation of `UserRepository`. UUIDs are read and written as canonical CHAR(36) strings.

use crate::domain::authentication_policy::LockoutPolicy;
use crate::domain::error::{DomainError, Result};
use crate::domain::login_identifier::LoginIdentifierMatch;
use crate::domain::repositories::UserRepository;
use crate::domain::tenant::TenantId;
use crate::domain::user::{LoginFailureRecord, User};
use crate::domain::values::{MembershipStatus, MembershipType, UserStatus};
use crate::infrastructure::db::Db;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use sqlx::mysql::MySqlRow;
use sqlx::{MySql, QueryBuilder, Row};
use uuid::Uuid;

pub struct SqlxUserRepository {
    pool: Db,
}

impl SqlxUserRepository {
    pub fn new(pool: Db) -> Self {
        Self { pool }
    }

    /// Body shared by the 2 resolutions that look up the registry (`user_login_identifiers`) (AP8, ADR-0009 §8).
    ///
    /// **If it matches multiple users, nobody is returned** (`Ambiguous` of [`LoginIdentifierMatch::Unresolved`],
    /// distinguished from "absent"; MT25). Within a tenant one normalized value belongs to one person
    /// (migration 0041), but normalization differs per type, so one input expands to several normalized values,
    /// and an input may be "A as a username, B as a phone number" (guest resolution also crosses the owning
    /// tenant).
    /// Choosing one with `LIMIT 1` would let the index decide which is returned. Rather than letting
    /// an ambiguous input authenticate, we choose not to (candidate generation also makes it unlikely;
    /// [`crate::domain::login_identifier::lookup_candidates`]).
    async fn resolve_login_identifier(
        &self,
        scope: IdentifierScope,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        let candidates = crate::domain::login_identifier::lookup_candidates(input);
        if candidates.is_empty() {
            return Ok(LoginIdentifierMatch::not_found());
        }
        let sql = login_identifier_sql(scope, candidates.len());
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for bind in scope.binds(tenant_id) {
            query = query.bind(bind);
        }
        for (kind, normalized) in &candidates {
            query = query.bind(kind.as_str()).bind(normalized.clone());
        }
        let rows = query.fetch_all(&self.pool).await.map_err(repo_err)?;
        match rows.len() {
            0 => Ok(LoginIdentifierMatch::not_found()),
            1 => map_row(&rows[0]).map(LoginIdentifierMatch::Resolved),
            _ => {
                // Ambiguous. The login path also records it in the audit log (`UnresolvedReason::audit_code`), but registration/rename
                // availability checks pass through here without an audit entry, so it is also logged operationally (the value is PII and not output).
                tracing::warn!(
                    tenant_id = %tenant_id,
                    "login identifier resolved to multiple users; refusing to authenticate"
                );
                Ok(LoginIdentifierMatch::ambiguous())
            }
        }
    }
}

/// Range of the registry lookup (ADR-0009 §8, ADR-0029). The login path chooses "look up as the owning tenant, as a guest of
/// the joined tenant, or restricted to the owning tenant determined by domain". Expressing it as an enum instead of
/// passing SQL fragments around as arguments closes the buildable shapes to these 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentifierScope {
    /// Registry of the owning tenant (`user_login_identifiers.tenant_id` = requested tenant).
    /// Uses the index matching the lookup, `user_login_identifiers_lookup_idx (tenant_id, type, normalized value)`
    /// (migration 0041 removed the type from the unique key, so the index became separate).
    Home,
    /// Looks up users participating in the requested tenant as ACTIVE GUESTs in **that user's owning tenant's**
    /// registry.
    ActiveGuest,
    /// When the owning tenant **is known** (determined from the domain; ADR-0029), looks up only that tenant's
    /// registry. Being an ACTIVE member of the requested tenant (HOME or GUEST) is
    /// required, as with [`Self::ActiveGuest`].
    ///
    /// **Ambiguity cannot arise in this range by construction.** Only one tenant's registry is looked up, and within it
    /// one normalized value belongs to one person (migration 0041). Guests are not scanned across, so
    /// however many guests with the same name participate, they don't interfere with each other.
    MemberWithHomeTenant(TenantId),
}

impl IdentifierScope {
    /// JOINs and WHERE following `FROM user_login_identifiers i JOIN users u ...`. Filters other than the candidates' IN clause
    /// go here, and it ends with a condition (the IN clause is appended with ` AND`).
    ///
    /// `ActiveGuest`'s `i.tenant_id = u.tenant_id` makes explicit the registry invariant "identifiers are registered in the
    /// owning tenant"; without it, rows registered in other tenants could resolve.
    ///
    /// `home.status = 'ACTIVE'` (owning tenant active) is also required (ADR-0009 §8). Disabling the owning tenant is
    /// the operation "stop that organization's users", not something that leaves a back door via joined tenants.
    /// `Home` doesn't need the same condition because its requested tenant = owning tenant, and the middleware
    /// (`TenantResolutionService`) already stops `DISABLED` with a 404. The same rule seen
    /// from the membership side is `TenantMembershipRepository::is_active_member`.
    ///
    /// Unlike `Home`, `ActiveGuest` doesn't use the lookup index (`user_login_identifiers_lookup_idx`
    /// = `(tenant_id, type, normalized value)`); it goes
    /// from the tenant's ACTIVE GUEST memberships
    /// (`tenant_memberships_tenant_type_status_idx (tenant_id, membership_type, status)`,
    /// migration 0040) to the user's identifiers (index on `(user_id, identifier_type)`). The equality conditions
    /// follow the index column order, so the scan is proportional to **the number of guests**, not the tenant's member count.
    ///
    /// This path runs when resolution in the owning tenant comes up empty, i.e. on **every guest login from the
    /// joined tenant's screen** and on **every login attempt with a nonexistent username**. The former is ordinary
    /// login, and the latter is the shape brute force sends most, so neither should be
    /// proportional to the member count.
    fn sql(self) -> &'static str {
        match self {
            Self::Home => "WHERE i.tenant_id = ?",
            Self::ActiveGuest => {
                "JOIN tenant_memberships m ON m.user_id = u.id \
                 JOIN tenants home ON home.id = u.tenant_id AND home.status = 'ACTIVE' \
                 WHERE m.tenant_id = ? AND m.membership_type = ? AND m.status = ? \
                   AND i.tenant_id = u.tenant_id"
            }
            // The owning tenant is fixed, so don't filter by membership type (HOME or GUEST both fine).
            // Instead the owning tenant is pinned with `u.tenant_id = ?`. This shape also suffices when the requested tenant itself
            // has the domain (then owning tenant = requested tenant, which is the HOME side).
            Self::MemberWithHomeTenant(_) => {
                "JOIN tenant_memberships m ON m.user_id = u.id \
                 JOIN tenants home ON home.id = u.tenant_id AND home.status = 'ACTIVE' \
                 WHERE m.tenant_id = ? AND m.status = ? \
                   AND u.tenant_id = ? AND i.tenant_id = u.tenant_id"
            }
        }
    }

    /// Values filling [`Self::sql`]'s placeholders before the candidates (type x normalized value). Membership
    /// type and status come from the Rust enums rather than literals, staying with the single source of allowed values.
    fn binds(self, tenant_id: TenantId) -> Vec<String> {
        match self {
            Self::Home => vec![tenant_id.to_string()],
            Self::ActiveGuest => vec![
                tenant_id.to_string(),
                MembershipType::Guest.as_str().to_string(),
                MembershipStatus::Active.as_str().to_string(),
            ],
            Self::MemberWithHomeTenant(home_tenant_id) => vec![
                tenant_id.to_string(),
                MembershipStatus::Active.as_str().to_string(),
                home_tenant_id.to_string(),
            ],
        }
    }
}

/// Builds the registry resolution query. External input always goes through bind; all that goes into this string
/// is literals from this module and the number of `?` (split into a function so its shape can be verified without a DB).
/// The resolution query.
///
/// Only the `email` type looks at the switch of **the tenant where the identifier is registered** (= the user's owning tenant)
/// (ADR-0050 decision 3). The requesting tenant is not consulted so that the settings of a tenant joined as a guest
/// don't open or close the entrance of the owning tenant.
fn login_identifier_sql(scope: IdentifierScope, candidate_count: usize) -> String {
    let placeholders = vec!["(?, ?)"; candidate_count].join(", ");
    let scope = scope.sql();
    format!(
        "SELECT DISTINCT {SELECT_COLUMNS} \
         FROM user_login_identifiers i \
         JOIN users u ON u.id = i.user_id \
         {scope} \
           AND i.is_active = 1 \
           AND (i.identifier_type <> 'email' OR EXISTS ( \
                 SELECT 1 FROM tenants et \
                  WHERE et.id = i.tenant_id AND et.email_login_enabled = 1)) \
           AND (i.identifier_type, i.normalized_value) IN ({placeholders}) \
         LIMIT 2"
    )
}

/// `users` columns, plus **the primary login identifier brought in from the registry**.
///
/// AP15b removed `users.preferred_username`, so this one column is looked up from
/// the primary identifier row of `user_login_identifiers` (`primary_of_user`). It is a correlated subquery rather than a JOIN
/// so users without a primary identifier (accounts created by an admin without a username)
/// aren't dropped -- otherwise `find_by_id` would suddenly start returning `None`.
const SELECT_COLUMNS: &str = "u.id AS id, u.tenant_id AS tenant_id, u.sub AS sub, \
     u.email AS email, u.email_verified AS email_verified, \
     (SELECT p.display_value FROM user_login_identifiers p WHERE p.primary_of_user = u.id) \
        AS preferred_username, \
     u.name AS name, u.language AS language, u.theme AS theme, \
     u.password_hash AS password_hash, \
     u.must_change_password AS must_change_password, \
     u.password_changed_at AS password_changed_at, u.status AS status, \
     u.pending_setup AS pending_setup, \
     u.failed_login_count AS failed_login_count, u.locked_until AS locked_until, \
     u.created_at AS created_at, u.updated_at AS updated_at";

fn repo_err<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Repository(e.to_string())
}

/// Returns a violation of the registry's unique constraint (tenant x normalized value; type-independent since migration 0041)
/// as `Conflict`. Concurrent executions that slipped past the pre-check are caught here
/// (since AP15b this constraint applies to primary identifiers too).
fn identifier_conflict(e: sqlx::Error) -> DomainError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => DomainError::Conflict(
            "preferred_username is already used as a login identifier by another user".to_string(),
        ),
        _ => DomainError::Repository(e.to_string()),
    }
}

fn to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&naive)
}

fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| DomainError::Repository(format!("invalid UUID `{s}`: {e}")))
}

fn map_row(row: &MySqlRow) -> Result<User> {
    let id: String = row.try_get("id").map_err(repo_err)?;
    let tenant_id: String = row.try_get("tenant_id").map_err(repo_err)?;
    let sub: String = row.try_get("sub").map_err(repo_err)?;
    let status: String = row.try_get("status").map_err(repo_err)?;
    let locked_until: Option<NaiveDateTime> = row.try_get("locked_until").map_err(repo_err)?;
    let password_changed_at: Option<NaiveDateTime> =
        row.try_get("password_changed_at").map_err(repo_err)?;
    Ok(User {
        id: parse_uuid(&id)?,
        tenant_id: parse_uuid(&tenant_id)?.into(),
        sub: parse_uuid(&sub)?,
        email: row.try_get("email").map_err(repo_err)?,
        email_verified: row.try_get("email_verified").map_err(repo_err)?,
        preferred_username: row.try_get("preferred_username").map_err(repo_err)?,
        name: row.try_get("name").map_err(repo_err)?,
        language: row.try_get("language").map_err(repo_err)?,
        theme: row.try_get("theme").map_err(repo_err)?,
        password_hash: row.try_get("password_hash").map_err(repo_err)?,
        must_change_password: row.try_get("must_change_password").map_err(repo_err)?,
        password_changed_at: password_changed_at.map(to_utc),
        status: UserStatus::parse(&status)?,
        pending_setup: row.try_get("pending_setup").map_err(repo_err)?,
        failed_login_count: row.try_get("failed_login_count").map_err(repo_err)?,
        locked_until: locked_until.map(to_utc),
        created_at: to_utc(row.try_get("created_at").map_err(repo_err)?),
        updated_at: to_utc(row.try_get("updated_at").map_err(repo_err)?),
    })
}

/// Writes the primary login identifier into the registry (which became **the only place for it** in AP15b).
///
/// When `preferred_username` is `None` or empty, the primary identifier row is deleted (unset).
///
/// # When someone else holds the same value
///
/// **Fails with `Conflict`.** During the first half (expand) it was enough to "give up on the registry and treat `users` as
/// authoritative" -- the value was in both, and kept resolving via `users`. With the column dropped,
/// giving up would **silently create a user who cannot log in with that username**.
///
/// Conflicts are hit by 2 paths. A value equal to someone else's identifier is caught by the pre-check below (**regardless of type**,
/// looking at the same range as the unique key), and ones that slip through concurrently by the registry's unique constraint
/// (tenant x normalized value). With the migration done,
/// the concurrency window ADR-0025 listed as a "remaining limitation" is closed on the DB side.
async fn sync_primary_login_identifier(
    conn: &mut sqlx::MySqlConnection,
    user_id: Uuid,
    preferred_username: Option<&str>,
) -> Result<()> {
    use crate::domain::login_identifier::LoginIdentifierType;

    let Some(value) = preferred_username.map(str::trim).filter(|v| !v.is_empty()) else {
        sqlx::query(
            "DELETE FROM user_login_identifiers WHERE user_id = ? AND primary_of_user IS NOT NULL",
        )
        .bind(user_id.to_string())
        .execute(&mut *conn)
        .await
        .map_err(repo_err)?;
        return Ok(());
    };
    let normalized = LoginIdentifierType::Username.normalize(value);

    // Does someone else hold the same value (the tenant is taken from the user's row; letting callers pass it
    // leaves room for disagreeing with `users`).
    //
    // **Don't filter by type.** Migration 0041 removed `identifier_type` from the unique key, so filtering by type
    // makes the check narrower than the constraint -- someone holding the same normalized value under another type would slip through,
    // defeating the purpose of this pre-check ("look at what the constraint rejects, in the same range, before writing").
    // The response seen by users doesn't change (if it slipped through, the write fails on the unique constraint and both paths
    // give `Conflict`), but we don't leave a path relying on a DB error in the middle of the transaction.
    // Inactive rows are checked too (just as the unique key ignores `is_active`; a disabled identifier's value is not
    // handed to someone else). The condition is the same 2 columns as the unique key, so the index applies as is.
    let taken_by_someone_else: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM user_login_identifiers i \
         JOIN users u ON u.id = ? \
         WHERE i.tenant_id = u.tenant_id \
           AND i.normalized_value = ? AND i.user_id <> u.id \
         LIMIT 1",
    )
    .bind(user_id.to_string())
    .bind(&normalized)
    .fetch_optional(&mut *conn)
    .await
    .map_err(repo_err)?;
    if taken_by_someone_else.is_some() {
        // The value itself is PII, so it is not output (`CLAUDE.md` "Logging").
        return Err(DomainError::Conflict(
            "preferred_username is already used as a login identifier by another user".to_string(),
        ));
    }

    // One primary identifier row per user (guaranteed by the UNIQUE on `primary_of_user`). If a row exists,
    // replace its value; otherwise create one. It isn't "INSERT if the update affected 0 rows" because MariaDB's
    // affected rows counts **changed rows**, so updating with the same value gives 0 (falling through to INSERT
    // would then fail on the unique constraint).
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM user_login_identifiers WHERE user_id = ? AND primary_of_user IS NOT NULL",
    )
    .bind(user_id.to_string())
    .fetch_optional(&mut *conn)
    .await
    .map_err(repo_err)?;

    match existing {
        Some(id) => {
            sqlx::query(
                "UPDATE user_login_identifiers \
                 SET identifier_type = 'username', display_value = ?, normalized_value = ?, \
                     is_active = 1 \
                 WHERE id = ?",
            )
            .bind(value)
            .bind(&normalized)
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(identifier_conflict)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO user_login_identifiers \
                 (id, tenant_id, user_id, identifier_type, display_value, normalized_value, \
                  is_active, primary_of_user) \
                 SELECT ?, u.tenant_id, u.id, 'username', ?, ?, 1, u.id FROM users u WHERE u.id = ?",
            )
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(value)
            .bind(&normalized)
            .bind(user_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(identifier_conflict)?;
        }
    }
    Ok(())
}

/// Writes the primary email address into the registry (ADR-0050 decision 1).
///
/// `users.email` is NOT NULL and can't be empty, so unlike the username there is no "unset" path.
///
/// # When **the user themself** holds the same value in another row
///
/// **No primary email row is created** (ADR-0050 decision 6). For users created without a username,
/// the username is the email address string (`unwrap_or_else(|| email.clone())`), and
/// creating a 2nd row with the same normalized value hits the unique constraint (0041). The value is already protected
/// by the registry as that person's, so there is no point adding a row.
///
/// In this case **the existing primary email row is deleted**. Otherwise, when the email is changed and then changed back,
/// the old row lingers and `users.email` and the registry split.
///
/// # When **someone else** holds the same value
///
/// Fails with `Conflict`. The check uses the same range as the unique key (tenant x normalized value, **not filtered by type**)
/// -- filtering makes it narrower than the constraint, letting someone holding the same value under another type slip through.
async fn sync_primary_email_identifier(
    conn: &mut sqlx::MySqlConnection,
    user_id: Uuid,
    email: &str,
) -> Result<()> {
    use crate::domain::login_identifier::LoginIdentifierType;

    let value = email.trim();
    if value.is_empty() {
        // `users.email` is NOT NULL. Reaching here is a caller assembly bug, so rather than
        // silently ignoring it, return without touching the row (the INSERT side would fail before the unique constraint).
        return Ok(());
    }
    let normalized = LoginIdentifierType::Email.normalize(value);

    // Does someone else hold the same normalized value (the tenant is taken from the user's row).
    let taken_by_someone_else: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM user_login_identifiers i \
         JOIN users u ON u.id = ? \
         WHERE i.tenant_id = u.tenant_id \
           AND i.normalized_value = ? AND i.user_id <> u.id \
         LIMIT 1",
    )
    .bind(user_id.to_string())
    .bind(&normalized)
    .fetch_optional(&mut *conn)
    .await
    .map_err(repo_err)?;
    if taken_by_someone_else.is_some() {
        // The value itself is PII, so it is not output (`CLAUDE.md` "Logging").
        return Err(DomainError::Conflict(
            "email is already used as a login identifier by another user".to_string(),
        ));
    }

    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM user_login_identifiers \
         WHERE user_id = ? AND primary_email_of_user IS NOT NULL",
    )
    .bind(user_id.to_string())
    .fetch_optional(&mut *conn)
    .await
    .map_err(repo_err)?;

    // Does another row of the same user (not the primary email row; usually the username) hold the same value?
    let held_by_self_elsewhere: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM user_login_identifiers i \
         JOIN users u ON u.id = ? \
         WHERE i.tenant_id = u.tenant_id \
           AND i.normalized_value = ? AND i.user_id = u.id \
           AND i.primary_email_of_user IS NULL \
         LIMIT 1",
    )
    .bind(user_id.to_string())
    .bind(&normalized)
    .fetch_optional(&mut *conn)
    .await
    .map_err(repo_err)?;

    if held_by_self_elsewhere.is_some() {
        if let Some(id) = existing {
            sqlx::query("DELETE FROM user_login_identifiers WHERE id = ?")
                .bind(id)
                .execute(&mut *conn)
                .await
                .map_err(repo_err)?;
        }
        return Ok(());
    }

    match existing {
        Some(id) => {
            sqlx::query(
                "UPDATE user_login_identifiers \
                 SET identifier_type = 'email', display_value = ?, normalized_value = ?, \
                     is_active = 1 \
                 WHERE id = ?",
            )
            .bind(value)
            .bind(&normalized)
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(identifier_conflict)?;
        }
        None => {
            // The tenant is taken from the user's row (letting callers pass it leaves room for disagreeing with `users`).
            // But **this is not an `INSERT ... SELECT`** -- it would take a shared lock on the source `users` row
            // and could deadlock with other transactions updating the same user.
            // Together with syncing the primary identifier it would happen twice per creation, so here the value is read and then
            // bound in (the read is a consistent read and takes no lock).
            let tenant_id: String = sqlx::query_scalar("SELECT tenant_id FROM users WHERE id = ?")
                .bind(user_id.to_string())
                .fetch_optional(&mut *conn)
                .await
                .map_err(repo_err)?
                .ok_or_else(|| DomainError::Repository("user not found".to_string()))?;
            sqlx::query(
                "INSERT INTO user_login_identifiers \
                 (id, tenant_id, user_id, identifier_type, display_value, normalized_value, \
                  is_active, primary_email_of_user) \
                 VALUES (?, ?, ?, 'email', ?, ?, 1, ?)",
            )
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(tenant_id)
            .bind(user_id.to_string())
            .bind(value)
            .bind(&normalized)
            .bind(user_id.to_string())
            .execute(&mut *conn)
            .await
            .map_err(identifier_conflict)?;
        }
    }
    Ok(())
}

/// INSERT into users, and registration of the primary login identifier.
///
/// **Always done in the same transaction.** If the username collides with someone else's, the identifier side fails with `Conflict`
/// (AP15b), and if only the `users` row remained, "a user with no means to log in" would
/// be created. That is why the caller passes in the transaction.
async fn insert_user(conn: &mut sqlx::MySqlConnection, user: &User) -> Result<()> {
    sqlx::query(
        "INSERT INTO users \
         (id, tenant_id, sub, email, email_verified, name, language, theme, \
          password_hash, must_change_password, password_changed_at, status, pending_setup, \
          failed_login_count, locked_until) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user.id.to_string())
    .bind(user.tenant_id.to_string())
    .bind(user.sub.to_string())
    .bind(&user.email)
    .bind(user.email_verified)
    .bind(&user.name)
    .bind(&user.language)
    .bind(&user.theme)
    .bind(&user.password_hash)
    .bind(user.must_change_password)
    .bind(user.password_changed_at.map(|d| d.naive_utc()))
    .bind(user.status.as_str())
    .bind(user.pending_setup)
    .bind(user.failed_login_count)
    .bind(user.locked_until.map(|d| d.naive_utc()))
    .execute(&mut *conn)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DomainError::Conflict("email already exists".to_string())
        }
        _ => DomainError::Repository(e.to_string()),
    })?;
    // The registry is the only place for the primary login identifier (AP15b). If the value collides with someone else's,
    // it becomes `Conflict` here and the whole user creation fails.
    sync_primary_login_identifier(conn, user.id, user.preferred_username.as_deref()).await?;
    // The email address is also placed under the registry's authoritative uniqueness (ADR-0050). For the same reason as the username
    // it is in the same transaction -- if only the `users` row remained, someone else could
    // take that email as a login identifier.
    sync_primary_email_identifier(conn, user.id, &user.email).await?;
    Ok(())
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn create(&self, user: &User) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        insert_user(&mut tx, user).await?;
        tx.commit().await.map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users u WHERE u.id = ?");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_sub(&self, sub: Uuid) -> Result<Option<User>> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM users u WHERE u.sub = ?");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(sub.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    async fn find_by_email(&self, tenant_id: TenantId, email: &str) -> Result<Option<User>> {
        let sql =
            format!("SELECT {SELECT_COLUMNS} FROM users u WHERE u.tenant_id = ? AND u.email = ?");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(tenant_id.to_string())
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    /// Looks up an ACTIVE GUEST of the joined tenant by `users.email` (MT26).
    ///
    /// The shape is the same as guest identifier resolution ([`IdentifierScope::ActiveGuest`]); only the match target is
    /// `users.email` instead of the registry. The index follows the same path -- from the tenant's ACTIVE GUEST
    /// memberships (`tenant_memberships_tenant_type_status_idx`, migration 0040) to the user.
    ///
    /// `LIMIT 2` is for detecting ambiguity. `users.email` is only unique within a tenant, so guests with different owning
    /// tenants can share an address. If 2 are seen, nobody is returned (the index must not decide
    /// where it is sent).
    ///
    /// **`u.status = 'ACTIVE'` is also required in SQL.** Ambiguity must be judged by the number of "people who could be
    /// recipients" -- disabled or locked users are dropped by the caller (`find_resettable_user`)
    /// anyway, so they are not candidates. Counting them would mean that a single `DISABLED` guest with the same address
    /// prevents the only active guest from receiving the reset email.
    async fn find_active_guest_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>> {
        let sql = format!(
            "SELECT DISTINCT {SELECT_COLUMNS} FROM users u \
             JOIN tenant_memberships m ON m.user_id = u.id \
             JOIN tenants home ON home.id = u.tenant_id AND home.status = 'ACTIVE' \
             WHERE m.tenant_id = ? AND m.membership_type = ? AND m.status = ? \
               AND u.status = ? AND u.email = ? \
             LIMIT 2"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(tenant_id.to_string())
            .bind(MembershipType::Guest.as_str())
            .bind(MembershipStatus::Active.as_str())
            .bind(UserStatus::Active.as_str())
            .bind(email)
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        match rows.len() {
            1 => map_row(&rows[0]).map(Some),
            0 => Ok(None),
            _ => {
                // The value (email address) is PII, so it is not output.
                tracing::warn!(
                    tenant_id = %tenant_id,
                    "password reset email matched multiple guests; refusing to choose one"
                );
                Ok(None)
            }
        }
    }

    /// Looks up the target of a guest invitation by `users.email` across tenants (ADR-0061).
    ///
    /// The shape is the same as the password reset above ([`find_active_guest_by_email`]), differing only in **not filtering
    /// by membership** -- the invitee isn't in the joined tenant yet.
    ///
    /// ⚠ **The `users` index is `(tenant_id, email)`, so this lookup doesn't use an index**
    /// (the leading column is the tenant). Invitations are rare, human-initiated operations and `users` is operationally small,
    /// so no email-only index has been added. Add one if it gets visibly slow as rows grow.
    ///
    /// `LIMIT 2` is for detecting ambiguity. If 2 are seen, nobody is returned (see the trait comment).
    async fn find_active_user_by_email_across_tenants(&self, email: &str) -> Result<Option<User>> {
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM users u \
             JOIN tenants home ON home.id = u.tenant_id AND home.status = 'ACTIVE' \
             WHERE u.status = ? AND u.email = ? \
             LIMIT 2"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(UserStatus::Active.as_str())
            .bind(email)
            .fetch_all(&self.pool)
            .await
            .map_err(repo_err)?;
        match rows.len() {
            1 => map_row(&rows[0]).map(Some),
            0 => Ok(None),
            _ => {
                // The value (email address) is PII, so it is not output.
                tracing::warn!(
                    "invitation lookup matched users in more than one tenant; refusing to choose one"
                );
                Ok(None)
            }
        }
    }

    /// Looks up by the primary login identifier (username).
    ///
    /// Matching uses the registry's normalized value (AP15b). Matching on `users.preferred_username` relied on the collation
    /// (`utf8mb4_unicode_ci`) to ignore case, but the registry holds per-type normalization
    /// **explicitly**. To apply the same rule, the input is normalized here too.
    async fn find_by_username(&self, tenant_id: TenantId, username: &str) -> Result<Option<User>> {
        use crate::domain::login_identifier::LoginIdentifierType;

        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM users u \
             JOIN user_login_identifiers p ON p.primary_of_user = u.id \
             WHERE u.tenant_id = ? AND p.normalized_value = ?"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(tenant_id.to_string())
            .bind(LoginIdentifierType::Username.normalize(username))
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        row.as_ref().map(map_row).transpose()
    }

    /// Resolves from the login field input (AP8).
    ///
    /// Looks up the registry's (`user_login_identifiers`) **active rows** by per-type normalized keys in one query.
    /// The approach "read everything and normalize/match in the app" is not taken (it breaks down in proportion to tenant size,
    /// and the uniqueness guarantee leaves the DB).
    ///
    /// The rule of not letting ambiguous input through lives in [`Self::resolve_login_identifier`], shared with
    /// guest resolution in joined tenants ([`Self::find_active_guest_by_login_identifier`]).
    ///
    /// **Only the registry is consulted.** Primary identifiers are registry rows too now (AP15b), so there is no
    /// fallback to `users`. The absence matters -- with a fallback left in,
    /// an identifier disabled in the registry would still resolve via `users` and authenticate, creating identifiers that
    /// "still work after being stopped".
    async fn find_by_login_identifier(
        &self,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        self.resolve_login_identifier(IdentifierScope::Home, tenant_id, input)
            .await
    }

    /// Resolves an ACTIVE GUEST of the joined tenant via **that user's owning tenant's** registry
    /// ([`IdentifierScope::ActiveGuest`]).
    async fn find_active_guest_by_login_identifier(
        &self,
        tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        self.resolve_login_identifier(IdentifierScope::ActiveGuest, tenant_id, input)
            .await
    }

    /// When the owning tenant is known, looks up only that tenant's registry
    /// ([`IdentifierScope::MemberWithHomeTenant`], ADR-0029).
    async fn find_member_by_login_identifier(
        &self,
        tenant_id: TenantId,
        home_tenant_id: TenantId,
        input: &str,
    ) -> Result<LoginIdentifierMatch> {
        self.resolve_login_identifier(
            IdentifierScope::MemberWithHomeTenant(home_tenant_id),
            tenant_id,
            input,
        )
        .await
    }

    async fn update_login_state(
        &self,
        id: Uuid,
        failed_login_count: i32,
        locked_until: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query("UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?")
            .bind(failed_login_count)
            .bind(locked_until.map(|d| d.naive_utc()))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn record_login_failure(
        &self,
        id: Uuid,
        lockout: LockoutPolicy,
        now: DateTime<Utc>,
    ) -> Result<LoginFailureRecord> {
        // Increment and lock decision in one statement (SEC13). With read-then-write-back, concurrent attempts read the same value
        // and write the same value, so N failures might advance it by only 1.
        //
        // **The order of assignments matters.** MariaDB / MySQL single-table UPDATE evaluates SET left to right, and
        // later expressions see the **new value** of columns updated earlier. Putting `locked_until` first makes
        // `failed_login_count` inside its CASE refer to the pre-update value (reversed, it would advance by 2).
        //
        // Progressive lockout (AP6): the lock duration depends on the failure count, but that count exists only inside
        // this UPDATE. Mirroring the formula in SQL would duplicate the definition, so **the list of steps is received from the domain
        // (`escalation_ladder`) and SQL only picks the matching step**. Steps are ordered by largest excess first,
        // so the first matching WHEN gives the longest lock duration.
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("UPDATE users SET locked_until = CASE");
        for (threshold, duration_secs) in lockout.escalation_ladder() {
            qb.push(" WHEN failed_login_count + 1 >= ");
            qb.push_bind(threshold);
            qb.push(" THEN ");
            qb.push_bind((now + chrono::Duration::seconds(duration_secs as i64)).naive_utc());
        }
        qb.push(" ELSE locked_until END, failed_login_count = failed_login_count + 1 WHERE id = ");
        qb.push_bind(id.to_string());
        qb.build().execute(&self.pool).await.map_err(repo_err)?;

        // Re-read the state after recording (MariaDB's UPDATE has no RETURNING). If a concurrent failure
        // slips in between, a more advanced value or newer lock expiry is returned. Both are correct for
        // deciding "is it locked now", and the count left in the audit log never falls below the actual number of attempts.
        let row = sqlx::query("SELECT failed_login_count, locked_until FROM users WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(repo_err)?;
        let Some(row) = row else {
            // The user disappeared during recording (deleted by an admin). There is simply nothing to lock,
            // so treat it as "not locked".
            return Ok(LoginFailureRecord {
                failed_login_count: 0,
                locked_until: None,
            });
        };
        let locked_until: Option<NaiveDateTime> = row.try_get("locked_until").map_err(repo_err)?;
        Ok(LoginFailureRecord {
            failed_login_count: row.try_get("failed_login_count").map_err(repo_err)?,
            // An expired lock is treated as "not in place" (judged at re-read time).
            locked_until: locked_until.map(to_utc).filter(|until| *until > now),
        })
    }

    async fn update_password(
        &self,
        id: Uuid,
        expected_current_hash: &str,
        password_hash: &str,
    ) -> Result<bool> {
        // Compare-and-swap including the current hash in the condition (see the trait definition for why).
        // The set time uses the DB clock (same as `created_at` / `updated_at`; AP7's expiry is
        // measured from this column).
        let result = sqlx::query(
            "UPDATE users SET password_hash = ?, must_change_password = 0, \
             password_changed_at = UTC_TIMESTAMP(6) WHERE id = ? AND password_hash = ?",
        )
        .bind(password_hash)
        .bind(id.to_string())
        .bind(expected_current_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn reset_password_forced(
        &self,
        id: Uuid,
        expected_current_hash: &str,
        password_hash: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE users SET password_hash = ?, must_change_password = 1, \
             password_changed_at = UTC_TIMESTAMP(6) WHERE id = ? AND password_hash = ?",
        )
        .bind(password_hash)
        .bind(id.to_string())
        .bind(expected_current_hash)
        .execute(&self.pool)
        .await
        .map_err(repo_err)?;
        Ok(result.rows_affected() == 1)
    }

    async fn update_status(&self, id: Uuid, status: UserStatus) -> Result<()> {
        sqlx::query("UPDATE users SET status = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn finish_setup(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE users SET pending_setup = 0 WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn mark_email_verified(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE users SET email_verified = 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_language(&self, id: Uuid, language: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE users SET language = ? WHERE id = ?")
            .bind(language)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }
    async fn update_theme(&self, id: Uuid, theme: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE users SET theme = ? WHERE id = ?")
            .bind(theme)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_name(&self, id: Uuid, name: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE users SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(repo_err)?;
        Ok(())
    }

    async fn update_profile(
        &self,
        id: Uuid,
        email: &str,
        preferred_username: Option<&str>,
        name: Option<&str>,
    ) -> Result<()> {
        // Update email, display name and username **in the same transaction**. If the username collides with someone else's,
        // the identifier side gives `Conflict` (AP15b), and if only the `users` change remained there,
        // we would expose a state where "an error was returned but the change happened".
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        sqlx::query("UPDATE users SET email = ?, name = ? WHERE id = ?")
            .bind(email)
            .bind(name)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| match &e {
                // Races with the pre-check (concurrent updates) are ultimately guaranteed by the DB's UNIQUE constraint.
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    DomainError::Conflict("email already exists".to_string())
                }
                _ => DomainError::Repository(e.to_string()),
            })?;
        // The registry is the only place for the username (AP15b).
        sync_primary_login_identifier(&mut tx, id, preferred_username).await?;
        // The primary email row follows in the same transaction too (ADR-0050). Without syncing here,
        // the old address would linger in the registry and the new address would belong to nobody.
        sync_primary_email_identifier(&mut tx, id, email).await?;
        tx.commit().await.map_err(repo_err)?;
        Ok(())
    }

    /// Promotes an alias email row to the primary email row (ADR-0052).
    ///
    /// # Write order
    ///
    /// Writes in the order **demote -> promote -> `users.email`**. `primary_email_of_user` is UNIQUE, so
    /// promoting first would make 2 rows primary email even momentarily, and the write would fail.
    ///
    /// Whether the target exists is checked **before writing**. Demoting first and then finding no target would leave
    /// the user without a primary email row until rollback.
    ///
    /// # The value is re-read from the registry
    ///
    /// The string put into `users.email` is not passed in by the caller; the target row's `display_value` is read within
    /// the same transaction. If it were passed in, when the value shown on screen and the row actually promoted
    /// disagree, it would succeed with `users.email` and the registry split.
    ///
    /// # The promoted row is always made active
    ///
    /// The primary email row can't be enabled/disabled per identifier (`set_active` excludes it). Promoting it while
    /// inactive would make a row that can never be enabled again the notification address. ADR-0050 decision 2's
    /// "the primary email is basically active" is for the same reason.
    ///
    /// # `email_verified` is not touched
    ///
    /// Treated the same as an admin's email change (MT25) keeping verified status (consistent with ADR-0050's decision
    /// not to require proof of ownership for email as an identifier).
    async fn promote_primary_email(&self, user_id: Uuid, identifier_id: Uuid) -> Result<bool> {
        let mut tx = self.pool.begin().await.map_err(repo_err)?;

        // 1. Check the row to promote and read the value to put into `users.email`. The condition is "the user's,
        //    email-type, non-primary-login-identifier row". The app layer checks the same, but
        //    the window between check and write is closed here (the row is locked with `FOR UPDATE` --
        //    otherwise the `display_value` read and the value of the row actually promoted could diverge).
        let display_value: Option<String> = sqlx::query_scalar(
            "SELECT display_value FROM user_login_identifiers \
             WHERE id = ? AND user_id = ? AND identifier_type = 'email' \
               AND primary_of_user IS NULL \
             FOR UPDATE",
        )
        .bind(identifier_id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(repo_err)?;
        let Some(display_value) = display_value else {
            return Ok(false);
        };

        // 2. Demote the current primary email row (there may be none; ADR-0050 decision 6).
        sqlx::query(
            "UPDATE user_login_identifiers SET primary_email_of_user = NULL \
             WHERE user_id = ? AND primary_email_of_user IS NOT NULL",
        )
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(repo_err)?;

        // 3. Promote the chosen row.
        sqlx::query(
            "UPDATE user_login_identifiers \
             SET primary_email_of_user = user_id, is_active = 1 WHERE id = ?",
        )
        .bind(identifier_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(repo_err)?;

        // 4. Make `users.email` a copy of the promoted row (ADR-0050 decision 4; the notification address moves with it).
        sqlx::query("UPDATE users SET email = ? WHERE id = ?")
            .bind(&display_value)
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| match &e {
                // As long as the registry's uniqueness (0041) holds it won't collide with someone else's `users.email`, but
                // the check isn't split into 2 places (same handling as `update_profile`).
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    DomainError::Conflict("email already exists".to_string())
                }
                _ => DomainError::Repository(e.to_string()),
            })?;

        tx.commit().await.map_err(repo_err)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Owning-tenant resolution looks up the registry by the requested tenant (same key as `user_login_identifiers_lookup_idx`).
    #[test]
    fn home_scope_filters_the_registry_by_the_requested_tenant() {
        let sql = login_identifier_sql(IdentifierScope::Home, 2);
        assert!(
            sql.contains("WHERE i.tenant_id = ? AND i.is_active = 1"),
            "{sql}"
        );
        assert!(!sql.contains("tenant_memberships"), "{sql}");
        // On the owning-tenant path, requested tenant = owning tenant, and the middleware stops DISABLED with a 404.
        // JOINing tenants here would leak the condition into non-login paths such as uniqueness checks.
        assert!(!sql.contains("JOIN tenants"), "{sql}");
        // One (?, ?) pair per candidate.
        assert!(sql.contains("IN ((?, ?), (?, ?)) LIMIT 2"), "{sql}");
    }

    /// Guest resolution looks up the requested tenant's ACTIVE GUEST in that user's owning tenant's registry.
    /// Dropping `i.tenant_id = u.tenant_id` would let identifiers of other tenants resolve, so
    /// the presence of the condition is pinned here.
    #[test]
    fn active_guest_scope_joins_membership_and_stays_in_the_home_registry() {
        let sql = login_identifier_sql(IdentifierScope::ActiveGuest, 1);
        assert!(
            sql.contains("JOIN tenant_memberships m ON m.user_id = u.id"),
            "{sql}"
        );
        // Don't resolve if the owning tenant is DISABLED (ADR-0009 §8). Dropping this JOIN would create users who
        // "can still get in via a joined tenant after the owning tenant was stopped".
        assert!(
            sql.contains("JOIN tenants home ON home.id = u.tenant_id AND home.status = 'ACTIVE'"),
            "{sql}"
        );
        assert!(
            sql.contains("WHERE m.tenant_id = ? AND m.membership_type = ? AND m.status = ?"),
            "{sql}"
        );
        assert!(sql.contains("AND i.tenant_id = u.tenant_id"), "{sql}");
        assert!(sql.contains("AND i.is_active = 1"), "{sql}");
        assert!(sql.contains("IN ((?, ?)) LIMIT 2"), "{sql}");
    }

    /// The number of binds matches the SQL placeholders (if they drift, a match key would be used as a tenant ID
    /// and silently nobody would resolve).
    #[test]
    fn scope_binds_match_the_placeholders_in_the_scope_fragment() {
        let tenant: TenantId = uuid::Uuid::now_v7().into();
        let home_tenant: TenantId = uuid::Uuid::now_v7().into();
        for (scope, expected) in [
            (IdentifierScope::Home, 1),
            (IdentifierScope::ActiveGuest, 3),
            (IdentifierScope::MemberWithHomeTenant(home_tenant), 3),
        ] {
            assert_eq!(scope.binds(tenant).len(), expected, "{scope:?}");
            assert_eq!(scope.sql().matches('?').count(), expected, "{scope:?}");
        }
        assert_eq!(
            IdentifierScope::ActiveGuest.binds(tenant),
            vec![
                tenant.to_string(),
                "GUEST".to_string(),
                "ACTIVE".to_string()
            ]
        );
        // The order must match the SQL's `?` sequence (m.tenant_id -> m.status -> u.tenant_id).
        assert_eq!(
            IdentifierScope::MemberWithHomeTenant(home_tenant).binds(tenant),
            vec![
                tenant.to_string(),
                "ACTIVE".to_string(),
                home_tenant.to_string()
            ]
        );
    }
}
