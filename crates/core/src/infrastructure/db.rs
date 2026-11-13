//! MariaDB connection pool and schema version check at startup.

use crate::config::Config;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Executor;

/// Type alias for the DB pool shared across the app.
pub type Db = MySqlPool;

/// Embedded migrations (`migrations/` at the repository root). Referenced by CI and the version check.
/// The path is relative to the crate (`assay-core`) manifest and points at `migrations/` at the workspace root.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

pub async fn connect(config: &Config) -> Result<Db, sqlx::Error> {
    MySqlPoolOptions::new()
        .max_connections(config.db_max_connections())
        // Pin the session time zone of every connection to UTC, so that CURRENT_TIMESTAMP(6) and
        // DATETIME reads/writes are always consistently UTC (CLAUDE.md "time is always UTC").
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("SET time_zone = '+00:00'").await?;
                Ok(())
            })
        })
        .connect(config.database_url())
        .await
}

/// Fail-fast schema consistency check.
///
/// Treats the latest embedded migration version as "the version the app expects" and compares it with the
/// maximum version applied to the DB. **Startup fails if the DB is below the expected version.** It is not an exact match;
/// "DB at or above the app's expected version" is allowed (supports rolling deploys).
///
/// Rationale: `docs/adr/0004-schema-version-sync.md` (read Alembic as sqlx version).
/// **Applying** migrations is not done by the app but by a dedicated job (`sqlx migrate run`).
/// The schema version this app (binary) expects = the maximum embedded migration version.
/// `None` if there are no migrations. Does not touch the DB.
pub fn embedded_schema_version() -> Option<i64> {
    MIGRATOR.iter().map(|m| m.version).max()
}

/// Maximum version of migrations applied to the DB (with a success record). `Ok(None)` if none applied or the table is empty.
/// `Err` if `_sqlx_migrations` can't be read (not migrated, etc.).
pub async fn applied_schema_version(pool: &Db) -> anyhow::Result<Option<i64>> {
    sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success = TRUE")
        .fetch_one(pool)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to read _sqlx_migrations \
                 (has `sqlx migrate run` been executed against this database?): {e}"
            )
        })
}

pub async fn verify_schema_version(pool: &Db) -> anyhow::Result<()> {
    let Some(expected) = embedded_schema_version() else {
        tracing::warn!("no embedded migrations found; skipping schema version check");
        return Ok(());
    };

    let applied = applied_schema_version(pool).await?;

    match applied {
        Some(applied) if applied >= expected => {
            tracing::info!(expected, applied, "schema version OK");
            Ok(())
        }
        Some(applied) => anyhow::bail!(
            "database schema is behind: expected version >= {expected}, but latest applied = {applied}. \
             run `sqlx migrate run`"
        ),
        None => anyhow::bail!(
            "database has no applied migrations, but expected version >= {expected}. \
             run `sqlx migrate run`"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::embedded_schema_version;

    /// Must return the maximum version of the embedded migrations (`migrations/` included at compile time).
    /// It is the source of "expected version" on the version info screen; after adding 0013 it is 13 or more (no DB needed).
    #[test]
    fn embedded_schema_version_reflects_latest_migration() {
        let version = embedded_schema_version().expect("migrations must be embedded");
        assert!(
            version >= 13,
            "expected embedded schema version >= 13 (0013 present), got {version}"
        );
    }
}
