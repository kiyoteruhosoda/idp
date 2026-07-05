//! MariaDB 接続プールと、起動時のスキーマバージョン照合。

use crate::config::Config;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Executor;

/// アプリ全体で共有する DB プールの型エイリアス。
pub type Db = MySqlPool;

/// 埋め込みマイグレーション（`migrations/`）。CI・照合で参照する。
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn connect(config: &Config) -> Result<Db, sqlx::Error> {
    MySqlPoolOptions::new()
        .max_connections(config.db_max_connections())
        // 全接続のセッションタイムゾーンを UTC に固定する。これにより CURRENT_TIMESTAMP(6) や
        // DATETIME の読み書きが常に UTC で一貫する（CLAUDE.md「時刻は常に UTC」）。
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("SET time_zone = '+00:00'").await?;
                Ok(())
            })
        })
        .connect(config.database_url())
        .await
}

/// スキーマ整合性の fail-fast チェック。
///
/// 埋め込みマイグレーションの最新 version を「アプリが期待する version」とし、DB に適用済みの
/// 最大 version と突合する。**DB が期待 version 未満なら起動を失敗**させる。厳密一致にはせず
/// 「DB がアプリの期待 version 以上」を許容する（ローリングデプロイ対応）。
///
/// 設計根拠: `docs/adr/0004-schema-version-sync.md`（Alembic→sqlx version と読み替え）。
/// マイグレーションの**適用そのもの**はアプリでは行わず、専用ジョブ（`sqlx migrate run`）が担う。
pub async fn verify_schema_version(pool: &Db) -> anyhow::Result<()> {
    let Some(expected) = MIGRATOR.iter().map(|m| m.version).max() else {
        tracing::warn!("no embedded migrations found; skipping schema version check");
        return Ok(());
    };

    let applied: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success = TRUE")
            .fetch_one(pool)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to read _sqlx_migrations \
                     (has `sqlx migrate run` been executed against this database?): {e}"
                )
            })?;

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
