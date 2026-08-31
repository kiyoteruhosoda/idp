//! liveness / readiness ヘルスチェック。
//!
//! - `GET /healthz`: プロセスが生きているか（依存先は見ない）。**無認証**。
//! - `GET /readyz`: DB へ到達可能かを確認する。**無認証**。
//! - `GET /internal/health`: 版数・稼働時間・依存先の検査結果。**内部トークンの内側**（ADR-0031）。
//!
//! 公開面（`/healthz`・`/readyz`）に載せるのは「どのサービスが答えたか」までで、それ以上は
//! `/internal/health` に置く。公開面へ足した情報は無認証で全世界から読めるため（ADR-0031 決定 1）。

use crate::infrastructure::db::{self, Db};
use crate::presentation::state::AppState;
use assay_contracts::health::{service, HealthCheck, LivenessResponse, ServiceHealth};
use assay_contracts::version::{
    BuildTimeVersionInfoProvider, SchemaVersionInfo, VersionInfo, VersionInfoProvider,
};
use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

/// liveness: プロセスが生きていれば 200。依存先は見ない。
///
/// 本文に `service` を載せるのは、domain-split（ADR-0019）で web と api が別ホストになった以上、
/// 「叩いたつもりのサービスと違う方が答えている」取り違えが起こり得るため。ホスト名ではなく
/// 応答そのものに書いておかないと、その取り違えは切り分けの最後まで残る。
pub async fn liveness() -> (StatusCode, Json<LivenessResponse>) {
    (StatusCode::OK, Json(LivenessResponse::ok(service::API)))
}

/// 内部向けの詳細ヘルス（`/internal/health`）。ルータが `require_service_token` の内側に置く。
///
/// 検査するのは api が実際に依存しているもの ——  DB への到達性と、スキーマ version の整合。
/// 全体の `status` は検査結果から決まるので、監視はこの 1 値だけを見ればよい。
pub async fn internal_health(State(state): State<AppState>) -> Json<ServiceHealth> {
    let mut checks = Vec::new();

    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => checks.push(HealthCheck::pass("database")),
        Err(e) => {
            tracing::error!(error = %e, "health check: database unreachable");
            // 例外の原文は載せず、ログへ送る（応答は状態の要約に留める）。
            checks.push(HealthCheck::fail("database", "database unreachable"));
        }
    }

    checks.push(schema_check(&state.pool).await);

    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    Json(ServiceHealth::new(
        service::API,
        provider.version_info(),
        state.started_at,
        state.clock.now(),
        checks,
    ))
}

/// スキーマ version の整合（`CLAUDE.md`「schema-version」の fail-fast と同じ判定）。
///
/// 「DB が遅れている」と「DB を読み取れない」は別の障害なので、`detail` で区別できるようにする。
async fn schema_check(pool: &Db) -> HealthCheck {
    let expected = db::embedded_schema_version();
    match db::applied_schema_version(pool).await {
        Ok(applied) => {
            if applied >= expected {
                HealthCheck::pass("schema").with_detail(format!(
                    "applied={} expected={}",
                    fmt_version(applied),
                    fmt_version(expected)
                ))
            } else {
                HealthCheck::fail(
                    "schema",
                    format!(
                        "database schema is behind (applied={} expected={})",
                        fmt_version(applied),
                        fmt_version(expected)
                    ),
                )
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "health check: schema version unreadable");
            HealthCheck::fail("schema", "_sqlx_migrations is unreadable")
        }
    }
}

fn fmt_version(v: Option<i64>) -> String {
    v.map(|v| v.to_string())
        .unwrap_or_else(|| "none".to_string())
}

pub async fn readiness(State(pool): State<Db>) -> (StatusCode, Json<Value>) {
    match sqlx::query("SELECT 1").execute(&pool).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(e) => {
            tracing::error!(error = %e, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
        }
    }
}

/// version: ビルド時に埋め込まれた Cargo / Git バージョン情報を返す。
pub async fn version() -> Json<VersionInfo> {
    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    Json(provider.version_info())
}

/// schema version: DB スキーマ（マイグレーション）の適用状態を返す。運用者が DB を直接見られなくても
/// 「適用済み version」と「アプリが期待する version」を確認できるようにする（web が表示に使う）。
///
/// DB を読み取れない場合は `db_readable = false`（`applied = null`）として区別する。**「DB が遅れている」
/// と「DB を読み取れない（運用障害）」を取り違えないため**、エラーを握り潰さずログにも残す。エンドポイント
/// 自体は状態レポートが役割なので、DB 読み取り失敗でも 200 で状態（読み取り不可）を返す（fail-soft）。
pub async fn schema_version(State(pool): State<Db>) -> Json<SchemaVersionInfo> {
    let (db_readable, applied) = match db::applied_schema_version(&pool).await {
        Ok(applied) => (true, applied),
        Err(e) => {
            tracing::warn!(error = %e, "failed to read applied schema version for /version/schema");
            (false, None)
        }
    };
    Json(SchemaVersionInfo {
        expected: db::embedded_schema_version(),
        db_readable,
        applied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-0031 決定 1: どのサービスが答えたかを本文で名乗る。
    #[tokio::test]
    async fn liveness_names_the_api_service() {
        let (status, Json(body)) = liveness().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ok");
        assert_eq!(body.service, service::API);
    }

    #[test]
    fn schema_versions_are_rendered_for_humans() {
        assert_eq!(fmt_version(Some(43)), "43");
        assert_eq!(fmt_version(None), "none");
    }
}
