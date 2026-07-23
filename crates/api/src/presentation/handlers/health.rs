//! liveness / readiness ヘルスチェック。
//!
//! - `GET /healthz`: プロセスが生きているか（依存先は見ない）。
//! - `GET /readyz`: DB へ到達可能かを確認する。

use crate::infrastructure::db::{self, Db};
use axum::{extract::State, http::StatusCode, Json};
use idp_contracts::version::{
    BuildTimeVersionInfoProvider, SchemaVersionInfo, VersionInfo, VersionInfoProvider,
};
use serde_json::{json, Value};

pub async fn liveness() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
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
/// DB を読めない場合でも `applied = null` として期待版だけ返す（fail-soft。500 にしない）。
pub async fn schema_version(State(pool): State<Db>) -> Json<SchemaVersionInfo> {
    Json(SchemaVersionInfo {
        expected: db::embedded_schema_version(),
        applied: db::applied_schema_version(&pool).await.ok().flatten(),
    })
}
