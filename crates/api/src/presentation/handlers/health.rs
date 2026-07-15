//! liveness / readiness ヘルスチェック。
//!
//! - `GET /healthz`: プロセスが生きているか（依存先は見ない）。
//! - `GET /readyz`: DB へ到達可能かを確認する。

use crate::infrastructure::db::Db;
use axum::{extract::State, http::StatusCode, Json};
use idp_contracts::version::{BuildTimeVersionInfoProvider, VersionInfo, VersionInfoProvider};
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
