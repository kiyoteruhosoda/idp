//! ヘルスチェック（ADR-0007 §8）。
//!
//! `/healthz` は liveness（依存を見ない）。`/readyz` は api への到達性を確認する
//! （web は DB を持たないため、readiness は api の可用性で判断する）。

use crate::state::WebState;
use crate::templates::{render, VersionTemplate};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;
use idp_contracts::version::{BuildTimeVersionInfoProvider, VersionInfoProvider};

/// liveness: プロセスが生きていれば 200。依存先は見ない。
pub async fn liveness() -> StatusCode {
    StatusCode::OK
}

/// readiness: api に到達できれば 200、できなければ 503。
pub async fn readiness(State(state): State<WebState>) -> StatusCode {
    if state.api.is_api_reachable().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// version: ビルド時に埋め込まれた Cargo / Git バージョン情報を返す。
pub async fn version() -> Html<String> {
    let provider = BuildTimeVersionInfoProvider::new(env!("CARGO_PKG_VERSION"));
    Html(render(&VersionTemplate {
        info: provider.version_info(),
    }))
}
