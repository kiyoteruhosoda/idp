//! ヘルスチェック（ADR-0007 §8）。
//!
//! `/healthz` は liveness（依存を見ない）。`/readyz` は api への到達性を確認する
//! （web は DB を持たないため、readiness は api の可用性で判断する）。

use crate::state::WebState;
use axum::extract::State;
use axum::http::StatusCode;

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
