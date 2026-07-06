//! web の axum ルータ組立。ログイン画面・管理コンソールは後続ステージで追加する。

use crate::handlers::health;
use crate::state::WebState;
use axum::routing::get;
use axum::Router;
use tower_http::trace::TraceLayer;

pub fn build(state: WebState) -> Router {
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
