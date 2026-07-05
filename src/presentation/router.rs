//! axum ルータの組立。各コンテキストのルータを `.merge()` / `.nest()` で集約する。

use crate::infrastructure::db::Db;
use crate::presentation::handlers::health;
use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;

pub fn build(pool: Db) -> Router {
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .layer(TraceLayer::new_for_http())
        .with_state(pool)
}
