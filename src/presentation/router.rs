//! axum ルータの組立。各コンテキストのルータを `.merge()` / `.nest()` で集約する。

use crate::presentation::handlers::{health, register};
use crate::presentation::state::AppState;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/auth/register", post(register::register))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
