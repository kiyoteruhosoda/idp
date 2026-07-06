//! web の axum ルータ組立。管理コンソールは後続ステージで追加する。

use crate::correlation;
use crate::handlers::{admin_console, health, login};
use crate::state::WebState;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub fn build(state: WebState) -> Router {
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/login", get(login::login_page).post(login::login))
        // 管理コンソール（ADR-0006 §6・ADR-0007 §4）。ログインはクライアント不要。
        .route(
            "/admin/console/login",
            get(admin_console::login_page).post(admin_console::login),
        )
        .route("/admin/console/logout", post(admin_console::logout))
        .route("/admin/console", get(admin_console::home))
        .layer(axum::middleware::from_fn(correlation::propagate))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
