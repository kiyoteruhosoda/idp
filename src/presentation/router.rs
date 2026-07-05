//! axum ルータの組立。各コンテキストのルータを `.merge()` / `.nest()` で集約する。

use crate::presentation::correlation;
use crate::presentation::handlers::{
    authorize, discovery, health, login, register, token, userinfo,
};
use crate::presentation::openapi::ApiDoc;
use crate::presentation::state::AppState;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/auth/register", post(register::register))
        .route("/authorize", get(authorize::authorize))
        .route("/login", get(login::login_page).post(login::login))
        .route("/token", post(token::token))
        .route("/userinfo", get(userinfo::userinfo))
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(discovery::jwks))
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(axum::middleware::from_fn(correlation::propagate))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
