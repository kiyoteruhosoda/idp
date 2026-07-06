//! axum ルータの組立。各コンテキストのルータを `.merge()` / `.nest()` で集約する。

use crate::presentation::correlation;
use crate::presentation::handlers::{
    admin, admin_audit, admin_clients, authorize, discovery, health, login, register, token,
    userinfo,
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
        // 管理コンソール（A2 基盤）。idp.admin 権限が必要（RequirePerms<IdpAdmin>）。内部用。
        .route("/admin/whoami", get(admin::whoami))
        // クライアント（RP）登録・管理 API（A1、設計仕様 §9.3）。idp.admin 必須。
        .route(
            "/admin/clients",
            post(admin_clients::create_client).get(admin_clients::list_clients),
        )
        .route(
            "/admin/clients/{client_id}",
            get(admin_clients::get_client).patch(admin_clients::update_client),
        )
        .route(
            "/admin/clients/{client_id}/secret",
            post(admin_clients::rotate_client_secret),
        )
        // 監査ログ参照（A3、設計仕様 §7）。idp.admin 必須。
        .route("/admin/audit-logs", get(admin_audit::list_audit_logs))
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
