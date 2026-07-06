//! axum ルータの組立。各コンテキストのルータを `.merge()` / `.nest()` で集約する。

use crate::presentation::correlation;
use crate::presentation::handlers::{
    admin, admin_audit, admin_clients, admin_clients_console, admin_console, admin_permissions,
    admin_status_console, admin_users_console, authorize, discovery, health, login, register,
    token, userinfo,
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
        // ブラウザ向け管理コンソール（A2 基盤・A1 画面）。サーバレンダリング（ADR-0006 §6）。
        // JSON 管理 API（/admin/<resource>）とは経路を分け /admin/console 配下に置く。
        // ログインはクライアント不要（鶏卵問題の回避）。ホーム/ログアウト/各画面は idp.admin で保護。
        .route(
            "/admin/console/login",
            get(admin_console::login_page).post(admin_console::login),
        )
        .route("/admin/console/logout", post(admin_console::logout))
        .route("/admin/console", get(admin_console::home))
        // クライアント（RP）管理画面（A1）。静的セグメント（new）は動的 {client_id} より優先される。
        .route("/admin/console/clients", get(admin_clients_console::list))
        .route(
            "/admin/console/clients/new",
            get(admin_clients_console::new_form).post(admin_clients_console::create),
        )
        .route(
            "/admin/console/clients/{client_id}",
            get(admin_clients_console::detail),
        )
        .route(
            "/admin/console/clients/{client_id}/edit",
            get(admin_clients_console::edit_form).post(admin_clients_console::update),
        )
        .route(
            "/admin/console/clients/{client_id}/rotate-secret",
            post(admin_clients_console::rotate_secret),
        )
        // 利用者権限の付与・剥奪画面（A2、ADR-0006）。JSON API（/admin/users/*）とは経路を分ける。
        .route("/admin/console/users", get(admin_users_console::search))
        .route(
            "/admin/console/users/{user_id}/permissions",
            get(admin_users_console::view),
        )
        .route(
            "/admin/console/users/{user_id}/permissions/grant",
            post(admin_users_console::grant),
        )
        .route(
            "/admin/console/users/{user_id}/permissions/revoke",
            post(admin_users_console::revoke),
        )
        // 状況確認画面（A3）。監査／ログインログ一覧・クライアント状況一覧。
        .route(
            "/admin/console/audit-logs",
            get(admin_status_console::audit_logs),
        )
        .route(
            "/admin/console/status",
            get(admin_status_console::client_status),
        )
        // 疎通確認用の内部 API（idp.admin 必須。RequirePerms<IdpAdmin>）。
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
        // 利用者権限の付与・剥奪・参照（A2、ADR-0006）。idp.admin 必須。
        .route(
            "/admin/users/{user_id}/permissions",
            get(admin_permissions::list_permissions).post(admin_permissions::grant_permission),
        )
        .route(
            "/admin/users/{user_id}/permissions/{permission_code}",
            axum::routing::delete(admin_permissions::revoke_permission),
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
