//! axum ルータの組立。各コンテキストのルータを `.merge()` / `.nest()` で集約する。

use crate::presentation::correlation;
use crate::presentation::handlers::{
    admin, admin_audit, admin_clients, admin_permissions, admin_users, authorize, discovery, health,
    internal_auth, register, token, userinfo,
};
use crate::presentation::openapi::ApiDoc;
use crate::presentation::state::AppState;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn build(state: AppState) -> Router {
    // 内部認証 API（ADR-0007 §3・§5）。web（将来）→api のサービス間 I/F。外部公開しない
    // （リバースプロキシで /internal/* を遮断する前提）。多層防御としてサービス認証トークン
    // （X-Internal-Auth-Token）を必須にする route_layer をこのサブルータにのみ付ける。
    let internal = Router::new()
        .route("/internal/authenticate", post(internal_auth::authenticate))
        .route(
            "/internal/authenticate/admin",
            post(internal_auth::authenticate_admin),
        )
        .route("/internal/logout", post(internal_auth::logout))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            internal_auth::require_service_token,
        ));

    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/auth/register", post(register::register))
        .route("/authorize", get(authorize::authorize))
        .route("/token", post(token::token))
        .route("/userinfo", get(userinfo::userinfo))
        // 管理者身元確認（idp.admin 必須。RequirePerms<IdpAdmin>）。web の管理コンソールが SSO Cookie
        // 転送で認証状態・身元を得るのに使う（ADR-0007 §4）。HTML 画面は web crate 側にある。
        .route("/admin/whoami", get(admin::whoami))
        // クライアント（RP）登録・管理 API（A1、設計仕様 §9.3）。idp.admin 必須。
        .route(
            "/admin/clients",
            post(admin_clients::create_client).get(admin_clients::list_clients),
        )
        // 状況一覧（静的 status は動的 {client_id} より優先）。
        .route(
            "/admin/clients/status",
            get(admin_clients::list_client_status),
        )
        .route(
            "/admin/clients/{client_id}",
            get(admin_clients::get_client).patch(admin_clients::update_client),
        )
        .route(
            "/admin/clients/{client_id}/secret",
            post(admin_clients::rotate_client_secret),
        )
        // 付与可能な権限コード（マスタ）と利用者検索・取得（管理コンソール支援 API）。idp.admin 必須。
        .route(
            "/admin/permissions",
            get(admin_permissions::list_available_permissions),
        )
        .route(
            "/admin/users",
            get(admin_users::search_user),
        )
        .route("/admin/users/{user_id}", get(admin_users::get_user))
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
        .merge(internal)
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(axum::middleware::from_fn(correlation::propagate))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
