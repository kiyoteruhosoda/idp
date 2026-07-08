//! axum ルータの組立。各コンテキストのルータを `.merge()` / `.nest()` で集約する。

use crate::presentation::correlation;
use crate::presentation::handlers::{
    admin, admin_audit, admin_clients, admin_permissions, admin_signing_keys, admin_users,
    authorize, consent, discovery, health, internal_auth, introspect, logout, mfa, passkey,
    register, revoke, token, userinfo,
};
use crate::presentation::openapi::ApiDoc;
use crate::presentation::security_headers::add_security_headers;
use crate::presentation::state::AppState;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn build(state: AppState) -> Router {
    let hsts_max_age = state.config.hsts_max_age();
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
        // 同意 API（F3: Consent）。
        .route(
            "/internal/consent-info",
            get(consent::consent_info),
        )
        .route(
            "/internal/consent/approve",
            post(consent::consent_approve),
        )
        .route(
            "/internal/consent/deny",
            post(consent::consent_deny),
        )
        // MFA（TOTP）自己登録・ログイン検証 API。
        .route("/internal/mfa/totp/setup", post(mfa::setup_totp))
        .route("/internal/mfa/totp/confirm", post(mfa::confirm_totp))
        .route("/internal/mfa/totp/delete", post(mfa::delete_totp))
        .route("/internal/mfa/totp/verify", post(mfa::verify_totp))
        // Passkey（WebAuthn）セルフ登録 API。
        .route("/internal/passkey/register/begin", post(passkey::register_begin))
        .route("/internal/passkey/register/complete", post(passkey::register_complete))
        .route("/internal/passkey/delete", post(passkey::passkey_delete))
        .route("/internal/passkey/list", post(passkey::passkey_list))
        // Passkey ログインフロー API。
        .route("/internal/passkey/login/begin", post(passkey::login_begin))
        .route("/internal/passkey/login/complete", post(passkey::login_complete))
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
        .route("/logout", get(logout::logout))
        .route("/revoke", post(revoke::revoke))
        .route("/introspect", post(introspect::introspect))
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
        .route("/admin/users", get(admin_users::search_user))
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
        // 署名鍵管理 API（K1）。idp.admin 必須。
        .route(
            "/admin/signing-keys",
            get(admin_signing_keys::list_keys).post(admin_signing_keys::generate_key),
        )
        .route(
            "/admin/signing-keys/{kid}/retire",
            post(admin_signing_keys::retire_key),
        )
        .route(
            "/admin/signing-keys/{kid}",
            axum::routing::delete(admin_signing_keys::delete_key),
        )
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(discovery::jwks))
        .merge(internal)
        .merge(SwaggerUi::new("/api/docs").url("/api/openapi.json", ApiDoc::openapi()))
        .layer(axum::middleware::from_fn(correlation::propagate))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(move |req, next| {
            add_security_headers(req, next, hsts_max_age)
        }))
        .with_state(state)
}
