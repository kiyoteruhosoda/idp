//! web の axum ルータ組立。管理コンソールは後続ステージで追加する。

use crate::correlation;
use crate::handlers::{
    admin_clients_console, admin_console, admin_signing_keys_console, admin_status_console,
    admin_users_console, consent, health, login, mfa_totp, passkey,
};
use crate::state::WebState;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub fn build(state: WebState) -> Router {
    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/login", get(login::login_page).post(login::login))
        // 同意画面（F3: Consent）。
        .route("/consent", get(consent::consent_page).post(consent::consent))
        // MFA: ログインフロー TOTP 入力（パスワード認証後）。
        .route("/mfa/totp", get(mfa_totp::verify_page).post(mfa_totp::verify))
        // MFA: ユーザー自己登録（TOTP セットアップ・削除）。SSO 認証が必要。
        .route(
            "/account/mfa/totp/setup",
            get(mfa_totp::setup_page).post(mfa_totp::setup_confirm),
        )
        .route("/account/mfa/totp/delete", post(mfa_totp::setup_delete))
        // Passkey（WebAuthn）自己登録。SSO 認証が必要。
        .route("/account/passkey", get(passkey::list_page))
        .route("/account/passkey/register", get(passkey::register_page))
        .route("/account/passkey/delete", post(passkey::delete))
        // Passkey 登録 JSON API（ブラウザ JS から呼ぶ）。
        .route("/passkey/register/begin", post(passkey::register_begin_api))
        .route(
            "/passkey/register/complete",
            post(passkey::register_complete_api),
        )
        // Passkey 認証 JSON API（ログイン画面 JS から呼ぶ）。
        .route("/passkey/login/begin", post(passkey::login_begin_api))
        .route("/passkey/login/complete", post(passkey::login_complete_api))
        // 管理コンソール（ADR-0006 §6・ADR-0007 §4）。ログインはクライアント不要。
        .route(
            "/admin/console/login",
            get(admin_console::login_page).post(admin_console::login),
        )
        .route("/admin/console/logout", post(admin_console::logout))
        .route("/admin/console", get(admin_console::home))
        // クライアント（RP）管理画面。静的セグメント（new）は動的 {client_id} より優先。
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
        // 利用者権限の付与・剥奪画面。
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
        // 状況確認画面（監査ログ・クライアント状況）。読み取り専用。
        .route(
            "/admin/console/audit-logs",
            get(admin_status_console::audit_logs),
        )
        .route(
            "/admin/console/status",
            get(admin_status_console::client_status),
        )
        // 署名鍵管理画面（K1）。
        .route(
            "/admin/console/signing-keys",
            get(admin_signing_keys_console::list),
        )
        .route(
            "/admin/console/signing-keys/generate",
            post(admin_signing_keys_console::generate),
        )
        .route(
            "/admin/console/signing-keys/retire",
            post(admin_signing_keys_console::retire),
        )
        .route(
            "/admin/console/signing-keys/delete",
            post(admin_signing_keys_console::delete),
        )
        .layer(axum::middleware::from_fn(correlation::propagate))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
