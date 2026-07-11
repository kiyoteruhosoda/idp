//! web の axum ルータ組立（ADR-0009 §6・§10、MT13）。
//!
//! テナント外パス（`/healthz`・`/readyz`）を除き、すべての画面 URL を `/{tenant_id}/...` 配下に
//! 一律配置する（root を含め特別分岐を設けない。api の router.rs と同じ方式）。

use crate::correlation;
use crate::handlers::{
    admin_clients_console, admin_console, admin_invitations_console, admin_members_console,
    admin_signing_keys_console, admin_status_console, admin_users_console, consent, health,
    login, mfa_totp, passkey, password_change,
};
use crate::state::WebState;
use crate::tenant::capture_tenant;
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub fn build(state: WebState) -> Router {
    let tenant_scoped = Router::new()
        .route("/login", get(login::login_page).post(login::login))
        // 強制パスワード変更（ADR-0009 §5、MT12）。パスワード認証成功後・SSO 発行前の pending 状態で使う。
        .route(
            "/password-change",
            get(password_change::page).post(password_change::submit),
        )
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
        // 管理コンソール（ADR-0006 §6・ADR-0007 §4・ADR-0009 §10）。ログインはクライアント不要。
        .route(
            "/admin/login",
            get(admin_console::login_page).post(admin_console::login),
        )
        .route(
            "/admin/password-change",
            get(admin_console::password_change_page).post(admin_console::password_change),
        )
        .route("/admin/logout", post(admin_console::logout))
        .route("/admin", get(admin_console::home))
        // クライアント（RP）管理画面。静的セグメント（new）は動的 {client_id} より優先。
        .route("/admin/clients", get(admin_clients_console::list))
        .route(
            "/admin/clients/new",
            get(admin_clients_console::new_form).post(admin_clients_console::create),
        )
        .route(
            "/admin/clients/{client_id}",
            get(admin_clients_console::detail),
        )
        .route(
            "/admin/clients/{client_id}/edit",
            get(admin_clients_console::edit_form).post(admin_clients_console::update),
        )
        .route(
            "/admin/clients/{client_id}/rotate-secret",
            post(admin_clients_console::rotate_secret),
        )
        // 利用者の作成・検索・権限付与/剥奪画面。
        .route("/admin/users", get(admin_users_console::search))
        .route(
            "/admin/users/new",
            get(admin_users_console::new_form).post(admin_users_console::create),
        )
        .route(
            "/admin/users/{user_id}/permissions",
            get(admin_users_console::view),
        )
        .route(
            "/admin/users/{user_id}/permissions/grant",
            post(admin_users_console::grant),
        )
        .route(
            "/admin/users/{user_id}/permissions/revoke",
            post(admin_users_console::revoke),
        )
        // メンバー（HOME/GUEST）一覧・ゲスト解除（ADR-0009 §3）。
        .route("/admin/members", get(admin_members_console::list))
        .route(
            "/admin/members/{user_id}/revoke",
            post(admin_members_console::revoke),
        )
        // ゲスト招待の作成（ADR-0009 §3）。
        .route(
            "/admin/invitations",
            get(admin_invitations_console::new_form).post(admin_invitations_console::create),
        )
        // 状況確認画面（監査ログ・クライアント状況）。読み取り専用。
        .route(
            "/admin/audit-logs",
            get(admin_status_console::audit_logs),
        )
        .route(
            "/admin/status",
            get(admin_status_console::client_status),
        )
        // 署名鍵管理画面（K1）。
        .route(
            "/admin/signing-keys",
            get(admin_signing_keys_console::list),
        )
        .route(
            "/admin/signing-keys/generate",
            post(admin_signing_keys_console::generate),
        )
        .route(
            "/admin/signing-keys/retire",
            post(admin_signing_keys_console::retire),
        )
        .route(
            "/admin/signing-keys/delete",
            post(admin_signing_keys_console::delete),
        )
        .route_layer(axum::middleware::from_fn(capture_tenant));

    Router::new()
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .nest("/{tenant_id}", tenant_scoped)
        .layer(axum::middleware::from_fn(correlation::propagate))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
