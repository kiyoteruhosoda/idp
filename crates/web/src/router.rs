//! web の axum ルータ組立（ADR-0009 §6・§10、MT13）。
//!
//! テナント外パス（`/healthz`・`/readyz`）を除き、すべての画面 URL を `/{tenant_id}/...` 配下に
//! 一律配置する（root を含め特別分岐を設けない。api の router.rs と同じ方式）。

use crate::correlation;
use crate::handlers::{
    admin_clients_console, admin_console, admin_invitations_console, admin_members_console,
    admin_saml_clients_console, admin_settings, admin_signing_keys_console, admin_status_console,
    admin_tenants_console, admin_users_console, consent, health, invitation_accept, locale, login,
    mfa_totp, passkey, password_change, password_reset, portal, react_assets, stylesheet,
    user_settings, vendor_assets, verify_email,
};
use crate::i18n::Messages;
use crate::security_headers::add_security_headers;
use crate::state::WebState;
use crate::templates::{render, MessagePage};
use crate::tenant::capture_tenant;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub fn build(state: WebState) -> Router {
    let hsts_max_age = state.config.hsts_max_age();
    let tenant_scoped = Router::new()
        .route("/login", get(login::login_page).post(login::login))
        // エンドユーザー・ポータルの TOTP 入力（`/login` 直接ログイン経路の 2 段階目）。
        .route("/login/mfa", get(portal::mfa_page).post(portal::mfa_submit))
        // エンドユーザー・ポータルの強制パスワード変更（初回ログイン時。ADR-0009 §5。管理コンソールと
        // 同じ共有画面を流用）。
        .route(
            "/login/password-change",
            get(portal::password_change_page).post(portal::password_change),
        )
        // エンドユーザーのログアウト（アカウント画面から。SSO 失効）。
        .route("/logout", post(portal::logout))
        // 強制パスワード変更（ADR-0009 §5、MT12）。パスワード認証成功後・SSO 発行前の pending 状態で使う。
        .route(
            "/password-change",
            get(password_change::page).post(password_change::submit),
        )
        // パスワードリセット（忘失時。MT18）。未ログイン経路（メールのリンクから開く）。
        .route(
            "/forgot-password",
            get(password_reset::forgot_page).post(password_reset::forgot_submit),
        )
        .route(
            "/password-reset",
            get(password_reset::reset_page).post(password_reset::reset_submit),
        )
        // メール検証画面（SEC6b）。自己登録の確認メールのリンクから開く。未ログイン経路（SSO 不要）。
        .route(
            "/verify-email",
            get(verify_email::page).post(verify_email::submit),
        )
        // 利用者のセルフサービス設定画面（MT15）。パスワード変更・言語・MFA 導線。SSO 認証が必要。
        .route("/settings", get(user_settings::page))
        .route("/settings/password", post(user_settings::change_password))
        .route("/settings/name", post(user_settings::change_name))
        // 招待承諾画面（ADR-0009 §3・MT17）。招待メールのリンクから開く。SSO 認証が必要。
        .route(
            "/invitations/accept",
            get(invitation_accept::page).post(invitation_accept::submit),
        )
        // 同意画面（F3: Consent）。
        .route(
            "/consent",
            get(consent::consent_page).post(consent::consent),
        )
        // MFA: ログインフロー TOTP 入力（パスワード認証後）。
        .route(
            "/mfa/totp",
            get(mfa_totp::verify_page).post(mfa_totp::verify),
        )
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
        // テナント切り替え（所属テナントの管理コンソールへ遷移。ADR-0009 §8）。
        .route("/admin/switch-tenant", get(admin_console::switch_tenant))
        // 設定画面（MT14）。テナント設定（idp.tenant.admin）＋ root のみのシステム設定区画（SMTP）。
        .route("/admin/settings", get(admin_settings::page))
        .route(
            "/admin/settings/tenant",
            post(admin_settings::update_tenant),
        )
        .route(
            "/admin/system-settings",
            post(admin_settings::update_system),
        )
        // ランタイム設定の DB 上書き（root のみ。反映には再起動が必要）。
        .route(
            "/admin/system-settings/runtime",
            post(admin_settings::update_runtime),
        )
        .route(
            "/admin/tenants",
            get(admin_tenants_console::list).post(admin_tenants_console::create),
        )
        // 子テナントの削除・管理者パスワード再発行（root のみ）。
        .route(
            "/admin/tenants/{child_id}/delete",
            post(admin_tenants_console::delete),
        )
        .route(
            "/admin/tenants/{child_id}/reset-admin-password",
            post(admin_tenants_console::reset_admin_password),
        )
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
        // SAML SP（クライアント）一覧・追加画面。
        .route(
            "/admin/saml-clients",
            get(admin_saml_clients_console::list).post(admin_saml_clients_console::create),
        )
        // SP メタデータ取り込み（登録フォームへ初期値反映）。
        .route(
            "/admin/saml-clients/import",
            post(admin_saml_clients_console::import_metadata),
        )
        // SP の更新・削除（HTML フォームは POST のみのため専用パス）。
        .route(
            "/admin/saml-clients/{id}/update",
            post(admin_saml_clients_console::update),
        )
        .route(
            "/admin/saml-clients/{id}/delete",
            post(admin_saml_clients_console::delete),
        )
        // 利用者の作成・権限付与/剥奪画面（一覧・検索の起点はメンバー画面。/admin/members）。
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
        // メンバー（HOME/GUEST）一覧・ゲスト解除（ADR-0009 §3）と、所属元（HOME）利用者の
        // 無効化・有効化・パスワード再発行・削除（ADR-0009 §5）。
        .route("/admin/members", get(admin_members_console::list))
        .route(
            "/admin/members/{user_id}/revoke",
            post(admin_members_console::revoke),
        )
        .route(
            "/admin/members/{user_id}/status",
            post(admin_members_console::set_status),
        )
        .route(
            "/admin/members/{user_id}/reset-password",
            post(admin_members_console::reset_password),
        )
        .route(
            "/admin/members/{user_id}/delete",
            post(admin_members_console::delete),
        )
        // ゲスト招待の作成（ADR-0009 §3）。
        .route(
            "/admin/invitations",
            get(admin_invitations_console::new_form).post(admin_invitations_console::create),
        )
        // 状況確認画面（監査ログ・クライアント状況）。読み取り専用。
        .route("/admin/audit-logs", get(admin_status_console::audit_logs))
        .route("/admin/status", get(admin_status_console::client_status))
        // 署名鍵管理画面（K1）。
        .route("/admin/signing-keys", get(admin_signing_keys_console::list))
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
        .route("/", get(root_entrypoint))
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/version", get(health::version))
        .route("/assets/app.css", get(stylesheet::app_css))
        .route(
            "/assets/vendor/bootstrap.min.css",
            get(vendor_assets::bootstrap_css),
        )
        .route(
            "/assets/vendor/bootstrap.bundle.min.js",
            get(vendor_assets::bootstrap_js),
        )
        .route(
            "/assets/vendor/fontawesome/css/all.min.css",
            get(vendor_assets::fontawesome_css),
        )
        .route(
            "/assets/vendor/fontawesome/webfonts/fa-solid-900.woff2",
            get(vendor_assets::fa_solid_woff2),
        )
        .route(
            "/assets/vendor/fontawesome/webfonts/fa-regular-400.woff2",
            get(vendor_assets::fa_regular_woff2),
        )
        .route(
            "/assets/vendor/fontawesome/webfonts/fa-brands-400.woff2",
            get(vendor_assets::fa_brands_woff2),
        )
        .route(
            "/assets/vendor/fontawesome/webfonts/fa-v4compatibility.woff2",
            get(vendor_assets::fa_v4compatibility_woff2),
        )
        .route("/assets/react/app.js", get(react_assets::app_js))
        .route("/assets/react/app.js.map", get(react_assets::app_js_map))
        // この nest 配下で `{user_id}` 等を持つルートは、ネスト元の `{tenant_id}` と合わせて
        // パスパラメータが 2 つになる。ハンドラは `Path<(String, String)>` のタプルで受けること
        // （`Path<String>` だと実行時に 500 "Wrong number of path arguments" になる）。
        .nest("/{tenant_id}", tenant_scoped)
        .layer(axum::middleware::from_fn(correlation::propagate))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(move |req, next| {
            add_security_headers(req, next, hsts_max_age)
        }))
        .with_state(state)
}

/// ルート（テナント未指定）のランディング。
///
/// 以前は `/{root_tenant_id}/admin/login` へリダイレクトしていたが、これは素のドメインへアクセス
/// しただけで root テナントの UUID と管理ログイン画面を露出させ、root を狙う攻撃の起点になり得た。
/// テナントを推測させないため、リダイレクトを廃止し、特定テナントに触れない汎用の案内ページを
/// 描画する（正規の利用者は管理者から案内された `/{tenant_id}/...` URL でアクセスする）。
async fn root_entrypoint(headers: HeaderMap) -> impl IntoResponse {
    let messages = Messages::new(locale(&headers));
    (
        StatusCode::NOT_FOUND,
        Html(render(&MessagePage {
            title: messages.get("root-landing-title"),
            message: messages.get("root-landing-message"),
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_state() -> WebState {
        WebState::build(Arc::new(
            crate::config::Config::from_env().expect("config with dev defaults"),
        ))
    }

    /// ルート `/` はリダイレクトせず案内ページ（404）を返し、レスポンスに root テナントの UUID を
    /// 一切含めない（素のドメインアクセスで root を露出させない）ことの回帰テスト。
    #[tokio::test]
    async fn root_does_not_redirect_or_leak_tenant() {
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // リダイレクトしない（Location ヘッダを付けない）。
        assert!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .is_none(),
            "root must not redirect"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        // UUID（`/{tenant_id}/...`）を本文に埋め込まない。
        assert!(
            !text.contains("/admin/login"),
            "root page must not expose an admin login link"
        );
        let uuid_re_hits = text
            .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
            .any(|tok| uuid::Uuid::parse_str(tok).is_ok());
        assert!(!uuid_re_hits, "root page must not embed any tenant UUID");
    }

    /// nest 配下の `{tenant_id}` ＋ `{user_id}` 等の 2 パラメータルートで `Path` 抽出が成立する
    /// ことの回帰テスト。抽出が不一致だと axum が 500（"Wrong number of path arguments"）を返す。
    /// ここではボディ無し POST のため `Form` 抽出の失敗（4xx）で止まるのが期待値であり、
    /// API への到達は不要（ネットワークに依存しない）。
    #[tokio::test]
    async fn nested_two_param_routes_extract_path_without_error() {
        let tenant = "019f6514-08ea-7138-ad71-838a7bdd3575";
        let id = "019f7576-b5b8-73f2-a496-0df7a83c667f";
        let post_uris = [
            format!("/{tenant}/admin/members/{id}/revoke"),
            format!("/{tenant}/admin/members/{id}/status"),
            format!("/{tenant}/admin/members/{id}/reset-password"),
            format!("/{tenant}/admin/members/{id}/delete"),
            format!("/{tenant}/admin/users/{id}/permissions/grant"),
            format!("/{tenant}/admin/users/{id}/permissions/revoke"),
            format!("/{tenant}/admin/clients/{id}/edit"),
            format!("/{tenant}/admin/clients/{id}/rotate-secret"),
            format!("/{tenant}/admin/tenants/{id}/delete"),
            format!("/{tenant}/admin/tenants/{id}/reset-admin-password"),
            format!("/{tenant}/admin/saml-clients/{id}/update"),
            format!("/{tenant}/admin/saml-clients/{id}/delete"),
        ];
        for uri in post_uris {
            let response = build(test_state())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_ne!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "path extraction failed for {uri}"
            );
            assert!(
                response.status().is_client_error(),
                "unexpected status for {uri}"
            );
        }
    }
}
