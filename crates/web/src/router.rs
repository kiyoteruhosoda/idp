//! web の axum ルータ組立（ADR-0009 §6・§10、MT13）。
//!
//! テナント外パス（`/healthz`・`/readyz`）を除き、すべての画面 URL を `/{tenant_id}/...` 配下に
//! 一律配置する（root を含め特別分岐を設けない。api の router.rs と同じ方式）。

use crate::client_ip::resolve_client_ip;
use crate::correlation;
use crate::error_pages;
use crate::handlers::{
    admin_authentication_policies_console, admin_clients_console, admin_console,
    admin_invitations_console, admin_members_console, admin_restart_console,
    admin_saml_clients_console, admin_settings, admin_signing_keys_console, admin_status_console,
    admin_tenants_console, admin_users_console, authenticators, consent, console_script,
    external_login, health, invitation_accept, locale, login, mfa_totp, page_scripts, passkey,
    password_change, password_reset, portal, react_assets, rp_logout, saml_sso, step_up,
    stylesheet, submit_feedback_script, user_security, user_settings, vendor_assets, verify_email,
};
use crate::i18n::Messages;
use crate::language::resolve_language;
use crate::login_context::load_rp_login_context;
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
    let trust_forwarded = state.config.trust_forwarded_headers();
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
        // GET: OIDC RP-initiated Logout（end_session_endpoint。ADR-0018 決定 2 で api から移設）。
        // POST: エンドユーザーのログアウト（アカウント画面から。SSO 失効）。
        .route("/logout", get(rp_logout::logout).post(portal::logout))
        // SAML SSO の継続（api の /saml/sso からのハンドオフ受領と、ログイン後のフロー復帰）。
        .route("/saml/continue", get(saml_sso::continue_sso))
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
        // 外部 IdP ログイン（AP10）。開始は 302、コールバックは外部 IdP からの戻り先。
        .route("/external/{provider}/start", get(external_login::start))
        .route(
            "/external/{provider}/callback",
            get(external_login::callback),
        )
        // MFA 入力画面から「メールでコードを送る」（AP9）。
        .route("/mfa/totp/email-code", post(mfa_totp::send_email_code))
        // 認証器の管理（一覧・一時停止・失効・リカバリーコード発行。AP9）。
        .route("/settings/authenticators", get(authenticators::page))
        .route(
            "/settings/authenticators/status",
            post(authenticators::set_status),
        )
        .route(
            "/settings/recovery-codes",
            post(authenticators::issue_recovery_codes),
        )
        // Step-up 認証の本人確認画面（重要操作の直前。AP5）。
        .route("/settings/verify", get(step_up::page))
        .route("/settings/verify", post(step_up::verify))
        // セルフサービスのセキュリティ画面（セッション一覧・失効／連携アプリ解除。G10）。
        .route("/settings/security", get(user_security::page))
        .route(
            "/settings/security/revoke-session",
            post(user_security::revoke_session),
        )
        .route(
            "/settings/security/revoke-consent",
            post(user_security::revoke_consent),
        )
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
        // 認証ポリシー（AP1）。一覧・作成・編集・削除。HTML フォームは PUT/DELETE を送れないため、
        // 更新・削除は専用の POST パスを経由して api の PUT/DELETE へ変換する。
        .route(
            "/admin/authentication-policies",
            get(admin_authentication_policies_console::list)
                .post(admin_authentication_policies_console::create),
        )
        .route(
            "/admin/authentication-policies/{policy_id}/update",
            post(admin_authentication_policies_console::update),
        )
        .route(
            "/admin/authentication-policies/{policy_id}/delete",
            post(admin_authentication_policies_console::delete),
        )
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
        // 保存したランタイム設定を反映するための api → web の再起動（root のみ。ADR-0017）。
        .route("/admin/restart", post(admin_restart_console::restart))
        .route(
            "/admin/tenants",
            get(admin_tenants_console::list).post(admin_tenants_console::create),
        )
        // 子テナントの編集（表示名・状態。MT23）・削除・管理者パスワード再発行（root のみ）。
        .route(
            "/admin/tenants/{child_id}/update",
            post(admin_tenants_console::update),
        )
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
        // IdP メタデータを web オリジンからダウンロードする（api への直接リンクを露出しない）。
        .route(
            "/admin/saml-clients/idp-metadata",
            get(admin_saml_clients_console::download_idp_metadata),
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
        // プロフィール（メール・ログイン識別子・表示名）の編集（MT25）。
        .route(
            "/admin/users/{user_id}/profile",
            post(admin_users_console::update_profile),
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
            "/admin/members/{user_id}/reset-mfa",
            post(admin_members_console::reset_mfa),
        )
        // ゲストメンバーシップの一時停止・再開（MT24）。解除（削除）と違い元に戻せる。
        .route(
            "/admin/members/{user_id}/suspend",
            post(admin_members_console::suspend),
        )
        .route(
            "/admin/members/{user_id}/resume",
            post(admin_members_console::resume),
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
        // エラー・警告ログ（`log` テーブル）。api 側は idp.system.admin を要求する。
        .route("/admin/logs", get(admin_status_console::application_logs))
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
        // 表示言語の決定（MT20）は tenant 解決より内側で行う。`?lang=` / ユーザー設定 / Cookie /
        // `ui_locales` / ブラウザ言語の優先順位をここへ一本化し、各ハンドラは `handlers::locale` を
        // 呼ぶだけにする。
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            resolve_language,
        ))
        // 認可要求が持ち込む文脈（`login_hint` / `ui_locales`。G12）の取り直し。言語決定が
        // `ui_locales` を読むため、`resolve_language` より外側（＝先に走る）に置く。
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            load_rp_login_context,
        ))
        .route_layer(axum::middleware::from_fn(capture_tenant));

    Router::new()
        .route("/", get(root_entrypoint))
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        .route("/version", get(health::version))
        .route("/assets/app.css", get(stylesheet::app_css))
        .route("/assets/console.js", get(console_script::console_js))
        .route(
            "/assets/submit-feedback.js",
            get(submit_feedback_script::submit_feedback_js),
        )
        // 画面固有スクリプト（旧インライン script。SEC12）。
        .route(
            "/assets/passkey-login.js",
            get(page_scripts::passkey_login_js),
        )
        .route(
            "/assets/passkey-register.js",
            get(page_scripts::passkey_register_js),
        )
        .route(
            "/assets/password-visibility.js",
            get(page_scripts::password_visibility_js),
        )
        .route("/assets/rp-logout.js", get(page_scripts::rp_logout_js))
        .route("/assets/auto-submit.js", get(page_scripts::auto_submit_js))
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
        // どのルートにも一致しないリクエストには 404 エラーページを返す（axum 既定の空応答を避ける）。
        .fallback(error_pages::fallback)
        .layer(axum::middleware::from_fn(correlation::propagate))
        // 接続元 IP の決定（SEC1）。`X-Forwarded-For` を信じるかは api と同じ設定キーでゲートし、
        // 非信頼時は TCP 接続元へ落とす。ハンドラは `Extension<ClientIp>` で結果だけを受け取る。
        .layer(axum::middleware::from_fn(move |req, next| {
            resolve_client_ip(trust_forwarded, req, next)
        }))
        // 全エラー応答（4xx / 5xx）の本文を共通エラーページへ揃える。ハンドラが本文なしで返した応答・
        // extractor の拒否・メソッド不一致（405）もここで HTML 化される（`error_pages` のモジュール
        // ドキュメント参照）。ルーティングの外側に置くことで、未マッチ・拒否経路も対象になる。
        .layer(axum::middleware::from_fn(error_pages::render_error_pages))
        // アクセススパンはパスのみを記録する（クエリ文字列に載る `?auth_session=` 等の単回ハンドルを
        // ログへ落とさない。SEC9）。組み立ては api と共有する。
        .layer(TraceLayer::new_for_http().make_span_with(idp_contracts::http_trace::request_span))
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

/// `build` が `route` に宣言したパスを、パラメータ名を潰した形（`/admin/users/{}`）で集める。
///
/// 自分のソースを読むのは、axum の `Router` が登録済みパスを公開しないため。ルート一覧を必要とする
/// 検査（テンプレートのリンク先・リバースプロキシの振り分け）が、ルート追加のたびに手で更新される
/// 別の一覧と食い違わないようにする。
#[cfg(test)]
pub(crate) fn declared_route_paths() -> std::collections::HashSet<String> {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/router.rs"))
        .expect("read router.rs");
    // 本関数より下（テスト専用コード）にはルートでないパス文字列が並ぶので切り落とす。
    // コメント行も落とす（説明として書いた `route` の例を実在のルートと数えないため）。
    let source: String = source
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut paths = std::collections::HashSet::new();
    for after in source.split(".route(").skip(1) {
        let Some(open) = after.find('"') else {
            continue;
        };
        let Some(len) = after[open + 1..].find('"') else {
            continue;
        };
        paths.insert(collapse_params(&after[open + 1..open + 1 + len]));
    }
    paths
}

/// `{{ expr }}`（Askama）・`{param}`（axum ルート）といったパラメータを `{}` に潰す。
/// 開き記号が連続する `{{` も 1 つのパラメータとして扱えるよう、閉じ記号までを一括で捨てる。
#[cfg(test)]
pub(crate) fn collapse_params(raw: &str) -> String {
    let mut out = String::new();
    let mut rest = raw;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        out.push_str("{}");
        // `}}` のように閉じ記号が連続する分を読み飛ばす。
        rest = rest[start + end..].trim_start_matches('}');
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    /// 単一オリジン構成（`PUBLISH_TOPOLOGY=single-origin`）のリバースプロキシは、パスを見て web と
    /// api へ振り分ける。web の画面のパスが `docker/nginx.conf` に列挙されていないと catch-all で
    /// api へ流れ、404 になる（web にルートはあるのに届かない。ドメイン分割構成で web オリジン相対
    /// リンクが api のパスへ届かないのと同じ、経路とサービスの取り違え）。
    ///
    /// 正規表現の評価まではしない。**画面の第 1 セグメントが設定に現れること**だけを見て、ルートを
    /// 足したのに振り分けを足し忘れた退行を検出する。
    #[test]
    fn single_origin_proxy_routes_every_web_page_to_web() {
        let conf = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docker/nginx.conf"
        ))
        .expect("read docker/nginx.conf");
        // `location` ブロックの宣言行だけを対象にする（コメントに書いてあるだけでは振り分けされない）。
        let locations: String = conf
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("location"))
            .collect::<Vec<_>>()
            .join("\n");
        // 非テナントのパスは対象外。`/`・`/version`・`/assets/...` はプロキシに個別の location が
        // あり、`/healthz`・`/readyz` は api にも同じルートがあるので catch-all で api が答えてよい。
        let non_tenant = ["/", "/healthz", "/readyz", "/version"];
        let mut checked = 0;
        for route in declared_route_paths() {
            if non_tenant.contains(&route.as_str()) || route.starts_with("/assets/") {
                continue;
            }
            let Some(segment) = route.trim_start_matches('/').split('/').next() else {
                continue;
            };
            checked += 1;
            assert!(
                locations.contains(segment),
                "route `{route}` is served by web but `{segment}` does not appear in any \
                 location of docker/nginx.conf; 単一オリジン構成で api へ流れて 404 になる"
            );
        }
        assert!(checked > 0, "expected routes to check");
    }

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

    /// どのルートにも一致しない URL は 404 のエラーページ（HTML 本文つき）を返す（axum 既定の空応答に
    /// しない）ことの回帰テスト。
    #[tokio::test]
    async fn unmatched_route_returns_404_error_page() {
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri("/no/such/path")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        // ステータスコードと説明文を含むエラーページが描画される。
        assert!(text.contains("404"), "error page must show the status code");
        assert!(
            text.contains("<!DOCTYPE html>"),
            "fallback must render the full error page, not an empty body"
        );
    }

    /// 実ルータでもエラーページのミドルウェアが効いていること（メソッド不一致の 405 と、
    /// extractor 拒否の内部メッセージ非露出）の回帰テスト。エラー応答の HTML 化は
    /// `error_pages` に集約しているため、ここでは配線されていることだけを確認する。
    #[tokio::test]
    async fn error_responses_are_rendered_as_pages_by_the_router() {
        // GET 専用ルートへ POST（405）。
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/version")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("405"), "error page must show the status code");
        assert!(text.contains("<!DOCTYPE html>"));

        // フォーム抽出の拒否で axum 既定のプレーンテキスト（内部詳細）を露出させない。
        let tenant = "019f6514-08ea-7138-ad71-838a7bdd3575";
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{tenant}/login"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(response.status().is_client_error());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("Failed to deserialize"),
            "internal rejection message must not leak: {text}"
        );
        assert!(text.contains("<!DOCTYPE html>"));
    }

    /// MT20: 表示言語の決定は middleware が担い、**全画面**で `?lang=` が効く。
    ///
    /// 未ログインのログイン画面（api を呼ばずに描画できる画面）で検証する。`?lang=` を付けた
    /// リクエストは (1) その応答が指定言語で描画され、(2) `lang` Cookie が保存される。
    /// 以前は画面ごとに `?lang=` を解釈する／しないが分かれていた（設定画面のみ対応）。
    #[tokio::test]
    async fn language_query_applies_to_every_page_and_is_persisted() {
        let tenant = "019f6514-08ea-7138-ad71-838a7bdd3575";
        let english = Messages::new(crate::i18n::Locale::En).get("login-title");
        let japanese = Messages::new(crate::i18n::Locale::Ja).get("login-title");

        for (uri, expected, expect_cookie) in [
            // `?lang=` が最優先（Accept-Language より強い）。
            (format!("/{tenant}/admin/login?lang=en"), &english, true),
            (format!("/{tenant}/login?lang=en"), &english, true),
            // 非対応値は無視して次順位（ここでは Accept-Language 無しのため既定 ja）。
            (format!("/{tenant}/admin/login?lang=fr"), &japanese, false),
            // `?lang=` 無しは既定 ja。Cookie も書き換えない。
            (format!("/{tenant}/admin/login"), &japanese, false),
        ] {
            let response = build(test_state())
                .oneshot(
                    Request::builder()
                        .uri(&uri)
                        .header("accept-language", "ja")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let cookies: Vec<String> = response
                .headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(str::to_string)
                .collect();
            let saved = cookies.iter().any(|c| c.starts_with("lang="));
            assert_eq!(saved, expect_cookie, "uri={uri} cookies={cookies:?}");

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let text = String::from_utf8_lossy(&body);
            assert!(text.contains(expected.as_str()), "uri={uri}: {text}");
        }
    }

    /// `?lang=` が無ければ `lang` Cookie が効き、それも無ければブラウザ言語へ落ちる。
    #[tokio::test]
    async fn language_falls_back_to_the_cookie_then_the_browser() {
        let tenant = "019f6514-08ea-7138-ad71-838a7bdd3575";
        let english = Messages::new(crate::i18n::Locale::En).get("login-title");
        let uri = format!("/{tenant}/admin/login");

        // Cookie はブラウザ言語より優先する。
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header(axum::http::header::COOKIE, "lang=en")
                    .header("accept-language", "ja")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(String::from_utf8_lossy(&body).contains(english.as_str()));

        // Cookie が無ければブラウザ言語。
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("accept-language", "en-US,en;q=0.9")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(String::from_utf8_lossy(&body).contains(english.as_str()));
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
            format!("/{tenant}/admin/members/{id}/reset-mfa"),
            format!("/{tenant}/admin/members/{id}/suspend"),
            format!("/{tenant}/admin/members/{id}/resume"),
            format!("/{tenant}/admin/members/{id}/delete"),
            format!("/{tenant}/admin/users/{id}/profile"),
            format!("/{tenant}/admin/users/{id}/permissions/grant"),
            format!("/{tenant}/admin/users/{id}/permissions/revoke"),
            format!("/{tenant}/admin/clients/{id}/edit"),
            format!("/{tenant}/admin/clients/{id}/rotate-secret"),
            format!("/{tenant}/admin/tenants/{id}/update"),
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
