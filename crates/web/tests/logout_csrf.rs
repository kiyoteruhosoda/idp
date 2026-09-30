//! アカウント設定と管理コンソールのログアウト（POST）は CSRF トークンを要る（task #143）。
//!
//! 以前はどちらもトークンを持たず、SSO Cookie の `SameSite=Lax` だけで守られていた。外部のページから
//! ログアウトを強制されないよう、他のログイン後のフォームと同じ `console_csrf_token`（SSO セッション
//! id 由来）を埋め、合わなければ api へ何も送らず、SSO Cookie も消さずに戻す。
//!
//! RP からのログアウト（OIDC の end_session_endpoint＝`GET /logout`）は別の口で、ここでは扱わない。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::body::Body;
use axum::http::header::COOKIE;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use support::{
    body_text, get_with_cookies, location, post_form, send, set_cookie, setup, WebEnv,
    TEST_CSRF_SECRET,
};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "logout-csrf-session";
const LOGOUT: &str = "/internal/logout";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    assay_web::csrf::console_csrf_token(SSO, TEST_CSRF_SECRET)
}

/// 無い・空・でたらめ・別のセッションのもの。どれも「合わない」。
fn wrong_tokens() -> Vec<Option<String>> {
    vec![
        None,
        Some(String::new()),
        Some("0".repeat(64)),
        Some(assay_web::csrf::console_csrf_token(
            "someone-else",
            TEST_CSRF_SECRET,
        )),
    ]
}

async fn mount_logout(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path(LOGOUT))
        .respond_with(ResponseTemplate::new(204))
        .mount(&env.api)
        .await;
}

async fn logout_calls(env: &WebEnv) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == LOGOUT)
        .count()
}

async fn post_logout(
    env: &WebEnv,
    target: &str,
    cookie: Option<&str>,
    fields: &[(&str, &str)],
) -> axum::http::Response<Body> {
    send(
        &env.app,
        post_form(&format!("{}{target}", env.prefix()), cookie, fields),
    )
    .await
}

fn with_token<'a>(
    fields: &[(&'a str, &'a str)],
    token: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut all = fields.to_vec();
    if let Some(token) = token {
        all.push(("csrf_token", token));
    }
    all
}

// ── アカウント設定のログアウト（`POST /{tenant_id}/logout`） ─────────────────

/// トークンが合わなければログアウトしない（SSO は api で失効させず、Cookie も消さない）。
/// 設定画面へ `?error=csrf` で戻し、バナーで伝える。
#[tokio::test]
async fn the_account_logout_keeps_the_session_without_the_right_token() {
    let env = setup().await;
    mount_logout(&env).await;

    for token in wrong_tokens() {
        let response = post_logout(
            &env,
            "/logout",
            Some(&cookies()),
            &with_token(&[], token.as_deref()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/settings?error=csrf", env.prefix()),
            "{token:?}"
        );
        assert_eq!(
            set_cookie(&response, SSO_SESSION_COOKIE),
            None,
            "the sso cookie must survive a mismatched token: {token:?}"
        );
    }
    assert_eq!(
        logout_calls(&env).await,
        0,
        "a mismatched token must not reach the api"
    );
}

/// 正しいトークンならログアウトする（api で SSO を失効させ、Cookie を消してログイン画面へ）。
#[tokio::test]
async fn the_account_logout_signs_out_with_the_right_token() {
    let env = setup().await;
    mount_logout(&env).await;

    let token = csrf();
    let response = post_logout(
        &env,
        "/logout",
        Some(&cookies()),
        &with_token(&[], Some(&token)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
    assert_eq!(
        set_cookie(&response, SSO_SESSION_COOKIE).as_deref(),
        Some(""),
        "the sso cookie is expired"
    );
    assert_eq!(logout_calls(&env).await, 1);
}

/// 管理コンソールから開いた設定画面の文脈は、トークンが合わずに戻したときも保つ。
#[tokio::test]
async fn a_rejected_account_logout_keeps_the_console_context() {
    let env = setup().await;
    let response = post_logout(&env, "/logout", Some(&cookies()), &[("from", "admin")]).await;
    assert_eq!(
        location(&response),
        format!("{}/settings?error=csrf&from=admin", env.prefix())
    );
}

/// 未ログイン（SSO Cookie が無い）なら失効させるものが無い。トークンを見ずにログイン画面へ送り、
/// api は呼ばない。
#[tokio::test]
async fn a_signed_out_logout_just_goes_to_the_login_page() {
    let env = setup().await;
    let response = post_logout(&env, "/logout", None, &[]).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
    assert_eq!(logout_calls(&env).await, 0);
}

/// フォームとして読めない POST（Content-Type も本文も無い）も 4xx にせず、トークン無しとして扱う
/// （ログイン中ならログアウトせずに戻す）。
#[tokio::test]
async fn a_bodyless_logout_is_treated_as_a_missing_token() {
    let env = setup().await;
    mount_logout(&env).await;
    for target in ["/logout", "/admin/logout"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}{target}", env.prefix()))
            .header(COOKIE, cookies())
            .body(Body::empty())
            .unwrap();
        let response = send(&env.app, request).await;
        assert_eq!(response.status(), StatusCode::FOUND, "{target}");
        assert!(
            location(&response).ends_with("?error=csrf"),
            "{target}: {}",
            location(&response)
        );
        assert_eq!(set_cookie(&response, SSO_SESSION_COOKIE), None, "{target}");
    }
    assert_eq!(logout_calls(&env).await, 0);
}

// ── 管理コンソールのログアウト（`POST /{tenant_id}/admin/logout`） ──────────

#[tokio::test]
async fn the_console_logout_keeps_the_session_without_the_right_token() {
    let env = setup().await;
    mount_logout(&env).await;

    for token in wrong_tokens() {
        let response = post_logout(
            &env,
            "/admin/logout",
            Some(&cookies()),
            &with_token(&[], token.as_deref()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/admin?error=csrf", env.prefix()),
            "{token:?}"
        );
        assert_eq!(
            set_cookie(&response, SSO_SESSION_COOKIE),
            None,
            "the sso cookie must survive a mismatched token: {token:?}"
        );
    }
    assert_eq!(
        logout_calls(&env).await,
        0,
        "a mismatched token must not reach the api"
    );
}

#[tokio::test]
async fn the_console_logout_signs_out_with_the_right_token() {
    let env = setup().await;
    mount_logout(&env).await;

    let token = csrf();
    let response = post_logout(
        &env,
        "/admin/logout",
        Some(&cookies()),
        &with_token(&[], Some(&token)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/admin/login", env.prefix()));
    assert_eq!(
        set_cookie(&response, SSO_SESSION_COOKIE).as_deref(),
        Some(""),
        "the sso cookie is expired"
    );
    assert_eq!(logout_calls(&env).await, 1);
}

#[tokio::test]
async fn a_signed_out_console_logout_just_goes_to_the_login_page() {
    let env = setup().await;
    let response = post_logout(&env, "/admin/logout", None, &[]).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/admin/login", env.prefix()));
    assert_eq!(logout_calls(&env).await, 0);
}

/// 戻った先のホームは `?error=csrf` でバナーを出し、ヘッダのログアウトにはトークンが埋まっている
/// （再読み込みせずにもう一度押せば通る）。
#[tokio::test]
async fn the_console_home_shows_the_banner_and_carries_the_logout_token() {
    let env = setup().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin User",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/admin?error=csrf", env.prefix()), &cookies()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains(r#"class="alert alert-danger""#), "{html}");
    let form = html
        .split(&format!(
            r#"<form method="post" action="{}/admin/logout">"#,
            env.prefix()
        ))
        .nth(1)
        .and_then(|rest| rest.split("</form>").next())
        .unwrap_or_else(|| panic!("no logout form: {html}"));
    assert!(
        form.contains(&format!(
            r#"<input type="hidden" name="csrf_token" value="{}">"#,
            csrf()
        )),
        "{form}"
    );
}
