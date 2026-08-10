//! 外部 IdP 設定画面のルータ経由の統合テスト（AP16。土台は G11）。
//!
//! この画面の要は**クライアントシークレットの扱い**である。api はシークレットを返さないため
//! 編集フォームに現在値を出せず、空欄の意味を決めなければならない。ここでは api をスタブして、
//! 実際に送られる HTTP ボディで「空欄＝変更しない」が守られていることを確かめる。
//! ここが崩れると、表示名を直しただけで外部 IdP との連携が壊れる。

mod support;

use axum::http::StatusCode;
use idp_contracts::cookies::SSO_SESSION_COOKIE;
use idp_web::csrf::console_csrf_token;
use serde_json::{json, Value};
use support::{body_text, get_with_cookies, post_form, send, setup, WebEnv};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "admin-session";
const PROVIDER_ID: &str = "019f8ea8-f5dd-7fc7-ac15-a7d4337e4611";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    console_csrf_token(SSO, support::TEST_CSRF_SECRET)
}

async fn stub_admin(env: &WebEnv) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin",
            "preferred_username": "admin"
        })))
        .mount(&env.api)
        .await;
}

fn sample_provider() -> Value {
    json!({
        "id": PROVIDER_ID,
        "provider_code": "corp",
        "display_name": "Corp IdP",
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
        "client_id": "abc",
        "has_client_secret": true,
        "scopes": ["openid", "email"],
        "enabled": true,
        "allow_auto_link": false,
        "redirect_uri": "https://web.example.com/external/corp/callback",
        "created_at": "2026-08-10T00:00:00Z",
        "updated_at": "2026-08-10T00:00:00Z"
    })
}

async fn stub_list(env: &WebEnv, providers: Value) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(providers))
        .mount(&env.api)
        .await;
}

async fn stub_patch(env: &WebEnv) {
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/[^/]+/admin/external-idps/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_provider()))
        .mount(&env.api)
        .await;
}

/// 更新で api へ届いた本文。
async fn patched_body(env: &WebEnv) -> Option<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::PATCH
                && r.url.path().contains("/admin/external-idps/")
        })
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
}

/// 登録済みの外部 IdP が一覧に出て、**外部 IdP へ登録すべきリダイレクト URI** も見える。
/// これが出ていないと、設定作業のたびに URL を組み立て方から調べ直すことになる。
#[tokio::test]
async fn the_list_shows_the_redirect_uri_to_register_with_the_provider() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/admin/external-idps", env.prefix()), &cookies()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("corp"), "{html}");
    assert!(
        html.contains("https://web.example.com/external/corp/callback"),
        "redirect uri is missing: {html}"
    );
}

/// **空欄のシークレットは送らない。** api の部分更新は未指定の項目に触れないため、これで
/// 「変更しない」になる。載せてしまうと、表示名を直しただけで連携が壊れる。
#[tokio::test]
async fn an_empty_secret_field_leaves_the_stored_secret_alone() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Corp IdP (renamed)"),
                ("issuer", "https://idp.example.com"),
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize",
                ),
                ("token_endpoint", "https://idp.example.com/token"),
                ("jwks_uri", "https://idp.example.com/jwks"),
                ("client_id", "abc"),
                ("client_secret", ""),
                ("scopes", "openid email"),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = patched_body(&env)
        .await
        .expect("the update reached the api");
    assert!(
        body.get("client_secret").is_none(),
        "an empty field must not be forwarded: {body}"
    );
    assert_eq!(body["display_name"], json!("Corp IdP (renamed)"));
    assert_eq!(body["scopes"], json!(["openid", "email"]));
    // チェックの外れたチェックボックスは送られてこないが、`false` として明示的に送る。
    // 未指定にすると api が「変更しない」と解釈し、チェックを外しても無効化できない。
    assert_eq!(body["allow_auto_link"], json!(false));
}

/// 入力されたシークレットは載せる（置き換え）。
#[tokio::test]
async fn a_filled_secret_field_replaces_the_stored_secret() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Corp IdP"),
                ("issuer", "https://idp.example.com"),
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize",
                ),
                ("token_endpoint", "https://idp.example.com/token"),
                ("jwks_uri", "https://idp.example.com/jwks"),
                ("client_id", "abc"),
                ("client_secret", "new-secret"),
                ("scopes", "openid"),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = patched_body(&env)
        .await
        .expect("the update reached the api");
    assert_eq!(body["client_secret"], json!("new-secret"));
}

/// CSRF トークンが合わなければ api を呼ばない。
#[tokio::test]
async fn a_bad_csrf_token_never_reaches_the_api() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Hijacked"),
                ("issuer", "https://evil.example.com"),
                ("authorization_endpoint", "https://evil.example.com/a"),
                ("token_endpoint", "https://evil.example.com/t"),
                ("jwks_uri", "https://evil.example.com/j"),
                ("client_id", "abc"),
                ("client_secret", ""),
                ("scopes", "openid"),
                ("csrf_token", "wrong"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        patched_body(&env).await.is_none(),
        "the request must not be forwarded when CSRF verification fails"
    );
}
