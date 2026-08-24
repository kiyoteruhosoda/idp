//! ログイン画面のルータ経由の統合テスト（G11）。
//!
//! api は `wiremock` でスタブする（DB 不要）。検証するのはハンドラの中身ではなく、その外側 ——
//! Cookie の発行と読み出し、CSRF 同期トークンの往復、リダイレクトの行き先とステータス、
//! api が落ちているときの処理である。

mod support;

use axum::http::StatusCode;
use idp_contracts::cookies::{AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};
use idp_contracts::csrf::login_csrf_token;
use idp_web::cookies::PORTAL_CSRF_COOKIE;
use serde_json::json;
use support::{
    body_text, get, get_with_cookies, location, post_form, send, set_cookie, set_cookie_raw, setup,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn portal_login_page_issues_a_csrf_seed_cookie_and_renders_the_form() {
    let env = setup().await;
    // 外部 IdP ボタンの取得（失敗してもパスワードログインは出る＝フェイルソフト）。
    Mock::given(method("POST"))
        .and(path("/internal/external/providers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "providers": []
        })))
        .mount(&env.api)
        .await;

    let response = send(&env.app, get(&format!("{}/login", env.prefix()))).await;
    assert_eq!(response.status(), StatusCode::OK);

    // CSRF の種は Cookie とフォームの両方に出る（片方だけだと必ず不一致になる）。
    let seed = set_cookie(&response, PORTAL_CSRF_COOKIE).expect("csrf seed cookie");
    assert!(!seed.is_empty(), "csrf seed must not be empty");
    let raw = set_cookie_raw(&response, PORTAL_CSRF_COOKIE).expect("raw cookie");
    assert!(
        raw.contains("HttpOnly"),
        "csrf seed must be HttpOnly: {raw}"
    );
    assert!(raw.contains("SameSite=Lax"), "unexpected attributes: {raw}");

    let html = body_text(response).await;
    assert!(html.contains("csrf_token"), "form must carry a csrf token");
    assert!(html.contains(r#"name="password""#), "password field");
}

#[tokio::test]
async fn portal_login_page_reuses_an_existing_seed_so_open_tabs_keep_working() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/external/providers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "providers": []
        })))
        .mount(&env.api)
        .await;

    let existing = "0123456789abcdef0123456789abcdef";
    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/login", env.prefix()),
            &format!("{PORTAL_CSRF_COOKIE}={existing}"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        set_cookie(&response, PORTAL_CSRF_COOKIE).as_deref(),
        Some(existing),
        "an existing seed must be reused, not rotated (open tabs would break)"
    );
}

#[tokio::test]
async fn oidc_login_success_sets_the_sso_cookie_and_redirects_to_the_rp() {
    let env = setup().await;
    let auth_session = "a".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "success",
            "redirect_to": "https://rp.example.com/cb?code=abc&state=xyz",
            "sso_session_id": "sso-value",
            "sso_absolute_ttl_secs": 3600,
            "user_language": null
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        "https://rp.example.com/cb?code=abc&state=xyz"
    );
    assert_eq!(
        set_cookie(&response, SSO_SESSION_COOKIE).as_deref(),
        Some("sso-value"),
        "the SSO cookie must be issued by web, not by api"
    );
    // フローは終わったので一時セッションの Cookie は掃除される。
    assert_eq!(
        set_cookie(&response, AUTH_SESSION_COOKIE).as_deref(),
        Some(""),
        "the auth session cookie must be expired after the flow completes"
    );
}

#[tokio::test]
async fn invalid_credentials_reshow_the_form_without_issuing_a_session() {
    let env = setup().await;
    let auth_session = "b".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "result": "invalid_credentials" })),
        )
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "wrong"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        set_cookie(&response, SSO_SESSION_COOKIE).is_none(),
        "a failed login must not issue an SSO cookie"
    );
    let html = body_text(response).await;
    assert!(html.contains("csrf_token"), "the form must be re-rendered");
}

#[tokio::test]
async fn a_csrf_mismatch_redirects_back_to_a_fresh_form() {
    let env = setup().await;
    let auth_session = "c".repeat(64);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "result": "csrf_mismatch" })),
        )
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", "not-the-right-token"),
            ],
        ),
    )
    .await;

    // PRG: 303 で GET へ付け替える（POST のままエラーを返すと、リロードが再送信になり復帰できない）。
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/login?error=csrf", env.prefix())
    );
}

#[tokio::test]
async fn an_unreachable_api_does_not_leak_a_panic_or_a_session() {
    let auth_session = "d".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);
    let prefix = support::tenant_prefix();
    let app = support::unreachable_api_app();

    let response = send(
        &app,
        post_form(
            &format!("{prefix}/login"),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert!(
        response.status().is_server_error(),
        "an unreachable api must surface as a server error, got {}",
        response.status()
    );
    assert!(
        set_cookie(&response, SSO_SESSION_COOKIE).is_none(),
        "no session may be issued when the api never answered"
    );
}

#[tokio::test]
async fn a_non_uuid_tenant_segment_is_not_a_screen() {
    let env = setup().await;
    let response = send(&env.app, get("/not-a-uuid/login")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// 存在しない（または `DISABLED` の）テナント ID を URL に打った送信は、**404** になる（MT28）。
///
/// `/internal/*` はテナントプレフィクスを持たないため api の `TenantResolver` を通らず、テナントの
/// 実在・状態は本文の `tenant_id` を見て api が判定して 400 で拒否する。web がその 400 を他の失敗と
/// 区別していなかった頃は、**URL のテナント ID を打ち間違えただけで素の 502** になっていた ——
/// 利用者の入力の誤りであって、web の実装/構成エラーではない。
#[tokio::test]
async fn an_unknown_tenant_renders_the_404_page_instead_of_a_bad_gateway() {
    let env = setup().await;
    let auth_session = "d".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": idp_contracts::auth::UNKNOWN_TENANT_ERROR_CODE,
            "error_description": "unknown or disabled tenant"
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // 本文は共通のエラーページ middleware が補完する（空のまま返さない）。
    let html = body_text(response).await;
    assert!(html.contains("404"), "404 ページが描画されること: {html}");
}

/// api の他の失敗は従来どおり 502（web の実装/構成エラー・api 障害）。MT28 で区別したのは
/// 「テナントを解決できない」だけで、それ以外の扱いは変えていない。
#[tokio::test]
async fn other_api_failures_still_render_a_bad_gateway() {
    let env = setup().await;
    let auth_session = "e".repeat(64);
    let csrf = login_csrf_token(&auth_session, support::TEST_CSRF_SECRET);

    Mock::given(method("POST"))
        .and(path("/internal/authenticate"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/login", env.prefix()),
            Some(&format!("{AUTH_SESSION_COOKIE}={auth_session}")),
            &[
                ("username", "alice"),
                ("password", "correct-horse-battery"),
                ("csrf_token", &csrf),
            ],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}
