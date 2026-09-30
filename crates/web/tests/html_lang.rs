//! 利用者向け画面の `<html lang>`（ADR-0048 のやり残し。task #81）。
//!
//! 画面の日時は `assets/local-time.js` が `<html lang>` の言語で整形し直す。属性が無いと
//! ブラウザの言語で出るため、利用者が `?lang=` や設定で選んだ言語と日付の表記が食い違う。
//! 言語は web が決める（`CLAUDE.md`「国際化」）ので、決めた言語がそのまま属性に出ることを、
//! 主要な画面（ログイン・同意・メッセージ・エラー）の入口ごとに確かめる。

mod support;

use assay_contracts::cookies::AUTH_SESSION_COOKIE;
use axum::body::Body;
use axum::http::header::{ACCEPT_LANGUAGE, COOKIE};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use support::{body_text, get, get_with_cookies, send, setup};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

/// `Accept-Language` 付きの GET（Cookie も任意で載せる）。
fn get_with_language(uri: &str, accept_language: &str, cookies: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(ACCEPT_LANGUAGE, accept_language);
    if let Some(cookies) = cookies {
        builder = builder.header(COOKIE, cookies);
    }
    builder.body(Body::empty()).unwrap()
}

/// 本文の `<html>` 開きタグに `lang="<expected>"` が付いていること。
fn assert_html_lang(html: &str, expected: &str) {
    let open = html
        .find("<html")
        .map(|start| &html[start..start + html[start..].find('>').unwrap_or(0) + 1])
        .unwrap_or_else(|| panic!("no <html> tag in the page: {html}"));
    assert_eq!(
        open,
        format!(r#"<html lang="{expected}">"#),
        "the page must declare the language web resolved"
    );
}

async fn mount_no_external_providers(env: &support::WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/external/providers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "providers": []
        })))
        .mount(&env.api)
        .await;
}

#[tokio::test]
async fn the_portal_login_page_declares_the_default_language() {
    let env = setup().await;
    mount_no_external_providers(&env).await;

    let response = send(&env.app, get(&format!("{}/login", env.prefix()))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_html_lang(&body_text(response).await, "ja");
}

#[tokio::test]
async fn the_lang_query_wins_over_the_browser_language_on_the_login_page() {
    let env = setup().await;
    mount_no_external_providers(&env).await;

    let response = send(
        &env.app,
        get_with_language(&format!("{}/login?lang=en", env.prefix()), "ja", None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_html_lang(&body_text(response).await, "en");
}

#[tokio::test]
async fn the_oidc_login_page_declares_the_resolved_language() {
    let env = setup().await;
    let cookie = format!("{AUTH_SESSION_COOKIE}={}", "a".repeat(64));

    let response = send(
        &env.app,
        get_with_language(&format!("{}/login", env.prefix()), "en-US", Some(&cookie)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains(r#"name="password""#), "the OIDC login form");
    assert_html_lang(&html, "en");
}

#[tokio::test]
async fn the_consent_page_declares_the_resolved_language() {
    let env = setup().await;
    let auth_session = "d".repeat(64);
    Mock::given(method("GET"))
        .and(path("/internal/consent-info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "auth_session_id": auth_session,
            "client_name": "Example RP",
            "client_id": "example-rp",
            "requested_scopes": ["profile"],
            "redirect_uri": "https://rp.example.com/cb"
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/consent?lang=en", env.prefix()),
            &format!("{AUTH_SESSION_COOKIE}={auth_session}"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("Example RP"), "the consent screen");
    assert_html_lang(&html, "en");
}

/// `MessagePage`（翻訳済みの文字列だけで描く画面）も、決めた言語を出す。
#[tokio::test]
async fn a_message_page_declares_the_resolved_language() {
    let env = setup().await;

    // 同意画面を Cookie 無しで開くと「セッション切れ」の MessagePage になる。
    let response = send(
        &env.app,
        get_with_language(&format!("{}/consent", env.prefix()), "en", None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_html_lang(&body_text(response).await, "en");

    // テナントを持たないルートの案内も同じ。
    let response = send(&env.app, get_with_language("/", "ja", None)).await;
    assert_html_lang(&body_text(response).await, "ja");
}

/// `ErrorPage`（未マッチ経路の 404 のようにテナント文脈を持たない画面）も、決めた言語を出す。
#[tokio::test]
async fn an_error_page_declares_the_resolved_language() {
    let env = setup().await;

    let response = send(
        &env.app,
        get_with_language(&format!("{}/no-such-screen", env.prefix()), "en", None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_html_lang(&body_text(response).await, "en");

    let response = send(
        &env.app,
        get_with_language("/no-such-screen/at-all", "ja", None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_html_lang(&body_text(response).await, "ja");
}

/// 「このアプリの利用は許可されていません」の画面（翻訳済みの文字列だけで描く 3 つ目）。
#[tokio::test]
async fn the_application_not_permitted_page_declares_the_language() {
    use assay_web::i18n::{Locale, Messages};

    let response = assay_web::application_denied::page(&Messages::new(Locale::En), "", "Example");
    assert_html_lang(&body_text(response).await, "en");
}
