//! パスキーでの本人確認（step-up。AP5・T38）をルータ経由で確かめる。
//!
//! この経路が無いと、パスキーで入った利用者は**認証器の管理へ入れない**（管理は step-up の対象で、
//! その step-up がパスワードしか受け付けなかった）。ここで見たいのは、導線を出す条件と、完了後に
//! どこへ戻すか —— どちらもハンドラ内の純関数では現れない。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE};
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{body_text, get_with_cookies, send, setup, WebEnv};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "user-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header(COOKIE, cookies())
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn stub_check(env: &WebEnv, passkey_available: bool) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "challenge_required",
            "second_factor_required": true,
            "passkey_available": passkey_available,
        })))
        .mount(&env.api)
        .await;
}

async fn stub_verify(env: &WebEnv, result: &str) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/passkey/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": result })))
        .mount(&env.api)
        .await;
}

async fn challenge_page(env: &WebEnv) -> String {
    let response = send(
        &env.app,
        get_with_cookies(
            &format!(
                "{}/settings/verify?operation=manage_authenticators&next={}%2Faccount%2Fpasskey",
                env.prefix(),
                env.prefix()
            ),
            &cookies(),
        ),
    )
    .await;
    body_text(response).await
}

/// 使えるパスキーを持つ利用者には、パスワードの隣にパスキーの導線を出す。**多要素を求められる
/// 操作（認証器の管理）でもパスキー 1 回で満たせる**ため、TOTP を持たない利用者の唯一の道になる。
#[tokio::test]
async fn the_challenge_offers_the_passkey_route_to_a_user_who_has_one() {
    let env = setup().await;
    stub_check(&env, true).await;

    let html = challenge_page(&env).await;

    assert!(html.contains(r#"id="btn-passkey-login""#), "{html}");
    assert!(
        html.contains(r#"data-complete-path="/settings/verify/passkey/complete""#),
        "{html}"
    );
    // 完了 API へ添える値（どの操作か・終わったらどこへ戻すか）を画面が渡す。
    assert!(
        html.contains(r#"data-operation="manage_authenticators""#),
        "{html}"
    );
    assert!(
        html.contains(&format!(r#"data-next="{}/account/passkey""#, env.prefix())),
        "{html}"
    );
}

/// パスキーを持たない利用者には出さない（押してもブラウザのダイアログが出てから失敗するだけ）。
#[tokio::test]
async fn the_challenge_hides_the_passkey_route_without_a_usable_passkey() {
    let env = setup().await;
    stub_check(&env, false).await;

    let html = challenge_page(&env).await;

    assert!(!html.contains(r#"id="btn-passkey-login""#), "{html}");
    assert!(!html.contains("/settings/verify/passkey/"), "{html}");
}

/// 確認が通ったら、元いた画面へ戻す（フォーム経路の 303 に当たるものを JSON で返す）。
#[tokio::test]
async fn a_verified_passkey_sends_the_user_back_to_the_operation() {
    let env = setup().await;
    stub_verify(&env, "ok").await;

    let response = send(
        &env.app,
        post_json(
            &format!("{}/settings/verify/passkey/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
                "operation": "manage_authenticators",
                "next": format!("{}/account/passkey", env.prefix()),
            }),
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_str(&body_text(response).await).expect("json");
    assert_eq!(
        body["redirect_to"],
        json!(format!("{}/account/passkey", env.prefix()))
    );
}

/// `next` はブラウザから来る値なので、この経路でも同一テナントのパスに限る
/// （オープンリダイレクトを JSON 応答で作らない）。
#[tokio::test]
async fn a_foreign_next_is_replaced_with_the_settings_page() {
    let env = setup().await;
    stub_verify(&env, "ok").await;

    let response = send(
        &env.app,
        post_json(
            &format!("{}/settings/verify/passkey/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
                "operation": "manage_authenticators",
                "next": "https://evil.example.com/",
            }),
        ),
    )
    .await;

    let body: Value = serde_json::from_str(&body_text(response).await).expect("json");
    assert_eq!(
        body["redirect_to"],
        json!(format!("{}/settings", env.prefix()))
    );
}

/// セッションが切れていたら文言を出さずログインへ送る（この画面で再試行しても通らない）。
#[tokio::test]
async fn an_expired_session_is_sent_to_the_login_page() {
    let env = setup().await;
    stub_verify(&env, "session_expired").await;

    let response = send(
        &env.app,
        post_json(
            &format!("{}/settings/verify/passkey/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
                "operation": "manage_authenticators",
                "next": format!("{}/account/passkey", env.prefix()),
            }),
        ),
    )
    .await;

    let body: Value = serde_json::from_str(&body_text(response).await).expect("json");
    assert_eq!(
        body["redirect_to"],
        json!(format!("{}/login", env.prefix()))
    );
}

/// アサーションが通らなかったときは、翻訳済みの文言へ写せるコードを返す（画面が文言を持つ）。
#[tokio::test]
async fn a_rejected_passkey_is_reported_as_a_code_the_screen_can_translate() {
    let env = setup().await;
    stub_verify(&env, "invalid_credential").await;

    let response = send(
        &env.app,
        post_json(
            &format!("{}/settings/verify/passkey/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
                "operation": "manage_authenticators",
                "next": format!("{}/account/passkey", env.prefix()),
            }),
        ),
    )
    .await;

    let body: Value = serde_json::from_str(&body_text(response).await).expect("json");
    assert_eq!(body["error"], json!("invalid_credential"));
    assert!(body["redirect_to"].is_null());
}

/// サインインしていなければチャレンジを配らない（引き上げる先が無い）。
#[tokio::test]
async fn beginning_without_a_session_is_unauthorized() {
    let env = setup().await;

    let response = send(
        &env.app,
        Request::builder()
            .method(Method::POST)
            .uri(format!("{}/settings/verify/passkey/begin", env.prefix()))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
