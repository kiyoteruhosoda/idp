//! 認証アプリの鍵の登録の確認の画面（task #892・ADR-0077）の web 側。
//!
//! - 「登録する」の送信は発行者のホストの戻り先（`/app/enrolled`）への 302 で終わるので、画面の CSP の
//!   `form-action` がそのオリジンを許していること（許さないと Chrome がリダイレクトを止め、Auth Tab へ戻らない）
//! - ログインしていなければ、受付を覚えてログインへ回すこと

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{get, get_with_cookies, location, send, setup};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const ENROLLMENT: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";

#[tokio::test]
async fn the_confirmation_page_lets_its_form_redirect_to_the_issuer() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/account/app-approver/enrollment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ready",
            "device_name": "Pixel test",
            "security_level": "strongbox",
            "created_at": "2026-11-05T00:00:00Z",
        })))
        .mount(&env.api)
        .await;
    let response = send(
        &env.app,
        get_with_cookies(
            &format!(
                "{}/settings/app-approver/confirm?enrollment={ENROLLMENT}",
                env.prefix()
            ),
            &format!("{SSO_SESSION_COOKIE}=sso-for-confirmation"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let csp = response
        .headers()
        .get("content-security-policy")
        .expect("csp")
        .to_str()
        .unwrap()
        .to_string();
    let form_action = csp
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("form-action"))
        .expect("form-action directive");
    assert!(
        form_action.split_whitespace().count() >= 3,
        "the issuer's origin is allowed besides 'self': {form_action}"
    );
    assert!(response
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("no-store"));
}

#[tokio::test]
async fn an_unauthenticated_confirmation_goes_to_the_login_and_remembers_the_enrollment() {
    let env = setup().await;
    let response = send(
        &env.app,
        get(&format!(
            "{}/settings/app-approver/confirm?enrollment={ENROLLMENT}",
            env.prefix()
        )),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        location(&response).ends_with("/login"),
        "{}",
        location(&response)
    );
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|c| c.contains("app_approver_enrollment=") && c.contains(ENROLLMENT)),
        "{cookies:?}"
    );
}
