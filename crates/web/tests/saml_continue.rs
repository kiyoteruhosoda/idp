//! SAML SSO の継続画面（`GET /{tenant_id}/saml/continue`）が、アプリの割り当てで断られたときの
//! 振る舞い（ADR-0054。task #66）。
//!
//! api が `application_not_permitted` を返したら、web は **ACS へ自動 POST するフォームを描かず**、
//! OIDC の経路と同じ「このアプリの利用は許可されていません」の画面で断る。進行状態は api 側で
//! 消費済みなので、`saml_request_id` Cookie も失効させる。

mod support;

use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get, send, setup};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn a_denied_saml_sign_in_is_told_on_the_assay_screen_not_posted_to_the_sp() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/saml/resume"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "application_not_permitted",
            "application_name": "Example SAML App",
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get(&format!("{}/saml/continue?handle=h", env.prefix())),
    )
    .await;

    // 403: 誰であるかは分かっているが、このアプリは使えない（OIDC の経路と同じ）。
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let saml_cookie = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|raw| raw.contains("saml_request_id="))
        .map(str::to_string)
        .expect("the saml_request_id cookie must be expired");
    assert!(
        saml_cookie.contains("Max-Age=0"),
        "the consumed request's cookie must be expired: {saml_cookie}"
    );
    let body = body_text(response).await;
    assert!(
        body.contains("Example SAML App"),
        "the page must name the application: {body}"
    );
    assert!(
        !body.contains("SAMLResponse"),
        "a denied sign-in must not be posted to the SP: {body}"
    );
    assert!(
        body.contains(&format!("{}/settings", env.prefix())),
        "the page must offer a way back to the account screen: {body}"
    );
}
