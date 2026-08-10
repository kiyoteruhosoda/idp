//! 管理コンソールの入口ガードと共通ヘッダのルータ経由の統合テスト（G11）。
//!
//! 管理コンソールの各画面は「api の `/admin/whoami` に SSO Cookie を転送し、その応答で
//! 通す／弾く」形になっている。**弾き方が api の応答ごとに違う**（未ログインはログイン画面へ、
//! 権限不足は 403、api 不通は 502）ため、ここが崩れると「権限が無いのにログイン画面へ飛ばされて
//! 無限に往復する」「api 障害を権限不足と誤って表示する」といった形で出る。単体テストは
//! ステータスの写像だけを見ており、Cookie の転送とルータの結線は通っていなかった。

mod support;

use axum::http::StatusCode;
use idp_contracts::cookies::SSO_SESSION_COOKIE;
use serde_json::json;
use support::{get, get_with_cookies, location, send, setup};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

/// `/admin/whoami` のスタブ（api は `/{tenant_id}/admin/whoami` で受ける）。
async fn stub_whoami(env: &support::WebEnv, status: u16, body: Option<serde_json::Value>) {
    let template = match body {
        Some(json) => ResponseTemplate::new(status).set_body_json(json),
        None => ResponseTemplate::new(status),
    };
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(template)
        .mount(&env.api)
        .await;
}

#[tokio::test]
async fn without_a_session_cookie_the_console_sends_you_to_the_admin_login() {
    let env = setup().await;
    // Cookie が無いので api は呼ばれない想定だが、呼ばれても 401 を返す形にしておく。
    stub_whoami(&env, 401, None).await;

    let response = send(&env.app, get(&format!("{}/admin", env.prefix()))).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        format!("{}/admin/login", env.prefix()),
        "an anonymous visitor must land on the admin login, not on an error page"
    );
}

#[tokio::test]
async fn an_expired_session_sends_you_to_the_admin_login() {
    let env = setup().await;
    stub_whoami(&env, 401, None).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=stale-session"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/admin/login", env.prefix()));
}

#[tokio::test]
async fn a_signed_in_user_without_admin_permission_gets_403_not_a_login_loop() {
    let env = setup().await;
    stub_whoami(&env, 403, None).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=valid-session"),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "sending an already signed-in user back to the login screen would loop forever"
    );
}

#[tokio::test]
async fn an_unreachable_api_is_reported_as_a_gateway_error_not_as_a_permission_problem() {
    let prefix = support::tenant_prefix();
    let app = support::unreachable_api_app();

    let response = send(
        &app,
        get_with_cookies(
            &format!("{prefix}/admin"),
            &format!("{SSO_SESSION_COOKIE}=valid-session"),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "an api outage must not be shown as a permission problem"
    );
}

#[tokio::test]
async fn an_authenticated_admin_sees_the_console() {
    let env = setup().await;
    stub_whoami(
        &env,
        200,
        Some(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin User",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })),
    )
    .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=valid-session"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn every_response_carries_the_shared_security_headers() {
    let env = setup().await;
    stub_whoami(&env, 401, None).await;

    let response = send(&env.app, get(&format!("{}/admin", env.prefix()))).await;
    let headers = response.headers();
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert!(
        headers.get("x-frame-options").is_some(),
        "clickjacking protection must be present even on redirects"
    );
    assert!(headers.get("referrer-policy").is_some());
    // HSTS の既定は 0（無効）。http のローカル配置で誤って固定化しないための回帰。
    assert!(
        headers.get("strict-transport-security").is_none(),
        "HSTS must stay off until HSTS_MAX_AGE is configured"
    );
}

#[tokio::test]
async fn liveness_is_answered_without_touching_the_api() {
    // api を持たない構成でも生存確認は答える（依存を持ち込んでいないことの回帰）。
    let app = support::unreachable_api_app();

    let response = send(&app, get("/healthz")).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "liveness must not depend on the api being up"
    );
}
