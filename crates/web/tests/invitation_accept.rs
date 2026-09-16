//! ゲスト招待の承諾を**ルータ経由で**通す（api は wiremock で差し替える）。
//!
//! ⚠ **被招待者は、まだ参加先テナントのメンバーではない。** したがって承諾の経路は
//! **そのテナントの管理トークンを前提にできない** ——承諾はメンバーになるための操作だからである。
//!
//! ⚠ **2026-09-16 まで、ここが管理トークンの交換（`POST /internal/admin/token`）を通っていた。**
//! 交換は「そのテナントで権限を持つ利用者」にしか通らないため、被招待者では必ず 401 になり、
//! 画面は「先に所属元テナントでログインしてください」へ戻っていた ——**ログインは済んでいるのに、である。**
//! 層ごとの試験（api の統合試験・core の単体試験）はどちらも通っていたので、
//! **web → api の並びを被招待者で通すこの試験でしか捕まらない。**
//!
//! そのため各試験は ⚠ **交換が 401 を返す状況を積んだうえで**承諾を叩く。交換に依存し直したら、
//! ここが落ちる。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use assay_web::csrf::console_csrf_token;
use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_text, mount_unauthenticated_management_token, post_form, send, setup, WebEnv,
    TEST_CSRF_SECRET,
};
use wiremock::matchers::{body_json, header, method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "test-sso-session-id";
const TOKEN: &str = "test-invitation-token";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

/// api 側の承諾の口を積む。⚠ **資格情報は Cookie**（`AuthenticatedUser`）で、Bearer ではない。
async fn mount_accept(env: &WebEnv, status: u16, body: Option<serde_json::Value>) {
    let cookie = cookies();
    let response = match body {
        Some(json) => ResponseTemplate::new(status).set_body_json(json),
        None => ResponseTemplate::new(status),
    };
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/invitations/accept$"))
        .and(header("cookie", cookie.as_str()))
        .and(body_json(json!({ "token": TOKEN })))
        .respond_with(response)
        .mount(&env.api)
        .await;
}

fn accept_request(env: &WebEnv) -> axum::http::Request<axum::body::Body> {
    let csrf = console_csrf_token(SSO, TEST_CSRF_SECRET);
    post_form(
        &format!("{}/invitations/accept", env.prefix()),
        Some(&cookies()),
        &[("token", TOKEN), ("csrf_token", &csrf)],
    )
}

#[tokio::test]
async fn accepting_forwards_the_session_cookie_without_a_management_token() {
    let env = setup().await;
    // ⚠ 交換は失敗する状況にしておく（被招待者はまだメンバーではないので、これが実態）。
    mount_unauthenticated_management_token(&env).await;
    mount_accept(&env, 204, None).await;

    let response = send(&env.app, accept_request(&env)).await;

    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains("alert-success"),
        "承諾の成功が出ていない: {html}"
    );
    // 承諾できたのにフォームが残っていると、利用者は「まだ済んでいない」と読む。
    assert!(
        !html.contains(r#"name="token""#),
        "成功後にフォームが残っている"
    );
}

#[tokio::test]
async fn unauthorized_from_the_api_asks_the_user_to_sign_in() {
    let env = setup().await;
    mount_unauthenticated_management_token(&env).await;
    mount_accept(&env, 401, Some(json!({ "error": "unauthorized" }))).await;

    let response = send(&env.app, accept_request(&env)).await;

    // セッションが本当に無効なときだけ、この案内が出る。
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        !html.contains("alert-success"),
        "失敗なのに成功が出ている: {html}"
    );
    assert!(
        !html.contains(r#"name="token""#),
        "未ログインの案内でフォームを出さない"
    );
}

#[tokio::test]
async fn an_invalid_token_is_reported_as_invalid_not_as_a_sign_in_problem() {
    let env = setup().await;
    mount_unauthenticated_management_token(&env).await;
    mount_accept(
        &env,
        400,
        Some(json!({ "error": "invalid_request", "message": "invalid or expired" })),
    )
    .await;

    let response = send(&env.app, accept_request(&env)).await;

    // ⚠ **トークンの問題とセッションの問題を同じ画面にしない。** 同じに見えると、
    //   利用者も運用も「ログインし直す」を延々と試すことになる（2026-09-16 の切り分けがそれだった）。
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let html = body_text(response).await;
    assert!(
        html.contains("alert-danger"),
        "無効の表示が出ていない: {html}"
    );
    assert!(
        html.contains(r#"name="token""#),
        "やり直せるようフォームは残す"
    );
}
