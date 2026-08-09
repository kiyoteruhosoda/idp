//! ログイン画面の文脈 API（`/internal/authorize/login-context`。G12）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test authorize_login_context
//!
//! `/authorize` が受け取った `login_hint` / `ui_locales` は auth_session に保存されるが、web は
//! resume の 303 でこれらを手元に残せない。web が `auth_session_id` から引き直せることと、
//! 他テナント・未知のセッションでは何も返らない（fail-closed）ことを検証する。

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_json, post_internal, send, CODE_CHALLENGE, REDIRECT_URI_ENC, SERVICE_TOKEN};

/// `login_hint` / `ui_locales` 付きの認可リクエスト URI。
fn authorize_uri(tenant: &str, client_id: &str, login_hint: &str, ui_locales: &str) -> String {
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}\
         &scope=openid&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256\
         &login_hint={login_hint}&ui_locales={ui_locales}"
    )
}

async fn login_context(app: &axum::Router, tenant: &str, auth_session_id: &str) -> Value {
    let response = send(
        app,
        post_internal(
            "/internal/authorize/login-context",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": tenant, "auth_session_id": auth_session_id }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "login-context");
    body_json(response).await
}

#[tokio::test]
async fn returns_the_hints_the_rp_sent_to_authorize() {
    let Some(env) = support::setup("authorize login context").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        // `%20` 区切りの複数タグ・地域コード付きも RP は送ってくる。
        &authorize_uri(
            &root_tenant_id,
            &client_id,
            "alice%40example.com",
            "fr%20en-GB",
        ),
    )
    .await;

    let body = login_context(&app, &root_tenant_id, &auth_session).await;
    assert_eq!(body["result"], "ok", "{body}");
    assert_eq!(body["login_hint"], "alice@example.com");
    assert_eq!(body["ui_locales"], "fr en-GB");
}

/// サービストークン無しは 401（他の `/internal/*` と同じ多層防御）。
#[tokio::test]
async fn requires_the_service_token() {
    let Some(env) = support::setup("authorize login context auth").await else {
        return;
    };
    let response = send(
        &env.app,
        post_internal(
            "/internal/authorize/login-context",
            None,
            json!({ "tenant_id": env.root_tenant_id, "auth_session_id": "whatever" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 未知の `auth_session_id`・他テナントからの問い合わせは `session_expired`（存在も漏らさない）。
#[tokio::test]
async fn unknown_session_and_other_tenants_get_nothing() {
    let Some(env) = support::setup("authorize login context isolation").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let body = login_context(&app, &root_tenant_id, "0000000000000000").await;
    assert_eq!(body["result"], "session_expired", "{body}");

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        &authorize_uri(&root_tenant_id, &client_id, "bob", "en"),
    )
    .await;
    let other_tenant = uuid::Uuid::now_v7().to_string();
    let body = login_context(&app, &other_tenant, &auth_session).await;
    assert_eq!(body["result"], "session_expired", "{body}");
}

/// `login_hint` / `ui_locales` を送らない RP では、両方とも `null` の `ok` が返る。
#[tokio::test]
async fn omitted_hints_are_null() {
    let Some(env) = support::setup("authorize login context empty").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        &support::authorize_uri_openid_only(&root_tenant_id, &client_id),
    )
    .await;

    let body = login_context(&app, &root_tenant_id, &auth_session).await;
    assert_eq!(body["result"], "ok", "{body}");
    assert!(body["login_hint"].is_null(), "{body}");
    assert!(body["ui_locales"].is_null(), "{body}");
}
