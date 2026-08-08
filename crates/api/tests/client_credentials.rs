//! `client_credentials` grant の統合テスト（G4）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test client_credentials
//!
//! 検証の要:
//! - 利用者が居ないため **ID Token も Refresh Token も返さない**こと。
//! - 許可されていないクライアント（grant 未登録・public）が使えないこと。
//! - `/userinfo` が本 grant のトークンを拒否し、`/introspect` は active として扱うこと。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::Value;
use support::{body_json, send};

/// `Authorization: Basic` ヘッダ値を組み立てる。
fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// `/token` へ `client_credentials` を投げる。
async fn request_token(
    app: &axum::Router,
    tenant_id: &str,
    client_id: &str,
    secret: &str,
    scope: Option<&str>,
) -> axum::response::Response {
    let mut body = "grant_type=client_credentials".to_string();
    if let Some(s) = scope {
        body.push_str(&format!(
            "&scope={}",
            percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC)
        ));
    }
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(client_id, secret))
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn issues_an_access_token_without_an_id_token_or_refresh_token() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["reports.read"]).await;

    let response = request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;

    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "reports.read");
    assert!(tokens["access_token"]
        .as_str()
        .is_some_and(|t| !t.is_empty()));
    // 利用者が居ないため、この 2 つは**存在してはならない**（OIDC Core の ID Token 定義に反する）。
    assert_eq!(
        tokens["id_token"],
        Value::Null,
        "client_credentials は ID Token を返さない"
    );
    assert_eq!(
        tokens["refresh_token"],
        Value::Null,
        "client_credentials は Refresh Token を返さない"
    );
}

/// 要求 scope は登録 scope の部分集合に限る（`/authorize` と同じ完全一致判定）。
#[tokio::test]
async fn rejects_a_scope_outside_the_registered_set() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["reports.read"]).await;

    let response = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some("reports.read reports.write"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_scope");
}

/// `offline_access` は登録済みでも本 grant では拒否する（資格情報を出し直せるため不要）。
#[tokio::test]
async fn rejects_offline_access() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) = support::insert_m2m_client(
        &env.pool,
        &env.root_tenant_id,
        &["reports.read", "offline_access"],
    )
    .await;

    let response = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some("offline_access"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_scope");
}

/// `client_credentials` を登録していない confidential client は使えない（既定は無効）。
#[tokio::test]
async fn rejects_a_client_without_the_grant_registered() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "unauthorized_client");
}

/// public client は資格情報を秘匿できないため本 grant を使えない。
#[tokio::test]
async fn rejects_a_public_client() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=client_credentials&client_id={client_id}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "unauthorized_client");
}

/// `/userinfo` は利用者主体のトークンしか受け付けない。`/introspect` は active として扱い、
/// `sub` にクライアント自身を返す。
#[tokio::test]
async fn the_token_is_rejected_by_userinfo_but_accepted_by_introspection() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid", "reports.read"])
            .await;

    let tokens = body_json(
        request_token(
            &env.app,
            &env.root_tenant_id,
            &client_id,
            &secret,
            Some("openid reports.read"),
        )
        .await,
    )
    .await;
    let access_token = tokens["access_token"].as_str().expect("access token");

    // /userinfo: openid scope を持っていても、利用者主体でないので 401。
    let response = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(format!("/{}/userinfo", env.root_tenant_id))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "client_credentials のトークンで /userinfo は取れない"
    );

    // /introspect: active。主体はクライアント自身。
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/introspect", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(&client_id, &secret))
            .body(Body::from(format!("token={access_token}")))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let introspection = body_json(response).await;
    assert_eq!(introspection["active"], true);
    assert_eq!(introspection["sub"], client_id);
    assert_eq!(introspection["client_id"], client_id);
}

/// Discovery は本 grant を広告する（RP のメタデータ検証が通るようにする）。
#[tokio::test]
async fn discovery_advertises_the_grant() {
    let Some(env) = support::setup("client_credentials").await else {
        return;
    };
    let response = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(format!(
                "/{}/.well-known/openid-configuration",
                env.root_tenant_id
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let doc = body_json(response).await;
    assert!(doc["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported")
        .iter()
        .any(|v| v == "client_credentials"));
}
