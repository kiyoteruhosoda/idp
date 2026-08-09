//! G1: ブラウザからの越境アクセス（CORS）。
//!
//! 既定トポロジ（`domain-split`）では SPA から api への呼び出しは常にクロスオリジンになる。
//! ここで固定するのは「誰にどこまで開くか」の境界:
//!
//!   * 公開メタデータは誰でも読める（`*`）
//!   * `/token`・`/userinfo` 等は**テナントに登録された public クライアントのオリジン**だけ
//!   * 管理 API には開けない
//!   * どの経路でも `Access-Control-Allow-Credentials` を付けない
//!
//! 実行方法は `schema.rs` と同じ（`TEST_DATABASE_URL` が必須）。

mod support;

use axum::body::Body;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN,
};
use axum::http::{Method, Request, StatusCode};

const SPA_ORIGIN: &str = "http://localhost:3000";
const OTHER_ORIGIN: &str = "https://evil.example.com";

fn with_origin(method: Method, uri: &str, origin: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(ORIGIN, origin)
        .body(Body::empty())
        .expect("build request")
}

fn allow_origin(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get(ACCESS_CONTROL_ALLOW_ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// 公開メタデータは client_id もトークンも載らないため誰かを特定できない。無認証で誰でも
/// 取得できる内容なので `*` で開く。
#[tokio::test]
async fn public_metadata_is_readable_from_any_origin() {
    let Some(env) = support::setup("cors_public_metadata").await else {
        return;
    };
    let tenant = &env.root_tenant_id;

    for path in [
        format!("/{tenant}/.well-known/openid-configuration"),
        format!("/{tenant}/.well-known/jwks.json"),
        format!("/{tenant}/saml/metadata"),
    ] {
        let response = support::send(&env.app, with_origin(Method::GET, &path, OTHER_ORIGIN)).await;
        assert_eq!(
            allow_origin(&response).as_deref(),
            Some("*"),
            "{path} must be readable cross-origin"
        );
        assert!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "{path}: api はブラウザ Cookie を読まない（ADR-0018）ので credentials は許可しない"
        );
    }
}

/// `/token` はテナントに登録された public クライアントの `redirect_uris` 由来のオリジンにだけ開く。
#[tokio::test]
async fn the_token_endpoint_opens_only_to_registered_public_client_origins() {
    let Some(env) = support::setup("cors_token_endpoint").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    // `REDIRECT_URI` は `http://localhost:3000/callback`（= SPA_ORIGIN）。
    let _client = support::insert_public_client(&env.pool, tenant, &["openid"]).await;

    // 登録済みオリジン: 実リクエストのレスポンスを読める。
    let uri = format!("/{tenant}/token");
    let allowed = support::send(&env.app, with_origin(Method::POST, &uri, SPA_ORIGIN)).await;
    assert_eq!(allow_origin(&allowed).as_deref(), Some(SPA_ORIGIN));
    assert!(
        allowed
            .headers()
            .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "credentials は許可しない"
    );

    // 未登録オリジン: ヘッダを付けない（ブラウザが読み取りを拒む）。
    let denied = support::send(&env.app, with_origin(Method::POST, &uri, OTHER_ORIGIN)).await;
    assert_eq!(allow_origin(&denied), None);
}

/// `/userinfo` は `Authorization: Bearer` が非 safelisted のため必ずプリフライトされる。
/// OPTIONS にトークンは載らないので、テナント単位の許可集合で答える。
#[tokio::test]
async fn the_userinfo_preflight_is_answered_without_hitting_the_handler() {
    let Some(env) = support::setup("cors_userinfo_preflight").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let _client = support::insert_public_client(&env.pool, tenant, &["openid"]).await;

    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri(format!("/{tenant}/userinfo"))
        .header(ORIGIN, SPA_ORIGIN)
        .header(ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .header(ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
        .body(Body::empty())
        .expect("build preflight");
    let response = support::send(&env.app, preflight).await;

    // ルータは OPTIONS を持たないため、ミドルウェアが受け止めないと 405 になる。
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(allow_origin(&response).as_deref(), Some(SPA_ORIGIN));
    let methods = response
        .headers()
        .get(ACCESS_CONTROL_ALLOW_METHODS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(methods.contains("GET"), "GET が許可されている: {methods}");
}

/// 未登録オリジンからのプリフライトは CORS ヘッダ無しで返す（実リクエストが飛ばない）。
#[tokio::test]
async fn a_preflight_from_an_unknown_origin_gets_no_cors_headers() {
    let Some(env) = support::setup("cors_unknown_preflight").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let _client = support::insert_public_client(&env.pool, tenant, &["openid"]).await;

    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri(format!("/{tenant}/userinfo"))
        .header(ORIGIN, OTHER_ORIGIN)
        .header(ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Body::empty())
        .expect("build preflight");
    let response = support::send(&env.app, preflight).await;
    assert_eq!(allow_origin(&response), None);
}

/// 管理 API はブラウザ JS から越境で叩く経路ではない。開けると管理操作が別オリジンから
/// 読める余地を作ってしまうので、登録済みオリジンからでもヘッダを付けない。
#[tokio::test]
async fn admin_endpoints_are_never_opened_cross_origin() {
    let Some(env) = support::setup("cors_admin_closed").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let _client = support::insert_public_client(&env.pool, tenant, &["openid"]).await;

    let uri = format!("/{tenant}/admin/clients");
    let response = support::send(&env.app, with_origin(Method::GET, &uri, SPA_ORIGIN)).await;
    assert_eq!(allow_origin(&response), None);
}
