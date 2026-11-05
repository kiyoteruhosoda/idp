//! 画面を出さずに試す往復（`prompt=none`）の 302 だけを、設定した親の枠に入れてよくする
//! （task #888・ADR-0076）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test silent_auth_framing
//!
//! 各アプリは切れたログインを、見えない枠で `/authorize?prompt=none` へ問い合わせて続ける。
//! 枠に入れてよいのはその 302 だけで、ほかの応答は今までどおり `X-Frame-Options: DENY`。

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use support::{send, CODE_CHALLENGE, REDIRECT_URI_ENC};

const PARENTS: &str = "https://*.nolumia.com";

async fn setup() -> Option<support::TestEnv> {
    // ⚠ このバイナリの中の試験は全部同じ値を使う（環境変数はプロセスで 1 つ）
    std::env::set_var("SILENT_AUTH_FRAME_ANCESTORS", PARENTS);
    support::setup("silent auth framing").await
}

fn authorize(tenant: &str, client_id: &str, prompt: Option<&str>) -> Request<Body> {
    let prompt = prompt.map(|p| format!("&prompt={p}")).unwrap_or_default();
    Request::builder()
        .uri(format!(
            "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}\
             &scope=openid&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256{prompt}"
        ))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn a_silent_authorize_may_be_framed_by_the_configured_parents() {
    let Some(env) = setup().await else {
        return;
    };
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = send(
        &env.app,
        authorize(&env.root_tenant_id, &client_id, Some("none")),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()["content-security-policy"],
        format!("frame-ancestors {PARENTS}")
    );
    assert!(response.headers().get("x-frame-options").is_none());
}

#[tokio::test]
async fn an_ordinary_authorize_is_never_framed() {
    let Some(env) = setup().await else {
        return;
    };
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    for prompt in [None, Some("login"), Some("consent")] {
        let response = send(&env.app, authorize(&env.root_tenant_id, &client_id, prompt)).await;
        assert_eq!(response.status(), StatusCode::FOUND, "{prompt:?}");
        assert_eq!(response.headers()["x-frame-options"], "DENY", "{prompt:?}");
        assert!(
            response.headers().get("content-security-policy").is_none(),
            "{prompt:?}"
        );
    }
}

/// 400 の本文は描かれるので、`prompt=none` でも枠に入れない。
#[tokio::test]
async fn a_refused_silent_authorize_is_not_framed() {
    let Some(env) = setup().await else {
        return;
    };

    let response = send(
        &env.app,
        authorize(&env.root_tenant_id, "no-such-client", Some("none")),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["x-frame-options"], "DENY");
}
