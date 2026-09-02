//! パスキーでのログイン完了（3 経路）の応答をルータ経由で確かめる。
//!
//! 見たいのは「api が返した結果が、**画面が文言に写せる形で**ブラウザまで届くか」である。
//! スクリプトは `#passkey-error` の data 属性からしか文言を引かないので、対応する属性が
//! 画面に無いコードは既定文言へ落ちる —— 応答だけを見ても、画面だけを見ても気づけない。

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{body_text, send, setup, WebEnv};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn stub_complete(env: &WebEnv, result: Value) {
    Mock::given(method("POST"))
        .and(path("/internal/passkey/login/complete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(result))
        .mount(&env.api)
        .await;
}

async fn complete(env: &WebEnv) -> Value {
    let response = send(
        &env.app,
        post_json(
            &format!("{}/passkey/login/complete", env.prefix()),
            json!({
                "challenge_id": "00000000-0000-7000-8000-000000000001",
                "credential": {},
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_str(&body_text(response).await).expect("json")
}

/// 認可フローのパスキーログインもレート制限に当たる（T39。直接ログインと同じ枠を消費する）。
#[tokio::test]
async fn a_rate_limited_passkey_login_reports_a_code_the_screen_can_translate() {
    let env = setup().await;
    stub_complete(&env, json!({ "result": "rate_limited" })).await;

    let body = complete(&env).await;

    assert_eq!(body["error"], json!("rate_limited"));
    assert!(body["redirect_to"].is_null());
}
