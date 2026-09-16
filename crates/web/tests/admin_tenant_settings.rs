//! テナントの設定値の画面（ADR-0058）のルータ経由の統合テスト。
//!
//! 要は 2 つ:
//!
//! - ⚠ **締め出し得る値は、確認を挟むまで保存されない。** api が 409 を返したら web は確認画面を
//!   出し、確認画面から `confirmed` を付けて送り直したときだけ保存が通る（判定は api の定義が
//!   唯一の出所で、web はキー名を知らない）
//! - 「全体の値に戻す」は api の DELETE（行を消す）へ渡る。同じ値を PUT するのとは違う

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use assay_web::csrf::console_csrf_token;
use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_text, location, post_form, send, setup, WebEnv};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "admin-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    console_csrf_token(SSO, support::TEST_CSRF_SECRET)
}

async fn stub_admin(env: &WebEnv) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin",
            "preferred_username": "admin"
        })))
        .mount(&env.api)
        .await;
}

fn list() -> Value {
    json!({ "settings": [{
        "key": "APPLICATION_ASSIGNMENT_ENFORCEMENT",
        "description": "割り当ての判定",
        "kind": "CHOICE",
        "choices": [
            { "value": "record_only", "locks_out": false },
            { "value": "enforce", "locks_out": true }
        ],
        "value": "record_only",
        "origin": "INHERITED",
        "whole_idp_value": "record_only"
    }]})
}

/// api へ届いた、設定値を書き換える要求（PUT / DELETE）の本文と方法。
async fn writes(env: &WebEnv) -> Vec<(String, Option<Value>)> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| {
            r.url.path().contains("/admin/settings/tenant/keys/")
                && r.method != wiremock::http::Method::GET
        })
        .map(|r| (r.method.to_string(), serde_json::from_slice(&r.body).ok()))
        .collect()
}

#[tokio::test]
async fn a_value_that_can_lock_people_out_goes_through_a_confirmation_page() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/settings/tenant/keys$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list()))
        .mount(&env.api)
        .await;
    // 確認の無い要求は 409、確認つきは 200（api の振る舞いを写す）。
    Mock::given(method("PUT"))
        .and(path_regex(
            r"^/[^/]+/admin/settings/tenant/keys/APPLICATION_ASSIGNMENT_ENFORCEMENT$",
        ))
        .and(wiremock::matchers::body_partial_json(
            json!({ "confirmed": false }),
        ))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "error": "conflict", "message": "needs confirmation"
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(
            r"^/[^/]+/admin/settings/tenant/keys/APPLICATION_ASSIGNMENT_ENFORCEMENT$",
        ))
        .and(wiremock::matchers::body_partial_json(
            json!({ "confirmed": true }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(list()))
        .mount(&env.api)
        .await;

    let uri = format!("{}/admin/settings/tenant/keys", env.prefix());
    let response = send(
        &env.app,
        post_form(
            &uri,
            Some(&cookies()),
            &[
                ("csrf_token", &csrf()),
                ("key", "APPLICATION_ASSIGNMENT_ENFORCEMENT"),
                ("value", "enforce"),
            ],
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a confirmation page, not a redirect"
    );
    let html = body_text(response).await;
    assert!(html.contains("name=\"confirmed\" value=\"1\""), "{html}");
    assert!(html.contains("name=\"value\" value=\"enforce\""), "{html}");
    assert!(
        html.contains("<code>record_only</code>"),
        "current value: {html}"
    );

    let response = send(
        &env.app,
        post_form(
            &uri,
            Some(&cookies()),
            &[
                ("csrf_token", &csrf()),
                ("key", "APPLICATION_ASSIGNMENT_ENFORCEMENT"),
                ("value", "enforce"),
                ("confirmed", "1"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        location(&response).contains("saved=1"),
        "{}",
        location(&response)
    );

    let sent = writes(&env).await;
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0].1.as_ref().unwrap()["confirmed"], json!(false));
    assert_eq!(sent[1].1.as_ref().unwrap()["confirmed"], json!(true));
    assert_eq!(sent[1].1.as_ref().unwrap()["value"], json!("enforce"));
}

#[tokio::test]
async fn returning_to_the_whole_idp_value_deletes_the_override() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("DELETE"))
        .and(path_regex(
            r"^/[^/]+/admin/settings/tenant/keys/PASSWORD_MIN_LENGTH$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "settings": [] })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/settings/tenant/keys/clear", env.prefix()),
            Some(&cookies()),
            &[("csrf_token", &csrf()), ("key", "PASSWORD_MIN_LENGTH")],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        location(&response).contains("saved=1"),
        "{}",
        location(&response)
    );
    let sent = writes(&env).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, "DELETE");
}

#[tokio::test]
async fn a_bad_csrf_token_never_reaches_the_api() {
    let env = setup().await;
    stub_admin(&env).await;
    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/settings/tenant/keys", env.prefix()),
            Some(&cookies()),
            &[
                ("csrf_token", "forged"),
                ("key", "PASSWORD_MIN_LENGTH"),
                ("value", "4"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).contains("error=csrf"));
    assert!(writes(&env).await.is_empty());
}
