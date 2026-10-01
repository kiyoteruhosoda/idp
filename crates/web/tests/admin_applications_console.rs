//! アプリの画面の、名乗りの移し替えと削除を**ルータ経由で**通す（api は wiremock で差し替える。ADR-0067）。
//!
//! 要は 3 つ:
//!
//! - ⚠ **別のアプリの名乗りを選んだら、すぐには送らない。** 「○○ から移す」確認を出し、確認から
//!   送り直したときだけ、移す元を名指しして api に頼む（api が外す＋結ぶを 1 回で行う）
//! - どこにも属していない相手は、確認なしでそのまま結ぶ
//! - 「このアプリを消す」は api の DELETE へ渡り、一覧へ戻す

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use assay_web::csrf::console_csrf_token;
use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_text, location, post_form, send, setup, WebEnv};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "admin-session";
const APP_ID: &str = "app-1";
const OWNER_ID: &str = "app-auto";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    console_csrf_token(SSO, support::TEST_CSRF_SECRET)
}

fn application() -> Value {
    json!({
        "id": APP_ID,
        "display_name": "wiki",
        "status": "ACTIVE",
        "assignment_mode": "INDIVIDUAL",
        "bindings": [],
        "assigned_count": 0,
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z"
    })
}

async fn stub(env: &WebEnv) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })))
        .mount(&env.api)
        .await;
    let mut detail = application();
    detail["assigned"] = json!([]);
    detail["assigned_service_accounts"] = json!([]);
    detail["enforcement"] = json!("enforce");
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/applications/app-1$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/[^/]+/admin/applications/app-1/binding-candidates$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [
                {
                    "kind": "oidc",
                    "reference": "wiki-login",
                    "identifier": "wiki-login",
                    "display_name": "wiki",
                    "application_id": OWNER_ID,
                    "application_name": "wiki（自動）"
                },
                {
                    "kind": "resource",
                    "reference": "api://wiki",
                    "identifier": "api://wiki",
                    "display_name": "wiki API",
                    "application_id": null,
                    "application_name": null
                }
            ]
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/applications/app-1/bindings$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(application()))
        .mount(&env.api)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/[^/]+/admin/applications/app-1$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&env.api)
        .await;
}

/// api へ届いた、名乗りを足す要求の本文。
async fn bind_requests(env: &WebEnv) -> Vec<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path().ends_with("/bindings") && r.method == wiremock::http::Method::POST)
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
        .collect()
}

#[tokio::test]
async fn a_target_owned_by_another_application_is_moved_only_after_confirmation() {
    let env = setup().await;
    stub(&env).await;
    let uri = format!("{}/admin/applications/{APP_ID}/bind", env.prefix());

    // 1 回目: 持ち主の居る相手を選ぶ → 確認画面。api にはまだ送らない。
    let response = send(
        &env.app,
        post_form(
            &uri,
            Some(&cookies()),
            &[("csrf_token", &csrf()), ("candidate", "oidc:wiki-login")],
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a confirmation, not a redirect"
    );
    let html = body_text(response).await;
    assert!(html.contains("「wiki（自動）」から移しますか？"), "{html}");
    assert!(
        html.contains(&format!(r#"name="move_from" value="{OWNER_ID}""#)),
        "{html}"
    );
    assert!(
        bind_requests(&env).await.is_empty(),
        "nothing is moved before the confirmation"
    );

    // 2 回目: 確認から送り直す → 移す元を名指しして api へ。
    let response = send(
        &env.app,
        post_form(
            &uri,
            Some(&cookies()),
            &[
                ("csrf_token", &csrf()),
                ("candidate", "oidc:wiki-login"),
                ("move_from", OWNER_ID),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/admin/applications/{APP_ID}", env.prefix())
    );
    let sent = bind_requests(&env).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        sent[0],
        json!({
            "kind": "oidc",
            "client_id": "wiki-login",
            "move_from_application_id": OWNER_ID,
        })
    );
}

#[tokio::test]
async fn a_free_target_is_bound_without_a_confirmation() {
    let env = setup().await;
    stub(&env).await;
    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/applications/{APP_ID}/bind", env.prefix()),
            Some(&cookies()),
            &[
                ("csrf_token", &csrf()),
                ("candidate", "resource:api://wiki"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let sent = bind_requests(&env).await;
    assert_eq!(
        sent,
        vec![json!({ "kind": "resource", "resource_uri": "api://wiki" })],
        "a URI containing ':' survives the choice value"
    );
}

#[tokio::test]
async fn deleting_an_application_goes_to_the_api_and_back_to_the_list() {
    let env = setup().await;
    stub(&env).await;

    // 消す前に、詳細の画面に「何が外れるか」と消すボタンが出ている。
    let response = send(
        &env.app,
        support::get_with_cookies(
            &format!("{}/admin/applications/{APP_ID}", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains("このアプリには名乗りも使う主体もありません。"),
        "{html}"
    );
    assert!(html.contains("/admin/applications/app-1/delete"), "{html}");

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/applications/{APP_ID}/delete", env.prefix()),
            Some(&cookies()),
            &[("csrf_token", &csrf())],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/admin/applications", env.prefix())
    );
    let deletes = env
        .api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.method == wiremock::http::Method::DELETE)
        .count();
    assert_eq!(deletes, 1, "the api's DELETE is called once");
}
