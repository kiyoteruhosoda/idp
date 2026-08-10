//! 認証ポリシー管理画面のルータ経由の統合テスト（AP1。土台は G11）。
//!
//! この画面の要は「api の更新が**全項目置換**である」こと。編集で出し忘れた条件は保存の瞬間に
//! 消えるため、ここでは *画面に全条件が出ること* と *送信内容が api へそのまま渡ること* を、
//! api をスタブして実際の HTTP ボディで確かめる。

mod support;

use axum::http::StatusCode;
use idp_contracts::cookies::SSO_SESSION_COOKIE;
use idp_web::csrf::console_csrf_token;
use serde_json::{json, Value};
use support::{body_text, get_with_cookies, location, post_form, send, setup, WebEnv};
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

fn sample_policy() -> Value {
    json!({
        "id": "019f8ea8-f5dd-7fc7-ac15-a7d4337e4610",
        "policy_code": "office-hours",
        "policy_name": "Office hours",
        "priority": 10,
        "enabled": true,
        "effect": "require_specific_method",
        "effect_params": { "methods": ["webauthn"], "user_verification": true },
        "client_ids": ["app-a", "app-b"],
        "user_ids": [],
        "ip_cidrs": ["10.0.0.0/8"],
        "time_windows": [
            { "days": [1, 2, 3, 4, 5], "start_minute": 540, "end_minute": 1080, "utc_offset_minutes": 540 }
        ],
        "requested_acr": [],
        "created_at": "2026-08-10T00:00:00Z",
        "updated_at": "2026-08-10T00:00:00Z"
    })
}

/// 管理ポリシーの**作成呼び出し**の本文（届いていなければ `None`）。
///
/// 記録された要求を単に「最初の POST」で拾わない。管理コンソールのレイアウトは表示のために
/// `/internal/account/profile` を POST するので、それを掴んでしまう。
async fn created_policy_body(env: &WebEnv) -> Option<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with("/admin/authentication-policies")
        })
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
}

/// ポリシーを書き換える呼び出し（作成・更新・削除）が api へ届いたか。
async fn wrote_a_policy(env: &WebEnv) -> bool {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .any(|r| {
            r.url.path().contains("/admin/authentication-policies")
                && r.method != wiremock::http::Method::GET
        })
}

async fn stub_list(env: &WebEnv, policies: Value) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "policies": policies })))
        .mount(&env.api)
        .await;
}

#[tokio::test]
async fn the_list_shows_the_default_effect_because_a_policy_alone_does_not_decide_anything() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/authentication-policies", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    // 既定動作が見えないと、同じ「deny 1 件」でも意味が読めない。
    assert!(
        html.contains("<code>allow</code>"),
        "default effect: {html}"
    );
}

#[tokio::test]
async fn editing_prefills_every_condition_so_a_save_cannot_silently_drop_one() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_policy()])).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!(
                "{}/admin/authentication-policies?edit=019f8ea8-f5dd-7fc7-ac15-a7d4337e4610",
                env.prefix()
            ),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;

    assert!(html.contains(r#"value="office-hours""#), "code: {html}");
    assert!(html.contains(r#"value="10""#), "priority: {html}");
    assert!(html.contains("app-a\napp-b"), "client ids: {html}");
    assert!(html.contains("10.0.0.0/8"), "cidrs: {html}");
    assert!(
        html.contains("mon,tue,wed,thu,fri 09:00-18:00 +09:00"),
        "time window must round-trip into the textarea: {html}"
    );
    // 更新は専用の POST パス経由（HTML フォームは PUT を送れない）。
    assert!(
        html.contains("/admin/authentication-policies/019f8ea8-f5dd-7fc7-ac15-a7d4337e4610/update"),
        "edit form must post to the update path: {html}"
    );
}

#[tokio::test]
async fn creating_a_policy_sends_the_conditions_the_operator_typed() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_policy()))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/authentication-policies", env.prefix()),
            Some(&cookies()),
            &[
                ("policy_code", "office-hours"),
                ("policy_name", "Office hours"),
                ("priority", "10"),
                ("enabled", "1"),
                ("effect", "require_specific_method"),
                ("method_webauthn", "1"),
                ("user_verification", "1"),
                ("client_ids", "app-a\napp-b"),
                ("user_ids", ""),
                ("ip_cidrs", "10.0.0.0/8"),
                ("time_windows", "mon,tue,wed,thu,fri 09:00-18:00 +09:00"),
                ("requested_acr", ""),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        location(&response).ends_with("?saved=1"),
        "{}",
        location(&response)
    );

    let body = created_policy_body(&env)
        .await
        .expect("the create call must reach the api");

    assert_eq!(body["policy_code"], "office-hours");
    assert_eq!(body["priority"], 10);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["effect"], "require_specific_method");
    assert_eq!(body["effect_params"]["methods"], json!(["webauthn"]));
    assert_eq!(body["effect_params"]["user_verification"], true);
    assert_eq!(body["client_ids"], json!(["app-a", "app-b"]));
    assert_eq!(body["ip_cidrs"], json!(["10.0.0.0/8"]));
    assert_eq!(body["time_windows"][0]["days"], json!([1, 2, 3, 4, 5]));
    assert_eq!(body["time_windows"][0]["start_minute"], 540);
    assert_eq!(body["time_windows"][0]["utc_offset_minutes"], 540);
}

/// 効果を切り替えたときにチェックが残っていただけ、という取り違えを web 側で落とす
/// （`require_specific_method` 以外で要求内容を送ると api が弾く）。
#[tokio::test]
async fn method_requirements_are_not_sent_for_other_effects() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_policy()))
        .mount(&env.api)
        .await;

    send(
        &env.app,
        post_form(
            &format!("{}/admin/authentication-policies", env.prefix()),
            Some(&cookies()),
            &[
                ("policy_code", "deny-legacy"),
                ("policy_name", "Deny legacy"),
                ("priority", "1"),
                ("effect", "deny"),
                ("method_webauthn", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;

    let body = created_policy_body(&env)
        .await
        .expect("the create call must reach the api");
    assert_eq!(body["effect_params"], Value::Null);
    // 未チェックのチェックボックスは送信されない = 無効として保存される。
    assert_eq!(body["enabled"], false);
}

/// 読めない時間帯は**保存させない**。読める行だけ送ると、書いたはずの条件が黙って消えたまま
/// 「保存しました」と表示される。
#[tokio::test]
async fn an_unreadable_time_window_stops_the_save_and_keeps_the_edit_context() {
    let env = setup().await;
    stub_admin(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!(
                "{}/admin/authentication-policies/019f8ea8-f5dd-7fc7-ac15-a7d4337e4610/update",
                env.prefix()
            ),
            Some(&cookies()),
            &[
                ("policy_code", "office-hours"),
                ("policy_name", "Office hours"),
                ("priority", "10"),
                ("effect", "deny"),
                ("client_ids", "app-a\napp-b"),
                ("time_windows", "mon 09:00-18:00\nnonsense"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        !wrote_a_policy(&env).await,
        "nothing may be written when a condition could not be read"
    );

    // 入力は消えない。1 項目直すために全部入れ直させない。
    let html = body_text(response).await;
    assert!(
        html.contains(r#"value="office-hours""#),
        "code kept: {html}"
    );
    assert!(html.contains("app-a\napp-b"), "client ids kept: {html}");
    assert!(
        html.contains("mon 09:00-18:00\nnonsense"),
        "the rejected time windows must stay so the operator can fix them: {html}"
    );
    // 編集対象を見失わない（新規作成のフォームに化けると別のポリシーが増える）。
    assert!(
        html.contains("/admin/authentication-policies/019f8ea8-f5dd-7fc7-ac15-a7d4337e4610/update"),
        "the form must still target the policy being edited: {html}"
    );
}

#[tokio::test]
async fn a_csrf_mismatch_never_reaches_the_api() {
    let env = setup().await;
    stub_admin(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/authentication-policies", env.prefix()),
            Some(&cookies()),
            &[
                ("policy_code", "x"),
                ("policy_name", "x"),
                ("priority", "1"),
                ("effect", "deny"),
                ("csrf_token", "wrong"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        created_policy_body(&env).await.is_none(),
        "a rejected form must not be forwarded"
    );
}

#[tokio::test]
async fn deleting_a_policy_forwards_to_the_api_and_reports_it() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies/[^/]+$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!(
                "{}/admin/authentication-policies/019f8ea8-f5dd-7fc7-ac15-a7d4337e4610/delete",
                env.prefix()
            ),
            Some(&cookies()),
            &[("csrf_token", &csrf())],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).ends_with("?deleted=1"));
}
