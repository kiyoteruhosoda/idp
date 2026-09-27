//! アカウント一覧と 1 件の画面（人・サービスアカウント）を**ルータ経由で**通す（api は wiremock で差し替える）。
//!
//! ⚠ **描画の単体テストだけでは足りなかった。** テンプレートを直接描く試験は通っていたのに、
//! 実際の経路は 500 を返していた（E2E が捕まえた）。ハンドラと api クライアントの結線まで
//! 通しておかないと、同じ形の見落としが繰り返される。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get_with_cookies, send, setup};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const USER_ID: &str = "11111111-1111-1111-1111-111111111111";
const CLIENT_ID: &str = "c0ffee";

async fn stub_admin(env: &support::WebEnv) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin User",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })))
        .mount(&env.api)
        .await;
}

fn member() -> serde_json::Value {
    json!({
        "user_id": USER_ID,
        "email": "u@example.com",
        "preferred_username": "u",
        "name": null,
        "membership_type": "HOME",
        "status": "ACTIVE",
        "user_status": "ACTIVE",
        "locked": false
    })
}

fn service_account() -> serde_json::Value {
    json!({
        "client_id": CLIENT_ID,
        "app_name": "夜間同期",
        "status": "ACTIVE",
        "created_at": "2026-09-25T00:00:00Z",
        "note": { "text": "経緯のメモ", "updated_at": "2026-09-25T00:00:00Z" }
    })
}

/// 一覧は探す場所。人とサービスアカウントが 1 つに並び、各行からその 1 件の画面へ行ける
/// （ADR-0065）。
#[tokio::test]
async fn the_account_list_renders_both_kinds_and_links_into_each() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/accounts$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [
                { "kind": "user", "user": member() },
                { "kind": "service_account", "service_account": service_account() }
            ],
            "kinds": ["user", "service_account"],
            "readable_kinds": ["user", "service_account"],
            "total": 2, "limit": 50, "offset": 0
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/accounts", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "アカウント一覧が描けません"
    );
    let html = body_text(response).await;
    assert!(
        html.contains(&format!("{}/admin/members/{USER_ID}", env.prefix())),
        "一覧に 1 人の画面への導線がありません: {html}"
    );
    assert!(
        html.contains(&format!(
            "{}/admin/service-accounts/{CLIENT_ID}",
            env.prefix()
        )),
        "一覧にサービスアカウントの画面への導線がありません: {html}"
    );
}

/// 旧来のメンバー一覧は、人に絞ったアカウントの一覧へ転送する（ブックマークを壊さない）。
#[tokio::test]
async fn the_old_member_list_forwards_to_the_account_list() {
    let env = setup().await;
    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members?q=abc", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        location,
        format!("{}/admin/accounts?kind=user&q=abc", env.prefix())
    );
}

/// サービスアカウント 1 件の画面を**ルータ経由で**描く（api 5 本の結線を通す）。
#[tokio::test]
async fn the_service_account_page_renders_the_same_cards_as_a_member() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/service-accounts/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service_account()))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/[^/]+/admin/service-accounts/[^/]+/applications$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "applications": [], "enforcement": "enforce"
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/clients/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "0197", "client_id": CLIENT_ID, "client_type": "confidential",
            "client_status": "ACTIVE", "app_name": "夜間同期", "redirect_uris": [],
            "grant_types": ["client_credentials"], "response_types": [], "scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic",
            "created_at": "2026-09-25T00:00:00Z", "updated_at": "2026-09-25T00:00:00Z"
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/clients/[^/]+/permissions$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "client_id": CLIENT_ID, "permission_codes": []
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/permissions$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "codes": ["idp.members:read"]
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/service-accounts/{CLIENT_ID}", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    let st = response.status();
    let html = body_text(response).await;
    assert_eq!(st, StatusCode::OK, "{}", &html[..html.len().min(900)]);
    let base = format!("{}/admin/service-accounts/{CLIENT_ID}", env.prefix());
    assert!(
        html.contains(&format!("{base}/note")),
        "メモの欄がありません: {html}"
    );
    assert!(html.contains("経緯のメモ"), "{html}");
    assert!(
        html.contains(&format!(
            "{}/admin/clients/{CLIENT_ID}/delete",
            env.prefix()
        )),
        "{html}"
    );
}

/// ⚠ **これが 500 を返していた。** 経路には `{tenant_id}` と `{user_id}` の 2 つがあるのに
/// api 側が `Path<Uuid>` 1 つで受けており、先頭のテナント ID を取っていた。
#[tokio::test]
async fn the_member_page_renders_the_actions() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/members/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(member()))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members/{USER_ID}", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    let st = response.status();
    let html = body_text(response).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "1 人の画面が描けません: {}",
        &html[..html.len().min(900)]
    );
    for action in ["reset-mfa", "reset-password", "reissue-tokens", "delete"] {
        assert!(
            html.contains(&format!(
                "{}/admin/members/{USER_ID}/{action}",
                env.prefix()
            )),
            "{action} が出ていません: {html}"
        );
    }
}

/// メンバーでない相手は一覧へ戻す（他テナントのメンバーの存在を推測させない）。
#[tokio::test]
async fn an_unknown_member_goes_back_to_the_list() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/members/[^/]+$"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members/{USER_ID}", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "一覧へ戻しません");
}
