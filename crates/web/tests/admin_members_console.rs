//! メンバー一覧と 1 人の画面を**ルータ経由で**通す（api は wiremock で差し替える）。
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

/// 一覧は探す場所。各行から 1 人の画面への導線が出る。
#[tokio::test]
async fn the_member_list_renders_and_links_into_each_member() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/members$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "members": [member()], "total": 1, "limit": 50, "offset": 0
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "メンバー一覧が描けません"
    );
    let html = body_text(response).await;
    assert!(
        html.contains(&format!("{}/admin/members/{USER_ID}", env.prefix())),
        "一覧に 1 人の画面への導線がありません: {html}"
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
