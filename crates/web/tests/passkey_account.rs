//! パスキーのセルフ管理画面（`/{tenant_id}/account/passkey*`）の動線をルータ経由で確かめる。
//!
//! ここで見たいのは「操作したあとどこに立っているか」である。削除の結果を専用ページで伝えると
//! 戻るリンクの無い 1 枚が残り、セッション切れを 401 の文言で伝えると利用者は抜け道を失う。
//! どちらも画面の描画としては成立するので、リダイレクト先まで見ないと壊れていても気づけない。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get_with_cookies, location, post_form, send, setup, WebEnv};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "user-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

/// 重要操作のゲート（AP5）は満たしている状態にしておく。
async fn stub_step_up_satisfied(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "satisfied" })))
        .mount(&env.api)
        .await;
}

async fn stub_list(env: &WebEnv, credentials: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/internal/passkey/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "credentials": credentials,
        })))
        .mount(&env.api)
        .await;
}

async fn stub_delete(env: &WebEnv, result: &str) {
    Mock::given(method("POST"))
        .and(path("/internal/passkey/delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": result })))
        .mount(&env.api)
        .await;
}

/// 削除は一覧へ戻して結果をバナーで伝える（戻るリンクの無い完了ページを挟まない）。
#[tokio::test]
async fn deleting_a_passkey_returns_to_the_list_with_a_banner() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_delete(&env, "ok").await;
    stub_list(&env, json!([])).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/passkey/delete", env.prefix()),
            Some(&cookies()),
            &[("credential_id", "00000000-0000-7000-8000-000000000001")],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/account/passkey?saved=deleted", env.prefix())
    );

    let list = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/passkey?saved=deleted", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    let html = body_text(list).await;
    assert!(html.contains("パスキーを削除しました"), "{html}");
}

/// 消えていないものを「消しました」と言わない（api の `not_found` は失敗として伝える）。
#[tokio::test]
async fn a_passkey_that_was_not_there_is_reported_as_a_failure() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_delete(&env, "not_found").await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/passkey/delete", env.prefix()),
            Some(&cookies()),
            &[("credential_id", "00000000-0000-7000-8000-000000000009")],
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/account/passkey?error=not-found", env.prefix())
    );
}

/// サインインしていなければログイン画面へ送る（設定配下の他の画面と同じ扱い）。
#[tokio::test]
async fn the_list_sends_a_signed_out_visitor_to_the_login_page() {
    let env = setup().await;

    let response = send(
        &env.app,
        support::get(&format!("{}/account/passkey", env.prefix())),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
}

/// セッションが切れていても行き止まりの 401 ページを出さない。
#[tokio::test]
async fn an_expired_session_sends_the_visitor_to_the_login_page() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/passkey/list"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "result": "session_expired" })),
        )
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/account/passkey", env.prefix()), &cookies()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
}

/// 一時停止中のパスキーは一覧に出る（鍵を引く経路は失効した行しか落とさない）。**出るのに
/// 使えない**ので、状態と外し方まで画面に出す。
#[tokio::test]
async fn a_suspended_passkey_is_marked_and_points_at_where_to_resume_it() {
    let env = setup().await;
    stub_list(
        &env,
        json!([{
            "id": "00000000-0000-7000-8000-000000000001",
            "name": "MacBook",
            "created_at": "2026-09-01T00:00:00+00:00",
            "last_used_at": null,
            "suspended": true,
        }]),
    )
    .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/account/passkey", env.prefix()), &cookies()),
    )
    .await;
    let html = body_text(response).await;

    assert!(html.contains("一時停止中"), "{html}");
    assert!(
        html.contains(&format!(
            r#"href="{}/settings/authenticators""#,
            env.prefix()
        )),
        "{html}"
    );
}

/// 削除の確認はフォームの `data-confirm`（`console.js`）で出す。`onclick` はインライン JS で、
/// CSP（`script-src 'self'`）に阻まれて**確認なしで送信される**。
#[tokio::test]
async fn the_delete_button_asks_for_confirmation_without_inline_script() {
    let env = setup().await;
    stub_list(
        &env,
        json!([{
            "id": "00000000-0000-7000-8000-000000000001",
            "name": "MacBook",
            "created_at": "2026-09-01T00:00:00+00:00",
            "last_used_at": null,
            "suspended": false,
        }]),
    )
    .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/account/passkey", env.prefix()), &cookies()),
    )
    .await;
    let html = body_text(response).await;

    assert!(html.contains("data-confirm="), "{html}");
    assert!(!html.contains("onclick="), "{html}");
    assert!(html.contains("/assets/console.js?v="), "{html}");
}
