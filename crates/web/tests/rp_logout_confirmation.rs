//! `id_token_hint` の無いサインアウト要求は、確認画面を挟んでから実行する（task #588）。
//!
//! 確認なしで終えていた頃は、リンク（`<img src>` でも）を踏ませるだけで他人をサインアウトさせられた。
//! hint 付きの要求（RP が自分の発行した ID Token を添える正規の経路）は今までどおり確認しない。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get_with_cookies, post_form, send, setup, WebEnv, TEST_CSRF_SECRET};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "rp-logout-session";
const RP_LOGOUT: &str = "/internal/logout/rp";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    assay_web::csrf::console_csrf_token(SSO, TEST_CSRF_SECRET)
}

async fn mount_rp_logout(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path(RP_LOGOUT))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "frontchannel_uris": [],
            "redirect_to": null,
        })))
        .mount(&env.api)
        .await;
}

async fn rp_logout_calls(env: &WebEnv) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == RP_LOGOUT)
        .count()
}

#[tokio::test]
async fn a_logout_link_without_a_hint_only_asks_for_confirmation() {
    let env = setup().await;
    mount_rp_logout(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/logout?state=xyz&client_id=rp-1", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains(&format!(r#"action="{}/logout/confirm""#, env.prefix())),
        "{html}"
    );
    assert!(
        html.contains(&format!(
            r#"<input type="hidden" name="csrf_token" value="{}">"#,
            csrf()
        )),
        "{html}"
    );
    // RP のパラメータは隠し項目で持ち回る。
    assert!(html.contains(r#"name="state" value="xyz""#), "{html}");
    assert!(html.contains(r#"name="client_id" value="rp-1""#), "{html}");
    assert_eq!(rp_logout_calls(&env).await, 0, "nothing is ended yet");
}

#[tokio::test]
async fn the_confirmation_signs_out_only_with_the_right_token() {
    let env = setup().await;
    mount_rp_logout(&env).await;
    let target = format!("{}/logout/confirm", env.prefix());

    for token in [
        String::new(),
        "0000".to_string(),
        assay_web::csrf::console_csrf_token("someone-else", TEST_CSRF_SECRET),
    ] {
        let response = send(
            &env.app,
            post_form(&target, Some(&cookies()), &[("csrf_token", token.as_str())]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{token:?}");
    }
    assert_eq!(rp_logout_calls(&env).await, 0);

    let response = send(
        &env.app,
        post_form(
            &target,
            Some(&cookies()),
            &[("csrf_token", csrf().as_str())],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(rp_logout_calls(&env).await, 1);
}

#[tokio::test]
async fn a_logout_with_an_id_token_hint_is_not_interrupted() {
    let env = setup().await;
    mount_rp_logout(&env).await;
    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/logout?id_token_hint=eyJ.hint.sig", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(rp_logout_calls(&env).await, 1);
}
