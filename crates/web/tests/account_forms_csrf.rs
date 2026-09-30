//! 設定画面の表示名・パスワードの変更と、TOTP の設定・削除は CSRF トークンを要る（task #118）。
//!
//! 以前はどれもトークンを持たず、SSO Cookie の `SameSite=Lax` だけで守られていた。利用者向けの
//! 他の画面（セッション一覧・認証器）と同じ `console_csrf_token`（SSO セッション id 由来）を
//! フォームへ埋め、合わなければ api へ何も送らずに戻す。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_text, get_with_cookies, location, post_form, send, setup, WebEnv, TEST_CSRF_SECRET,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "account-forms-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    assay_web::csrf::console_csrf_token(SSO, TEST_CSRF_SECRET)
}

/// 無い・空・でたらめ・別のセッションのもの。どれも「合わない」。
fn wrong_tokens() -> Vec<Option<String>> {
    vec![
        None,
        Some(String::new()),
        Some("0".repeat(64)),
        Some(assay_web::csrf::console_csrf_token(
            "someone-else",
            TEST_CSRF_SECRET,
        )),
    ]
}

/// `fields` に（あれば）トークンを足した POST。
async fn post_with_token(
    env: &WebEnv,
    target: &str,
    fields: &[(&str, &str)],
    token: Option<&str>,
) -> axum::http::Response<axum::body::Body> {
    let mut all: Vec<(&str, &str)> = fields.to_vec();
    if let Some(token) = token {
        all.push(("csrf_token", token));
    }
    send(
        &env.app,
        post_form(&format!("{}{target}", env.prefix()), Some(&cookies()), &all),
    )
    .await
}

async fn mount_ok(env: &WebEnv, target: &str) {
    Mock::given(method("POST"))
        .and(path(target))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
        .mount(&env.api)
        .await;
}

async fn calls_to(env: &WebEnv, target: &str) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == target)
        .count()
}

async fn stub_step_up_satisfied(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "satisfied" })))
        .mount(&env.api)
        .await;
}

// ── 表示名 ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_display_name_is_changed_only_with_the_right_token() {
    let env = setup().await;
    mount_ok(&env, "/internal/account/update-name").await;
    let fields = [("name", "新しい 名前")];

    for token in wrong_tokens() {
        let response = post_with_token(&env, "/settings/name", &fields, token.as_deref()).await;
        assert_eq!(response.status(), StatusCode::FOUND, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/settings?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(
        calls_to(&env, "/internal/account/update-name").await,
        0,
        "a mismatched token must not reach the api"
    );

    let response = post_with_token(&env, "/settings/name", &fields, Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!("{}/settings?saved=name", env.prefix())
    );
    assert_eq!(calls_to(&env, "/internal/account/update-name").await, 1);
}

/// 管理コンソールから開いた文脈は、トークンが合わずに戻したときも保つ。
#[tokio::test]
async fn a_rejected_change_keeps_the_console_context() {
    let env = setup().await;
    let response = post_with_token(
        &env,
        "/settings/name",
        &[("name", "x"), ("from", "admin")],
        None,
    )
    .await;
    assert_eq!(
        location(&response),
        format!("{}/settings?error=csrf&from=admin", env.prefix())
    );
}

// ── パスワード ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_password_is_changed_only_with_the_right_token() {
    let env = setup().await;
    mount_ok(&env, "/internal/account/change-password").await;
    let fields = [
        ("current_password", "current-password"),
        ("new_password", "a-brand-new-password"),
        ("new_password_confirm", "a-brand-new-password"),
    ];

    for token in wrong_tokens() {
        let response = post_with_token(&env, "/settings/password", &fields, token.as_deref()).await;
        assert_eq!(
            location(&response),
            format!("{}/settings?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(
        calls_to(&env, "/internal/account/change-password").await,
        0,
        "a mismatched token must not reach the api"
    );

    let response = post_with_token(&env, "/settings/password", &fields, Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!("{}/settings?saved=password", env.prefix())
    );
    assert_eq!(calls_to(&env, "/internal/account/change-password").await, 1);
}

// ── TOTP ─────────────────────────────────────────────────────────────────────

/// 確認コードの送信（有効化）はトークンが合わなければ api へ送らず、設定画面を取り直させる。
#[tokio::test]
async fn the_totp_setup_is_confirmed_only_with_the_right_token() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    mount_ok(&env, "/internal/mfa/totp/confirm").await;
    let fields = [("code", "123456")];

    for token in wrong_tokens() {
        let response =
            post_with_token(&env, "/account/mfa/totp/setup", &fields, token.as_deref()).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/account/mfa/totp/setup?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(calls_to(&env, "/internal/mfa/totp/confirm").await, 0);

    let response = post_with_token(&env, "/account/mfa/totp/setup", &fields, Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!("{}/settings/authenticators?saved=totp", env.prefix())
    );
    assert_eq!(calls_to(&env, "/internal/mfa/totp/confirm").await, 1);
}

/// 設定画面はトークンを埋め、`?error=csrf` で戻ったときはバナーを出す。
#[tokio::test]
async fn the_totp_setup_page_carries_the_token_and_shows_the_banner() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/setup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "totp_uri": "otpauth://totp/assay:?secret=JBSWY3DPEHPK3PXP&issuer=assay",
            "secret_base32": "JBSWY3DPEHPK3PXP",
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup?error=csrf", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains(&format!(
            r#"<input type="hidden" name="csrf_token" value="{}">"#,
            csrf()
        )),
        "{html}"
    );
    assert!(html.contains(r#"class="alert alert-danger""#), "{html}");
}

/// 削除（MFA を外す）も同じ。トークンが合わなければ認証器の画面へ戻してバナーで伝える。
#[tokio::test]
async fn the_totp_is_deleted_only_with_the_right_token() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    mount_ok(&env, "/internal/mfa/totp/delete").await;

    for token in wrong_tokens() {
        let response =
            post_with_token(&env, "/account/mfa/totp/delete", &[], token.as_deref()).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/settings/authenticators?error=csrf", env.prefix()),
            "{token:?}"
        );
    }
    assert_eq!(calls_to(&env, "/internal/mfa/totp/delete").await, 0);

    let response = post_with_token(&env, "/account/mfa/totp/delete", &[], Some(&csrf())).await;
    assert_eq!(
        location(&response),
        format!(
            "{}/settings/authenticators?saved=totp-deleted",
            env.prefix()
        )
    );
    assert_eq!(calls_to(&env, "/internal/mfa/totp/delete").await, 1);
}
