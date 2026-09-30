//! TOTP の自己登録（`/{tenant_id}/account/mfa/totp/setup`。AP9）をルータ経由で確かめる。
//!
//! この経路には試験が 1 本も無く、本番で 500 になっていることに画面からしか気付けなかった。
//! ここで見たいのはハンドラ内の純関数ではなく、その外側 —— step-up のゲートを抜けたあとに
//! 画面が実際に描けるか。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use serde_json::json;
use support::{
    assert_status, body_text, get_with_cookies, location, post_form, send, setup, WebEnv,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "user-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

/// step-up はもう満たされている（別画面で本人確認を済ませた直後）。
async fn stub_step_up_satisfied(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "satisfied" })))
        .mount(&env.api)
        .await;
}

async fn stub_totp_setup_ok(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/setup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "totp_uri": "otpauth://totp/assay:?secret=JBSWY3DPEHPK3PXP&issuer=assay",
            "secret_base32": "JBSWY3DPEHPK3PXP",
        })))
        .mount(&env.api)
        .await;
}

/// 本人確認を済ませた利用者には、セットアップ画面（QR と生シークレット）がそのまま出る。
#[tokio::test]
async fn the_setup_page_renders_for_a_stepped_up_user() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_setup_ok(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(&response, axum::http::StatusCode::OK, "setup page");
    let html = body_text(response).await;
    assert!(html.contains("JBSWY3DPEHPK3PXP"), "{html}");
    assert!(html.contains("<svg"), "{html}");
}

/// 本人確認がまだなら、セットアップ画面ではなく本人確認へ送る（500 にはしない）。
#[tokio::test]
async fn a_user_who_has_not_verified_recently_is_sent_to_the_challenge() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/step-up/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "challenge_required",
            "second_factor_required": false,
            "passkey_available": true,
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::FOUND,
        "challenge redirect",
    );
    assert!(
        location(&response).starts_with(&format!("{}/settings/verify?", env.prefix())),
        "{}",
        location(&response)
    );
}

/// **api が内部エラーを返したときでも、利用者は戻れる。** 画面に出口が無いと、
/// ブラウザの戻る以外に手が無くなる（実際にそうなっていた）。
#[tokio::test]
async fn the_error_page_lets_the_user_get_back_to_settings() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/setup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "internal" })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "api internal error",
    );
    let prefix = env.prefix();
    let html = body_text(response).await;
    assert!(
        html.contains(&format!(r#"href="{prefix}/settings""#)),
        "戻り先のリンクが無い: {html}"
    );
}

/// **セットアップ画面から戻れる。** 設定を中断したい利用者に、ブラウザの戻る以外の出口を
/// 置く（task #82）。パスキーの画面と同じく、本文の先頭の「戻る」と左上の名乗りの両方を
/// アカウント設定へのリンクにする。
#[tokio::test]
async fn the_setup_page_links_back_to_settings() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    stub_totp_setup_ok(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            &cookies(),
        ),
    )
    .await;

    assert_status(&response, axum::http::StatusCode::OK, "setup page");
    let prefix = env.prefix();
    let html = body_text(response).await;
    assert!(
        html.contains(&format!(
            r#"<a class="navbar-brand mb-0 h1 text-decoration-none" href="{prefix}/settings""#
        )),
        "左上の名乗りがリンクになっていない: {html}"
    );
    assert!(
        html.contains(&format!(r#"<a href="{prefix}/settings">"#)),
        "本文に戻る導線が無い: {html}"
    );
}

/// **設定を終えたら、認証器の画面へ戻して結果をバナーで伝える。** 完了を行き止まりの
/// 画面で告げると、次にどこへ行けばよいかが画面に無い（task #82）。PRG にするので、
/// 再読み込みで確認コードを二重に送ることも無い。
#[tokio::test]
async fn a_confirmed_setup_returns_to_the_authenticators_page() {
    let env = setup().await;
    stub_step_up_satisfied(&env).await;
    Mock::given(method("POST"))
        .and(path("/internal/mfa/totp/confirm"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/account/mfa/totp/setup", env.prefix()),
            Some(&cookies()),
            &[("code", "123456")],
        ),
    )
    .await;

    assert_status(
        &response,
        axum::http::StatusCode::SEE_OTHER,
        "confirm redirect",
    );
    assert_eq!(
        location(&response),
        format!("{}/settings/authenticators?saved=totp", env.prefix())
    );
}
