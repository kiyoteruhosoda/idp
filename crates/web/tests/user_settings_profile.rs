//! 設定画面のプロフィール取得は 1 リクエストにつき 1 回（task #80）。
//!
//! `GET /{tenant_id}/settings` は、表示設定の middleware（言語・配色）と画面（表示名・ログイン
//! 識別子）の両方がプロフィールを要る。以前はそれぞれが `/internal/account/profile` を呼び、
//! 同じ応答を 2 回取っていた。middleware が引いた応答をリクエスト拡張で画面へ渡すので、api へ
//! 届く呼び出しは 1 回になる。ここでは api のスタブが受けた要求を数えて確かめる。

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get_with_cookies, location, send, setup, WebEnv};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const PROFILE_PATH: &str = "/internal/account/profile";

/// ログイン中の利用者のプロフィール（配色は dark を保存済み）を返すスタブ。
async fn mount_profile(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path(PROFILE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "name": "設定 太郎",
            "preferred_username": "settings-taro",
            "email": "taro@example.com",
            "language": "ja",
            "theme": "dark"
        })))
        .mount(&env.api)
        .await;
}

/// 表示設定の保存を受けるスタブ。GET の `?lang=` / `?theme=` は一時切替で保存しない
/// （task #79）ので、積んでおいて「呼ばれなかった」ことを数える。
async fn mount_preference_updates(env: &WebEnv) {
    for update in [
        "/internal/account/update-language",
        "/internal/account/update-theme",
    ] {
        Mock::given(method("POST"))
            .and(path(update))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
            .mount(&env.api)
            .await;
    }
}

/// api のスタブが受けた、指定の経路への要求の数。
async fn calls_to(env: &WebEnv, target: &str) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == target)
        .count()
}

fn sso_cookie() -> String {
    format!("{SSO_SESSION_COOKIE}={}", "s".repeat(64))
}

#[tokio::test]
async fn the_settings_page_reads_the_profile_once() {
    let env = setup().await;
    mount_profile(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/settings", env.prefix()), &sso_cookie()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;

    // 画面は middleware が引いた応答から表示名・ログイン識別子・保存済みの配色を描く。
    assert!(
        html.contains(r#"value="設定 太郎""#),
        "display name: {html}"
    );
    assert!(
        html.contains(r#"value="settings-taro""#),
        "login identifier: {html}"
    );
    assert!(
        html.contains(r#"<option value="dark" selected>"#),
        "stored theme is selected: {html}"
    );
    assert_eq!(
        calls_to(&env, PROFILE_PATH).await,
        1,
        "the middleware and the page must share one profile lookup"
    );
}

/// `?theme=` だけが明示されたときも、言語のために middleware が引いた 1 回を画面が使う。
/// セレクタはこのリクエストでも明示された値（一時切替）を示す。
#[tokio::test]
async fn choosing_a_theme_still_reads_the_profile_once() {
    let env = setup().await;
    mount_profile(&env).await;
    mount_preference_updates(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings?theme=light", env.prefix()),
            &sso_cookie(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains(r#"<option value="light" selected>"#),
        "the explicit choice is selected: {html}"
    );
    assert!(
        html.contains(r#"value="設定 太郎""#),
        "display name: {html}"
    );
    assert_eq!(calls_to(&env, PROFILE_PATH).await, 1);
    assert_eq!(
        calls_to(&env, "/internal/account/update-theme").await,
        0,
        "a GET ?theme= is a temporary switch and must not be saved (task #79)"
    );
}

/// `?lang=` と `?theme=` の両方で表示設定が決まると middleware はプロフィールを引かない。
/// そのときは画面が自分で 1 回だけ引く（表示名が空にならない）。
#[tokio::test]
async fn the_page_reads_the_profile_itself_when_the_middleware_did_not() {
    let env = setup().await;
    mount_profile(&env).await;
    mount_preference_updates(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings?lang=en&theme=light", env.prefix()),
            &sso_cookie(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains(r#"value="設定 太郎""#),
        "display name: {html}"
    );
    assert_eq!(calls_to(&env, PROFILE_PATH).await, 1);
    // 一時切替は保存しない（task #79）。
    assert_eq!(calls_to(&env, "/internal/account/update-language").await, 0);
    assert_eq!(calls_to(&env, "/internal/account/update-theme").await, 0);
}

/// **未ログインならログイン画面へ送る**（task #121）。以前は中身が空の設定画面を 200 で
/// 描いていた。認証器・セッション一覧など他のアカウント画面と同じく `{tenant}/login` へ
/// 302 し、プロフィールは引かない。
#[tokio::test]
async fn the_settings_page_sends_a_visitor_without_a_session_to_sign_in() {
    let env = setup().await;
    mount_profile(&env).await;

    let response = send(
        &env.app,
        support::get(&format!("{}/settings", env.prefix())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
    assert_eq!(calls_to(&env, PROFILE_PATH).await, 0);
}

/// 管理コンソールから開いた（`?from=admin`）ときも同じ。
#[tokio::test]
async fn the_settings_page_from_the_console_also_requires_sign_in() {
    let env = setup().await;

    let response = send(
        &env.app,
        support::get(&format!("{}/settings?from=admin", env.prefix())),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
}

/// Cookie はあってもセッションが切れていれば、他のアカウント画面と同じくログイン画面へ送る。
#[tokio::test]
async fn the_settings_page_sends_an_expired_session_to_sign_in() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path(PROFILE_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "result": "session_expired" })),
        )
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/settings", env.prefix()), &sso_cookie()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
}

/// プロフィールが引けなかった（api の内部エラー）だけなら、従来どおり欄を空にして描く
/// （表示の都合で画面を落とさない。ログインし直しても直らない）。
#[tokio::test]
async fn the_settings_page_still_renders_when_the_profile_lookup_fails() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path(PROFILE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "internal" })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/settings", env.prefix()), &sso_cookie()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}
