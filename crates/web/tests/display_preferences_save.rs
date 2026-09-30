//! 表示設定（言語・配色）の保存は POST + CSRF だけ（task #79）。
//!
//! 以前は `?lang=` / `?theme=` を付けた**どの GET でも**、ログイン中ならユーザー設定
//! （`users.language` / `users.theme`）へ保存していた。SSO Cookie は `SameSite=Lax` なので
//! 外部のリンクや RP のログイン導線（トップレベル遷移）にも載り、他人のリンクで保存済みの設定を
//! 書き換えられた。いまは GET は一時切替（その画面の表示と Cookie）だけで、保存は
//! `POST /{tenant_id}/settings/display`（CSRF トークン付き）に限る。
//!
//! web は DB を持たない（保存は api の `/internal/account/update-*` 越し）ので、「DB へ保存
//! されない」は「api の保存口が呼ばれない」で確かめる。

mod support;

use assay_contracts::cookies::{AUTH_SESSION_COOKIE, SSO_SESSION_COOKIE};
use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_text, get, get_with_cookies, location, post_form, send, set_cookie, setup, WebEnv,
    TEST_CSRF_SECRET,
};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, ResponseTemplate};

const UPDATE_LANGUAGE: &str = "/internal/account/update-language";
const UPDATE_THEME: &str = "/internal/account/update-theme";
const PROFILE: &str = "/internal/account/profile";

fn sso() -> String {
    "s".repeat(64)
}

fn sso_cookie() -> String {
    format!("{SSO_SESSION_COOKIE}={}", sso())
}

/// この SSO セッションのフォームに埋まる CSRF トークン。
fn csrf() -> String {
    assay_web::csrf::console_csrf_token(&sso(), TEST_CSRF_SECRET)
}

/// ログイン中の利用者（日本語・ライトを保存済み）と、表示設定の保存口のスタブ。
async fn mount_signed_in_user(env: &WebEnv) {
    Mock::given(method("POST"))
        .and(path(PROFILE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "name": "表示 花子",
            "preferred_username": "display-hanako",
            "email": "hanako@example.com",
            "language": "ja",
            "theme": "light"
        })))
        .mount(&env.api)
        .await;
    for update in [UPDATE_LANGUAGE, UPDATE_THEME] {
        Mock::given(method("POST"))
            .and(path(update))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
            .mount(&env.api)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/internal/external/providers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "providers": []
        })))
        .mount(&env.api)
        .await;
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

// ── GET は一時切替だけ ────────────────────────────────────────────────────────

/// **外部のリンク（`?lang=` / `?theme=` 付きの GET）では保存されない。** 以前はログイン中なら
/// どの画面でも保存していた（この試験は修正前に落ちる）。画面の表示と Cookie には効く。
#[tokio::test]
async fn a_get_with_lang_or_theme_does_not_save_the_users_settings() {
    let env = setup().await;
    mount_signed_in_user(&env).await;

    for screen in ["/settings", "/login", "/settings/security"] {
        let response = send(
            &env.app,
            get_with_cookies(
                &format!("{}{screen}?lang=en&theme=dark", env.prefix()),
                &sso_cookie(),
            ),
        )
        .await;
        // 一時切替として Cookie には書く（その端末のこの後の未ログイン画面にも効く）。
        assert_eq!(
            set_cookie(&response, "lang").as_deref(),
            Some("en"),
            "{screen}"
        );
        assert_eq!(
            set_cookie(&response, "theme").as_deref(),
            Some("dark"),
            "{screen}"
        );
    }
    assert_eq!(
        calls_to(&env, UPDATE_LANGUAGE).await,
        0,
        "a GET ?lang= must not reach users.language"
    );
    assert_eq!(
        calls_to(&env, UPDATE_THEME).await,
        0,
        "a GET ?theme= must not reach users.theme"
    );
}

/// 一時切替はその画面の表示にも効く（設定画面は英語で描かれ、配色のセレクタも切替後を指す）。
#[tokio::test]
async fn a_get_with_lang_still_switches_the_screen_temporarily() {
    let env = setup().await;
    mount_signed_in_user(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings?lang=en&theme=dark", env.prefix()),
            &sso_cookie(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains(r#"<html lang="en">"#), "{html}");
    assert!(html.contains(r#"<option value="en" selected>"#), "{html}");
    assert!(html.contains(r#"<option value="dark" selected>"#), "{html}");
}

/// **未ログインの一時切替は Cookie だけで働く。** api の保存口もプロフィールも呼ばない。
#[tokio::test]
async fn a_signed_out_visitor_switches_with_the_cookie_only() {
    let env = setup().await;
    mount_signed_in_user(&env).await;

    let response = send(&env.app, get(&format!("{}/login?lang=en", env.prefix()))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(set_cookie(&response, "lang").as_deref(), Some("en"));
    let html = body_text(response).await;
    assert!(html.contains(r#"<html lang="en">"#), "{html}");

    // 次の画面は `?lang=` 無しでも Cookie で英語のまま。
    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/login", env.prefix()), "lang=en"),
    )
    .await;
    assert!(set_cookie(&response, "lang").is_none(), "no rewrite");
    let html = body_text(response).await;
    assert!(html.contains(r#"<html lang="en">"#), "{html}");

    assert_eq!(calls_to(&env, UPDATE_LANGUAGE).await, 0);
    assert_eq!(calls_to(&env, PROFILE).await, 0);
}

/// **`ui_locales` の採用は Cookie に残さない**（RP の希望を利用者の選択として残さない）。
/// 画面は RP の要求した英語で描くが、`lang` Cookie も保存口も触らない。
#[tokio::test]
async fn ui_locales_is_not_kept_in_the_cookie() {
    let env = setup().await;
    mount_signed_in_user(&env).await;
    Mock::given(method("POST"))
        .and(path("/internal/authorize/login-context"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "ok",
            "login_hint": null,
            "ui_locales": "en",
            "redirect_uri": "https://rp.example.com/cb",
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/login", env.prefix()),
            &format!("{AUTH_SESSION_COOKIE}={}", "a".repeat(64)),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        set_cookie(&response, "lang").is_none(),
        "ui_locales must not be written to the lang cookie"
    );
    let html = body_text(response).await;
    assert!(html.contains(r#"<html lang="en">"#), "{html}");
    assert_eq!(calls_to(&env, UPDATE_LANGUAGE).await, 0);
}

// ── 保存は POST + CSRF ───────────────────────────────────────────────────────

/// 正しいトークンの POST は保存し（別端末へ追随する）、Cookie も揃えて元の画面へ 303 で戻す。
/// 戻り先に残っていた一時切替（`lang` / `theme`）は落とす。
#[tokio::test]
async fn a_post_with_the_right_token_saves_the_language_and_returns() {
    let env = setup().await;
    mount_signed_in_user(&env).await;
    let back = format!("{}/admin/clients?page=2&lang=ja", env.prefix());

    let response = send(
        &env.app,
        post_form(
            &format!("{}/settings/display", env.prefix()),
            Some(&sso_cookie()),
            &[
                ("lang", "en"),
                ("csrf_token", &csrf()),
                ("return_to", &back),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/admin/clients?page=2", env.prefix())
    );
    assert_eq!(set_cookie(&response, "lang").as_deref(), Some("en"));

    let saved = env
        .api
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == UPDATE_LANGUAGE)
        .collect::<Vec<_>>();
    assert_eq!(saved.len(), 1, "saved once");
    let body: serde_json::Value = serde_json::from_slice(&saved[0].body).unwrap();
    assert_eq!(body["language"], "en");
    assert_eq!(body["sso_session_id"], sso());
    assert_eq!(calls_to(&env, UPDATE_THEME).await, 0, "theme was not sent");
}

/// 配色も同じ。設定画面から送れば設定画面へ戻る（管理コンソール発の文脈も保つ）。
#[tokio::test]
async fn a_post_with_the_right_token_saves_the_theme() {
    let env = setup().await;
    mount_signed_in_user(&env).await;
    Mock::given(method("POST"))
        .and(path(UPDATE_THEME))
        .and(body_partial_json(json!({ "theme": "dark" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "result": "ok" })))
        .expect(1)
        .with_priority(1)
        .mount(&env.api)
        .await;
    let back = format!("{}/settings?from=admin", env.prefix());

    let response = send(
        &env.app,
        post_form(
            &format!("{}/settings/display", env.prefix()),
            Some(&sso_cookie()),
            &[
                ("theme", "dark"),
                ("csrf_token", &csrf()),
                ("return_to", &back),
                ("from", "admin"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), back);
    assert_eq!(set_cookie(&response, "theme").as_deref(), Some("dark"));
    assert_eq!(calls_to(&env, UPDATE_LANGUAGE).await, 0);
}

/// **トークンが無い・合わない POST は保存しない。** 設定画面へ戻してバナーで伝える。
#[tokio::test]
async fn a_post_without_the_right_token_saves_nothing() {
    let env = setup().await;
    mount_signed_in_user(&env).await;
    let other_session = assay_web::csrf::console_csrf_token("another-session", TEST_CSRF_SECRET);

    for token in [
        None,
        Some(String::new()),
        Some("0".repeat(64)),
        Some(other_session),
    ] {
        let mut fields = vec![("lang", "en".to_string()), ("theme", "dark".to_string())];
        if let Some(token) = &token {
            fields.push(("csrf_token", token.clone()));
        }
        let fields: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let response = send(
            &env.app,
            post_form(
                &format!("{}/settings/display", env.prefix()),
                Some(&sso_cookie()),
                &fields,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{token:?}");
        assert_eq!(
            location(&response),
            format!("{}/settings?error=csrf", env.prefix()),
            "{token:?}"
        );
        assert!(set_cookie(&response, "lang").is_none(), "{token:?}");
        // 配色 Cookie は保存済みの値（light）へ揃うことはあっても（middleware が DB に追いつく）、
        // 送られた値にはならない。
        assert_ne!(
            set_cookie(&response, "theme").as_deref(),
            Some("dark"),
            "{token:?}"
        );
    }
    assert_eq!(calls_to(&env, UPDATE_LANGUAGE).await, 0);
    assert_eq!(calls_to(&env, UPDATE_THEME).await, 0);

    // バナーが出る。
    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/settings?error=csrf", env.prefix()),
            &sso_cookie(),
        ),
    )
    .await;
    let html = body_text(response).await;
    assert!(html.contains(r#"class="alert alert-danger""#), "{html}");
}

/// 戻り先は**このテナント配下のパスだけ**（オープンリダイレクトにしない）。外れたら設定画面。
#[tokio::test]
async fn the_return_path_is_restricted_to_this_tenant() {
    let env = setup().await;
    mount_signed_in_user(&env).await;

    for back in [
        "https://evil.example.com/",
        "//evil.example.com/",
        "/another-tenant/admin",
        "",
    ] {
        let response = send(
            &env.app,
            post_form(
                &format!("{}/settings/display", env.prefix()),
                Some(&sso_cookie()),
                &[("lang", "en"), ("csrf_token", &csrf()), ("return_to", back)],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{back}");
        assert_eq!(
            location(&response),
            format!("{}/settings", env.prefix()),
            "{back}"
        );
    }
}

/// 未ログインの POST はログインへ送る（保存先が無い）。
#[tokio::test]
async fn a_post_without_a_session_goes_to_sign_in() {
    let env = setup().await;
    mount_signed_in_user(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/settings/display", env.prefix()),
            None,
            &[("lang", "en"), ("csrf_token", &csrf())],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), format!("{}/login", env.prefix()));
    assert_eq!(calls_to(&env, UPDATE_LANGUAGE).await, 0);
}

// ── 画面のフォーム ────────────────────────────────────────────────────────────

/// 設定画面の言語・配色のセレクタは、CSRF トークン付きで保存口へ POST する（GET ではない）。
#[tokio::test]
async fn the_settings_page_posts_the_display_preferences_with_a_token() {
    let env = setup().await;
    mount_signed_in_user(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/settings", env.prefix()), &sso_cookie()),
    )
    .await;
    let html = body_text(response).await;
    let action = format!(
        r#"<form method="post" action="{}/settings/display""#,
        env.prefix()
    );
    assert_eq!(
        html.matches(&action).count(),
        2,
        "language and theme: {html}"
    );
    assert!(!html.contains(r#"<form method="get""#), "{html}");
    // 表示名・パスワード・言語・配色・ログアウトの 5 つのフォームすべてにトークン（task #118・
    // #143 と共通）。
    assert_eq!(
        html.matches(&format!(
            r#"<input type="hidden" name="csrf_token" value="{}">"#,
            csrf()
        ))
        .count(),
        5,
        "{html}"
    );
}
