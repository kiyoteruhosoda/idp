//! Saving display preferences (language, color scheme) is POST + CSRF only (task #79).
//!
//! Previously **any GET** with `?lang=` / `?theme=` saved to the user settings while logged in
//! (`users.language` / `users.theme`). The SSO Cookie is `SameSite=Lax`, so it is sent on
//! external links and RP login flows (top-level navigation), letting someone else's link rewrite saved
//! settings. Now GET is only a temporary switch (that screen's display and the Cookie); saving is
//! limited to `POST /{tenant_id}/settings/display` (with a CSRF token).
//!
//! web has no DB (saving goes via the api's `/internal/account/update-*`), so "not saved to the DB"
//! is checked as "the api's save endpoint is not called".

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

/// CSRF token embedded in this SSO session's forms.
fn csrf() -> String {
    assay_web::csrf::console_csrf_token(&sso(), TEST_CSRF_SECRET)
}

/// A logged-in user (Japanese and light saved) and stubs for the display preference save endpoint.
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

/// Number of requests to the given path received by the api stub.
async fn calls_to(env: &WebEnv, target: &str) -> usize {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path() == target)
        .count()
}

// ── GET is only a temporary switch ──────────────────────────────────────────────

/// **External links (GET with `?lang=` / `?theme=`) do not save.** Previously it saved on any screen while
/// logged in (this test fails before the fix). It does affect the screen's display and the Cookie.
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
        // Written to the Cookie as a temporary switch (affects later logged-out screens on this device too).
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

/// The temporary switch also affects that screen's display (the settings screen renders in English, and the scheme selector points to the new value).
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

/// **A logged-out temporary switch works with the Cookie only.** Neither the api's save endpoint nor profile is called.
#[tokio::test]
async fn a_signed_out_visitor_switches_with_the_cookie_only() {
    let env = setup().await;
    mount_signed_in_user(&env).await;

    let response = send(&env.app, get(&format!("{}/login?lang=en", env.prefix()))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(set_cookie(&response, "lang").as_deref(), Some("en"));
    let html = body_text(response).await;
    assert!(html.contains(r#"<html lang="en">"#), "{html}");

    // The next screen stays English via the Cookie even without `?lang=`.
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

/// **Adopting `ui_locales` is not kept in the Cookie** (an RP's wish is not stored as the user's choice).
/// The screen renders in the English the RP requested, but neither the `lang` Cookie nor the save endpoint is touched.
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

// ── Saving is POST + CSRF ───────────────────────────────────────────────────────

/// A POST with the correct token saves (followed on other devices), aligns the Cookie, and returns to the original screen with 303.
/// Leftover temporary switches (`lang` / `theme`) in the return target are dropped.
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

/// Color scheme too. Submitting from the settings screen returns to it (keeping the admin-console context).
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

/// **A POST with a missing or mismatching token does not save.** Back to the settings screen with a banner.
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
        // The scheme Cookie may align to the saved value (light) (the middleware catches up with the DB),
        // but never becomes the submitted value.
        assert_ne!(
            set_cookie(&response, "theme").as_deref(),
            Some("dark"),
            "{token:?}"
        );
    }
    assert_eq!(calls_to(&env, UPDATE_LANGUAGE).await, 0);
    assert_eq!(calls_to(&env, UPDATE_THEME).await, 0);

    // The banner appears.
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

/// Return targets are **only paths under this tenant** (no open redirect). Otherwise the settings screen.
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

/// A logged-out POST goes to login (nowhere to save).
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

// ── The screen's forms ───────────────────────────────────────────────────────────

/// The settings screen's language/scheme selectors POST to the save endpoint with a CSRF token (not GET).
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
    // Language and scheme are saved together with one form (one save button).
    assert_eq!(
        html.matches(&action).count(),
        1,
        "language and theme share one form: {html}"
    );
    assert!(html.contains(r#"name="lang""#), "{html}");
    assert!(html.contains(r#"name="theme""#), "{html}");
    assert!(!html.contains(r#"<form method="get""#), "{html}");
    // Tokens in all 4 forms: display name, display (language and scheme), password, logout
    // (shared with task #118, #143).
    assert_eq!(
        html.matches(&format!(
            r#"<input type="hidden" name="csrf_token" value="{}">"#,
            csrf()
        ))
        .count(),
        4,
        "{html}"
    );
}
