//! Integration tests (with DB) for localized API error messages (MT19).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test api_i18n
//!
//! What is checked:
//!
//! 1. The response language is decided **only** by `Accept-Language` (cookies and query are ignored).
//! 2. The default is `ja`, and unsupported languages also fall back to `ja`.
//! 3. **The error code (`error`) is language-independent**; only `message` changes.
//! 4. Domain / application validation errors (`MessageKey`) are translated, and interpolated values
//!    (invalid scope names etc.) appear in the text.
//! 5. Extractor rejections (401 / 403) also come back in the same language.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{admin_token, body_json, send};

/// Builds an admin API request with `Accept-Language` (`None` means no header).
fn request(
    method: Method,
    token: &str,
    uri: &str,
    accept_language: Option<&str>,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"));
    if let Some(lang) = accept_language {
        builder = builder.header("accept-language", lang);
    }
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap()
}

#[tokio::test]
async fn error_messages_follow_accept_language_while_codes_stay_invariant() {
    let Some(env) = support::setup("api i18n").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    // Operation on an unknown user → 404 (message is `api-user-not-found`).
    let uri = format!(
        "/{}/admin/users/{}",
        env.root_tenant_id,
        uuid::Uuid::now_v7()
    );

    let cases = [
        // (Accept-Language, whether the expected language is Japanese)
        (None, true),                    // unspecified: default ja
        (Some("ja"), true),              // explicit ja
        (Some("ja-JP,en;q=0.8"), true),  // region code ignored
        (Some("fr-FR"), true),           // unsupported falls back to ja
        (Some("en"), false),             // explicit en
        (Some("en-US,ja;q=0.5"), false), // first one wins
    ];
    for (header, expect_ja) in cases {
        let res = send(
            &env.app,
            request(Method::GET, &admin_tok, &uri, header, None),
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "header={header:?}");
        let body = body_json(res).await;
        // The code is language-independent.
        assert_eq!(body["error"], "not_found", "header={header:?}");
        let message = body["message"].as_str().expect("message");
        if expect_ja {
            assert_eq!(message, "ユーザーが見つかりません。", "header={header:?}");
        } else {
            assert_eq!(message, "User not found.", "header={header:?}");
        }
    }

    // Even if the language is passed by cookie, the API ignores it (deciding the display language is web's job; CLAUDE.md "i18n").
    // Credentials are Bearer, so the cookie here is attached only to carry `lang`.
    let res = send(
        &env.app,
        Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .header(AUTHORIZATION, format!("Bearer {admin_tok}"))
            .header(COOKIE, "lang=en")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let body = body_json(res).await;
    assert_eq!(
        body["message"], "ユーザーが見つかりません。",
        "the lang cookie must not change the API's language: {body}"
    );
}

/// Domain / application validation errors (`MessageKey`) are translated with interpolated values.
#[tokio::test]
async fn validation_errors_from_the_domain_are_translated_with_their_value() {
    let Some(env) = support::setup("api i18n validation").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/clients", env.root_tenant_id);
    let body = json!({
        "app_name": "X",
        "client_type": "public",
        "redirect_uris": ["https://app.example.com/cb"],
        "scopes": ["openid", "no-such-scope"],
    });

    let res = send(
        &env.app,
        request(
            Method::POST,
            &admin_tok,
            &uri,
            Some("en"),
            Some(body.clone()),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let response = body_json(res).await;
    assert_eq!(response["error"], "invalid_request");
    let message = response["message"].as_str().expect("message");
    // The translation is shown, and the translation key does not leak as is.
    assert!(!message.starts_with("api-"), "untranslated key: {message}");
    // The interpolated value (the invalid scope name) appears in the text.
    assert!(message.contains("no-such-scope"), "{message}");
    assert!(message.contains("not supported"), "{message}");

    // Sending the same input with ja gives Japanese (same code).
    let res = send(
        &env.app,
        request(Method::POST, &admin_tok, &uri, Some("ja"), Some(body)),
    )
    .await;
    let response = body_json(res).await;
    assert_eq!(response["error"], "invalid_request");
    let message = response["message"].as_str().expect("message");
    assert!(message.contains("no-such-scope"), "{message}");
    assert!(message.contains("対応していません"), "{message}");
}

/// Extractor rejections (unauthenticated 401, insufficient permission 403) also come back in the same language.
#[tokio::test]
async fn extractor_rejections_are_translated_too() {
    let Some(env) = support::setup("api i18n rejections").await else {
        return;
    };
    let uri = format!("/{}/admin/whoami", env.root_tenant_id);

    // Unauthenticated (no token).
    for (header, expected) in [
        (Some("en"), "Sign-in is required."),
        (Some("ja"), "サインインが必要です。"),
        (None, "サインインが必要です。"),
    ] {
        let mut builder = Request::builder().method(Method::GET).uri(&uri);
        if let Some(lang) = header {
            builder = builder.header("accept-language", lang);
        }
        let res = send(&env.app, builder.body(Body::empty()).unwrap()).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(res).await;
        assert_eq!(body["error"], "unauthorized", "code is language-invariant");
        assert_eq!(body["message"], expected, "header={header:?}");
    }

    // Insufficient permission (signed in but without idp.tenant.admin).
    let plain = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    for (header, expected) in [
        ("en", "You do not have permission to perform this action."),
        ("ja", "この操作を行う権限がありません。"),
    ] {
        let res = send(
            &env.app,
            request(Method::GET, &plain_tok, &uri, Some(header), None),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body = body_json(res).await;
        assert_eq!(body["error"], "forbidden");
        assert_eq!(body["message"], expected, "header={header}");
    }
}
