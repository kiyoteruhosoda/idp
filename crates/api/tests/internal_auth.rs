//! Integration tests (with DB) for the internal auth API (`/internal/authenticate*`, ADR-0007 §3, §5).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test internal_auth
//!
//! Tests the service-to-service I/F from web to api. web forwards credentials, auth_session reference and client info
//! as JSON, and api issues SSO/code and returns JSON with a `result` tag. Without the service auth token
//! (`X-Internal-Auth-Token`) it is blocked with 401.

mod support;

use assay_api::application::login::csrf_token;
use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_json, post_internal, register_user, send, CODE_CHALLENGE, REDIRECT_URI, SERVICE_TOKEN,
};

/// Starts `/authorize` and obtains an `auth_session_id` (handoff → resume; ADR-0018 decision 2).
async fn start_authorize(app: &axum::Router, tenant: &str, client_id: &str) -> String {
    let uri = format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid%20profile%20email&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
        "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
    );
    support::begin_login(app, tenant, &uri).await
}

#[tokio::test]
async fn authenticate_requires_service_token_and_issues_sso_and_code() {
    let Some(env) = support::setup("internal auth").await else {
        return;
    };
    let (app, pool, root_tenant_id, csrf_secret) =
        (env.app, env.pool, env.root_tenant_id, env.csrf_secret);

    let client_id =
        support::insert_public_client(&pool, &root_tenant_id, &["openid", "profile", "email"])
            .await;
    let username = format!("int{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let password = "correct-horse-battery";
    register_user(&app, &root_tenant_id, &username, password).await;
    support::mark_email_verified(&pool, &root_tenant_id, &username).await;

    // Without the service token, 401 (the body is never reached).
    let auth_session = start_authorize(&app, &root_tenant_id, &client_id).await;
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            None,
            json!({
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session, &csrf_secret),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "missing token");

    // A wrong token is also 401.
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some("wrong-token"),
            json!({
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session, &csrf_secret),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "wrong token");

    // CSRF mismatch (correct token but different csrf) → result=csrf_mismatch.
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": root_tenant_id,
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": "0".repeat(64),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["result"], "csrf_mismatch");

    // Happy path: authentication succeeds. The first time, profile/email are not consented, so it goes to the consent step (F3).
    // The SSO session id is issued at this point.
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": root_tenant_id,
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session, &csrf_secret),
                "ip_address": "203.0.113.7",
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "authenticate success");
    let body = body_json(response).await;
    assert_eq!(body["result"], "consent_required");
    let consent_session = body["auth_session_id"]
        .as_str()
        .expect("auth_session_id")
        .to_string();
    assert!(!body["sso_session_id"].as_str().unwrap().is_empty());
    assert!(body["sso_absolute_ttl_secs"].as_u64().unwrap() > 0);

    // Accepting consent returns a redirect with a code.
    let response = send(
        &app,
        post_internal(
            "/internal/consent/approve",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": root_tenant_id, "auth_session_id": consent_session }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "consent approve");
    let body = body_json(response).await;
    assert_eq!(body["result"], "success");
    assert!(
        body["redirect_to"]
            .as_str()
            .unwrap()
            .starts_with(REDIRECT_URI),
        "redirect_to should point at the RP: {body}"
    );

    // The SSO session is created in the DB and records the client IP forwarded from web
    // (filtered by an IP unique to this attempt so as not to interfere with other parallel tests).
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE ip_address = ?")
        .bind("203.0.113.7")
        .fetch_one(&pool)
        .await
        .expect("query sso_sessions");
    assert!(count >= 1, "an SSO session recorded with the forwarded IP");
}

#[tokio::test]
async fn admin_authenticate_rejects_unknown_user() {
    let Some(env) = support::setup("internal auth").await else {
        return;
    };
    let (app, root_tenant_id) = (env.app, env.root_tenant_id);

    // Wrong credentials (unregistered user) → result=invalid_credentials.
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate/admin",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": root_tenant_id,
                "username": format!("nobody-{}", uuid::Uuid::new_v4()),
                "password": "whatever",
                "ip_address": "203.0.113.9",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["result"], "invalid_credentials");

    // Without the service token, 401.
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate/admin",
            None,
            json!({ "username": "x", "password": "y" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Internal requests with a missing / invalid tenant_id are 400 (fail-closed; SEC4).
    for bad in [
        json!({ "username": "x", "password": "y" }),
        json!({ "tenant_id": "not-a-uuid", "username": "x", "password": "y" }),
    ] {
        let response = send(
            &app,
            post_internal("/internal/authenticate/admin", Some(SERVICE_TOKEN), bad),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "missing/invalid tenant_id -> 400"
        );
    }
}
