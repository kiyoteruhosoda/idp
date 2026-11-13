//! Integration tests that "re-authenticating" on an authorization session leaves no previous authentication behind.
//!
//! On an authorization session awaiting consent (= authenticated), if only a password passes as another user and it
//! stops before the second stage (forced password change, MFA), that authorization session has **no completed
//! authentication of anyone** anymore. If the previous user's `auth_time` / `sid` remained, accepting consent would
//! read it as "authenticated" and issue a code to a user who has not finished the second stage.
//!
//! Runs only when `TEST_DATABASE_URL` is set.

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use support::{
    body_json, handoff_handle, resume_authorize, send, CODE_CHALLENGE, REDIRECT_URI_ENC,
    SERVICE_TOKEN, SERVICE_TOKEN_HEADER,
};

async fn internal_post(app: &axum::Router, uri: &str, body: Value) -> Value {
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    body_json(response).await
}

async fn authenticate(
    env: &support::TestEnv,
    auth_session: &str,
    username: &str,
    password: &str,
) -> Value {
    internal_post(
        &env.app,
        "/internal/authenticate",
        json!({
            "tenant_id": env.root_tenant_id,
            "auth_session_id": auth_session,
            "username": username,
            "password": password,
            "csrf_token": assay_api::application::login::csrf_token(auth_session, &env.csrf_secret),
        }),
    )
    .await
}

#[tokio::test]
async fn password_only_reauthentication_does_not_inherit_the_previous_login() {
    let Some(env) = support::setup("auth_session_reauthentication").await else {
        return;
    };
    let tenant = env.root_tenant_id.clone();
    // Request profile so the first user stops at the consent screen.
    let client_id = support::insert_public_client(&env.pool, &tenant, &["openid", "profile"]).await;

    // First user (one's own account): signs in normally and reaches awaiting consent.
    let first = format!("reauth-a-{}", support::unique());
    support::register_user(&env.app, &tenant, &first, "first-password-1").await;
    support::mark_email_verified(&env.pool, &tenant, &first).await;

    // Second user (someone whose password alone is known): put in the forced change state.
    let second = format!("reauth-b-{}", support::unique());
    support::register_user(&env.app, &tenant, &second, "second-password-1").await;
    support::mark_email_verified(&env.pool, &tenant, &second).await;
    let second_id = support::find_user_id_by_username(&env.pool, &tenant, &second)
        .await
        .expect("second user");
    support::force_password_change(&env.pool, &second_id, "second-password-1").await;

    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope=openid%20profile&state=s&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let handle = handoff_handle(&response);
    let body = resume_authorize(&env.app, &tenant, &handle, None).await;
    assert_eq!(body["result"], "login_required");
    let session = body["auth_session_id"].as_str().unwrap().to_string();

    let body = authenticate(&env, &session, &first, "first-password-1").await;
    assert_eq!(body["result"], "consent_required", "{body}");
    let session = body["auth_session_id"].as_str().unwrap().to_string();

    // On the same authorization session, pass only the password as the second user (stops before the forced change).
    let body = authenticate(&env, &session, &second, "second-password-1").await;
    assert_eq!(body["result"], "password_change_required", "{body}");
    let session = body["auth_session_id"].as_str().unwrap().to_string();

    // The consent screen is not shown either (do not show a screen whose button cannot work at a stage where consent is impossible).
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/internal/consent-info?tenant_id={tenant}&auth_session_id={session}"
            ))
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(
        body["result"], "session_expired",
        "the consent page must not be shown before authentication completes: {body}"
    );

    // ⚠ Even if consent is accepted here, no code must be issued. The second user has not finished authenticating,
    //   and the first user's authentication no longer owns this authorization session.
    let body = internal_post(
        &env.app,
        "/internal/consent/approve",
        json!({ "tenant_id": tenant, "auth_session_id": session }),
    )
    .await;
    assert_ne!(
        body["result"], "success",
        "consent must not issue a code for a login that stopped half-way: {body}"
    );
}
