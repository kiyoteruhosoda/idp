//! On reopening the login screen, continue authorization from an SSO set up in another tab
//! (`POST /internal/authorize/continue`; task #643).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test authorize_continue
//!
//! The handle was consumed on first receipt, so web passes its `auth_session_id` and the SSO cookie value.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{
    authorize_uri_openid_only, begin_login, body_json, insert_public_client, post_internal,
    query_param, send, setup, REDIRECT_URI, SERVICE_TOKEN,
};

async fn continue_authorize(
    app: &axum::Router,
    tenant: &str,
    auth_session_id: &str,
    sso_session_id: Option<&str>,
) -> Value {
    let response = send(
        app,
        post_internal(
            "/internal/authorize/continue",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "auth_session_id": auth_session_id,
                "sso_session_id": sso_session_id,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "authorize continue");
    body_json(response).await
}

/// If an SSO session appears after the login screen was shown, the same authorization request returns a code.
/// A used `auth_session_id` can never be used again.
#[tokio::test]
async fn a_later_sso_session_completes_the_pending_login() {
    let Some(env) = setup("authorize continue with sso").await else {
        return;
    };
    let client_id = insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let auth_session_id = begin_login(
        &env.app,
        &env.root_tenant_id,
        &authorize_uri_openid_only(&env.root_tenant_id, &client_id),
    )
    .await;

    // Signed in in another tab (an SSO session was created).
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let sso_cookie = support::create_sso_session(&env.pool, &user_id).await;

    let body = continue_authorize(
        &env.app,
        &env.root_tenant_id,
        &auth_session_id,
        Some(&sso_cookie),
    )
    .await;
    assert_eq!(body["result"], "redirect", "{body}");
    let callback = body["redirect_to"].as_str().expect("redirect_to");
    assert!(callback.starts_with(REDIRECT_URI), "{callback}");
    assert_eq!(query_param(callback, "state").as_deref(), Some("st"));
    assert!(query_param(callback, "code").is_some(), "{callback}");

    let body = continue_authorize(
        &env.app,
        &env.root_tenant_id,
        &auth_session_id,
        Some(&sso_cookie),
    )
    .await;
    assert_eq!(body["result"], "expired_handle", "{body}");
}

/// Without an SSO session, go back to the login form with the same `auth_session_id`.
#[tokio::test]
async fn without_sso_the_login_form_stays() {
    let Some(env) = setup("authorize continue without sso").await else {
        return;
    };
    let client_id = insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let auth_session_id = begin_login(
        &env.app,
        &env.root_tenant_id,
        &authorize_uri_openid_only(&env.root_tenant_id, &client_id),
    )
    .await;

    for sso in [None, Some("not-a-session")] {
        let body = continue_authorize(&env.app, &env.root_tenant_id, &auth_session_id, sso).await;
        assert_eq!(body["result"], "login_required", "{body}");
        assert_eq!(body["auth_session_id"], auth_session_id.as_str());
    }
}

/// `prompt=login` requests re-authentication, so do not continue from another tab's SSO.
#[tokio::test]
async fn prompt_login_is_not_completed_by_another_tab() {
    let Some(env) = setup("authorize continue prompt=login").await else {
        return;
    };
    let client_id = insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let auth_session_id = begin_login(
        &env.app,
        &env.root_tenant_id,
        &format!(
            "{}&prompt=login",
            authorize_uri_openid_only(&env.root_tenant_id, &client_id)
        ),
    )
    .await;
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let sso_cookie = support::create_sso_session(&env.pool, &user_id).await;

    let body = continue_authorize(
        &env.app,
        &env.root_tenant_id,
        &auth_session_id,
        Some(&sso_cookie),
    )
    .await;
    assert_eq!(body["result"], "login_required", "{body}");
}
