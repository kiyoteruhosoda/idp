//! Changing one's own password signs out other devices and apps (ADR-0045).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test password_change_signs_out_other_devices
//!
//! Three things are checked.
//!
//! 1. **Other devices' SSO sessions are removed.** Otherwise whoever got in with the previous password
//!    stays — betraying the motive "change it because it may have leaked".
//! 2. **One's own session remains.** Calling `delete_all_for_user` would lock out the person who changed it on the spot.
//!    The reset link path may delete everything because it is the path for "someone who forgot" and
//!    has no session at hand; the situation here differs.
//! 3. **All refresh tokens are dropped.** The duplicate keys apps hold may be fetched again.
//!    The session at hand is alive, so fetching again passes through via SSO.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::json;
use sqlx::MySqlPool;
use support::{
    body_json, handoff_handle, post_internal, query_param, resume_authorize, send, TestEnv,
    CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

const PASSWORD: &str = "correct-horse-battery";
const NEW_PASSWORD: &str = "a-brand-new-passphrase-42";

fn basic_auth(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

fn unique_username() -> String {
    format!("pc{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

async fn register_user(app: &axum::Router, tenant: &str, username: &str) {
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": format!("{username}@example.com"),
                    "preferred_username": username,
                    "password": PASSWORD,
                    "name": "Password Change Tester",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
}

/// Signs in and gets the SSO cookie. When `offline_access` is requested, a refresh token is returned too.
async fn log_in(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    username: &str,
    offline: bool,
    state: &str,
) -> (String, Option<String>) {
    let scope = if offline {
        "openid offline_access"
    } else {
        "openid"
    };
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state={state}&nonce=nc&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode(scope, NON_ALPHANUMERIC)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to /login");
    let handle = handoff_handle(&response);

    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    let auth_session = body["auth_session_id"].as_str().unwrap().to_string();
    let csrf = assay_api::application::login::csrf_token(&auth_session, &env.csrf_secret);

    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "auth_session_id": auth_session,
                "username": username,
                "password": PASSWORD,
                "csrf_token": csrf,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let sso_cookie = body["sso_session_id"].as_str().unwrap().to_string();

    let callback = match body["result"].as_str() {
        Some("consent_required") => {
            let consent_session = body["auth_session_id"].as_str().unwrap().to_string();
            let response = send(
                &env.app,
                post_internal(
                    "/internal/consent/approve",
                    Some(SERVICE_TOKEN),
                    json!({
                        "tenant_id": env.root_tenant_id,
                        "auth_session_id": consent_session,
                    }),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            body_json(response).await["redirect_to"]
                .as_str()
                .unwrap()
                .to_string()
        }
        _ => body["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string(),
    };
    assert!(callback.starts_with(REDIRECT_URI));
    let code = query_param(&callback, "code").expect("authorization code");

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "token endpoint");
    let tokens = body_json(response).await;
    let refresh = tokens["refresh_token"].as_str().map(|s| s.to_string());
    (sso_cookie, refresh)
}

async fn sso_session_exists(pool: &MySqlPool, sso_cookie: &str) -> bool {
    let hash = assay_api::infrastructure::crypto::sha256_hex(sso_cookie);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE session_hash = ?")
        .bind(hash)
        .fetch_one(pool)
        .await
        .expect("count sso sessions");
    count > 0
}

async fn refresh_works(env: &TestEnv, client_id: &str, secret: &str, token: &str) -> bool {
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    response.status() == StatusCode::OK
}

#[tokio::test]
async fn changing_your_password_signs_out_other_devices_but_not_you() {
    let Some(env) = support::setup("password change signs out other devices").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();
    register_user(&env.app, &env.root_tenant_id, &username).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    // Device A: the one that will make the change (also holds a refresh token).
    let (device_a, refresh_a) = log_in(&env, &client_id, &secret, &username, true, "sa").await;
    let refresh_a = refresh_a.expect("refresh token");
    // Device B: the one left behind.
    let (device_b, _) = log_in(&env, &client_id, &secret, &username, false, "sb").await;

    assert!(sso_session_exists(&env.pool, &device_a).await);
    assert!(sso_session_exists(&env.pool, &device_b).await);
    assert!(refresh_works(&env, &client_id, &secret, &refresh_a).await);

    let response = send(
        &env.app,
        post_internal(
            "/internal/account/change-password",
            Some(SERVICE_TOKEN),
            json!({
                "sso_session_id": device_a,
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "change password");
    assert_eq!(body_json(response).await["result"], "ok");

    // 1. Other devices are signed out.
    assert!(
        !sso_session_exists(&env.pool, &device_b).await,
        "another device's session remains (whoever got in with the previous password stays)"
    );
    // 2. One's own remains (otherwise one is locked out right after the change).
    assert!(
        sso_session_exists(&env.pool, &device_a).await,
        "even the session of the person who changed it was removed"
    );
    // 3. All refresh tokens are dropped.
    assert!(
        !refresh_works(&env, &client_id, &secret, &refresh_a).await,
        "the password was changed, but the app's duplicate key still works"
    );
}
