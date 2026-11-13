//! The "status" the user sees about themselves (task #896, ADR-0078).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test security_status
//!
//! "Status" is assembled from 8 tables. Unit tests cannot prove column names or join directions, so
//! this runs login -> device mark -> code exchange against a real DB and checks the shape handed to
//! the screen (`/internal/account/security/status`). For bound + registered, instead of producing a
//! DBSC signature, it writes the columns binding and registration write (`sso_session_contexts.key_*`, `user_devices`) directly.

mod support;

use assay_api::domain::crypto;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use support::{
    body_json, handoff_handle, post_internal, query_param, resume_authorize, send, TestEnv,
    CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

const PASSWORD: &str = "correct-horse-battery";
const DEVICE_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn unique_username() -> String {
    format!("ss{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

async fn begin(env: &TestEnv, client_id: &str) -> String {
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st&nonce=nc&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode("openid offline_access", NON_ALPHANUMERIC)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to /login");
    let handle = handoff_handle(&response);
    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], "login_required");
    body["auth_session_id"].as_str().unwrap().to_string()
}

async fn authenticate(env: &TestEnv, auth_session: &str, username: &str) -> Value {
    let csrf = assay_api::application::login::csrf_token(auth_session, &env.csrf_secret);
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
                "ip_address": "203.0.113.10",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            }),
        ),
    )
    .await;
    body_json(response).await
}

async fn code_from(env: &TestEnv, body: &Value) -> String {
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
    query_param(&callback, "code").expect("authorization code")
}

async fn status(env: &TestEnv, sso_cookie: &str) -> Value {
    let response = send(
        &env.app,
        post_internal(
            "/internal/account/security/status",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": sso_cookie,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "security status");
    body_json(response).await
}

/// **A login with neither binding nor registration reads "short, unbound, unregistered"; with both it reads "long".**
#[tokio::test]
async fn the_status_tells_a_bound_registered_session_from_a_plain_one() {
    let Some(env) = support::setup("security status").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();
    support::register_user(&env.app, &env.root_tenant_id, &username, PASSWORD).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    // 1. Log in and bind the device mark with a response that sets the cookie as web does (unregistered device).
    let auth_session = begin(&env, &client_id).await;
    let body = authenticate(&env, &auth_session, &username).await;
    let sso_cookie = body["sso_session_id"]
        .as_str()
        .expect("sso session")
        .to_string();
    let response = send(
        &env.app,
        post_internal(
            "/internal/devices/observe",
            Some(SERVICE_TOKEN),
            json!({ "sso_session_id": sso_cookie, "device_token": DEVICE_TOKEN, "country": "JP" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // 2. The app exchanges the code and holds an unbound refresh token.
    let code = code_from(&env, &body).await;
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{client_id}:{secret}"))
                ),
            )
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // 3. State with neither.
    let plain = status(&env, &sso_cookie).await;
    assert_eq!(plain["result"], "ok", "{plain}");
    let current = &plain["sessions"][0];
    assert_eq!(current["current"], true, "{plain}");
    assert_eq!(current["methods"], json!(["password"]));
    assert_eq!(current["multi_factor"], false);
    assert_eq!(current["device_identified"], true);
    assert!(current["device_name"].is_null(), "{current}");
    assert_eq!(current["country"], "JP");
    assert_eq!(current["binding"], "unbound");
    assert_eq!(current["lifetime_basis"], "unbound");
    assert!(current["key_algorithm"].is_null());
    let apps = plain["apps"].as_array().unwrap();
    let app = apps
        .iter()
        .find(|a| a["client_id"] == client_id)
        .unwrap_or_else(|| panic!("the app with a refresh token is listed: {plain}"));
    assert_eq!(app["active_refresh_tokens"], 1, "{app}");
    assert_eq!(app["dpop_bound_refresh_tokens"], 0, "{app}");
    assert!(app["last_issued_at"].is_string(), "{app}");
    assert!(
        plain["belongings"].as_array().unwrap().is_empty(),
        "{plain}"
    );
    assert!(plain["policy"]["bound_ttl_secs"].as_i64().unwrap() > 0);
    assert_eq!(plain["policy"]["device_expiry_days"], 180);
    assert_eq!(
        plain["warnings"]["unregistered_sign_ins"]["count"], 1,
        "{plain}"
    );
    assert_eq!(plain["warnings"]["session_key_mismatch"]["count"], 0);

    // 4. Write the columns binding and registration write (in place of a DBSC signature and passkey registration).
    let user_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("user id");
    let session_hash = crypto::sha256_hex(&sso_cookie);
    sqlx::query(
        "UPDATE sso_session_contexts SET key_session_identifier = ?, key_algorithm = 'ES256', \
         key_public_jwk = '{}', key_thumbprint = ?, key_bound_at = UTC_TIMESTAMP(6) \
         WHERE session_hash = ?",
    )
    .bind(uuid::Uuid::new_v4().simple().to_string())
    .bind("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
    .bind(session_hash)
    .execute(&env.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_devices (id, user_id, device_hash, name, user_agent, registered_at, last_used_at) \
         VALUES (?, ?, ?, '家の PC', 'Mozilla/5.0 (Windows NT 10.0) Chrome/141', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(crypto::sha256_hex(DEVICE_TOKEN))
    .execute(&env.pool)
    .await
    .unwrap();

    let bound = status(&env, &sso_cookie).await;
    let current = &bound["sessions"][0];
    assert_eq!(current["device_name"], "家の PC", "{current}");
    assert_eq!(current["binding"], "device_key");
    assert_eq!(current["lifetime_basis"], "bound_on_registered_device");
    assert_eq!(current["key_algorithm"], "ES256");
    assert!(current["key_bound_at"].is_string());
    let belongings = bound["belongings"].as_array().unwrap();
    assert_eq!(belongings.len(), 1, "{bound}");
    assert_eq!(belongings[0]["kind"], "device");
    assert!(belongings[0]["expires_at"].is_string());

    // 5. A finished login state cannot read it (there is no route to fetch someone else's status).
    let gone = status(&env, "not-a-session").await;
    assert_eq!(gone["result"], "session_expired", "{gone}");
}
