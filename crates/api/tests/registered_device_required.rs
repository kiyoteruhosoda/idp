//! Let logins finish only from registered devices (task #916; ADR-0079).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test registered_device_required
//!
//! ⚠ The setting is enabled only for the organization this test creates (enabling it on root would make every login
//! of other tests running alongside "registration required").

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    body_json, mark_email_verified, register_user, send, unique, TestEnv, SERVICE_TOKEN,
};

const PASSWORD: &str = "correct-horse-battery";
const DEVICE_HEADER: &str = "x-assay-client-device";

async fn create_tenant(env: &TestEnv, required: bool) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, self_registration_enabled) \
         VALUES (?, ?, ?, 1)",
    )
    .bind(&id)
    .bind(&env.root_tenant_id)
    .bind(format!("rdr-{}", unique()))
    .execute(&env.pool)
    .await
    .expect("create tenant");
    if required {
        sqlx::query(
            "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
             VALUES (?, 'REGISTERED_DEVICE_REQUIRED', 'true', 0)",
        )
        .bind(&id)
        .execute(&env.pool)
        .await
        .expect("insert tenant setting");
    }
    id
}

fn device_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn internal(uri: &str, device: Option<&str>, payload: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header("x-internal-auth-token", SERVICE_TOKEN);
    if let Some(device) = device {
        builder = builder.header(DEVICE_HEADER, device);
    }
    builder.body(Body::from(payload.to_string())).unwrap()
}

async fn portal_login(env: &TestEnv, tenant: &str, username: &str, device: Option<&str>) -> Value {
    let response = send(
        &env.app,
        internal(
            "/internal/authenticate/portal",
            device,
            json!({
                "tenant_id": tenant,
                "username": username,
                "password": PASSWORD,
                "ip_address": "203.0.113.20",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/145.0",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

async fn user_id(env: &TestEnv, tenant: &str, username: &str) -> String {
    support::find_user_id_by_username(&env.pool, tenant, username)
        .await
        .expect("user")
}

async fn register_device_row(env: &TestEnv, user_id: &str, token: &str) {
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    sqlx::query(
        "INSERT INTO user_devices (id, user_id, device_hash, name, registered_at, last_used_at) \
         VALUES (?, ?, ?, 'test', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(user_id)
    .bind(hash)
    .execute(&env.pool)
    .await
    .expect("insert device");
}

async fn new_member(env: &TestEnv, tenant: &str) -> String {
    let username = format!("rd{}", unique());
    register_user(&env.app, tenant, &username, PASSWORD).await;
    mark_email_verified(&env.pool, tenant, &username).await;
    username
}

/// **On an unregistered device, no signed-in state is created even with the correct password. On a registered device it is.**
#[tokio::test]
async fn only_a_registered_device_finishes_the_sign_in() {
    let Some(env) = support::setup("registered device required").await else {
        return;
    };
    let tenant = create_tenant(&env, true).await;
    let username = new_member(&env, &tenant).await;
    let uid = user_id(&env, &tenant, &username).await;

    // No mark / an unregistered mark → only a ticket comes back, no SSO.
    for device in [None, Some(device_token())] {
        let body = portal_login(&env, &tenant, &username, device.as_deref()).await;
        assert_eq!(body["result"], "device_enrollment_required", "{body}");
        assert!(body["ticket"].as_str().is_some_and(|t| !t.is_empty()));
        assert!(body["sso_session_id"].is_null(), "{body}");
    }
    let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE user_id = ?")
        .bind(&uid)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0, "no SSO session for an unregistered device");
    let refused: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND event_type = 'login.unregistered_device_refused'",
    )
    .bind(&uid)
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(refused, 2, "both refusals are audited");

    // Registered device → sign in as before.
    let token = device_token();
    register_device_row(&env, &uid, &token).await;
    let body = portal_login(&env, &tenant, &username, Some(&token)).await;
    assert_eq!(body["result"], "success", "{body}");
    assert!(body["sso_session_id"].is_string());
}

/// **Organizations without the setting work as before (one can get in without a mark).**
#[tokio::test]
async fn an_organization_without_the_setting_signs_in_as_before() {
    let Some(env) = support::setup("registered device not required").await else {
        return;
    };
    let tenant = create_tenant(&env, false).await;
    let username = new_member(&env, &tenant).await;
    let body = portal_login(&env, &tenant, &username, None).await;
    assert_eq!(body["result"], "success", "{body}");
}

/// **The ticket opens only in the browser that issued it (device mark), and no login happens unless the passkey passes.**
#[tokio::test]
async fn the_ticket_opens_only_in_the_same_browser_and_needs_a_passkey() {
    let Some(env) = support::setup("device enrollment ticket").await else {
        return;
    };
    let tenant = create_tenant(&env, true).await;
    let username = new_member(&env, &tenant).await;
    let uid = user_id(&env, &tenant, &username).await;
    let token = device_token();
    let body = portal_login(&env, &tenant, &username, Some(&token)).await;
    let ticket = body["ticket"].as_str().expect("ticket").to_string();

    let describe = |device: String| {
        let env = &env;
        let tenant = tenant.clone();
        let ticket = ticket.clone();
        async move {
            let response = send(
                &env.app,
                internal(
                    "/internal/device-enrollment/describe",
                    Some(&device),
                    json!({ "tenant_id": tenant, "ticket": ticket }),
                ),
            )
            .await;
            body_json(response).await
        }
    };
    let same = describe(token.clone()).await;
    assert_eq!(same["result"], "ok", "{same}");
    assert_eq!(same["username"], username);
    let other = describe(device_token()).await;
    assert_eq!(
        other["result"], "ticket_invalid",
        "another browser: {other}"
    );

    // A rewritten ticket does not open.
    let response = send(
        &env.app,
        internal(
            "/internal/device-enrollment/describe",
            Some(&token),
            json!({ "tenant_id": tenant, "ticket": format!("{ticket}0") }),
        ),
    )
    .await;
    assert_eq!(body_json(response).await["result"], "ticket_invalid");

    // Completion without a passkey does not pass, and neither a device nor SSO is created.
    let response = send(
        &env.app,
        internal(
            "/internal/device-enrollment/passkey/complete",
            Some(&token),
            json!({
                "tenant_id": tenant,
                "ticket": ticket,
                "challenge_id": uuid::Uuid::new_v4().to_string(),
                "credential": {},
                "device_name": "Windows Chrome",
            }),
        ),
    )
    .await;
    assert_eq!(body_json(response).await["result"], "passkey_rejected");
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_devices WHERE user_id = ?")
        .bind(&uid)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    assert_eq!(devices, 0);
}

/// **The device header of requests coming to api directly from outside is not read** (only inside the `/internal/*` service token).
#[tokio::test]
async fn the_device_header_is_ignored_without_the_service_token() {
    let Some(env) = support::setup("device header outside").await else {
        return;
    };
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/internal/authenticate/portal")
            .header(CONTENT_TYPE, "application/json")
            .header(DEVICE_HEADER, device_token())
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
