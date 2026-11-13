//! Behavior follows the tenant's settings (ADR-0058, #109).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test tenant_settings_consumers
//!
//! ⚠ **Every test uses 2 or more tenants with different values.** With only 1 tenant it would pass
//! even when reading the global value. It also checks that **a tenant without rows follows the global value**.
//!
//! Rows are inserted directly into `tenant_settings` (the write route comes in a separate task). Tenants are
//! created fresh each time, so no stale value remains in the resolver's cache.

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{
    body_json, mark_email_verified, post_internal, register_user, send, unique, TestEnv,
    SERVICE_TOKEN,
};

/// Creates a tenant with self-registration enabled.
async fn create_tenant(env: &TestEnv, label: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, self_registration_enabled) \
         VALUES (?, ?, ?, 1)",
    )
    .bind(&id)
    .bind(&env.root_tenant_id)
    .bind(format!("{label}-{}", unique()))
    .execute(&env.pool)
    .await
    .expect("create tenant");
    id
}

/// Inserts a tenant row (override for that tenant).
async fn set_tenant_setting(env: &TestEnv, tenant_id: &str, key: &str, value: &str) {
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
         VALUES (?, ?, ?, 0)",
    )
    .bind(tenant_id)
    .bind(key)
    .bind(value)
    .execute(&env.pool)
    .await
    .expect("insert tenant setting");
}

/// Returns the global row's (`system_settings`) value for the key if present. Used as the expectation for a tenant without rows.
async fn global_value(env: &TestEnv, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT setting_value FROM system_settings WHERE setting_key = ? AND setting_value <> ''",
    )
    .bind(key)
    .fetch_optional(&env.pool)
    .await
    .expect("read system setting")
}

async fn register(env: &TestEnv, tenant: &str, password: &str) -> StatusCode {
    let username = format!("ts{}", unique());
    let response = send(
        &env.app,
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": format!("{username}@example.com"),
                    "preferred_username": username,
                    "password": password,
                    "name": "Tenant Settings Tester",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    response.status()
}

/// Creates a verified user with a known password in home tenant `tenant`. `(user_id, username, password)`.
async fn create_user(env: &TestEnv, tenant: &str) -> (String, String, String) {
    let username = format!("ts{}", unique());
    let password = format!("tenant-settings-{}", unique());
    register_user(&env.app, tenant, &username, &password).await;
    mark_email_verified(&env.pool, tenant, &username).await;
    let user_id = support::find_user_id_by_username(&env.pool, tenant, &username)
        .await
        .expect("registered user");
    (user_id, username, password)
}

/// Tries a portal login once and returns the response JSON.
///
/// `ip` changes per attempt (per-IP rate limits are shared within the process, and tests in the same
/// binary compete for the bucket).
async fn portal_login(
    env: &TestEnv,
    tenant: &str,
    ip: &str,
    username: &str,
    password: &str,
) -> Value {
    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "username": username,
                "password": password,
                "ip_address": ip,
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

/// Minimum password length is decided by the registering tenant's value. A tenant without rows follows the global value.
#[tokio::test]
async fn self_registration_is_judged_by_the_registering_tenants_password_policy() {
    let Some(env) = support::setup("tenant settings: password policy").await else {
        return;
    };
    let strict = create_tenant(&env, "strict").await;
    let lenient = create_tenant(&env, "lenient").await;
    let follower = create_tenant(&env, "follower").await;
    set_tenant_setting(&env, &strict, "PASSWORD_MIN_LENGTH", "16").await;
    set_tenant_setting(&env, &lenient, "PASSWORD_MIN_LENGTH", "6").await;

    // 12 characters: only strict rejects.
    let twelve = "abcdefghijkl";
    assert_eq!(
        register(&env, &strict, twelve).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(register(&env, &lenient, twelve).await, StatusCode::CREATED);
    assert_eq!(register(&env, &follower, twelve).await, StatusCode::CREATED);

    // 7 characters: lenient accepts. The follower without rows follows the global minimum length.
    let seven = "abcdefg";
    assert_eq!(register(&env, &lenient, seven).await, StatusCode::CREATED);
    let global_min: usize = global_value(&env, "PASSWORD_MIN_LENGTH")
        .await
        .map(|v| v.parse().expect("numeric PASSWORD_MIN_LENGTH"))
        .unwrap_or(8);
    let expected = if seven.len() < global_min {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::CREATED
    };
    assert_eq!(register(&env, &follower, seven).await, expected);
}

/// The lockout threshold is the user's home tenant's value. ⚠ Even when a guest fails on the host tenant's
/// screen, it counts by the home tenant's value, not the host's (lock state is on the user row, managed by the home tenant).
#[tokio::test]
async fn lockout_counts_against_the_users_home_tenant_threshold() {
    let Some(env) = support::setup("tenant settings: lockout").await else {
        return;
    };
    let quick = create_tenant(&env, "quick-lock").await;
    let follower = create_tenant(&env, "follower-lock").await;
    let host = create_tenant(&env, "host-lock").await;
    set_tenant_setting(&env, &quick, "LOGIN_MAX_FAILED_ATTEMPTS", "2").await;
    // The host tenant sets a lenient value, but it does not apply to guests.
    set_tenant_setting(&env, &host, "LOGIN_MAX_FAILED_ATTEMPTS", "50").await;

    let (quick_user, quick_name, _) = create_user(&env, &quick).await;
    let (_, follower_name, _) = create_user(&env, &follower).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&host)
    .bind(&quick_user)
    .execute(&env.pool)
    .await
    .expect("make the quick-lock user a guest of the host");

    // quick's user: 2 failures on the host's screen -> locked at the home tenant's threshold of 2.
    let first = portal_login(&env, &host, "203.0.113.201", &quick_name, "wrong-password").await;
    assert_eq!(first["result"], "invalid_credentials", "{first}");
    let second = portal_login(&env, &host, "203.0.113.202", &quick_name, "wrong-password").await;
    assert_eq!(second["result"], "locked", "{second}");

    // User of a tenant without rows: 2 failures do not reach the global threshold (default 10).
    let global_threshold: u32 = global_value(&env, "LOGIN_MAX_FAILED_ATTEMPTS")
        .await
        .map(|v| v.parse().expect("numeric LOGIN_MAX_FAILED_ATTEMPTS"))
        .unwrap_or(10);
    if global_threshold > 2 {
        for ip in ["203.0.113.203", "203.0.113.204"] {
            let outcome = portal_login(&env, &follower, ip, &follower_name, "wrong-password").await;
            assert_eq!(outcome["result"], "invalid_credentials", "{outcome}");
        }
    }
}

/// The SSO session lifetime (the value web uses for the cookie's `Max-Age`) is the user's home tenant's value.
/// A tenant without rows follows the global value.
#[tokio::test]
async fn the_sso_cookie_lives_as_long_as_the_home_tenant_says() {
    let Some(env) = support::setup("tenant settings: sso lifetime").await else {
        return;
    };
    let short = create_tenant(&env, "short-sso").await;
    let follower = create_tenant(&env, "follower-sso").await;
    let host = create_tenant(&env, "host-sso").await;
    set_tenant_setting(&env, &short, "SSO_ABSOLUTE_TTL_SECS", "1234").await;
    set_tenant_setting(&env, &host, "SSO_ABSOLUTE_TTL_SECS", "999").await;

    let (short_user, short_name, short_password) = create_user(&env, &short).await;
    let (_, follower_name, follower_password) = create_user(&env, &follower).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&host)
    .bind(&short_user)
    .execute(&env.pool)
    .await
    .expect("make the short-sso user a guest of the host");

    let home = portal_login(&env, &short, "203.0.113.211", &short_name, &short_password).await;
    assert_eq!(home["result"], "success", "{home}");
    assert_eq!(home["sso_absolute_ttl_secs"], 1234);

    // Even entering from the host's screen, the SSO session is shared across tenants, so the home tenant's value decides.
    let as_guest = portal_login(&env, &host, "203.0.113.212", &short_name, &short_password).await;
    assert_eq!(as_guest["result"], "success", "{as_guest}");
    assert_eq!(as_guest["sso_absolute_ttl_secs"], 1234);

    let expected: u64 = global_value(&env, "SSO_ABSOLUTE_TTL_SECS")
        .await
        .map(|v| v.parse().expect("numeric SSO_ABSOLUTE_TTL_SECS"))
        .unwrap_or(86_400);
    let followed = portal_login(
        &env,
        &follower,
        "203.0.113.213",
        &follower_name,
        &follower_password,
    )
    .await;
    assert_eq!(followed["result"], "success", "{followed}");
    assert_eq!(followed["sso_absolute_ttl_secs"], expected);
}
