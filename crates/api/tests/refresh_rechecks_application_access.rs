//! On every refresh, re-check whether the user may still use the app (task #582; ADR-0054).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test refresh_rechecks_application_access
//!
//! App access used to be decided **only when issuing a code**, so even after removing a user from the app or
//! suspending the app, the refresh token they held kept producing new tokens until its lifetime (30 days by default).

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::Value;
use sqlx::MySqlPool;
use support::{body_json, create_plain_user, send, TestEnv};

/// Creates one tenant under root and sets the assignment decision to `enforce`.
/// ⚠ Does not touch the global row or the root tenant (other tests running in parallel rely on them).
async fn enforcing_tenant(pool: &MySqlPool, root_tenant_id: &str) -> String {
    let tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status, self_registration_enabled) \
         VALUES (?, ?, ?, 'ACTIVE', 0)",
    )
    .bind(&tenant)
    .bind(root_tenant_id)
    .bind(format!("refresh-assignment-{}", &tenant[..8]))
    .execute(pool)
    .await
    .expect("create tenant");
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
         VALUES (?, 'APPLICATION_ASSIGNMENT_ENFORCEMENT', 'enforce', 0)",
    )
    .bind(&tenant)
    .execute(pool)
    .await
    .expect("insert tenant setting");
    tenant
}

/// Creates an app for "only individually assigned people" and binds the client as its OIDC identity. Returns the app id.
async fn individual_application(pool: &MySqlPool, tenant: &str, client_id: &str) -> String {
    let client_row_id: String =
        sqlx::query_scalar("SELECT id FROM clients WHERE tenant_id = ? AND client_id = ?")
            .bind(tenant)
            .bind(client_id)
            .fetch_one(pool)
            .await
            .expect("the client must exist");
    let application_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO applications (id, tenant_id, display_name, status, assignment_mode) \
         VALUES (?, ?, 'Refresh Recheck', 'ACTIVE', 'INDIVIDUAL')",
    )
    .bind(&application_id)
    .bind(tenant)
    .execute(pool)
    .await
    .expect("insert application");
    sqlx::query(
        "INSERT INTO application_bindings (id, application_id, kind, client_id) \
         VALUES (?, ?, 'oidc', ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&application_id)
    .bind(&client_row_id)
    .execute(pool)
    .await
    .expect("insert oidc binding");
    application_id
}

async fn assign(pool: &MySqlPool, application_id: &str, user_id: &str) {
    sqlx::query(
        "INSERT INTO application_assignments (id, application_id, kind, user_id) \
         VALUES (?, ?, 'USER', ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(application_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("assign user");
}

/// Inserts one valid refresh token and returns the plaintext.
async fn insert_refresh_token(
    pool: &MySqlPool,
    tenant: &str,
    user_id: &str,
    client_id: &str,
) -> String {
    let plain = format!("rt-{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, client_id, scope, expires_at) \
         VALUES (?, ?, ?, ?, '[\"openid\"]', DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))",
    )
    .bind(assay_api::infrastructure::crypto::sha256_hex(&plain))
    .bind(tenant)
    .bind(user_id)
    .bind(client_id)
    .execute(pool)
    .await
    .expect("insert refresh token");
    plain
}

async fn refresh(
    env: &TestEnv,
    tenant: &str,
    client_id: &str,
    secret: &str,
    token: &str,
) -> (StatusCode, Value) {
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic}"))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    let status = res.status();
    (status, body_json(res).await)
}

async fn active_tokens(pool: &MySqlPool, user_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("count refresh tokens")
}

#[tokio::test]
async fn a_user_removed_from_the_application_can_no_longer_refresh() {
    let Some(env) = support::setup("refresh rechecks assignment").await else {
        return;
    };
    let tenant = enforcing_tenant(&env.pool, &env.root_tenant_id).await;
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &tenant, &["openid"]).await;
    let application_id = individual_application(&env.pool, &tenant, &client_id).await;
    let user_id = create_plain_user(&env.pool, &tenant).await;
    assign(&env.pool, &application_id, &user_id).await;

    // While assigned, refreshing works as before.
    let token = insert_refresh_token(&env.pool, &tenant, &user_id, &client_id).await;
    let (status, body) = refresh(&env, &tenant, &client_id, &secret, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rotated = body["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_string();

    // Remove from the app.
    sqlx::query("DELETE FROM application_assignments WHERE application_id = ? AND user_id = ?")
        .bind(&application_id)
        .bind(&user_id)
        .execute(&env.pool)
        .await
        .expect("unassign");
    let (status, body) = refresh(&env, &tenant, &client_id, &secret, &rotated).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // Tokens issued under that permission stop, whole family included.
    assert_eq!(active_tokens(&env.pool, &user_id).await, 0);
}

#[tokio::test]
async fn a_disabled_application_stops_its_refresh_tokens() {
    let Some(env) = support::setup("refresh rechecks disabled app").await else {
        return;
    };
    let tenant = enforcing_tenant(&env.pool, &env.root_tenant_id).await;
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &tenant, &["openid"]).await;
    let application_id = individual_application(&env.pool, &tenant, &client_id).await;
    let user_id = create_plain_user(&env.pool, &tenant).await;
    assign(&env.pool, &application_id, &user_id).await;
    let token = insert_refresh_token(&env.pool, &tenant, &user_id, &client_id).await;

    sqlx::query("UPDATE applications SET status = 'DISABLED' WHERE id = ?")
        .bind(&application_id)
        .execute(&env.pool)
        .await
        .expect("disable application");
    let (status, body) = refresh(&env, &tenant, &client_id, &secret, &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
}
