//! Integration tests (with DB) for the login screen context API (`/internal/authorize/login-context`; G12).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test authorize_login_context
//!
//! The `login_hint` / `ui_locales` received by `/authorize` are stored in the auth_session, but web cannot keep them
//! across the resume 303. Checks that web can re-read them from the `auth_session_id`, and that nothing is returned
//! for other tenants or unknown sessions (fail-closed).

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_json, post_internal, send, CODE_CHALLENGE, REDIRECT_URI_ENC, SERVICE_TOKEN};

/// Authorization request URI with `login_hint` / `ui_locales`.
fn authorize_uri(tenant: &str, client_id: &str, login_hint: &str, ui_locales: &str) -> String {
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}\
         &scope=openid&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256\
         &login_hint={login_hint}&ui_locales={ui_locales}"
    )
}

async fn login_context(app: &axum::Router, tenant: &str, auth_session_id: &str) -> Value {
    let response = send(
        app,
        post_internal(
            "/internal/authorize/login-context",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": tenant, "auth_session_id": auth_session_id }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "login-context");
    body_json(response).await
}

#[tokio::test]
async fn returns_the_hints_the_rp_sent_to_authorize() {
    let Some(env) = support::setup("authorize login context").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        // RPs also send multiple `%20`-separated tags and tags with region codes.
        &authorize_uri(
            &root_tenant_id,
            &client_id,
            "alice%40example.com",
            "fr%20en-GB",
        ),
    )
    .await;

    let body = login_context(&app, &root_tenant_id, &auth_session).await;
    assert_eq!(body["result"], "ok", "{body}");
    assert_eq!(body["login_hint"], "alice@example.com");
    assert_eq!(body["ui_locales"], "fr en-GB");
}

/// No service token is 401 (same defence in depth as other `/internal/*`).
#[tokio::test]
async fn requires_the_service_token() {
    let Some(env) = support::setup("authorize login context auth").await else {
        return;
    };
    let response = send(
        &env.app,
        post_internal(
            "/internal/authorize/login-context",
            None,
            json!({ "tenant_id": env.root_tenant_id, "auth_session_id": "whatever" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Unknown `auth_session_id` and queries from other tenants give `session_expired` (without leaking existence).
#[tokio::test]
async fn unknown_session_and_other_tenants_get_nothing() {
    let Some(env) = support::setup("authorize login context isolation").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let body = login_context(&app, &root_tenant_id, "0000000000000000").await;
    assert_eq!(body["result"], "session_expired", "{body}");

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        &authorize_uri(&root_tenant_id, &client_id, "bob", "en"),
    )
    .await;

    // From another tenant that exists, nothing can be read even though the session exists (auth_session lookup is
    // tenant-scoped). **Use an existing ACTIVE tenant** — with a fictitious UUID
    // `require_internal_tenant` rejects with 400 first and it would not test the tenant scope.
    let other_tenant = insert_active_tenant(&pool, &root_tenant_id).await;
    let body = login_context(&app, &other_tenant, &auth_session).await;
    assert_eq!(body["result"], "session_expired", "{body}");

    // A nonexistent (or disabled) tenant fails with 400 before credentials or sessions are looked at
    // (the internal API has no tenant prefix and does not go through `TenantResolver`, so
    // `require_internal_tenant` is this line of defence; ADR-0009 §7, §8).
    let response = send(
        &app,
        post_internal(
            "/internal/authorize/login-context",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": uuid::Uuid::now_v7().to_string(),
                "auth_session_id": auth_session,
            }),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "an unknown tenant must be rejected before the session is looked up"
    );
    // The reason for rejection must be **machine-distinguishable**. web maps only this code to the 404 screen and
    // other non-2xx to 502 (MT28). Distinguishing by description would break silently the moment the wording changes.
    assert_eq!(
        body_json(response).await["error"],
        assay_contracts::auth::UNKNOWN_TENANT_ERROR_CODE,
        "the web side distinguishes this rejection by its error code"
    );
}

/// Creates one ACTIVE child tenant directly (this test needs only "an existing other tenant",
/// no admins or memberships).
async fn insert_active_tenant(pool: &sqlx::MySqlPool, parent_id: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status) VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(&id)
    .bind(parent_id)
    .bind(format!("Other {}", &id[..8]))
    .execute(pool)
    .await
    .expect("insert active tenant");
    id
}

/// For RPs sending neither `login_hint` nor `ui_locales`, `ok` comes back with both `null`.
#[tokio::test]
async fn omitted_hints_are_null() {
    let Some(env) = support::setup("authorize login context empty").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        &support::authorize_uri_openid_only(&root_tenant_id, &client_id),
    )
    .await;

    let body = login_context(&app, &root_tenant_id, &auth_session).await;
    assert_eq!(body["result"], "ok", "{body}");
    assert!(body["login_hint"].is_null(), "{body}");
    assert!(body["ui_locales"].is_null(), "{body}");
}
