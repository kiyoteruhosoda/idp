//! Integration test that the 2 keys deciding the verdict itself apply per tenant (ADR-0058 §4, §10).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test tenant_decision_settings
//!
//! What is verified (each checked by **putting different values in 2 tenants**; with only 1 tenant it
//! would pass even when reading the global value):
//! - `AUTH_POLICY_DEFAULT_EFFECT`: when no policy matches, the `deny` tenant refuses the login and
//!   the `allow` tenant lets it through. The admin API list returns each tenant's value
//! - `APPLICATION_ASSIGNMENT_ENFORCEMENT`: a person without an assignment is refused by the `enforce`
//!   tenant and let through with only a record by the `record_only` tenant. The admin API app list returns each value
//!
//! ⚠ Values go only into the `tenant_settings` of **tenants created for this test**. The global row
//! (`system_settings`) and the root tenant are not touched, so the premises of other parallel tests stay unchanged.

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{
    admin_token, authorize_uri_openid_only, begin_login, body_json, create_plain_user, get, send,
    TestEnv, SERVICE_TOKEN, SERVICE_TOKEN_HEADER,
};

const PASSWORD: &str = "CorrectHorse9!";

/// Creates a tenant under root and inserts `settings` as that tenant's rows.
async fn tenant_with_settings(env: &TestEnv, settings: &[(&str, &str)]) -> String {
    let tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status, self_registration_enabled) \
         VALUES (?, ?, ?, 'ACTIVE', 1)",
    )
    .bind(&tenant)
    .bind(&env.root_tenant_id)
    .bind(format!("decision-settings-{}", &tenant[..8]))
    .execute(&env.pool)
    .await
    .expect("create tenant");
    for (key, value) in settings {
        sqlx::query(
            "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
             VALUES (?, ?, ?, 0)",
        )
        .bind(&tenant)
        .bind(key)
        .bind(value)
        .execute(&env.pool)
        .await
        .expect("insert tenant setting");
    }
    tenant
}

/// Creates a user via self-registration and completes email verification (so they can log in).
async fn register_verified_user(env: &TestEnv, tenant: &str) -> String {
    let username = format!("decision-{}", support::unique());
    let payload = json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": PASSWORD,
    });
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
    support::mark_email_verified(&env.pool, tenant, &username).await;
    username
}

/// Starts at `/authorize`, authenticates with a password and returns the internal auth response.
async fn log_in(env: &TestEnv, tenant: &str, client_id: &str, username: &str) -> Value {
    let auth_session = begin_login(
        &env.app,
        tenant,
        &authorize_uri_openid_only(tenant, client_id),
    )
    .await;
    let csrf = assay_api::application::login::csrf_token(&auth_session, &env.csrf_secret);
    let body = json!({
        "tenant_id": tenant,
        "auth_session_id": auth_session,
        "username": username,
        "password": PASSWORD,
        "csrf_token": csrf,
    });
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/internal/authenticate")
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "internal authenticate");
    body_json(response).await
}

/// Admin token of that tenant's administrator.
async fn tenant_admin_token(env: &TestEnv, tenant: &str) -> String {
    let admin = create_plain_user(&env.pool, tenant).await;
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, ?, ?)",
    )
    .bind(&admin)
    .bind("idp.tenant.admin")
    .bind(tenant)
    .execute(&env.pool)
    .await
    .expect("grant idp.tenant.admin");
    admin_token(&env.app, &env.pool, tenant, &admin).await
}

async fn get_json(env: &TestEnv, token: &str, uri: &str) -> Value {
    let response = send(&env.app, get(token, uri)).await;
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    body_json(response).await
}

/// `result` of the assignment decision audit row (`application.access_denied`).
async fn access_denied_results(pool: &MySqlPool, tenant: &str) -> Vec<String> {
    sqlx::query(
        "SELECT result FROM audit_log WHERE tenant_id = ? AND event_type = 'application.access_denied' \
         ORDER BY occurred_at",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
    .expect("read audit")
    .iter()
    .map(|row| row.get::<String, _>("result"))
    .collect()
}

#[tokio::test]
async fn each_tenant_decides_what_happens_when_no_policy_matches() {
    let Some(env) = support::setup("tenant policy default effect").await else {
        return;
    };
    let strict = tenant_with_settings(&env, &[("AUTH_POLICY_DEFAULT_EFFECT", "deny")]).await;
    let lenient = tenant_with_settings(&env, &[("AUTH_POLICY_DEFAULT_EFFECT", "allow")]).await;

    // Neither tenant has any policy; only the default effect separates the outcomes.
    for (tenant, expected) in [(&strict, "policy_denied"), (&lenient, "success")] {
        let client_id = support::insert_public_client(&env.pool, tenant, &["openid"]).await;
        let username = register_verified_user(&env, tenant).await;
        let body = log_in(&env, tenant, &client_id, &username).await;
        assert_eq!(body["result"], expected, "tenant {tenant}: {body}");
    }

    // The values the admin console renders are also that tenant's (web holds no values).
    for (tenant, expected) in [(&strict, "deny"), (&lenient, "allow")] {
        let token = tenant_admin_token(&env, tenant).await;
        let listed = get_json(
            &env,
            &token,
            &format!("/{tenant}/admin/authentication-policies"),
        )
        .await;
        assert_eq!(
            listed["default_effect"], expected,
            "tenant {tenant}: {listed}"
        );
    }
}

#[tokio::test]
async fn each_tenant_decides_whether_to_enforce_application_assignments() {
    let Some(env) = support::setup("tenant assignment enforcement").await else {
        return;
    };
    let enforcing =
        tenant_with_settings(&env, &[("APPLICATION_ASSIGNMENT_ENFORCEMENT", "enforce")]).await;
    let recording = tenant_with_settings(
        &env,
        &[("APPLICATION_ASSIGNMENT_ENFORCEMENT", "record_only")],
    )
    .await;

    // An app with "individual" assignment, and the user is not on its roster.
    for (tenant, expected, audited) in [
        (&enforcing, "application_not_permitted", "failure"),
        (&recording, "success", "success"),
    ] {
        let client_id = support::insert_public_client(&env.pool, tenant, &["openid"]).await;
        let application_id =
            support::open_client_as_application(&env.pool, tenant, &client_id).await;
        sqlx::query("UPDATE applications SET assignment_mode = 'INDIVIDUAL' WHERE id = ?")
            .bind(&application_id)
            .execute(&env.pool)
            .await
            .expect("make the application individual");
        let username = register_verified_user(&env, tenant).await;

        let body = log_in(&env, tenant, &client_id, &username).await;
        assert_eq!(body["result"], expected, "tenant {tenant}: {body}");
        assert_eq!(
            access_denied_results(&env.pool, tenant).await,
            vec![audited.to_string()],
            "tenant {tenant}"
        );
    }

    for (tenant, expected) in [(&enforcing, "enforce"), (&recording, "record_only")] {
        let token = tenant_admin_token(&env, tenant).await;
        let listed = get_json(&env, &token, &format!("/{tenant}/admin/applications")).await;
        assert_eq!(listed["enforcement"], expected, "tenant {tenant}: {listed}");
    }
}

/// When an app without permission is requested with `prompt=none`, return to the RP with `access_denied`
/// without showing a screen (task #648). Without `prompt`, assay's screen refuses as before.
#[tokio::test]
async fn prompt_none_returns_access_denied_for_an_unassigned_application() {
    let Some(env) = support::setup("prompt=none unassigned application").await else {
        return;
    };
    let tenant =
        tenant_with_settings(&env, &[("APPLICATION_ASSIGNMENT_ENFORCEMENT", "enforce")]).await;
    let client_id = support::insert_public_client(&env.pool, &tenant, &["openid"]).await;
    let application_id = support::open_client_as_application(&env.pool, &tenant, &client_id).await;
    sqlx::query("UPDATE applications SET assignment_mode = 'INDIVIDUAL' WHERE id = ?")
        .bind(&application_id)
        .execute(&env.pool)
        .await
        .expect("make the application individual");
    let user_id = create_plain_user(&env.pool, &tenant).await;
    let sso_cookie = support::create_sso_session(&env.pool, &user_id).await;

    for (prompt, expected) in [
        ("&prompt=none", "error_redirect"),
        ("", "application_not_permitted"),
    ] {
        let response = send(
            &env.app,
            Request::builder()
                .uri(format!(
                    "{}{prompt}",
                    authorize_uri_openid_only(&tenant, &client_id)
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND, "handoff ({prompt})");
        let handle = support::handoff_handle(&response);
        let body = support::resume_authorize(&env.app, &tenant, &handle, Some(&sso_cookie)).await;
        assert_eq!(body["result"], expected, "{prompt}: {body}");
        if expected == "error_redirect" {
            let callback = body["redirect_to"].as_str().expect("redirect_to");
            assert_eq!(
                support::query_param(callback, "error").as_deref(),
                Some("access_denied"),
                "{callback}"
            );
        }
    }
}
