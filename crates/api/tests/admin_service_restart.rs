//! Integration tests (with DB; ADR-0017) for restarting from the settings screen and the now DB-managed `ISSUER`.
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_service_restart
//!
//! What is checked:
//!
//! 1. `ISSUER` is editable from the settings screen (`DB_MANAGED` / `editable` / shared with web).
//! 2. A broken `ISSUER` cannot be saved (if it could, token validation of every RP would fail from the next start).
//! 3. Only root admins with `idp.system.admin` can request a restart.
//! 4. The request returns accepted (202) and is left in the audit log.
//!
//! **The `ISSUER` row of `system_settings` is not rewritten.** This table is an assay-wide shared table without a
//! tenant column, and test binaries run in parallel. `ISSUER` affects a wide part of `Config` (cookie Secure decision,
//! production secret fail-fast, public URLs), so rewriting it would drag in the `Config` of other tests running
//! concurrently. The save path is checked on the side that leaves the DB unchanged ("invalid values are rejected"),
//! and that DB overrides reach `Config` is pinned by a unit test in `assay-core`
//! (`config::tests::issuer_is_overridden_by_db_settings`).
//!
//! A restart request in the test only sets the `ServiceRestart` flag, and no `axum::serve` is waiting on it,
//! so the test process does not stop.

mod support;

use assay_api::config::Config;
use assay_api::domain::clock::Clock;
use assay_api::presentation::{router, state::AppState};
use axum::http::StatusCode;
use serde_json::{json, Value};
use std::sync::Arc;
use support::{admin_token, body_json, create_plain_user, get, post, put, send};

async fn start_api(pool: &sqlx::MySqlPool) -> axum::Router {
    let db_settings = assay_api::load_db_managed_settings(pool)
        .await
        .expect("load DB-managed settings");
    let config = Config::from_env_and_db_settings(&db_settings).expect("resolve api config");
    let clock: Arc<dyn Clock> = Arc::new(support::SystemClock);
    router::build(AppState::build(pool.clone(), Arc::new(config), clock))
}

async fn runtime_setting(app: &axum::Router, token: &str, tenant_id: &str, key: &str) -> Value {
    let response = send(
        app,
        get(token, &format!("/{tenant_id}/admin/system-settings")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "system settings");
    body_json(response).await["runtime_settings"]
        .as_array()
        .expect("runtime_settings array")
        .iter()
        .find(|item| item["key"] == key)
        .unwrap_or_else(|| panic!("{key} not present in runtime settings"))
        .clone()
}

#[tokio::test]
async fn issuer_is_editable_from_the_settings_screen_but_rejects_broken_values() {
    let Some(env) = support::setup("admin issuer setting").await else {
        return;
    };
    let pool = env.pool.clone();
    let admin_tok = admin_token(&env.app, &pool, &env.root_tenant_id, &env.root_admin_id).await;
    let app = start_api(&pool).await;

    // 1. It shows as a key editable from the screen (if still ENV-managed the row would show but could not be saved).
    let item = runtime_setting(&app, &admin_tok, &env.root_tenant_id, "ISSUER").await;
    assert_eq!(item["owner"], "DB_MANAGED", "{item}");
    assert_eq!(item["editable"], true, "{item}");
    assert_eq!(item["restart_required"], true, "{item}");
    assert_eq!(
        item["shared_with_web"], true,
        "web consumes it too, so the screen shows both need restarting: {item}"
    );

    // 2. Broken values cannot be saved (the DB does not change).
    for broken in ["idp.example.com", "ftp://idp.example.com", "not a url"] {
        let response = send(
            &app,
            put(
                &admin_tok,
                &format!("/{}/admin/system-settings/runtime", env.root_tenant_id),
                json!({ "key": "ISSUER", "value": broken }),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "`{broken}` must be rejected"
        );
    }
    let item = runtime_setting(&app, &admin_tok, &env.root_tenant_id, "ISSUER").await;
    assert!(
        item["db_value"].is_null(),
        "rejected values are not saved: {item}"
    );
}

#[tokio::test]
async fn restarting_requires_the_system_admin_and_is_audited() {
    let Some(env) = support::setup("admin service restart").await else {
        return;
    };
    let pool = env.pool.clone();
    let app = start_api(&pool).await;
    let path = format!("/{}/admin/restart", env.root_tenant_id);

    // Ordinary users without permission cannot request it (it brings the process down, so root only).
    let plain_user_id = create_plain_user(&pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &pool, &env.root_tenant_id, &plain_user_id).await;
    let response = send(&app, post(&plain_token, &path, json!({}))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Unauthenticated likewise.
    let response = send(&app, post("", &path, json!({}))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A root system admin is accepted (the stop happens after the response, so 202 is returned).
    let admin_tok = admin_token(&env.app, &pool, &env.root_tenant_id, &env.root_admin_id).await;
    let response = send(&app, post(&admin_tok, &path, json!({}))).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = body_json(response).await;
    assert_eq!(body["service"], "api");
    assert_eq!(body["restarting"], true);

    // It cuts off all requests, so who requested it is left in the audit log.
    let recorded: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE event_type = 'service.restart_requested' \
         AND user_id = ?",
    )
    .bind(&env.root_admin_id)
    .fetch_one(&pool)
    .await
    .expect("count audit rows");
    assert!(recorded >= 1, "restart request must be audited");
}
