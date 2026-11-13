//! Integration tests (with DB) for showing "saved but not applied" (`GET /{tenant_id}/admin/system-settings`; MT27).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_pending_restart
//!
//! Runtime settings are `restart_required`; saving alone does not change the running process's behaviour.
//! If that is not visible on screen, operators wrongly conclude "I saved it but it is not fixed". What is checked:
//!
//! 1. If the startup value and the saved value match, it is not pending.
//! 2. Changing the saved value makes it pending (api has not been restarted).
//! 3. **Removing the override is pending too** (at startup the value came from the DB, so it is not back to the default yet).
//! 4. Restarting api in that state clears the pending state.
//! 5. Shared keys (`shared_with_web`) say so in the response (applying needs a web restart too).
//! 6. Leftover rows of keys whose source changed from `DbManaged` to `EnvLocked` are not pending
//!    (`EnvLocked` does not read the DB, so comparing would give a warning that never goes away after restarts).
//!
//! `system_settings` is an assay-wide shared table without a tenant column, and test binaries run in parallel.
//! Rewriting keys other tests use would make them conflict, so a key dedicated to this test
//! (`TENANT_CACHE_TTL_SECS`) is handled only inside one test function. Shared keys are checked **without
//! rewriting**, only by the presence of the flag.

mod support;

use assay_api::config::Config;
use assay_api::domain::clock::Clock;
use assay_api::presentation::{router, state::AppState};
use axum::http::StatusCode;
use serde_json::Value;
use std::sync::Arc;
use support::{admin_token, body_json, get, send};

/// Key dedicated to this test (`DB_MANAGED` / not secret / `restart_required`; not shared with web).
const KEY: &str = "TENANT_CACHE_TTL_SECS";
/// Representative shared key. Its value is not rewritten; used only to check the `shared_with_web` flag.
const SHARED_KEY: &str = "COOKIE_SECURE";
/// An `EnvLocked` key (moved from `DbManaged` in ADR-0012). Used to check leftover rows are not reported as pending.
/// `EnvLocked` does not read the DB when resolving, so inserting this row does not affect setting resolution.
const ENV_LOCKED_KEY: &str = "PUBLIC_WEB_BASE_URL";

async fn upsert_setting(pool: &sqlx::MySqlPool, key: &str, value: &str) {
    sqlx::query(
        "INSERT INTO system_settings (setting_key, setting_value, is_secret) VALUES (?, ?, 0) \
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    .expect("upsert system setting");
}

async fn delete_setting(pool: &sqlx::MySqlPool, key: &str) {
    sqlx::query("DELETE FROM system_settings WHERE setting_key = ?")
        .bind(key)
        .execute(pool)
        .await
        .expect("delete system setting");
}

/// Reproduces api's startup sequence (read DB-managed settings → resolve `Config` → assemble the router).
/// In this test, which looks at the gap between the "startup snapshot" and the current DB values, this is how a restart is expressed.
async fn start_api(pool: &sqlx::MySqlPool) -> axum::Router {
    let db_settings = assay_api::load_db_managed_settings(pool)
        .await
        .expect("load DB-managed settings");
    let config = Config::from_env_and_db_settings(&db_settings).expect("resolve api config");
    let clock: Arc<dyn Clock> = Arc::new(support::SystemClock);
    router::build(AppState::build(pool.clone(), Arc::new(config), clock))
}

/// Takes the entry for the target key out of the response the settings screen reads.
async fn runtime_setting(app: &axum::Router, token: &str, tenant_id: &str, key: &str) -> Value {
    let response = send(
        app,
        get(token, &format!("/{tenant_id}/admin/system-settings")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "system settings");
    let body = body_json(response).await;
    body["runtime_settings"]
        .as_array()
        .expect("runtime_settings array")
        .iter()
        .find(|item| item["key"] == key)
        .unwrap_or_else(|| panic!("{key} not present in runtime settings"))
        .clone()
}

#[tokio::test]
async fn saved_settings_are_reported_as_pending_until_the_api_restarts() {
    let Some(env) = support::setup("admin pending restart").await else {
        return;
    };
    let pool = env.pool.clone();
    let admin_tok = admin_token(&env.app, &pool, &env.root_tenant_id, &env.root_admin_id).await;

    // ── 1. "Start" api with the override saved → applied.
    upsert_setting(&pool, KEY, "120").await;
    let app = start_api(&pool).await;
    let item = runtime_setting(&app, &admin_tok, &env.root_tenant_id, KEY).await;
    assert_eq!(item["source"], "DB");
    assert_eq!(item["value"], "120");
    assert_eq!(item["db_value"], "120");
    assert_eq!(
        item["pending_restart"], false,
        "not pending if the startup value equals the saved value: {item}"
    );

    // ── 2. Change the saved value (api not restarted) → pending.
    upsert_setting(&pool, KEY, "300").await;
    let item = runtime_setting(&app, &admin_tok, &env.root_tenant_id, KEY).await;
    assert_eq!(
        item["value"], "120",
        "the running api keeps the startup value"
    );
    assert_eq!(item["db_value"], "300", "the saved value is new");
    assert_eq!(
        item["pending_restart"], true,
        "it is visible that saving alone has not taken effect: {item}"
    );

    // ── 3. Remove the override → **also pending** (not back to the default yet).
    delete_setting(&pool, KEY).await;
    let item = runtime_setting(&app, &admin_tok, &env.root_tenant_id, KEY).await;
    assert!(
        item["db_value"].is_null(),
        "the saved value is gone: {item}"
    );
    assert_eq!(
        item["value"], "120",
        "the running api keeps the startup value"
    );
    assert_eq!(
        item["pending_restart"], true,
        "missing the pending removal would hide \"removed but not reverted\": {item}"
    );

    // ── 4. Restarting clears it.
    let restarted = start_api(&pool).await;
    let item = runtime_setting(&restarted, &admin_tok, &env.root_tenant_id, KEY).await;
    assert_ne!(
        item["source"], "DB",
        "the DB override has been removed: {item}"
    );
    assert_eq!(
        item["pending_restart"], false,
        "a restart clears it: {item}"
    );

    // ── 5. For shared keys the response shows "a web restart is needed too" (the value is not rewritten).
    let shared = runtime_setting(&restarted, &admin_tok, &env.root_tenant_id, SHARED_KEY).await;
    assert_eq!(shared["shared_with_web"], true, "{shared}");
    let own = runtime_setting(&restarted, &admin_tok, &env.root_tenant_id, KEY).await;
    assert_eq!(own["shared_with_web"], false, "{own}");

    // ── 6. Leftover rows of keys whose source changed from `DbManaged` to `EnvLocked` are not pending.
    // `EnvLocked` does not read the DB when resolving, so `source` can never be `DB`, and comparing would keep
    // showing a warning that **never goes away after restarts**. And `editable` is false, so it cannot be cleared on screen.
    upsert_setting(&pool, ENV_LOCKED_KEY, "https://legacy.example.com").await;
    let legacy = start_api(&pool).await;
    let item = runtime_setting(&legacy, &admin_tok, &env.root_tenant_id, ENV_LOCKED_KEY).await;
    assert_ne!(
        item["source"], "DB",
        "EnvLocked does not read the DB: {item}"
    );
    assert_eq!(
        item["editable"], false,
        "confirms the key cannot be cleared on screen: {item}"
    );
    assert_eq!(
        item["pending_restart"], false,
        "leftover rows do not affect setting resolution, so they are not pending: {item}"
    );
    delete_setting(&pool, ENV_LOCKED_KEY).await;
}
