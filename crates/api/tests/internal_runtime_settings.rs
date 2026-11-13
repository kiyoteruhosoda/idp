//! Integration tests (with DB) for shared runtime settings (`GET /internal/runtime-settings`; MT26 / ADR-0013).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test internal_runtime_settings
//!
//! web has no DB, so this endpoint is the single source of DB-managed settings consumed by both api and web
//! (`COOKIE_SECURE` etc.). Five things are checked:
//!
//! 1. It is protected by the service token common to `/internal/*` (missing / mismatched is 401).
//! 2. It returns **only** DB override values of `shared_with_web` keys (api-only keys do not leak).
//! 3. **DB → api (real server) → HTTP → web's `Config`** is connected. If broken, api alone would run with
//!    new values while web keeps old ones, a silent mismatch.
//!    The reason for using web as a dev-dependency is the same as `e2e_domain_split.rs` (it does not violate
//!    the crate boundary of web not depending on sqlx).
//! 4. What is returned is **the running api's startup snapshot**, not the current value of `system_settings`
//!    (ADR-0013 §1-a). Rewriting the DB does not change the response of an api that has not restarted. If this broke,
//!    in the "saved but api not restarted" state web alone would pick up new values, causing the very mismatch
//!    this endpoint is meant to prevent.
//! 5. Removing an override (empty string) is not returned as "unset" (web falls back to its own ENV).
//!
//! `system_settings` is an assay-wide shared table without a tenant column, and test binaries run in parallel.
//! Splitting cases that rewrite the same key into several test functions would make them conflict, so they are
//! serialized into **one test function**.

mod support;

use assay_api::config::Config;
use assay_api::domain::clock::Clock;
use assay_api::presentation::{router, state::AppState};
use assay_contracts::runtime_settings::{
    SharedRuntimeSettingsResponse, SHARED_RUNTIME_SETTINGS_PATH,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::collections::HashMap;
use std::future::IntoFuture;
use std::sync::Arc;
use support::{send, SERVICE_TOKEN, SERVICE_TOKEN_HEADER};

/// Shared key this test rewrites (= a key expected to be passed to web).
const SHARED_KEYS: [&str; 3] = ["COOKIE_SECURE", "HSTS_MAX_AGE", "AUTH_SESSION_TTL_SECS"];

/// Calls the shared runtime settings API (attaches the service token only when `token` is `Some`).
fn get_shared_settings(token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(SHARED_RUNTIME_SETTINGS_PATH);
    if let Some(t) = token {
        builder = builder.header(SERVICE_TOKEN_HEADER, t);
    }
    builder.body(Body::empty()).unwrap()
}

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
/// Going through the same `assay_api::load_db_managed_settings` as production guarantees in tests too that
/// "the values api applied at startup" and the values the endpoint serves are the same.
async fn start_api(pool: &sqlx::MySqlPool) -> axum::Router {
    let db_settings = assay_api::load_db_managed_settings(pool)
        .await
        .expect("load DB-managed settings");
    let config = Config::from_env_and_db_settings(&db_settings).expect("resolve api config");
    let clock: Arc<dyn Clock> = Arc::new(support::SystemClock);
    router::build(AppState::build(pool.clone(), Arc::new(config), clock))
}

async fn fetch_settings(app: &axum::Router) -> SharedRuntimeSettingsResponse {
    let response = send(app, get_shared_settings(Some(SERVICE_TOKEN))).await;
    assert_eq!(response.status(), StatusCode::OK, "shared runtime settings");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&body).expect("decode shared runtime settings")
}

#[tokio::test]
async fn shared_runtime_settings_are_protected_scoped_and_reach_the_web_configuration() {
    let Some(env) = support::setup("internal runtime settings").await else {
        return;
    };
    let pool = env.pool.clone();

    // ── 1. Without the service token, 401 (the body is never reached).
    let response = send(&env.app, get_shared_settings(None)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "missing token");
    let response = send(&env.app, get_shared_settings(Some("wrong-token"))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "wrong token");

    // ── 2. Put shared keys into the DB and "start" api in that state.
    upsert_setting(&pool, "COOKIE_SECURE", "true").await;
    upsert_setting(&pool, "HSTS_MAX_AGE", "31536000").await;
    upsert_setting(&pool, "AUTH_SESSION_TTL_SECS", "1200").await;
    let app = start_api(&pool).await;

    let body = fetch_settings(&app).await;
    assert_eq!(
        body.settings.get("COOKIE_SECURE").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        body.settings.get("HSTS_MAX_AGE").map(String::as_str),
        Some("31536000")
    );
    assert_eq!(
        body.settings
            .get("AUTH_SESSION_TTL_SECS")
            .map(String::as_str),
        Some("1200")
    );
    // Nothing other than shared keys (api-only TTL, SMTP settings, secrets) is included. Even if other tests write
    // other keys in parallel, checking it is a subset confirms this without misses.
    for key in body.settings.keys() {
        assert!(
            SHARED_KEYS.contains(&key.as_str()),
            "only web-shared settings may be exposed, got {key}"
        );
    }

    // ── 3. Start api as a real server and follow web's startup procedure (bootstrap → fetch → re-resolve).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind api listener");
    let api_base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    // Put a value **different** from the DB in ENV, to check the DB wins. Env vars are process-shared, but
    // this binary has only this one test function, so there is no conflict.
    std::env::set_var("API_BASE_URL", &api_base);
    std::env::set_var("COOKIE_SECURE", "false");
    std::env::set_var("HSTS_MAX_AGE", "1");
    std::env::set_var("AUTH_SESSION_TTL_SECS", "60");

    let bootstrap = assay_web::config::Bootstrap::from_env().expect("bootstrap web config");
    let client = assay_web::api_client::ApiClient::new(
        bootstrap.api_base_url(),
        bootstrap.internal_service_token(),
    );
    let shared: HashMap<String, String> = client
        .fetch_shared_runtime_settings()
        .await
        .expect("fetch shared runtime settings from api");
    let web_config = assay_web::config::Config::from_env_and_shared_settings(&shared)
        .expect("resolve web config");

    assert!(web_config.cookie_secure(), "DB value must win over ENV");
    assert_eq!(web_config.hsts_max_age(), 31_536_000);
    assert_eq!(web_config.auth_session_ttl_secs(), 1_200);
    let mut applied = web_config.shared_settings_from_api().to_vec();
    applied.sort();
    assert_eq!(
        applied,
        ["AUTH_SESSION_TTL_SECS", "COOKIE_SECURE", "HSTS_MAX_AGE"],
        "web must report which keys came from the DB"
    );

    // ── 4. Rewriting the DB does not change the response of an api that has not restarted (startup snapshot).
    // If this broke, web alone could pick up new values while api still runs with old ones.
    upsert_setting(&pool, "HSTS_MAX_AGE", "63072000").await;
    let shared = client
        .fetch_shared_runtime_settings()
        .await
        .expect("refetch shared runtime settings");
    assert_eq!(
        shared.get("HSTS_MAX_AGE").map(String::as_str),
        Some("31536000"),
        "a running api must keep serving the value it started with"
    );

    // ── 5. Removing an override (empty string) becomes "unset" once api restarts → web falls back to ENV.
    upsert_setting(&pool, "HSTS_MAX_AGE", "").await;
    let restarted = start_api(&pool).await;
    let body = fetch_settings(&restarted).await;
    assert!(
        !body.settings.contains_key("HSTS_MAX_AGE"),
        "cleared overrides must be absent, not empty: {:?}",
        body.settings
    );
    let web_config = assay_web::config::Config::from_env_and_shared_settings(
        &body.settings.clone().into_iter().collect(),
    )
    .expect("resolve web config");
    assert_eq!(web_config.hsts_max_age(), 1, "falls back to the web ENV");

    for key in SHARED_KEYS {
        std::env::remove_var(key);
        delete_setting(&pool, key).await;
    }
    std::env::remove_var("API_BASE_URL");
}
