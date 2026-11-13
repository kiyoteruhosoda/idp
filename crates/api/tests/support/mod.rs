//! Shared support module for integration tests (REF1).
//!
//! Each test binary pulls it in with `mod support;` (cargo builds only `.rs` files directly under `tests/`
//! as test binaries, and subdirectories can be shared as modules).
//!
//! What is gathered here:
//! - DB connection, migrations and signing key bootstrap (each only once per process, preventing
//!   seed races and multiple ACTIVE keys when several tests' setups run in parallel against a fresh DB)
//! - Building `AppState` / the router (`TestEnv`)
//! - Generating test data for SSO sessions, users and clients
//! - Request builders and response readers
#![allow(dead_code)]

use assay_api::config::Config;
use assay_api::domain::clock::Clock;
use assay_api::domain::password::PasswordHasher as _;
use assay_api::infrastructure::crypto;
use assay_api::infrastructure::password::Argon2PasswordHasher;
use assay_api::presentation::router;
use assay_api::presentation::state::AppState;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{Method, Request};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use sqlx::Row as _;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Migrations run only once per process (prevents races between parallel seed INSERTs).
static MIGRATIONS: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// Signing key bootstrap also runs only once per process (even if `insert_if_no_active` is exclusive,
/// there is no need to call it per test).
static KEY_BOOTSTRAP: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// Service token for the internal auth endpoints (`/internal/*`) (ADR-0007 §5).
/// `setup()` injects it into `INTERNAL_SERVICE_TOKEN` as a fixed value.
// 32 characters or more (`assay_contracts::deployment::INTERNAL_SERVICE_TOKEN_MIN_LEN`). SEC11.
pub const SERVICE_TOKEN: &str = "test-internal-service-token-0123456789";
pub const SERVICE_TOKEN_HEADER: &str = "x-internal-auth-token";

// Test vector from RFC 7636 Appendix B (S256).
pub const CODE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub const CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub const REDIRECT_URI: &str = "http://localhost:3000/callback";
pub const REDIRECT_URI_ENC: &str = "http%3A%2F%2Flocalhost%3A3000%2Fcallback";

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

/// An assembled test environment.
pub struct TestEnv {
    pub app: axum::Router,
    pub pool: MySqlPool,
    /// Base issuer (`config.issuer()`). The per-tenant issuer is `<issuer>/<tenant_id>`.
    pub issuer: String,
    /// Public base URL of the web screens (`config.public_web_base_url()`). The login and consent redirects of
    /// `/authorize` became based on this absolute URL in ADR-0012 §4 (by default the same origin as the issuer).
    pub public_web_base_url: String,
    /// UUID of the seeded root tenant (a fixed value, but fetched from the DB by the structure `parent_tenant_id IS NULL`).
    pub root_tenant_id: String,
    /// Internal ID of the seeded initial admin (in root, holds idp.system.admin).
    pub root_admin_id: String,
    /// CSRF HMAC key LoginService verifies with (follows CI's `CSRF_SECRET` override).
    pub csrf_secret: [u8; 32],
}

/// Default connection limit of the test pool (same as sqlx's default). Tests whose parallelism exceeds this
/// set the limit explicitly with `connect_pool_with_max_connections`.
pub const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 10;

/// Connects to the `TEST_DATABASE_URL` DB and applies migrations only once per process.
/// By default, unset fails (so CI/--check cannot skip DB tests).
/// Set `IDP_ALLOW_DB_TEST_SKIP=1` only to deliberately skip DB integration tests locally.
pub async fn connect_pool(test_name: &str) -> Option<MySqlPool> {
    connect_pool_with_max_connections(test_name, DEFAULT_POOL_MAX_CONNECTIONS).await
}

/// Environment variable preparation shared by DB tests. Done in the connect function (which every test goes
/// through), not in `setup()`, so that **every test binary gets the same values**.
///
/// - `INTERNAL_SERVICE_TOKEN`: a known value for tests hitting `/internal/*`. 32 characters or more (SEC11).
/// - `KEY_ENCRYPTION_KEY` / `CSRF_SECRET`: **only when unset**, explicitly injects the same bytes as the development
///   defaults in base64. Tests using a non-loopback host name (`e2e_domain_split`) are judged
///   production-like and cannot start with development defaults (SEC11). The effective value does not change, so
///   signing keys in the shared test DB remain decryptable from every test binary (when given by
///   environment variables, as in CI, those are respected).
fn prepare_test_env() {
    std::env::set_var("INTERNAL_SERVICE_TOKEN", SERVICE_TOKEN);
    set_env_if_unset(
        "KEY_ENCRYPTION_KEY",
        &STANDARD.encode(assay_api::config::DEV_KEY_ENCRYPTION_KEY),
    );
    set_env_if_unset(
        "CSRF_SECRET",
        &STANDARD.encode(assay_api::config::DEV_CSRF_SECRET),
    );
}

fn set_env_if_unset(key: &str, value: &str) {
    if std::env::var_os(key).is_none_or(|v| v.is_empty()) {
        std::env::set_var(key, value);
    }
}

/// Connects with an explicit connection limit (for tests that match concurrency against the pool budget).
/// If the limit is below the parallelism, work that holds a connection while proceeding (e.g. an advisory lock section) waits on acquire.
pub async fn connect_pool_with_max_connections(
    test_name: &str,
    max_connections: u32,
) -> Option<MySqlPool> {
    prepare_test_env();
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        if std::env::var("IDP_ALLOW_DB_TEST_SKIP").ok().as_deref() == Some("1") {
            eprintln!(
                "TEST_DATABASE_URL not set; intentionally skipping {test_name} integration test"
            );
            return None;
        }
        panic!("TEST_DATABASE_URL is required for {test_name} integration test; set IDP_ALLOW_DB_TEST_SKIP=1 only for local unit-only runs");
    };
    let pool = MySqlPoolOptions::new()
        .max_connections(max_connections)
        .connect(&url)
        .await
        .expect("connect to test database");
    MIGRATIONS
        .get_or_init(|| async {
            MIGRATOR.run(&pool).await.expect("run migrations");
        })
        .await;
    Some(pool)
}

/// Assembles the whole app (AppState + router). Signing keys are bootstrapped only once per process.
pub async fn setup(test_name: &str) -> Option<TestEnv> {
    setup_with(test_name, |_| {}).await
}

/// Same as `setup`, but `AppState` parts can be swapped before building the router (e.g. faking parts that
/// make outbound HTTP).
pub async fn setup_with(test_name: &str, customize: impl FnOnce(&mut AppState)) -> Option<TestEnv> {
    let pool = connect_pool(test_name).await?;

    let root_tenant_id: String =
        sqlx::query_scalar("SELECT id FROM tenants WHERE parent_tenant_id IS NULL")
            .fetch_one(&pool)
            .await
            .expect("root tenant seeded");
    let root_admin_id: String = sqlx::query_scalar(
        "SELECT id FROM users WHERE tenant_id = ? AND email = 'admin@example.com'",
    )
    .bind(&root_tenant_id)
    .fetch_one(&pool)
    .await
    .expect("initial admin seeded");

    // Self-registration is OFF by default (SEC6). Enable it on the root tenant so test flows using register work
    // (the disabled behavior is verified by register tests that explicitly switch it OFF).
    sqlx::query("UPDATE tenants SET self_registration_enabled = 1 WHERE id = ?")
        .bind(&root_tenant_id)
        .execute(&pool)
        .await
        .expect("enable self-registration for root tenant");

    let config = Arc::new(Config::from_env().expect("load config"));
    let issuer = config.issuer().to_string();
    let public_web_base_url = config.public_web_base_url().to_string();
    let csrf_secret = *config.csrf_secret();
    let mut state = AppState::build(pool.clone(), config, Arc::new(SystemClock));
    customize(&mut state);
    KEY_BOOTSTRAP
        .get_or_init(|| async {
            state
                .keys
                .ensure_active_key()
                .await
                .expect("bootstrap signing key");
        })
        .await;
    Some(TestEnv {
        app: router::build(state),
        pool,
        issuer,
        public_web_base_url,
        root_tenant_id,
        root_admin_id,
        csrf_secret,
    })
}

/// Advisory lock serializing tests that touch SMTP settings (`smtp.*` in `system_settings`) **across binaries**.
///
/// There is only one destination set for the system, not per tenant. If tests rewriting the setting run in parallel,
/// one side's mail goes to the destination the other set, and the waiting side never receives it.
///
/// ⚠ **An in-process `Mutex` is not enough.** `cargo test` runs test binaries **as separate processes in
/// parallel**, so serializing only within `password_reset` still breaks when another binary
/// (`admin_smtp_settings`) rewrites the same setting (actually hit on 2026-09-13).
/// A DB advisory lock is per connection = session, so it works across processes.
///
/// ⚠ **Not released on `Drop`** (release is async). Call `release()`. If it panics without calling it,
/// the connection closes and releases it when the process ends (other binaries wait until then).
pub struct SmtpSettingsLock {
    conn: sqlx::pool::PoolConnection<sqlx::MySql>,
}

impl SmtpSettingsLock {
    /// Waits until acquired (up to 60 seconds).
    pub async fn acquire(pool: &MySqlPool) -> Self {
        let mut conn = pool
            .acquire()
            .await
            .expect("acquire connection for smtp lock");
        let got =
            sqlx::query_scalar::<_, Option<i64>>("SELECT GET_LOCK('assay_test_smtp_settings', 60)")
                .fetch_one(&mut *conn)
                .await
                .expect("get smtp settings lock")
                .unwrap_or(0);
        assert_eq!(got, 1, "timed out waiting for the smtp settings lock");
        Self { conn }
    }

    pub async fn release(mut self) {
        let _ = sqlx::query("SELECT RELEASE_LOCK('assay_test_smtp_settings')")
            .execute(&mut *self.conn)
            .await;
    }
}

/// Saves the `smtp.*` rows as is (including the encrypted password; kept in a form that can be restored without interpreting values).
pub async fn snapshot_smtp_settings(pool: &MySqlPool) -> Vec<(String, String, bool)> {
    sqlx::query("SELECT setting_key, setting_value, is_secret FROM system_settings WHERE setting_key LIKE 'smtp.%'")
        .fetch_all(pool)
        .await
        .expect("snapshot smtp settings")
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("setting_key"),
                row.get::<String, _>("setting_value"),
                row.get::<bool, _>("is_secret"),
            )
        })
        .collect()
}

/// Restores the state saved by [`snapshot_smtp_settings`] (rows not in the snapshot are deleted).
pub async fn restore_smtp_settings(pool: &MySqlPool, snapshot: &[(String, String, bool)]) {
    sqlx::query("DELETE FROM system_settings WHERE setting_key LIKE 'smtp.%'")
        .execute(pool)
        .await
        .expect("clear smtp settings");
    for (key, value, is_secret) in snapshot {
        sqlx::query(
            "INSERT INTO system_settings (setting_key, setting_value, is_secret) VALUES (?, ?, ?)",
        )
        .bind(key)
        .bind(value)
        .bind(is_secret)
        .execute(pool)
        .await
        .expect("restore smtp setting");
    }
}

/// Marks a user created by the registration API as email-verified.
/// Existing OIDC / internal auth flow tests want to verify consent, CSRF and token issuance rather than the email
/// verification gate, so only the test data is explicitly set to verified.
///
/// ⚠ **Look up first, then update by primary key (not an UPDATE with a JOIN).** Updating while joined makes
/// this UPDATE scan `user_login_identifiers_primary_uk` taking shared locks while waiting for the exclusive lock
/// on the `users` row. A concurrent registration proceeds in the opposite order (holding the `users` row while
/// INSERTing into the registry), so **parallel runs deadlock** (observed; registration returns 500).
/// Split into 2 statements, each touches only one table, so no cycle can form.
pub async fn mark_email_verified(pool: &MySqlPool, tenant_id: &str, username: &str) {
    let user_id = find_user_id_by_username(pool, tenant_id, username)
        .await
        .expect("registered user");
    let result = sqlx::query("UPDATE users SET email_verified = 1 WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("mark email verified");
    assert_eq!(
        result.rows_affected(),
        1,
        "mark one registered user verified"
    );
}

/// Looks up a user id by the primary login identifier (username).
///
/// AP15b moved its location from `users.preferred_username` to the registry
/// (`user_login_identifiers.primary_of_user`), so tests look there too.
pub async fn find_user_id_by_username(
    pool: &MySqlPool,
    tenant_id: &str,
    username: &str,
) -> Option<String> {
    sqlx::query_scalar(
        "SELECT u.id FROM users u \
         JOIN user_login_identifiers p ON p.primary_of_user = u.id \
         WHERE u.tenant_id = ? AND p.normalized_value = ?",
    )
    .bind(tenant_id)
    .bind(username.trim().to_lowercase())
    .fetch_optional(pool)
    .await
    .expect("find user by username")
}

/// The primary login identifier (display value). `None` if unset.
pub async fn primary_username(pool: &MySqlPool, user_id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT display_value FROM user_login_identifiers WHERE primary_of_user = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .expect("read primary login identifier")
}

/// Display value of the primary email row (ADR-0050). `None` means there is no row: when the user holds the same
/// value in another row (usually the username), no primary email row is created (decision 6).
pub async fn primary_email(pool: &MySqlPool, user_id: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT display_value FROM user_login_identifiers WHERE primary_email_of_user = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .expect("read primary email identifier")
}

// ── Test data generation ─────────────────────────────────────────────────────────

/// Creates a valid SSO session for the given user and returns the plain session_id for the cookie.
pub async fn create_sso_session(pool: &MySqlPool, user_id: &str) -> String {
    let session_id = crypto::random_hex(32);
    let session_hash = crypto::sha256_hex(&session_id);
    sqlx::query(
        "INSERT INTO sso_sessions \
         (session_hash, user_id, auth_time, idle_expires_at, absolute_expires_at) \
         VALUES (?, ?, UTC_TIMESTAMP(6), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 HOUR), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 8 HOUR))",
    )
    .bind(&session_hash)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert sso session");
    session_id
}

/// Creates an SSO session, exchanges it for an **admin token** via `POST /internal/admin/token` and returns it
/// (ADR-0037). The exchange the admin console (web) does per request goes through the same path in tests.
///
/// The token is tied to `tenant_id` (`iss` / `aud` are the per-tenant issuer). Even for the same user,
/// a different tenant needs a different token.
pub async fn admin_token(
    app: &axum::Router,
    pool: &MySqlPool,
    tenant_id: &str,
    user_id: &str,
) -> String {
    let sso = create_sso_session(pool, user_id).await;
    exchange_admin_token(app, tenant_id, &sso).await
}

/// Exchanges an existing SSO session (plain session_id) for an admin token.
///
/// Tests that want to verify failures of the exchange itself (401 etc.) use `post_internal` directly. This is
/// for callers that "assume the exchange succeeds", and it panics on failure.
pub async fn exchange_admin_token(
    app: &axum::Router,
    tenant_id: &str,
    sso_session_id: &str,
) -> String {
    let response = send(
        app,
        post_internal(
            "/internal/admin/token",
            Some(SERVICE_TOKEN),
            serde_json::json!({ "tenant_id": tenant_id, "sso_session_id": sso_session_id }),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "management token exchange failed"
    );
    body_json(response)
        .await
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token in the exchange response")
        .to_string()
}

/// Creates a user without permissions directly in the given tenant and returns its internal ID.
/// Creates one user via the self-registration API (`POST /{tenant}/auth/register`).
///
/// Going through the normal creation path fills not only `users` but also the HOME membership and the login
/// identifier registry (AP8) in the same shape as production.
pub async fn register_user(app: &axum::Router, tenant: &str, username: &str, password: &str) {
    let payload = serde_json::json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": password,
        "name": "Integration Tester",
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::CREATED,
        "user registration"
    );
}

/// Sets a known password and raises `must_change_password` (creates **the forced-change state**).
///
/// ⚠ **This state cannot be created via the admin API** (ADR-0062). Admin reissue now replaces it with
/// "a value nobody knows" and hands over a link, so **hitting a forced change while knowing the value**
/// is only possible through this test route. It goes through the same hasher as the implementation (argon2).
pub async fn force_password_change(pool: &MySqlPool, user_id: &str, password: &str) {
    let hash = Argon2PasswordHasher::new()
        .hash(password)
        .expect("hash the password");
    // "Has a known password" = the user has finished setup once (not provisional; ADR-0064).
    sqlx::query(
        "UPDATE users SET password_hash = ?, must_change_password = 1, pending_setup = 0 WHERE id = ?",
    )
        .bind(hash)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("force a password change");
}

/// Removes the provisional state of a user created via the admin API (in place of the user setting credentials via the setup link; ADR-0064).
///
/// A user created via the admin API is provisional, so even an SSO session created directly cannot be exchanged
/// for an admin token (`is_active` refuses). Call this to use that person as a "usable" test actor.
pub async fn finish_setup(pool: &MySqlPool, user_id: &str) {
    sqlx::query("UPDATE users SET pending_setup = 0 WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("finish the setup");
}

pub async fn create_plain_user(pool: &MySqlPool, tenant_id: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, 'x', 'ACTIVE')",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!("plain-{}@example.com", unique()))
    .execute(pool)
    .await
    .expect("insert plain user");
    // Project the HOME membership (ACTIVE) too, as real user creation does. Granting and revoking permissions
    // requires being an ACTIVE member of the tenant (ADR-0009 §4), so without it the result is 404.
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'HOME', 'ACTIVE')",
    )
    .bind(tenant_id)
    .bind(&id)
    .execute(pool)
    .await
    .expect("insert home membership");
    id
}

/// Registers a unique public client directly in the given tenant and returns the client_id.
/// `scopes` are the allowed scopes (e.g. `&["openid"]`, `&["openid", "profile", "email"]`).
pub async fn insert_public_client(pool: &MySqlPool, tenant_id: &str, scopes: &[&str]) -> String {
    let client_id = format!("it-public-{}", unique());
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method) \
         VALUES (?, ?, ?, NULL, 'public', 'ACTIVE', 'Integration Test App', ?, \
         '[\"authorization_code\"]', '[\"code\"]', ?, 'none')",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(json!([REDIRECT_URI]).to_string())
    .bind(json!(scopes).to_string())
    .execute(pool)
    .await
    .expect("insert public client");
    client_id
}

/// Opens a directly registered client as **one app + one OIDC binding** and returns the app id
/// (ADR-0054). The same shape the migration (`0054_applications`) and registration via the admin API produce.
///
/// `insert_*_client` inserts directly into the table (not through the service), so no app comes with it. Tests
/// of an authentication policy's `application_ids` explicitly open it here and then use the id.
pub async fn open_client_as_application(
    pool: &MySqlPool,
    tenant_id: &str,
    client_id: &str,
) -> String {
    let client_row_id: String =
        sqlx::query_scalar("SELECT id FROM clients WHERE tenant_id = ? AND client_id = ?")
            .bind(tenant_id)
            .bind(client_id)
            .fetch_one(pool)
            .await
            .expect("the client must exist");
    let application_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO applications (id, tenant_id, display_name, status, assignment_mode) \
         VALUES (?, ?, ?, 'ACTIVE', 'EVERYONE')",
    )
    .bind(&application_id)
    .bind(tenant_id)
    .bind(format!("app for {client_id}"))
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
    .expect("insert application binding");
    application_id
}

/// Registers a unique confidential client directly in the given tenant and returns `(client_id, client_secret)`.
pub async fn insert_confidential_client(
    pool: &MySqlPool,
    tenant_id: &str,
    scopes: &[&str],
) -> (String, String) {
    let client_id = format!("it-conf-{}", unique());
    let secret = "e2e-super-secret-value";
    let secret_hash = Argon2PasswordHasher::new()
        .hash(secret)
        .expect("hash secret");
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method) \
         VALUES (?, ?, ?, ?, 'confidential', 'ACTIVE', 'Integration Confidential App', ?, \
         '[\"authorization_code\"]', '[\"code\"]', ?, 'client_secret_basic')",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(secret_hash)
    .bind(json!([REDIRECT_URI]).to_string())
    .bind(json!(scopes).to_string())
    .execute(pool)
    .await
    .expect("insert confidential client");
    (client_id, secret.to_string())
}

/// Registers a confidential client allowing the `client_credentials` grant and
/// returns `(client_id, client_secret)` (G4). It differs from [`insert_confidential_client`] only in
/// including `client_credentials` in `grant_types`.
pub async fn insert_m2m_client(
    pool: &MySqlPool,
    tenant_id: &str,
    scopes: &[&str],
) -> (String, String) {
    insert_m2m_client_with_auth_method(pool, tenant_id, scopes, "client_secret_basic").await
}

/// Same as [`insert_m2m_client`], but specifies the client authentication method (G3).
pub async fn insert_m2m_client_with_auth_method(
    pool: &MySqlPool,
    tenant_id: &str,
    scopes: &[&str],
    auth_method: &str,
) -> (String, String) {
    let client_id = format!("it-m2m-{}", unique());
    let secret = "e2e-super-secret-value";
    let secret_hash = Argon2PasswordHasher::new()
        .hash(secret)
        .expect("hash secret");
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method) \
         VALUES (?, ?, ?, ?, 'confidential', 'ACTIVE', 'Integration M2M App', ?, \
         '[\"authorization_code\", \"client_credentials\"]', '[\"code\"]', ?, ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(secret_hash)
    .bind(json!([REDIRECT_URI]).to_string())
    .bind(json!(scopes).to_string())
    .bind(auth_method)
    .execute(pool)
    .await
    .expect("insert m2m client");
    (client_id, secret.to_string())
}

/// Registers a service account (a confidential client using **only** `client_credentials`; ADR-0038) and
/// returns `(client_id, client_secret)`.
///
/// [`insert_m2m_client`] also has `authorization_code`, so as an app identity it is not a
/// service account (`Client::is_service_account`; ADR-0059).
pub async fn insert_service_account(pool: &MySqlPool, tenant_id: &str) -> (String, String) {
    let client_id = format!("it-svc-{}", unique());
    let secret = "e2e-super-secret-value";
    let secret_hash = Argon2PasswordHasher::new()
        .hash(secret)
        .expect("hash secret");
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method) \
         VALUES (?, ?, ?, ?, 'confidential', 'ACTIVE', 'Integration Service Account', '[]', \
         '[\"client_credentials\"]', '[]', '[]', 'client_secret_basic')",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(secret_hash)
    .execute(pool)
    .await
    .expect("insert service account");
    (client_id, secret.to_string())
}

/// Fetches an admin token with `client_credentials` + `resource={issuer}/{tenant}/admin` and returns the response
/// (the caller checks success).
pub async fn request_management_token(
    app: &axum::Router,
    issuer: &str,
    tenant_id: &str,
    client_id: &str,
    secret: &str,
) -> axum::response::Response {
    let resource = format!("{issuer}/{tenant_id}/admin");
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}"))),
            )
            .body(Body::from(format!(
                "grant_type=client_credentials&resource={}",
                percent_encoding::utf8_percent_encode(
                    &resource,
                    percent_encoding::NON_ALPHANUMERIC
                )
            )))
            .unwrap(),
    )
    .await
}

/// Creates a `private_key_jwt` M2M client and returns `(client_id, private key PEM, kid)` (ADR-0030).
///
/// No secret is issued (clients of this method hold no shared secret). A key pair is generated per test,
/// and only the public key is registered in `clients.jwks`.
pub async fn insert_private_key_jwt_client(
    pool: &MySqlPool,
    tenant_id: &str,
    scopes: &[&str],
) -> (String, String, String) {
    let client_id = format!("it-pkjwt-{}", unique());
    let kid = format!("kid-{}", unique());
    let (private_pem, public_pem) =
        assay_api::domain::jwt::generate_rsa_keypair().expect("generate keypair");
    let jwk = assay_api::domain::jwt::rsa_public_jwk(&kid, &public_pem).expect("build jwk");
    let jwks = serde_json::to_string(&assay_api::domain::jwt::Jwks { keys: vec![jwk] })
        .expect("serialize jwks");
    sqlx::query(
        "INSERT INTO clients (id, tenant_id, client_id, client_secret_hash, client_type, \
         client_status, app_name, redirect_uris, grant_types, response_types, scopes, \
         token_endpoint_auth_method, jwks) \
         VALUES (?, ?, ?, NULL, 'confidential', 'ACTIVE', 'Integration Machine App', ?, \
         '[\"authorization_code\", \"client_credentials\"]', '[\"code\"]', ?, \
         'private_key_jwt', ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(tenant_id)
    .bind(&client_id)
    .bind(json!([REDIRECT_URI]).to_string())
    .bind(json!(scopes).to_string())
    .bind(jwks)
    .execute(pool)
    .await
    .expect("insert private_key_jwt client");
    (client_id, private_pem, kid)
}

/// Makes one verification key (a JWK Set JSON string) that can be passed to the registration API.
///
/// `insert_private_key_jwt_client` is the version that inserts into the DB directly. This one is put in the
/// `jwks` field of `POST /admin/clients` to go through the registration path itself.
pub fn sample_client_jwks() -> String {
    let kid = format!("kid-{}", unique());
    let (_private_pem, public_pem) =
        assay_api::domain::jwt::generate_rsa_keypair().expect("generate keypair");
    let jwk = assay_api::domain::jwt::rsa_public_jwk(&kid, &public_pem).expect("build jwk");
    serde_json::to_string(&assay_api::domain::jwt::Jwks { keys: vec![jwk] })
        .expect("serialize jwks")
}

/// A random identifier fragment (used to make emails and names unique; 12 hex chars).
pub fn unique() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

// ── Request and response helpers ───────────────────────────────────────────

pub async fn send(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.expect("send request")
}

/// Reads the body as a string as is (non-JSON responses, such as Prometheus text format).
pub async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

pub async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Builds a request with an admin token (the JSON body is added only when `Some`).
///
/// The admin API's only credential is Bearer (ADR-0037). `token` is what [`admin_token`] got from
/// `POST /internal/admin/token`, and **differs per tenant**
/// (`iss` / `aud` are fixed to the per-tenant issuer, so carrying it to another tenant's path gives 401).
pub fn request(method: Method, token: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"));
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap()
}

pub fn get(token: &str, uri: &str) -> Request<Body> {
    request(Method::GET, token, uri, None)
}

pub fn post(token: &str, uri: &str, body: Value) -> Request<Body> {
    request(Method::POST, token, uri, Some(body))
}

/// A POST without a body (command-style endpoints such as `/unlock` and `/mfa-reset`).
pub fn post_empty(token: &str, uri: &str) -> Request<Body> {
    request(Method::POST, token, uri, None)
}

pub fn patch(token: &str, uri: &str, body: Value) -> Request<Body> {
    request(Method::PATCH, token, uri, Some(body))
}

pub fn put(token: &str, uri: &str, body: Value) -> Request<Body> {
    request(Method::PUT, token, uri, Some(body))
}

pub fn delete(token: &str, uri: &str) -> Request<Body> {
    request(Method::DELETE, token, uri, None)
}

/// A request using the SSO cookie as the credential (the `AuthenticatedUser` path; invitation acceptance).
///
/// The admin API looks only at Bearer (ADR-0037), but invitation acceptance is a browser path that only requires
/// "being logged in", and its credential is still the cookie. Keeping separate helpers makes it readable from the
/// code which path a test is hitting.
pub fn cookie_request(
    method: Method,
    sso_session_id: &str,
    uri: &str,
    body: Option<Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(COOKIE, format!("sso_session_id={sso_session_id}"));
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap()
}

pub fn cookie_post(sso_session_id: &str, uri: &str, body: Value) -> Request<Body> {
    cookie_request(Method::POST, sso_session_id, uri, Some(body))
}

/// A request with no cookie and no SSO (used to verify unauthenticated 401 etc.).
pub fn anonymous(method: Method, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or(Body::empty(), |b| Body::from(b.to_string())))
        .unwrap()
}

/// POST to `/internal/*` (the service token is added only when `Some`).
pub fn post_internal(uri: &str, token: Option<&str>, payload: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        builder = builder.header(SERVICE_TOKEN_HEADER, t);
    }
    builder.body(Body::from(payload.to_string())).unwrap()
}

/// Extracts the value of `name` from `Set-Cookie` headers.
pub fn cookie_value(response: &axum::response::Response, name: &str) -> Option<String> {
    response.headers().get_all(SET_COOKIE).iter().find_map(|v| {
        let raw = v.to_str().ok()?;
        let (k, rest) = raw.split_once('=')?;
        (k == name).then(|| rest.split(';').next().unwrap_or("").to_string())
    })
}

pub fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string()
}

pub fn query_param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .expect("parse redirect URL")
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Builds an authorization request URI with only the `openid` scope (no consent step needed).
pub fn authorize_uri_openid_only(tenant: &str, client_id: &str) -> String {
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope=openid&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
    )
}

/// Extracts the single-use handle (`?auth_session=`) from the `/authorize` handoff 302 (decision 2 of ADR-0018).
/// Also verifies that "api issues no browser cookies at all".
pub fn handoff_handle(response: &axum::response::Response) -> String {
    assert!(
        response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .next()
            .is_none(),
        "the api must not set browser cookies on /authorize (ADR-0018)"
    );
    query_param(&location(response), "auth_session").expect("auth_session handle in Location")
}

/// Calls `/internal/authorize/resume` (in place of web). `sso_session_id` being `Some` involves the SSO decision.
/// The response is JSON tagged with `result`.
pub async fn resume_authorize(
    app: &axum::Router,
    tenant: &str,
    handle: &str,
    sso_session_id: Option<&str>,
) -> Value {
    let response = send(
        app,
        post_internal(
            "/internal/authorize/resume",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "handle": handle,
                "sso_session_id": sso_session_id,
            }),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "authorize resume"
    );
    body_json(response).await
}

/// Shortcut to get `auth_session_id` via `/authorize` -> resume (no SSO) (equivalent to the old Set-Cookie).
pub async fn begin_login(app: &axum::Router, tenant: &str, authorize_uri: &str) -> String {
    let response = send(
        app,
        Request::builder()
            .uri(authorize_uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::FOUND,
        "handoff to web /login"
    );
    let handle = handoff_handle(&response);
    let body = resume_authorize(app, tenant, &handle, None).await;
    assert_eq!(body["result"], "login_required", "no SSO yet: {body}");
    body["auth_session_id"]
        .as_str()
        .expect("auth_session_id")
        .to_string()
}

/// Exchanges an authorization code for tokens (public client, PKCE).
pub async fn exchange_code(
    app: &axum::Router,
    tenant: &str,
    client_id: &str,
    code: &str,
) -> axum::response::Response {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}&client_id={client_id}"
            )))
            .unwrap(),
    )
    .await
}
