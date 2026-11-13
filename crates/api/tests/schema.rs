//! Integration test for migration consistency.
//!
//! Requires `TEST_DATABASE_URL` (fails if unset; set `IDP_ALLOW_DB_TEST_SKIP=1` only to skip it deliberately locally).
//! Locally, use the docker-compose MariaDB and run, for example:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test schema
//!
//! DB-level guarantees of the multi-tenant foundation (ADR-0009 MT1/MT2) are also verified here:
//!   * the root tenant is "at most 1 row" (is_root sentinel column + UNIQUE)
//!   * `idp.system.admin` can exist only in root scope (CHECK constraint on grants)
//!   * email uniqueness is per tenant (the same email across tenants is allowed)

use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const EXPECTED_TABLES: &[&str] = &[
    "tenants",
    "tenant_memberships",
    "users",
    "clients",
    "permissions",
    "user_permissions",
    "client_permissions",
    "auth_sessions",
    "authentication_policies",
    "sso_sessions",
    "authorization_codes",
    "refresh_tokens",
    "client_consents",
    "revoked_access_tokens",
    "signing_keys",
    "passkey_challenges",
    "audit_log",
    "log",
    "backchannel_logout_deliveries",
    "user_authenticators",
    "external_identity_providers",
    "user_external_identities",
    "external_login_requests",
    "saml_sso_requests",
    "user_login_identifiers",
    "user_password_history",
    "tenant_domains",
    "client_assertion_jtis",
    "dpop_proof_jtis",
    "tenant_settings",
];

/// Pins "no bearer credential is stored in plain text" in terms of column shape (SEC6).
/// Verifies each `(table, column)`, a column holding only 64 hex chars of SHA-256, is `CHAR(64)` with
/// no room for plain text, and that no column name from the plain-text era remains.
const HASHED_CREDENTIAL_COLUMNS: &[(&str, &str)] = &[
    ("auth_sessions", "id_hash"),
    ("saml_sso_requests", "id_hash"),
    ("passkey_challenges", "auth_session_id_hash"),
    ("external_login_requests", "auth_session_id_hash"),
    ("sso_sessions", "session_hash"),
    ("authorization_codes", "code_hash"),
    ("refresh_tokens", "token_hash"),
];

/// Tables that must not exist once contracted (after the DROP migration is applied).
/// Append-only migrations can revive them on down, so the post-up state is pinned explicitly.
const DROPPED_TABLES: &[&str] = &[
    "saml_identity_providers",
    // Authenticator secrets were consolidated into the registry (`user_authenticators`) (AP11b, migration 0038).
    // If it remained, reads with an ambiguous "which one is real" would become possible again.
    "user_totp_secrets",
    "user_webauthn_credentials",
];

async fn count(pool: &MySqlPool, sql: &str) -> i64 {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .fetch_one(pool)
        .await
        .expect("count query")
        .get::<i64, _>(0)
}

/// Is a canonical UUIDv7 string (36 chars, version nibble '7', variant nibble 8..b).
fn assert_uuid_v7(id: &str, label: &str) {
    assert_eq!(id.len(), 36, "{label}: length");
    assert_eq!(
        id.as_bytes()[14],
        b'7',
        "{label}: version nibble must be 7 in {id}"
    );
    assert!(
        matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
        "{label}: variant nibble must be 8..b in {id}"
    );
}

#[tokio::test]
async fn migrations_apply_and_multi_tenant_guarantees_hold() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        if std::env::var("IDP_ALLOW_DB_TEST_SKIP").ok().as_deref() == Some("1") {
            eprintln!("TEST_DATABASE_URL not set; intentionally skipping schema integration test");
            return;
        }
        panic!("TEST_DATABASE_URL is required for schema integration test; set IDP_ALLOW_DB_TEST_SKIP=1 only for local unit-only runs");
    };

    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");

    MIGRATOR.run(&pool).await.expect("run migrations");

    for table in EXPECTED_TABLES {
        let n = sqlx::query(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_name = ?",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("query information_schema")
        .get::<i64, _>(0);
        assert_eq!(n, 1, "table `{table}` must exist after migration");
    }

    for table in DROPPED_TABLES {
        let n = sqlx::query(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_name = ?",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .expect("query information_schema")
        .get::<i64, _>(0);
        assert_eq!(n, 0, "table `{table}` must be dropped after migration");
    }

    // --- SEC6: secret columns are hashes (CHAR(64)); no plain-text column remains --------------
    for (table, column) in HASHED_CREDENTIAL_COLUMNS {
        let row = sqlx::query(
            "SELECT column_type FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(&pool)
        .await
        .expect("query information_schema")
        .unwrap_or_else(|| panic!("`{table}`.`{column}` must exist"));
        assert_eq!(
            row.get::<String, _>(0),
            "char(64)",
            "`{table}`.`{column}` must be a fixed-width SHA-256 hex column"
        );
    }
    for (table, column) in [
        ("auth_sessions", "id"),
        ("saml_sso_requests", "id"),
        ("passkey_challenges", "auth_session_id"),
        ("external_login_requests", "auth_session_id"),
    ] {
        let n = sqlx::query(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
        )
        .bind(table)
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("query information_schema")
        .get::<i64, _>(0);
        assert_eq!(
            n, 0,
            "`{table}`.`{column}` must be gone (plaintext credential)"
        );
    }

    // --- seed: root tenant (fixed UUID; ADR-0011) --------------------
    let root: String = sqlx::query("SELECT id FROM tenants WHERE parent_tenant_id IS NULL")
        .fetch_one(&pool)
        .await
        .expect("root tenant must be seeded")
        .get(0);
    assert_uuid_v7(&root, "root tenant id");
    assert_eq!(
        root, "00000000-0000-7000-8000-000000000001",
        "root tenant must use the fixed UUID (ADR-0011)"
    );

    // --- seed: initial admin (in root, HOME membership, system.admin; ADR-0009 Phase 1-5)
    let admin_row = sqlx::query(
        "SELECT id, sub, must_change_password FROM users \
         WHERE tenant_id = ? AND email = 'admin@example.com'",
    )
    .bind(&root)
    .fetch_one(&pool)
    .await
    .expect("initial admin must be seeded into the root tenant");
    let admin: String = admin_row.get("id");
    assert_uuid_v7(&admin, "admin user id");
    assert_uuid_v7(admin_row.get::<&str, _>("sub"), "admin sub");
    assert!(
        admin_row.get::<bool, _>("must_change_password"),
        "seeded admin must be flagged must_change_password"
    );

    let n = sqlx::query(
        "SELECT COUNT(*) FROM tenant_memberships \
         WHERE tenant_id = ? AND user_id = ? \
           AND membership_type = 'HOME' AND status = 'ACTIVE'",
    )
    .bind(&root)
    .bind(&admin)
    .fetch_one(&pool)
    .await
    .expect("query membership")
    .get::<i64, _>(0);
    assert_eq!(n, 1, "admin must have an ACTIVE HOME membership in root");

    let n = sqlx::query(
        "SELECT COUNT(*) FROM user_permissions \
         WHERE user_id = ? AND permission_code = 'idp.system.admin' AND tenant_id = ?",
    )
    .bind(&admin)
    .bind(&root)
    .fetch_one(&pool)
    .await
    .expect("query admin grant")
    .get::<i64, _>(0);
    assert_eq!(
        n, 1,
        "admin must be granted idp.system.admin with scope = root"
    );

    for code in ["idp.system.admin", "idp.tenant.admin"] {
        let n = sqlx::query("SELECT COUNT(*) FROM permissions WHERE code = ?")
            .bind(code)
            .fetch_one(&pool)
            .await
            .expect("query permissions master")
            .get::<i64, _>(0);
        assert_eq!(n, 1, "permission code `{code}` must be seeded");
    }

    // --- Guarantee 1: root is at most 1 row (is_root sentinel column + UNIQUE; ADR-0009 §1) ----------
    let second_root = uuid::Uuid::new_v4().to_string();
    let err = sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, NULL, 'evil root')",
    )
    .bind(&second_root)
    .execute(&pool)
    .await
    .expect_err("inserting a second root tenant must fail");
    assert!(
        err.as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_unique_violation),
        "second root must be rejected by tenants_single_root_uk, got: {err}"
    );

    // --- Guarantee 2: idp.system.admin can exist only in root scope (CHECK; ADR-0009 §4)
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS \
             WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME = 'user_permissions' \
               AND CONSTRAINT_NAME = 'user_permissions_system_admin_scope_chk'"
        )
        .await,
        1,
        "seed must attach the system-admin scope CHECK constraint"
    );

    let child = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, ?, 'child tenant')")
        .bind(&child)
        .bind(&root)
        .execute(&pool)
        .await
        .expect("create child tenant");

    let err = sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) \
         VALUES (?, 'idp.system.admin', ?)",
    )
    .bind(&admin)
    .bind(&child)
    .execute(&pool)
    .await
    .expect_err("idp.system.admin with non-root scope must fail");
    assert!(
        err.as_database_error()
            .is_some_and(|e| e.is_check_violation()),
        "non-root idp.system.admin must be rejected by the CHECK constraint, got: {err}"
    );

    // Contrast: idp.tenant.admin can be granted in any tenant scope.
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) \
         VALUES (?, 'idp.tenant.admin', ?)",
    )
    .bind(&admin)
    .bind(&child)
    .execute(&pool)
    .await
    .expect("idp.tenant.admin with a non-root scope must be allowed");

    // --- Guarantee 3: email is unique per tenant (same email across tenants allowed; ADR-0009 §2)
    let dup_in_root = sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, password_hash) VALUES (?, ?, ?, 'admin@example.com', 'x')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&root)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&pool)
    .await
    .expect_err("duplicate email within the same tenant must fail");
    assert!(
        dup_in_root
            .as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_unique_violation),
        "same-tenant duplicate email must violate users_tenant_email_uk, got: {dup_in_root}"
    );

    let guest_in_child = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, password_hash) VALUES (?, ?, ?, 'admin@example.com', 'x')",
    )
    .bind(&guest_in_child)
    .bind(&child)
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&pool)
    .await
    .expect("same email in a different tenant must be allowed");

    // --- Cleanup (only rows this test created; the seed stays) -------------------------
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&guest_in_child)
        .execute(&pool)
        .await
        .expect("cleanup guest user");
    sqlx::query("DELETE FROM user_permissions WHERE tenant_id = ?")
        .bind(&child)
        .execute(&pool)
        .await
        .expect("cleanup child grants");
    sqlx::query("DELETE FROM tenants WHERE id = ?")
        .bind(&child)
        .execute(&pool)
        .await
        .expect("cleanup child tenant");
}
