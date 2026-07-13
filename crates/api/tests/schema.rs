//! マイグレーション整合の統合テスト。
//!
//! `TEST_DATABASE_URL` を必須として実行する（未設定は失敗。ローカルで意図的に省略する場合のみ `IDP_ALLOW_DB_TEST_SKIP=1`）。
//! ローカルでは docker-compose の MariaDB を使い、例えば次のように実行する:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test schema
//!
//! マルチテナント基盤（ADR-0009 MT1/MT2）の DB レベル保証もここで検証する:
//!   * root テナントが「高々 1 行」であること（is_root 番兵列 + UNIQUE）
//!   * `idp.system.admin` が root scope でしか存在できないこと（投入時付与の CHECK 制約）
//!   * email 一意性がテナント内に限られること（テナント跨ぎの同一 email は許容）

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
    "auth_sessions",
    "sso_sessions",
    "authorization_codes",
    "refresh_tokens",
    "client_consents",
    "revoked_access_tokens",
    "signing_keys",
    "user_totp_secrets",
    "user_webauthn_credentials",
    "passkey_challenges",
    "audit_log",
];

async fn count(pool: &MySqlPool, sql: &str) -> i64 {
    sqlx::query(sql)
        .fetch_one(pool)
        .await
        .expect("count query")
        .get::<i64, _>(0)
}

/// UUIDv7 の正準文字列（36 文字・version ニブル '7'・variant ニブル 8〜b）であること。
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

    // --- seed: root テナント（動的採番の UUIDv7。ADR-0009 §1） --------------------
    let root: String = sqlx::query("SELECT id FROM tenants WHERE parent_tenant_id IS NULL")
        .fetch_one(&pool)
        .await
        .expect("root tenant must be seeded")
        .get(0);
    assert_uuid_v7(&root, "root tenant id");

    // --- seed: 初期管理者（root 所属・HOME メンバーシップ・system.admin。ADR-0009 Phase 1-5）
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

    // --- 保証 1: root は高々 1 行（is_root 番兵列 + UNIQUE。ADR-0009 §1） ----------
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

    // --- 保証 2: idp.system.admin は root scope でしか存在できない（CHECK。ADR-0009 §4）
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

    // 対照: idp.tenant.admin は任意テナント scope で付与できる。
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) \
         VALUES (?, 'idp.tenant.admin', ?)",
    )
    .bind(&admin)
    .bind(&child)
    .execute(&pool)
    .await
    .expect("idp.tenant.admin with a non-root scope must be allowed");

    // --- 保証 3: email はテナント内一意（テナント跨ぎの同一 email は許容。ADR-0009 §2）
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

    // --- 後片付け（このテストが作った行のみ。seed は残す） -------------------------
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
