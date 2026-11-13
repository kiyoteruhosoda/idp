//! Integration tests (with DB) for suspending / resuming guest memberships
//! (`PATCH /{tenant_id}/admin/members/{user_id}`; MT24).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_member_suspension
//!
//! Removal (`DELETE`) deletes both the membership row and the permission rows scoped to the tenant, so undoing it
//! means starting over from an invitation. Suspension is required to be **reversible**; what is checked:
//!
//! 1. Authorization (unauthenticated 401 / no permission 403) and input validation (invalid status is 400).
//! 2. Suspending sets `SUSPENDED` and **keeps the membership and permission rows** (= resuming restores it).
//! 3. Suspending revokes refresh tokens for that tenant and **keeps those for other tenants**.
//!    Suspending a guest is a measure for one tenant and must not affect use in the home tenant.
//! 4. Transition constraints (HOME cannot be suspended, double suspension and resuming a non-suspended one are all 403).
//! 5. Suspension and resumption are left in the audit log.

mod support;

use axum::http::{Method, StatusCode};
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{admin_token, create_plain_user, patch, send};

/// Creates a GUEST membership (`ACTIVE`) in the tenant directly (the invitation flow is another test's concern).
async fn insert_active_guest(pool: &MySqlPool, tenant_id: &str, user_id: &str) {
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(tenant_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert guest membership");
}

/// `refresh_tokens` references `clients` via the composite foreign key `(tenant_id, client_id)`, so
/// the issuing client must exist (the caller provides `client_id`).
async fn insert_refresh_token(
    pool: &MySqlPool,
    tenant_id: &str,
    user_id: &str,
    client_id: &str,
) -> String {
    let hash = format!("{:064x}", uuid::Uuid::now_v7().as_u128());
    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, client_id, scope, expires_at) \
         VALUES (?, ?, ?, ?, '[\"openid\"]', DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))",
    )
    .bind(&hash)
    .bind(tenant_id)
    .bind(user_id)
    .bind(client_id)
    .execute(pool)
    .await
    .expect("insert refresh token");
    hash
}

async fn is_revoked(pool: &MySqlPool, token_hash: &str) -> bool {
    sqlx::query("SELECT revoked_at IS NOT NULL AS revoked FROM refresh_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .fetch_one(pool)
        .await
        .expect("read refresh token")
        .get::<i64, _>("revoked")
        == 1
}

async fn membership_status(pool: &MySqlPool, tenant_id: &str, user_id: &str) -> Option<String> {
    sqlx::query("SELECT status FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?")
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .expect("read membership")
        .map(|row| row.get::<String, _>("status"))
}

async fn grant_permission(pool: &MySqlPool, tenant_id: &str, user_id: &str, code: &str) {
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, ?, ?)",
    )
    .bind(user_id)
    .bind(code)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("grant permission");
}

async fn count_permissions(pool: &MySqlPool, tenant_id: &str, user_id: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM user_permissions WHERE tenant_id = ? AND user_id = ?")
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count permissions")
        .get::<i64, _>("c")
}

async fn count_audit(pool: &MySqlPool, event_type: &str, target_id: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log \
         WHERE event_type = ? AND result = 'success' AND reason LIKE ?",
    )
    .bind(event_type)
    .bind(format!("%member={target_id}%"))
    .fetch_one(pool)
    .await
    .expect("count audit")
    .get::<i64, _>("c")
}

#[tokio::test]
async fn admin_suspends_and_resumes_a_guest_without_losing_membership_or_permissions() {
    let Some(env) = support::setup("admin member suspension").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    // Use the real-world shape: the guest **belongs to another tenant** (home = home_tenant) and joins root as a
    // GUEST. `create_plain_user` creates a HOME membership in the given tenant, so unless the home is another
    // tenant it would collide on the primary key with the root GUEST row.
    let home_tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, ?, ?)")
        .bind(&home_tenant)
        .bind(&env.root_tenant_id)
        .bind(format!("guest-home-{}", &home_tenant[..8]))
        .execute(&env.pool)
        .await
        .expect("create home tenant for the guest");
    let guest = create_plain_user(&env.pool, &home_tenant).await;

    let uri = format!("/{}/admin/members/{guest}", env.root_tenant_id);

    // ── Authorization: no token is 401, a user without permission is 403.
    let res = send(
        &env.app,
        support::anonymous(Method::PATCH, &uri, Some(json!({"status": "SUSPENDED"}))),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    let res = send(
        &env.app,
        patch(&plain_token, &uri, json!({"status": "SUSPENDED"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no admin perm -> 403");

    // ── Setup: an ACTIVE GUEST, permissions scoped to the tenant, refresh tokens for both tenants.
    insert_active_guest(&env.pool, &env.root_tenant_id, &guest).await;
    grant_permission(&env.pool, &env.root_tenant_id, &guest, "idp.tenant.admin").await;
    let host_client =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let home_client = support::insert_public_client(&env.pool, &home_tenant, &["openid"]).await;
    let host_token =
        insert_refresh_token(&env.pool, &env.root_tenant_id, &guest, &host_client).await;
    // A token issued in the home tenant. Suspension is a measure on the host tenant and must not affect it.
    let home_token = insert_refresh_token(&env.pool, &home_tenant, &guest, &home_client).await;

    // ── Invalid status is 400 (INVITED is managed by the invitation flow and cannot be set directly).
    for bad in ["INVITED", "nonsense", ""] {
        let res = send(&env.app, patch(&admin_tok, &uri, json!({"status": bad}))).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status={bad}");
    }

    // ── Suspend.
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({"status": "SUSPENDED"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "suspend");
    assert_eq!(
        membership_status(&env.pool, &env.root_tenant_id, &guest).await,
        Some("SUSPENDED".to_string())
    );
    // Unlike removal, both membership and permissions remain (resuming restores them).
    assert_eq!(
        count_permissions(&env.pool, &env.root_tenant_id, &guest).await,
        1
    );
    // Only that tenant's refresh tokens are revoked.
    assert!(
        is_revoked(&env.pool, &host_token).await,
        "host token revoked"
    );
    assert!(
        !is_revoked(&env.pool, &home_token).await,
        "the guest's home-tenant token must survive"
    );
    assert_eq!(
        count_audit(&env.pool, "tenant_membership.suspended", &guest).await,
        1
    );

    // ── Double suspension is 403 (not a valid transition).
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({"status": "SUSPENDED"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "double suspend");

    // ── Resume. Permissions are unchanged, so it returns to the pre-suspension state.
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({"status": "ACTIVE"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "resume");
    assert_eq!(
        membership_status(&env.pool, &env.root_tenant_id, &guest).await,
        Some("ACTIVE".to_string())
    );
    assert_eq!(
        count_permissions(&env.pool, &env.root_tenant_id, &guest).await,
        1
    );
    assert_eq!(
        count_audit(&env.pool, "tenant_membership.resumed", &guest).await,
        1
    );

    // ── Resuming a non-suspended one is 403.
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({"status": "ACTIVE"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "resume when active");
}

#[tokio::test]
async fn home_membership_cannot_be_suspended() {
    let Some(env) = support::setup("admin member suspension home").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    // create_plain_user creates it with a HOME membership.
    let home_user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/members/{home_user}", env.root_tenant_id);

    // HOME is the home tenant itself; suspending it would leave nowhere to sign in (use account disabling instead).
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({"status": "SUSPENDED"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "home -> 403");
    assert_eq!(
        membership_status(&env.pool, &env.root_tenant_id, &home_user).await,
        Some("ACTIVE".to_string()),
        "home membership must stay active"
    );

    // No membership means 404 (prevents existence guessing).
    let unknown = uuid::Uuid::now_v7();
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("/{}/admin/members/{unknown}", env.root_tenant_id),
            json!({"status": "SUSPENDED"}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
