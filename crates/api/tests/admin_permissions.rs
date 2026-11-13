//! E2E integration tests for the user permission grant / revoke API (Progress A2, ADR-0006, design spec §7).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_permissions
//!
//! Authorization is by permission code (`idp.permissions:read` / `:write`; `idp.tenant.admin` and `idp.system.admin`
//! are allowed by implication; ADR-0037).
//! Creates the SSO session of the initial admin (granted `idp.system.admin` on the root tenant by seed)
//! directly, exchanges it for an admin token and calls the admin API. Checks users without permission get 403,
//! and that grants and revocations are recorded in `audit_log`.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{
    admin_token, body_json, create_plain_user, create_sso_session, delete, exchange_admin_token,
    get, post, send,
};

const ADMIN_PERM: &str = "idp.tenant.admin";

/// Number of audit rows filtered by actor (user_id) and target (target UUID in reason).
/// The shared test DB keeps rows from past runs, so count only targets created in this run.
async fn count_audit(pool: &MySqlPool, event_type: &str, actor_id: &str, target_id: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log \
         WHERE event_type = ? AND user_id = ? AND result = 'success' AND reason LIKE ?",
    )
    .bind(event_type)
    .bind(actor_id)
    .bind(format!("%target={target_id}%"))
    .fetch_one(pool)
    .await
    .expect("count audit")
    .get::<i64, _>("c")
}

#[tokio::test]
async fn admin_can_grant_and_revoke_permissions() {
    let Some(env) = support::setup("admin permissions").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let perms_uri = format!("/{}/admin/users/{target}/permissions", env.root_tenant_id);

    // Unauthenticated (no token) → 401.
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(&perms_uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // User without permission → 403. Keep the SSO session to exchange again later.
    let target_sso = create_sso_session(&env.pool, &target).await;
    let plain_token = exchange_admin_token(&env.app, &env.root_tenant_id, &target_sso).await;
    let res = send(&env.app, get(&plain_token, &perms_uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // user_id is not a UUID → 400.
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/users/not-a-uuid/permissions", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "bad user_id -> 400");

    // Granting to a nonexistent user → 404.
    let ghost = uuid::Uuid::new_v4();
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/users/{ghost}/permissions", env.root_tenant_id),
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "unknown user -> 404");

    // Unknown permission code → 400.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &perms_uri,
            json!({ "permission_code": "idp.does-not-exist" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown code -> 400");

    // Initial state: no permissions.
    let res = send(&env.app, get(&admin_tok, &perms_uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed = body_json(res).await;
    assert!(listed["permission_codes"].as_array().unwrap().is_empty());

    // Grant → 200, reflected in the list, audit granted recorded.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &perms_uri,
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant -> 200");
    let granted = body_json(res).await;
    assert_eq!(
        granted["permission_codes"].as_array().unwrap(),
        &vec![json!(ADMIN_PERM)]
    );
    assert_eq!(
        count_audit(
            &env.pool,
            "user_permission.granted",
            &env.root_admin_id,
            &target
        )
        .await,
        1,
        "granted audit recorded (actor = admin)"
    );

    // Idempotent: granting again does not duplicate.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &perms_uri,
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted = body_json(res).await;
    assert_eq!(granted["permission_codes"].as_array().unwrap().len(), 1);

    // A token issued **before** the grant still has no permission after the grant (ADR-0037 decision 2).
    // The source of permissions is the token's `perms` claim and is not re-read per request. If this changes,
    // the decision "put permissions in the token" itself has broken.
    let res = send(&env.app, get(&plain_token, &perms_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a token minted before the grant keeps the permissions it was minted with"
    );

    // Re-exchanging the same SSO session carries the new permission (this is also why the admin console exchanges
    // per request; a grant takes effect from the next operation).
    let refreshed_token = exchange_admin_token(&env.app, &env.root_tenant_id, &target_sso).await;
    let res = send(&env.app, get(&refreshed_token, &perms_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "granted user can now access admin"
    );

    // Revoke → 200, empty list, audit revoked recorded.
    let res = send(
        &env.app,
        delete(&admin_tok, &format!("{perms_uri}/{ADMIN_PERM}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke -> 200");
    let revoked = body_json(res).await;
    assert!(revoked["permission_codes"].as_array().unwrap().is_empty());
    assert_eq!(
        count_audit(
            &env.pool,
            "user_permission.revoked",
            &env.root_admin_id,
            &target
        )
        .await,
        1,
        "revoked audit recorded"
    );

    // Revocation is idempotent (200 even when not held).
    let res = send(
        &env.app,
        delete(&admin_tok, &format!("{perms_uri}/{ADMIN_PERM}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke again -> 200");
}
