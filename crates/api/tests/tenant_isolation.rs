//! E2E integration test of tenant isolation and permission boundaries (MT16; ADR-0009 §1, §3, §4, §6, §8).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test tenant_isolation
//!
//! MariaDB has no RLS and the app layer is the only isolation defense, so negative tests are verified
//! as mandatory cases (ADR-0009 §8). Guarantees verified:
//!
//! 1. **root can create but cannot operate inside** (§1, §4, §9): `idp.system.admin` (scope = root) can
//!    create tenants, but gets a uniform 403 on the created tenant's admin API. Only `idp.tenant.admin`
//!    scoped to that tenant can operate inside.
//! 2. **Exact-match permission boundary** (§4): `idp.tenant.admin`'s scope covers only its tenant, and other tenants'
//!    (including root's) admin API, system settings and tenant creation get a uniform 403. `idp.system.admin`'s
//!    scope = root is also enforced by a DB CHECK constraint.
//! 3. **Data isolation between tenants** (§8): users and clients are invisible from other tenants' admin API
//!    (absent from lists; search/fetch is 404).
//! 4. **Guest protection** (§3): an invitation token can be accepted only by the invitee in that tenant, and does not leak into audit logs.
//!    The host admin cannot operate on the guest's `users` record and can only remove the membership and clean up
//!    scoped permissions. A HOME membership cannot be removed.
//! 5. **Membership checks and issuer isolation in the OIDC flow** (§6, §8): an SSO session without membership
//!    is treated as unauthenticated in that tenant's flow. An access token issued by tenant A is
//!    rejected at tenant B's `/userinfo` (exact `iss` match). After accepting membership, a guest can
//!    join the host tenant's flow via SSO.

mod support;

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use serde_json::json;
use sqlx::Row;
use support::{
    authorize_uri_openid_only as authorize_uri, body_json, cookie_post, create_sso_session, delete,
    exchange_admin_token, exchange_code, get, post, query_param, send, setup as support_setup,
    unique, TestEnv, REDIRECT_URI,
};

async fn setup() -> Option<TestEnv> {
    support_setup("tenant isolation").await
}

/// Exchanges an SSO session for an admin token for the given tenant (ADR-0037).
///
/// Admin tokens have `iss` / `aud` fixed to the per-tenant issuer, so they cannot be reused across
/// tenants. That is the very subject of this test (tenant boundaries), so the exchange is done on the spot each time.
async fn tok(env: &TestEnv, sso: &str, tenant_id: &str) -> String {
    exchange_admin_token(&env.app, tenant_id, sso).await
}

/// A tenant created via the API and its proper HOME admin.
struct CreatedTenant {
    id: String,
    admin_id: String,
    /// SSO session of the HOME admin (plain session_id). When calling the admin API, exchange it with [`tok`]
    /// for an admin token for the target tenant (admin tokens are per tenant; ADR-0037).
    admin_sso: String,
}

/// Runs the tenant creation bootstrap flow and prepares a proper HOME admin (ADR-0009 §4). Steps:
///   1. root creates the tenant -> root becomes an ACTIVE GUEST admin of the new tenant.
///   2. root (the bootstrap admin) creates the proper HOME admin.
///   3. Grant `idp.tenant.admin` to that HOME admin.
///
/// The returned `admin_id`/`admin_cookie` belong to this HOME admin. The creator (root) still remains a guest admin of
/// the tenant at this point (each test operates inside with the HOME admin's cookie; root leaves only in tests that
/// explicitly call [`root_leaves_tenant`], avoiding DELETE races on the shared root row).
async fn create_tenant(env: &TestEnv, root_sso: &str, name: &str) -> CreatedTenant {
    // 1. root creates the tenant (root gets ACTIVE GUEST + idp.tenant.admin).
    let res = send(
        &env.app,
        post(
            &tok(env, root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": name }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create tenant {name}");
    let id = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();

    // 2. root (the bootstrap admin) creates the proper HOME admin.
    let admin_email = format!("owner-{}@{}.example.com", unique(), name.to_lowercase());
    let res = send(
        &env.app,
        post(
            &tok(env, root_sso, &id).await,
            &format!("/{id}/admin/users"),
            json!({ "email": admin_email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create home admin");
    let admin_id = body_json(res).await["user_id"]
        .as_str()
        .expect("admin id")
        .to_string();

    // 3. Grant idp.tenant.admin to the HOME admin.
    let res = send(
        &env.app,
        post(
            &tok(env, root_sso, &id).await,
            &format!("/{id}/admin/users/{admin_id}/permissions"),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.tenant.admin");

    support::finish_setup(&env.pool, &admin_id).await;
    let admin_sso = create_sso_session(&env.pool, &admin_id).await;
    CreatedTenant {
        id,
        admin_id,
        admin_sso,
    }
}

/// The creator (root) removes its own guest membership and leaves the tenant (on removal, permission rows scoped to
/// that tenant are also cleaned up; ADR-0009 §3, §4). After leaving, root cannot operate inside the tenant.
async fn root_leaves_tenant(env: &TestEnv, root_sso: &str, tenant_id: &str) {
    let res = send(
        &env.app,
        delete(
            &tok(env, root_sso, tenant_id).await,
            &format!("/{tenant_id}/admin/members/{}", env.root_admin_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "root leaves the tenant"
    );
}

/// Creates a user as tenant admin and returns `(user_id, email)`.
async fn create_user(env: &TestEnv, admin_sso: &str, tenant_id: &str) -> (String, String) {
    let email = format!("user-{}@example.com", unique());
    let res = send(
        &env.app,
        post(
            &tok(env, admin_sso, tenant_id).await,
            &format!("/{tenant_id}/admin/users"),
            json!({ "email": email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create user");
    let created = body_json(res).await;
    let user_id = created["user_id"].as_str().expect("user id").to_string();
    // The created person is used directly as a test actor, so remove the provisional state (in place of the user finishing setup; ADR-0064).
    support::finish_setup(&env.pool, &user_id).await;
    (user_id, email)
}

/// Registers a public client with only the `openid` scope (no consent step needed).
async fn insert_public_client(pool: &sqlx::MySqlPool, tenant_id: &str) -> String {
    support::insert_public_client(pool, tenant_id, &["openid"]).await
}

/// Guarantee 1: root (idp.system.admin) can create tenants and operate inside during bootstrap, but after
/// removing its own guest membership and leaving, it gets a uniform 403 on the created tenant's internals (the whole admin API).
/// Only idp.tenant.admin scoped to that tenant can operate inside.
#[tokio::test]
async fn root_can_create_but_cannot_operate_inside_created_tenant() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let tenant = create_tenant(&env, &root_sso, "Inner").await;
    // After bootstrap, the creator (root) removes its own guest membership and leaves.
    root_leaves_tenant(&env, &root_sso, &tenant.id).await;

    // After leaving, root's system admin has no access at all to the created child tenant's admin API (§4, §9).
    let forbidden_requests = vec![
        get(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/whoami", tenant.id),
        ),
        get(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/members", tenant.id),
        ),
        get(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/clients", tenant.id),
        ),
        get(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/audit-logs", tenant.id),
        ),
        get(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/settings/tenant", tenant.id),
        ),
        get(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/signing-keys", tenant.id),
        ),
        post(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/users", tenant.id),
            json!({ "email": "intruder@example.com" }),
        ),
        post(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/clients", tenant.id),
            json!({
                "app_name": "X",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
        post(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/invitations", tenant.id),
            json!({ "user_id": env.root_admin_id }),
        ),
        delete(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/members/{}", tenant.id, tenant.admin_id),
        ),
        // root cannot create tenants on the child tenant side either (system.admin's scope is root only).
        post(
            &tok(&env, &root_sso, &tenant.id).await,
            &format!("/{}/admin/tenants", tenant.id),
            json!({ "name": "Grand" }),
        ),
    ];
    for req in forbidden_requests {
        let (method, uri) = (req.method().clone(), req.uri().to_string());
        let res = send(&env.app, req).await;
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "root system admin must get 403 for {method} {uri}"
        );
    }

    // The tenant's admin (idp.tenant.admin) can operate inside.
    let res = send(
        &env.app,
        get(
            &tok(&env, &tenant.admin_sso, &tenant.id).await,
            &format!("/{}/admin/whoami", tenant.id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "tenant admin whoami");
    assert_eq!(
        body_json(res).await["user_id"].as_str(),
        Some(tenant.admin_id.as_str())
    );

    // System settings are idp.system.admin (scope = root) only: 200 on root, 403 for a tenant admin even on its
    // own tenant (§9).
    let res = send(
        &env.app,
        get(
            &tok(&env, &root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/system-settings", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "root reads system settings");
    let res = send(
        &env.app,
        get(
            &tok(&env, &tenant.admin_sso, &tenant.id).await,
            &format!("/{}/admin/system-settings", tenant.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "tenant admin cannot read system settings even in own tenant"
    );
}

/// Guarantees 2 and 3: idp.tenant.admin's permission boundary is decided by exact match with the scope tenant,
/// and other tenants (including root) get a uniform 403. Data (users, clients) is also invisible from other tenants.
#[tokio::test]
async fn tenant_admin_boundary_is_exact_match_and_data_is_isolated() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let a = create_tenant(&env, &root_sso, "AlphaCo").await;
    let b = create_tenant(&env, &root_sso, "BravoCo").await;

    // A's admin has no access at all to B's or root's admin API (exact match; ancestors and siblings are irrelevant; §4).
    let cross_tenant_requests = vec![
        get(
            &tok(&env, &a.admin_sso, &b.id).await,
            &format!("/{}/admin/whoami", b.id),
        ),
        get(
            &tok(&env, &a.admin_sso, &b.id).await,
            &format!("/{}/admin/members", b.id),
        ),
        get(
            &tok(&env, &a.admin_sso, &b.id).await,
            &format!("/{}/admin/clients", b.id),
        ),
        get(
            &tok(&env, &a.admin_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/whoami", env.root_tenant_id),
        ),
        get(
            &tok(&env, &a.admin_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/tenants", env.root_tenant_id),
        ),
        post(
            &tok(&env, &a.admin_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": "Rogue" }),
        ),
        delete(
            &tok(&env, &a.admin_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/tenants/{}", env.root_tenant_id, b.id),
        ),
        get(
            &tok(&env, &a.admin_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/system-settings", env.root_tenant_id),
        ),
    ];
    for req in cross_tenant_requests {
        let (method, uri) = (req.method().clone(), req.uri().to_string());
        let res = send(&env.app, req).await;
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "tenant A admin must get 403 for {method} {uri}"
        );
    }

    // Data isolation: A's clients do not appear in B's list (§8).
    let res = send(
        &env.app,
        post(
            &tok(&env, &a.admin_sso, &a.id).await,
            &format!("/{}/admin/clients", a.id),
            json!({
                "app_name": "Alpha App",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "A creates own client");
    let a_client_id = body_json(res).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let res = send(
        &env.app,
        get(
            &tok(&env, &b.admin_sso, &b.id).await,
            &format!("/{}/admin/clients", b.id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    // The list returns a paged object (`{clients, total, limit, offset}`) (G7).
    let b_clients = body_json(res).await;
    assert!(
        b_clients["clients"]
            .as_array()
            .expect("clients array")
            .iter()
            .all(|c| c["client_id"].as_str() != Some(a_client_id.as_str())),
        "tenant A's client must not appear in tenant B's list"
    );
    // Fetching A's client directly from B is also 404 (existence is not leaked).
    let res = send(
        &env.app,
        get(
            &tok(&env, &b.admin_sso, &b.id).await,
            &format!("/{}/admin/clients/{a_client_id}", b.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant client -> 404"
    );

    // Data isolation: A's users cannot be searched or fetched from B (404, same as nonexistent; §8).
    let (a_user_id, a_user_email) = create_user(&env, &a.admin_sso, &a.id).await;
    let res = send(
        &env.app,
        get(
            &tok(&env, &b.admin_sso, &b.id).await,
            &format!("/{}/admin/users?q={a_user_email}", b.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant search -> 404"
    );
    let res = send(
        &env.app,
        get(
            &tok(&env, &b.admin_sso, &b.id).await,
            &format!("/{}/admin/users/{a_user_id}", b.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant get -> 404"
    );
    // Granting and viewing permissions across tenants is also impossible (targets are limited to the home tenant).
    let res = send(
        &env.app,
        post(
            &tok(&env, &b.admin_sso, &b.id).await,
            &format!("/{}/admin/users/{a_user_id}/permissions", b.id),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant permission grant -> 404"
    );

    // Granting idp.system.admin is for holders only (a tenant admin gets 403 even on its own tenant; §4).
    let res = send(
        &env.app,
        post(
            &tok(&env, &a.admin_sso, &a.id).await,
            &format!("/{}/admin/users/{a_user_id}/permissions", a.id),
            json!({ "permission_code": "idp.system.admin" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "tenant admin cannot grant idp.system.admin"
    );

    // DB-level double defense: idp.system.admin cannot exist in a scope other than root (CHECK constraint; §4).
    let direct_insert = sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, 'idp.system.admin', ?)",
    )
    .bind(&a_user_id)
    .bind(&a.id)
    .execute(&env.pool)
    .await;
    assert!(
        direct_insert.is_err(),
        "DB CHECK must reject idp.system.admin scoped to a non-root tenant"
    );

    // A tenant that still has users or clients cannot be deleted even by root (ON DELETE RESTRICT -> 409; §1).
    let res = send(
        &env.app,
        delete(
            &tok(&env, &root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/tenants/{}", env.root_tenant_id, a.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "tenant with users/clients cannot be deleted"
    );
}

/// Guarantee 4: an invitation holds only when token possession + the invitee's own logged-in session + the tenant's
/// acceptance route all line up. The host admin cannot touch the guest's users record, and on removal only scoped
/// permissions are cleaned up (the guest itself and other tenants' scopes remain). HOME cannot be removed.
#[tokio::test]
async fn guest_invitation_protects_user_state_and_cleans_up_scoped_permissions() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "HostCo").await;
    let home = create_tenant(&env, &root_sso, "HomeCo").await;

    // The guest candidate is a user of the home tenant.
    let (guest_id, guest_email) = create_user(&env, &home.admin_sso, &home.id).await;
    let guest_sso = create_sso_session(&env.pool, &guest_id).await;

    // The host admin creates an invitation -> the token is returned only once in the response and does not leak into audit logs (§3).
    let res = send(
        &env.app,
        post(
            &tok(&env, &host.admin_sso, &host.id).await,
            &format!("/{}/admin/invitations", host.id),
            json!({ "user_id": guest_id }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "invitation created");
    let invitation = body_json(res).await;
    let token = invitation["token"].as_str().expect("token").to_string();
    assert!(token.len() >= 32, "invitation token is high-entropy");
    let leaked: i64 = sqlx::query("SELECT COUNT(*) AS c FROM audit_log WHERE reason LIKE ?")
        .bind(format!("%{token}%"))
        .fetch_one(&env.pool)
        .await
        .expect("audit scan")
        .get::<i64, _>("c");
    assert_eq!(leaked, 0, "invitation token must not appear in audit log");

    // Only the invitee can accept (another person's session -> 403).
    let accept_uri = format!("/{}/invitations/accept", host.id);
    let res = send(
        &env.app,
        cookie_post(&host.admin_sso, &accept_uri, json!({ "token": token })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "non-invitee -> 403");

    // Acceptance only via that tenant's route (presenting it to another tenant's accept -> 400).
    let res = send(
        &env.app,
        cookie_post(
            &guest_sso,
            &format!("/{}/invitations/accept", home.id),
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "wrong tenant -> 400");

    // The invitee + correct tenant -> 204. The membership becomes ACTIVE / GUEST.
    let res = send(
        &env.app,
        cookie_post(&guest_sso, &accept_uri, json!({ "token": token })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "accept -> 204");
    let (mtype, mstatus): (String, String) = sqlx::query_as(
        "SELECT membership_type, status FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?",
    )
    .bind(&host.id)
    .bind(&guest_id)
    .fetch_one(&env.pool)
    .await
    .expect("membership row");
    assert_eq!((mtype.as_str(), mstatus.as_str()), ("GUEST", "ACTIVE"));

    // Token reuse (replay) is not possible.
    let res = send(
        &env.app,
        cookie_post(&guest_sso, &accept_uri, json!({ "token": token })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "token replay -> 400");

    // The guest appears in the member list as GUEST.
    let res = send(
        &env.app,
        get(
            &tok(&env, &host.admin_sso, &host.id).await,
            &format!("/{}/admin/members", host.id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    // The list returns a paged object (`{members, total, limit, offset}`) (MT22).
    let body = body_json(res).await;
    let guest_entry = body["members"]
        .as_array()
        .expect("members array")
        .iter()
        .find(|m| m["user_id"].as_str() == Some(guest_id.as_str()))
        .expect("guest appears in member list");
    assert_eq!(guest_entry["membership_type"], "GUEST");

    // The host admin cannot reach the guest's users record (404 for both fetch and search; §3).
    let res = send(
        &env.app,
        get(
            &tok(&env, &host.admin_sso, &host.id).await,
            &format!("/{}/admin/users/{guest_id}", host.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "guest user record -> 404"
    );
    let res = send(
        &env.app,
        get(
            &tok(&env, &host.admin_sso, &host.id).await,
            &format!("/{}/admin/users?q={guest_email}", host.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "guest user search -> 404"
    );

    // A membership alone does not grant the admin API (no permission -> 403).
    let res = send(
        &env.app,
        get(
            &tok(&env, &guest_sso, &host.id).await,
            &format!("/{}/admin/whoami", host.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "guest without perms -> 403"
    );

    // A HOME membership cannot be removed (§3).
    let res = send(
        &env.app,
        delete(
            &tok(&env, &host.admin_sso, &host.id).await,
            &format!("/{}/admin/members/{}", host.id, host.admin_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "HOME revoke -> 403");

    // On guest removal only permission rows scoped to the host are cleaned up; the guest itself and other scopes remain (§3).
    // (Scoped permissions are inserted directly into the DB, since the grant API is limited to the home tenant.)
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, 'idp.tenant.admin', ?), (?, 'idp.tenant.admin', ?)",
    )
    .bind(&guest_id)
    .bind(&host.id)
    .bind(&guest_id)
    .bind(&home.id)
    .execute(&env.pool)
    .await
    .expect("seed guest permissions");
    let res = send(
        &env.app,
        delete(
            &tok(&env, &host.admin_sso, &host.id).await,
            &format!("/{}/admin/members/{guest_id}", host.id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "guest revoke -> 204");
    let membership_left: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?",
    )
    .bind(&host.id)
    .bind(&guest_id)
    .fetch_one(&env.pool)
    .await
    .unwrap()
    .get::<i64, _>("c");
    assert_eq!(membership_left, 0, "guest membership removed");
    let scoped: Vec<String> =
        sqlx::query_scalar("SELECT tenant_id FROM user_permissions WHERE user_id = ?")
            .bind(&guest_id)
            .fetch_all(&env.pool)
            .await
            .unwrap();
    assert_eq!(
        scoped,
        vec![home.id.clone()],
        "only host-scoped permission rows are cleaned up"
    );
    let (still_home, status): (String, String) =
        sqlx::query_as("SELECT tenant_id, status FROM users WHERE id = ?")
            .bind(&guest_id)
            .fetch_one(&env.pool)
            .await
            .expect("guest user still exists");
    assert_eq!(
        still_home, home.id,
        "guest user record remains in home tenant"
    );
    assert_eq!(status, "ACTIVE", "guest user state untouched by host admin");
}

/// Guarantee 5: the OIDC flow is isolated by membership checks and per-tenant issuers.
/// - An SSO session without membership is treated as unauthenticated in that tenant (goes to login).
/// - An access token issued by tenant A is rejected at tenant B's /userinfo (exact iss match).
/// - Clients are not resolved across tenant boundaries either.
/// - After accepting, a guest can join the host tenant's flow via SSO.
#[tokio::test]
async fn oidc_flow_enforces_membership_and_per_tenant_issuer() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let a = create_tenant(&env, &root_sso, "OidcA").await;
    let b = create_tenant(&env, &root_sso, "OidcB").await;
    let client_a = insert_public_client(&env.pool, &a.id).await;
    let client_b = insert_public_client(&env.pool, &b.id).await;

    // A user of tenant A (with HOME membership) and their SSO session.
    let (user_a, _) = create_user(&env, &a.admin_sso, &a.id).await;
    let sso_cookie = create_sso_session(&env.pool, &user_a).await;

    // In tenant B's flow without membership it is treated as unauthenticated (no code; goes to login; §8).
    // Decision 2 of ADR-0018: the SSO decision is made in resume (web passes it in the body), not in /authorize (cookie).
    let res = send(
        &env.app,
        Request::builder()
            .uri(authorize_uri(&b.id, &client_b))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let handle = support::handoff_handle(&res);
    let body = support::resume_authorize(&env.app, &b.id, &handle, Some(&sso_cookie)).await;
    assert_eq!(
        body["result"], "login_required",
        "SSO session without membership must not resume in tenant B: {body}"
    );

    // In home tenant A, a code is issued via SSO.
    let res = send(
        &env.app,
        Request::builder()
            .uri(authorize_uri(&a.id, &client_a))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let handle = support::handoff_handle(&res);
    let body = support::resume_authorize(&env.app, &a.id, &handle, Some(&sso_cookie)).await;
    assert_eq!(body["result"], "redirect", "SSO resume in tenant A: {body}");
    let callback = body["redirect_to"].as_str().unwrap().to_string();
    assert!(
        callback.starts_with(REDIRECT_URI),
        "expected code redirect, got {callback}"
    );
    let code = query_param(&callback, "code").expect("authorization code");

    // Using A's code at B's /token is rejected because the client is not resolved across the tenant boundary.
    let res = exchange_code(&env.app, &b.id, &client_a, &code).await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "tenant A client must not resolve in tenant B token endpoint"
    );

    // It can be exchanged at the correct tenant A's /token.
    let res = exchange_code(&env.app, &a.id, &client_a, &code).await;
    assert_eq!(res.status(), StatusCode::OK, "token exchange in tenant A");
    let tokens = body_json(res).await;
    let access_token = tokens["access_token"].as_str().unwrap().to_string();

    // An access token issued by A is rejected at B's /userinfo (exact iss match; §6).
    let res = send(
        &env.app,
        Request::builder()
            .uri(format!("/{}/userinfo", b.id))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "tenant A access token must be rejected by tenant B userinfo"
    );
    // It is accepted at A's /userinfo.
    let res = send(
        &env.app,
        Request::builder()
            .uri(format!("/{}/userinfo", a.id))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "tenant A userinfo accepts");

    // Guest join: B invites user_a, and once the user accepts they can join B's flow via SSO (§8).
    let res = send(
        &env.app,
        post(
            &tok(&env, &b.admin_sso, &b.id).await,
            &format!("/{}/admin/invitations", b.id),
            json!({ "user_id": user_a }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let token = body_json(res).await["token"].as_str().unwrap().to_string();
    let res = send(
        &env.app,
        cookie_post(
            &sso_cookie,
            &format!("/{}/invitations/accept", b.id),
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "guest accepts invitation"
    );

    let res = send(
        &env.app,
        Request::builder()
            .uri(authorize_uri(&b.id, &client_b))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let handle = support::handoff_handle(&res);
    let body = support::resume_authorize(&env.app, &b.id, &handle, Some(&sso_cookie)).await;
    assert_eq!(
        body["result"], "redirect",
        "guest with ACTIVE membership resumes SSO in tenant B: {body}"
    );
    let callback = body["redirect_to"].as_str().unwrap().to_string();
    let code_b = query_param(&callback, "code").expect("code for tenant B");

    // The guest's token is also issued by B's issuer and usable at B's /userinfo.
    let res = exchange_code(&env.app, &b.id, &client_b, &code_b).await;
    assert_eq!(res.status(), StatusCode::OK, "guest token exchange in B");
    let guest_tokens = body_json(res).await;
    let guest_access = guest_tokens["access_token"].as_str().unwrap();
    let res = send(
        &env.app,
        Request::builder()
            .uri(format!("/{}/userinfo", b.id))
            .header(AUTHORIZATION, format!("Bearer {guest_access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "guest userinfo in tenant B");
}

/// There is one signing key set for all tenants, so child tenant admins must not touch it (task #580).
///
/// Previously the route only checked `idp.keys:write`, and any child tenant's `idp.tenant.admin` could
/// create, retire or delete the global keys (deleting would make tokens of every tenant, root included, unverifiable).
#[tokio::test]
async fn child_tenant_admin_cannot_touch_the_global_signing_keys() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let tenant = create_tenant(&env, &root_sso, "Keys").await;
    let child = tok(&env, &tenant.admin_sso, &tenant.id).await;

    let keys_before: i64 = sqlx::query("SELECT COUNT(*) AS n FROM signing_keys")
        .fetch_one(&env.pool)
        .await
        .expect("count keys")
        .get("n");
    let kid: Option<String> = sqlx::query("SELECT kid FROM signing_keys LIMIT 1")
        .fetch_optional(&env.pool)
        .await
        .expect("pick a key")
        .map(|row| row.get("kid"));
    let kid = kid.unwrap_or_else(|| "no-such-kid".to_string());

    let forbidden = vec![
        get(&child, &format!("/{}/admin/signing-keys", tenant.id)),
        post(
            &child,
            &format!("/{}/admin/signing-keys", tenant.id),
            json!({ "algorithm": "ES256", "activate_immediately": true }),
        ),
        support::post_empty(
            &child,
            &format!("/{}/admin/signing-keys/{kid}/retire", tenant.id),
        ),
        delete(&child, &format!("/{}/admin/signing-keys/{kid}", tenant.id)),
    ];
    for request in forbidden {
        let uri = request.uri().to_string();
        let res = send(&env.app, request).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{uri}");
    }
    let keys_after: i64 = sqlx::query("SELECT COUNT(*) AS n FROM signing_keys")
        .fetch_one(&env.pool)
        .await
        .expect("count keys")
        .get("n");
    assert_eq!(keys_before, keys_after, "child admin must not add keys");

    // Key permissions cannot be handed out in a child tenant (do not leave permissions that cannot be exercised).
    let (user_id, _) = create_user(&env, &tenant.admin_sso, &tenant.id).await;
    let res = send(
        &env.app,
        post(
            &child,
            &format!("/{}/admin/users/{user_id}/permissions", tenant.id),
            json!({ "permission_code": "idp.keys:write" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "grant idp.keys:write");

    // Admin console tailoring: in a child tenant, key permissions do not appear in the "exercisable" list.
    let res = send(
        &env.app,
        get(&child, &format!("/{}/admin/whoami", tenant.id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let perms = body_json(res).await["permissions"].clone();
    let perms: Vec<String> = serde_json::from_value(perms).expect("permissions");
    assert!(
        perms.iter().any(|code| code == "idp.users:write"),
        "{perms:?}"
    );
    assert!(
        !perms.iter().any(|code| code.starts_with("idp.keys:")),
        "{perms:?}"
    );

    // root's admin can handle them as before.
    let root = tok(&env, &root_sso, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        get(
            &root,
            &format!("/{}/admin/signing-keys", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "root lists keys");
    let res = send(
        &env.app,
        get(&root, &format!("/{}/admin/whoami", env.root_tenant_id)),
    )
    .await;
    let perms: Vec<String> =
        serde_json::from_value(body_json(res).await["permissions"].clone()).expect("permissions");
    assert!(
        perms.iter().any(|code| code == "idp.keys:write"),
        "{perms:?}"
    );
}
