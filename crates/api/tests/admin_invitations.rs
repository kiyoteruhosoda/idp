//! How the invitee of a guest invitation is specified (ADR-0061).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_invitations
//!
//! The invitee is a user homed in another tenant, and ⚠ **the inviting tenant's admin cannot see the invitee's tenant roster**
//! (ADR-0009 §3). So when only internal IDs were accepted, admins had to enter a value that appears nowhere
//! in assay. What is checked here is that resolution works correctly across tenants:
//!
//! 1. **Invitations by email address work** (when it resolves to one person across tenants).
//! 2. **If users with the same address exist in two tenants, nobody is invited** — which one gets invited must not
//!    be decided by index order. ⚠ The response is "not found" and does not say it was ambiguous.
//! 3. **Internal IDs (old field name `user_id`) work as before** (do not break machines already calling it).
//! 4. Input that is neither is rejected with 400 before talking about existence.
//!
//! Resolution itself is SQL (looking up `users` across tenants), so unit tests with fakes
//! (`application::invitation`) cannot check it.

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_json, create_sso_session, exchange_admin_token, post, send, setup as support_setup,
    unique, TestEnv,
};

async fn setup() -> Option<TestEnv> {
    support_setup("admin invitations").await
}

/// Exchanges the SSO session for an admin token for the target tenant (ADR-0037).
async fn tok(env: &TestEnv, sso: &str, tenant_id: &str) -> String {
    exchange_admin_token(&env.app, tenant_id, sso).await
}

/// root creates a new tenant (the creator root becomes its ACTIVE GUEST admin; §4).
async fn create_tenant(env: &TestEnv, root_sso: &str, name: &str) -> String {
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
    body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string()
}

/// Creates a user in the given tenant with a chosen email address and returns its internal ID.
async fn create_user(env: &TestEnv, root_sso: &str, tenant_id: &str, email: &str) -> String {
    let res = send(
        &env.app,
        post(
            &tok(env, root_sso, tenant_id).await,
            &format!("/{tenant_id}/admin/users"),
            json!({ "email": email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create user {email}");
    body_json(res).await["user_id"]
        .as_str()
        .expect("user id")
        .to_string()
}

/// Creates an invitation with the root tenant as the guest's destination.
async fn invite(
    env: &TestEnv,
    root_sso: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    send(
        &env.app,
        post(
            &tok(env, root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/invitations", env.root_tenant_id),
            body,
        ),
    )
    .await
}

#[tokio::test]
async fn a_guest_can_be_invited_by_email_address() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let home = create_tenant(&env, &root_sso, &format!("InviteByEmail{}", unique())).await;
    let email = format!("invitee-{}@example.com", unique());
    create_user(&env, &root_sso, &home, &email).await;

    let res = invite(&env, &root_sso, json!({ "invitee": email })).await;

    assert_eq!(res.status(), StatusCode::CREATED, "invited by email");
    let created = body_json(res).await;
    assert_eq!(
        created["invitee_email"].as_str(),
        Some(email.as_str()),
        "the invitation names the person that address belongs to"
    );
    assert!(
        created["token"].as_str().is_some_and(|t| t.len() >= 32),
        "the one-time token still comes back"
    );
}

/// ⚠ When users with the same email address exist in two tenants, **nobody is invited**.
///
/// `users.email` is unique only within a tenant. Picking one would let index order decide the invitee.
#[tokio::test]
async fn an_email_shared_by_two_tenants_invites_nobody() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let one = create_tenant(&env, &root_sso, &format!("SharedOne{}", unique())).await;
    let other = create_tenant(&env, &root_sso, &format!("SharedTwo{}", unique())).await;
    let email = format!("shared-{}@example.com", unique());
    create_user(&env, &root_sso, &one, &email).await;
    create_user(&env, &root_sso, &other, &email).await;

    let res = invite(&env, &root_sso, json!({ "invitee": email })).await;

    // ⚠ Do not say "ambiguous" (saying so would leak only the existence of another tenant's user).
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "nobody is invited");
}

/// Invitations by internal ID and the old field name `user_id` work as before.
#[tokio::test]
async fn the_old_user_id_field_still_names_the_guest() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let home = create_tenant(&env, &root_sso, &format!("InviteById{}", unique())).await;
    let email = format!("by-id-{}@example.com", unique());
    let user_id = create_user(&env, &root_sso, &home, &email).await;

    let res = invite(&env, &root_sso, json!({ "user_id": user_id })).await;

    assert_eq!(res.status(), StatusCode::CREATED, "invited by internal id");
    // ⚠ When invited by internal ID, the invitee's address is not returned (task #591; otherwise an ID alone
    //   could extract the addresses of other tenants' users).
    let created = body_json(res).await;
    assert!(created.get("invitee_email").is_none(), "{created}");
    assert!(!created.to_string().contains(&email), "{created}");
}

#[tokio::test]
async fn an_invitee_that_is_neither_an_email_nor_an_id_is_refused() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;

    let res = invite(&env, &root_sso, json!({ "invitee": "guest" })).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "not an identifier");
}
