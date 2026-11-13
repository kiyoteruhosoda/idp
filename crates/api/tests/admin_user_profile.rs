//! Integration tests (with DB) for the admin user profile edit API
//! (`PATCH /{tenant_id}/admin/users/{user_id}/profile`; MT25).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_user_profile
//!
//! What is checked:
//!
//! 1. Authorization (unauthenticated 401 / no permission 403 / other tenant or nonexistent 404), and unlike state
//!    changes, **one can edit oneself** (profile changes do not cause lockout).
//! 2. Partial updates (omitted fields are unchanged) and clearing `name` with an empty string.
//! 3. Duplicates within the tenant (email / preferred_username) are 409, format / length violations are 400.
//! 4. Only the changed field names remain in the audit log; values (PII) do not leak.

mod support;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{admin_token, body_json, create_plain_user, patch, send};

/// Audit rows limited to the targets created in this run (the shared test DB keeps rows from past runs).
async fn audit_reasons(pool: &MySqlPool, actor_id: &str, target_id: &str) -> Vec<String> {
    sqlx::query(
        "SELECT reason FROM audit_log \
         WHERE event_type = 'user.profile_updated' AND user_id = ? AND result = 'success' \
           AND reason LIKE ?",
    )
    .bind(actor_id)
    .bind(format!("%user={target_id}%"))
    .fetch_all(pool)
    .await
    .expect("audit rows")
    .iter()
    .map(|row| row.get::<String, _>("reason"))
    .collect()
}

async fn stored_profile(
    pool: &MySqlPool,
    user_id: &str,
) -> (String, Option<String>, Option<String>) {
    // The username lives in the registry (AP15b). It is no longer in `users`.
    let row = sqlx::query("SELECT email, name FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("load user");
    (
        row.get("email"),
        support::primary_username(pool, user_id).await,
        row.get("name"),
    )
}

#[tokio::test]
async fn admin_edits_email_username_and_display_name() {
    let Some(env) = support::setup("admin user profile").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let bystander = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/profile", env.root_tenant_id);
    let unique = uuid::Uuid::now_v7().simple().to_string();

    // ── Authorization: no token is 401, a user without permission is 403.
    let res = send(
        &env.app,
        support::anonymous(axum::http::Method::PATCH, &uri, Some(json!({}))),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &bystander).await;
    let res = send(&env.app, patch(&plain_token, &uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no admin perm -> 403");

    // ── Update three fields at once.
    let email = format!("renamed-{unique}@example.com");
    let username = format!("renamed-{unique}");
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &uri,
            json!({ "email": email, "preferred_username": username, "name": "Renamed User" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "admin can edit the profile");
    let body = body_json(res).await;
    assert_eq!(body["email"], email);
    assert_eq!(body["preferred_username"], username);
    assert_eq!(body["name"], "Renamed User");
    assert_eq!(
        stored_profile(&env.pool, &target).await,
        (
            email.clone(),
            Some(username.clone()),
            Some("Renamed User".to_string())
        )
    );

    // ── Partial update: only name as empty string = clear. email / preferred_username unchanged.
    let res = send(&env.app, patch(&admin_tok, &uri, json!({ "name": "" }))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        stored_profile(&env.pool, &target).await,
        (email.clone(), Some(username.clone()), None)
    );

    // ── The audit log keeps only "the changed field names", not the values (PII).
    let reasons = audit_reasons(&env.pool, &env.root_admin_id, &target).await;
    assert_eq!(reasons.len(), 2, "one row per change: {reasons:?}");
    assert!(
        reasons[0].contains("fields=email,preferred_username,name"),
        "{}",
        reasons[0]
    );
    assert!(reasons[1].contains("fields=name"), "{}", reasons[1]);
    assert!(
        reasons.iter().all(|r| !r.contains(&email)),
        "email must not leak into the audit log: {reasons:?}"
    );
    assert!(
        reasons.iter().all(|r| !r.contains("Renamed User")),
        "display name must not leak into the audit log: {reasons:?}"
    );
}

/// Changing the email address makes the primary email row follow (ADR-0050 decision 1).
///
/// Otherwise `users.email` and the registry diverge, and the old address squats in the registry
/// (nobody can take that value, yet it belongs to nobody).
///
/// **Also checks the row disappears when the same value is held as the username** (decision 6).
/// Only one row per normalized value can exist, so it was decided not to create a primary email row there.
/// If it is not deleted, reverting the email leaves an old row that disagrees with `users.email`.
#[tokio::test]
async fn changing_the_email_moves_the_primary_email_row() {
    let Some(env) = support::setup("primary email follows the profile").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/profile", env.root_tenant_id);
    let unique = uuid::Uuid::now_v7().simple().to_string();
    let first = format!("pe1-{unique}@example.com");
    let second = format!("pe2-{unique}@example.com");
    // ⚠ Make the username **email-shaped**. When a user is created without a username, the username
    //   is the email address as is (ADR-0009 §8), so this shape exists in reality.
    let username = format!("pe-{unique}@example.com");

    // ── Created from nothing (users created directly with SQL have no registry row).
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &uri,
            json!({ "email": first, "preferred_username": username }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await,
        Some(first)
    );

    // ── Follows on change (the update branch).
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({ "email": second })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await,
        Some(second)
    );

    // ── Setting the email to **the same value as one's own username** deletes the primary email row (decision 6).
    //    Only one row per normalized value can exist, so when the username row already holds that value
    //    no primary email row is created. If not deleted, `users.email` and the registry disagree.
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({ "email": username })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await,
        None,
        "only one row per value; the username row holds it, so no primary email row is created"
    );
    assert_eq!(
        support::primary_username(&env.pool, &target).await,
        Some(username),
        "the username row remains"
    );

    // ── Changing the email back to another value creates the primary email row again.
    let third = format!("pe3-{unique}@example.com");
    let res = send(&env.app, patch(&admin_tok, &uri, json!({ "email": third }))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await,
        Some(third)
    );
}

/// **The email address cannot be changed to a value someone else holds as a login identifier**
/// (ADR-0050 decision 1; the core of the requirement "email addresses should be unique").
///
/// ⚠ This direction used to pass unchecked. `update_profile` only looked at the unique constraint on `users`
/// (`(tenant_id, email)`) and not at the registry, so **A's email could be set to a value B holds as a
/// username or alias email**. With email login allowed, one input would then
/// match two people.
#[tokio::test]
async fn an_email_held_by_another_user_as_an_identifier_is_rejected() {
    let Some(env) = support::setup("primary email uniqueness").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let unique = uuid::Uuid::now_v7().simple().to_string();
    let alice = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let bob = create_plain_user(&env.pool, &env.root_tenant_id).await;

    // Add an alias email address to bob (a different value from bob's `users.email`).
    let alias = format!("alias-{unique}@example.com");
    let res = send(
        &env.app,
        support::post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{bob}/login-identifiers",
                env.root_tenant_id
            ),
            json!({"identifier_type": "email", "value": alias}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);

    // Changing alice's email to that value gives 409.
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("/{}/admin/users/{alice}/profile", env.root_tenant_id),
            json!({ "email": alias }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "an email cannot equal someone else's identifier"
    );

    // After refusing, `users` alone must not have been rewritten (it fails in the same transaction).
    let (stored_email, _, _) = stored_profile(&env.pool, &alice).await;
    assert_ne!(
        stored_email, alias,
        "refused, so users alone must not change"
    );
}

#[tokio::test]
async fn profile_edit_rejects_duplicates_and_invalid_input() {
    let Some(env) = support::setup("admin user profile guards").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let other = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/profile", env.root_tenant_id);
    let (other_email, ..) = stored_profile(&env.pool, &other).await;

    // An email already in use is 409.
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({ "email": other_email })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT, "duplicate email -> 409");

    // Format violations and clearing the login identifier are 400.
    for body in [
        json!({ "email": "not-an-email" }),
        json!({ "preferred_username": "" }),
        json!({ "name": "x".repeat(256) }),
    ] {
        let res = send(&env.app, patch(&admin_tok, &uri, body.clone())).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "body={body}");
    }

    // Nonexistent and invalid UUID are both 404 (prevents existence guessing).
    for unknown in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_string()] {
        let uri = format!("/{}/admin/users/{unknown}/profile", env.root_tenant_id);
        let res = send(&env.app, patch(&admin_tok, &uri, json!({}))).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "target={unknown}");
    }
}

/// State changes, deletion, password reissue and MFA reset forbid acting on oneself, but profile editing is allowed
/// (it causes no lockout; operations get stuck if admins cannot fix their own email).
#[tokio::test]
async fn admin_can_edit_their_own_profile() {
    let Some(env) = support::setup("admin self profile").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!(
        "/{}/admin/users/{}/profile",
        env.root_tenant_id, env.root_admin_id
    );

    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({ "name": "Root Operator" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "self edit is allowed");
    let (_, _, name) = stored_profile(&env.pool, &env.root_admin_id).await;
    assert_eq!(name.as_deref(), Some("Root Operator"));

    // Contrast: state changes on oneself are 403 (the existing line of defence has not loosened).
    let status_uri = format!("/{}/admin/users/{}", env.root_tenant_id, env.root_admin_id);
    let res = send(
        &env.app,
        patch(&admin_tok, &status_uri, json!({ "status": "DISABLED" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "self disable -> 403");
}
