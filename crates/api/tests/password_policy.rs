//! Integration tests for the password policy (AP7; spec §11.2).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test password_policy
//!
//! Unit tests (`assay_core::application::password_policy`) look at the decision itself; here we look at
//! **whether the inputs to the decision actually land in the DB**. That history rows pile up and get pruned, that the
//! password set time is recorded, and that expiry turns into a forced change at login cannot be checked with fake
//! repositories.
//!
//! The expiry is decided by a setting (`PASSWORD_MAX_AGE_DAYS`), so this file is a dedicated test binary that
//! sets the env var at startup. Every test sets the same value, so parallel runs do not disagree.

mod support;

use serde_json::json;
use support::{body_json, create_sso_session, post_internal, send, SERVICE_TOKEN};

/// Policy settings of this binary. History is "current + 2 retired", expiry is 30 days.
fn apply_policy_env() {
    std::env::set_var("PASSWORD_HISTORY_COUNT", "3");
    std::env::set_var("PASSWORD_MAX_AGE_DAYS", "30");
}

/// Calls self-service password change (`/internal/account/change-password`) once.
async fn change_password(
    app: &axum::Router,
    sso_session_id: &str,
    current: &str,
    new: &str,
) -> serde_json::Value {
    let response = send(
        app,
        post_internal(
            "/internal/account/change-password",
            Some(SERVICE_TOKEN),
            json!({
                "sso_session_id": sso_session_id,
                "current_password": current,
                "new_password": new,
            }),
        ),
    )
    .await;
    body_json(response).await
}

#[tokio::test]
async fn rejects_reused_passwords_and_prunes_history_to_the_policy_depth() {
    apply_policy_env();
    let Some(env) = support::setup("password_policy_reuse").await else {
        return;
    };
    let username = format!("pw-reuse-{}", support::unique());
    let p1 = "initial-password-1";
    support::register_user(&env.app, &env.root_tenant_id, &username, p1).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    let user_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("registered user");
    let sso = create_sso_session(&env.pool, &user_id).await;

    // The set time is recorded at self-registration (the start of expiry; if NULL it falls back to the creation time).
    let changed_at: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT password_changed_at FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_one(&env.pool)
            .await
            .expect("read password_changed_at");
    assert!(
        changed_at.is_some(),
        "self-registration must record when the password was set"
    );

    // The same value as the current one is rejected as reuse (the depth-1 part of the history).
    let body = change_password(&env.app, &sso, p1, p1).await;
    assert_eq!(body["result"], "weak_password");
    assert_eq!(body["reason"], "reused");

    // Changing to another value works.
    let p2 = "second-password-2";
    let body = change_password(&env.app, &sso, p1, p2).await;
    assert_eq!(body["result"], "ok", "unexpected response: {body}");

    // One retired hash is stored.
    let history: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_password_history WHERE user_id = ?")
            .bind(&user_id)
            .fetch_one(&env.pool)
            .await
            .expect("count history");
    assert_eq!(history, 1);

    // Cannot go back to a retired password.
    let body = change_password(&env.app, &sso, p2, p1).await;
    assert_eq!(body["result"], "weak_password");
    assert_eq!(body["reason"], "reused");

    // Changing twice more prunes the retired side to the depth (3 - 1 current = 2).
    let p3 = "third-password-333";
    let p4 = "fourth-password-44";
    assert_eq!(
        change_password(&env.app, &sso, p2, p3).await["result"],
        "ok"
    );
    assert_eq!(
        change_password(&env.app, &sso, p3, p4).await["result"],
        "ok"
    );
    let history: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_password_history WHERE user_id = ?")
            .bind(&user_id)
            .fetch_one(&env.pool)
            .await
            .expect("count history");
    assert_eq!(history, 2, "history must be pruned to the policy depth");

    // The oldest password pruned away can be used again (makes explicit that what is not kept cannot be checked).
    let body = change_password(&env.app, &sso, p4, p1).await;
    assert_eq!(
        body["result"], "ok",
        "a password older than the retained depth is accepted again: {body}"
    );
}

#[tokio::test]
async fn expired_password_sends_the_user_to_the_forced_change_form() {
    apply_policy_env();
    let Some(env) = support::setup("password_policy_expiry").await else {
        return;
    };
    let username = format!("pw-expiry-{}", support::unique());
    let password = "expiring-password-1";
    support::register_user(&env.app, &env.root_tenant_id, &username, password).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    let login = json!({
        "tenant_id": env.root_tenant_id,
        "username": username,
        "password": password,
    });

    // Right after setting it is within the expiry.
    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            login.clone(),
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["result"], "success", "unexpected response: {body}");

    // Moving the set time back 31 days (= beyond the 30-day validity) requires a change at the next login.
    let aged_user_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("registered user");
    sqlx::query(
        "UPDATE users SET password_changed_at = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 31 DAY) \
         WHERE id = ?",
    )
    .bind(&aged_user_id)
    .execute(&env.pool)
    .await
    .expect("age the password");

    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            login.clone(),
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["result"], "password_change_required",
        "an expired password must not sign in directly: {body}"
    );

    // The change form (forced change path) accepts it even if `must_change_password` is not set.
    let new_password = "renewed-password-22";
    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal/change-password",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "username": username,
                "current_password": password,
                "new_password": new_password,
            }),
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["result"], "success", "unexpected response: {body}");

    // The change updates the set time and brings it back within the expiry.
    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "username": username,
                "password": new_password,
            }),
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["result"], "success", "unexpected response: {body}");
}
