//! Integration tests (with DB) for the admin MFA reset API
//! (`POST /{tenant_id}/admin/users/{user_id}/mfa-reset`; MT21).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_mfa_reset
//!
//! A recovery path for when a device is lost and the user cannot reset it themselves. What is checked:
//!
//! 1. Authorization (unauthenticated 401 / no permission 403 / other tenant or nonexistent 404 / oneself 403).
//! 2. Removes **both** TOTP and Passkey. If either remains the user still cannot sign in, so it would not
//!    work as recovery. Other people's credentials are not affected.
//! 3. SSO sessions held by the lost device are revoked.
//! 4. Succeeds even without MFA set up, and the response shows "nothing was removed".
//! 5. The audit log records the granularity of the reset, and secrets do not leak.

mod support;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{admin_token, body_json, create_plain_user, post, send};

/// Inserts the target user's TOTP directly (creates "configured" without the setup API;
/// this test is about reset, not the registration flow). Secrets live in the authenticator registry
/// (`user_authenticators`; unified in AP11b).
async fn insert_totp(pool: &MySqlPool, user_id: &str) {
    sqlx::query(
        "INSERT INTO user_authenticators \
         (id, user_id, authenticator_type, status, secret_encrypted, confirmed_at, created_at) \
         VALUES (?, ?, 'totp', 'active', 'test-ciphertext', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert totp secret");
}

async fn insert_passkey(pool: &MySqlPool, user_id: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO user_authenticators \
         (id, user_id, authenticator_type, status, label, secret_encrypted, credential_id, \
          confirmed_at, created_at) \
         VALUES (?, ?, 'webauthn', 'active', 'test device', '{}', ?, UTC_TIMESTAMP(6), \
                 UTC_TIMESTAMP(6))",
    )
    .bind(&id)
    .bind(user_id)
    .bind(format!("cred-{id}"))
    .execute(pool)
    .await
    .expect("insert passkey");
    id
}

/// Number of authenticators "still usable". Reset does not delete rows but **drops the secret to invalidate**,
/// so count by whether a secret exists, not by rows (if any remain, recovery has not succeeded).
async fn count_usable(pool: &MySqlPool, user_id: &str, authenticator_type: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS c FROM user_authenticators \
         WHERE user_id = ? AND authenticator_type = ? AND status <> 'revoked' \
           AND secret_encrypted IS NOT NULL",
    )
    .bind(user_id)
    .bind(authenticator_type)
    .fetch_one(pool)
    .await
    .expect("count usable authenticators")
    .get::<i64, _>("c")
}

async fn count_totp(pool: &MySqlPool, user_id: &str) -> i64 {
    count_usable(pool, user_id, "totp").await
}

async fn count_passkeys(pool: &MySqlPool, user_id: &str) -> i64 {
    count_usable(pool, user_id, "webauthn").await
}

async fn count_sso_sessions(pool: &MySqlPool, user_id: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM sso_sessions WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count sso sessions")
        .get::<i64, _>("c")
}

/// Audit rows limited to the targets created in this run (the shared test DB keeps rows from past runs).
async fn audit_reasons(pool: &MySqlPool, actor_id: &str, target_id: &str) -> Vec<String> {
    sqlx::query(
        "SELECT reason FROM audit_log \
         WHERE event_type = 'user.mfa_reset' AND user_id = ? AND result = 'success' \
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

#[tokio::test]
async fn admin_resets_both_mfa_factors_and_revokes_sessions() {
    let Some(env) = support::setup("admin mfa reset").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let bystander = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/mfa-reset", env.root_tenant_id);

    // ── Authorization: no token is 401, a user without permission is 403.
    let res = send(
        &env.app,
        support::anonymous(axum::http::Method::POST, &uri, None),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &bystander).await;
    let res = send(&env.app, post(&plain_token, &uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no admin perm -> 403");

    // ── Give the target a TOTP and 2 Passkeys, and an unrelated user one Passkey.
    insert_totp(&env.pool, &target).await;
    insert_passkey(&env.pool, &target).await;
    insert_passkey(&env.pool, &target).await;
    insert_passkey(&env.pool, &bystander).await;
    // An SSO session assumed to be held by the lost device.
    admin_token(&env.app, &env.pool, &env.root_tenant_id, &target).await;
    assert!(count_sso_sessions(&env.pool, &target).await > 0);

    let res = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::OK, "admin can reset mfa");
    let body = body_json(res).await;
    assert_eq!(body["user_id"], target);
    assert_eq!(body["totp_removed"], true);
    assert_eq!(body["passkeys_removed"], 2);

    // Both TOTP and Passkeys are gone; the unrelated user's remain.
    assert_eq!(count_totp(&env.pool, &target).await, 0);
    assert_eq!(count_passkeys(&env.pool, &target).await, 0);
    assert_eq!(
        count_passkeys(&env.pool, &bystander).await,
        1,
        "other users' passkeys must survive"
    );
    // The lost device's session is revoked too.
    assert_eq!(count_sso_sessions(&env.pool, &target).await, 0);

    // The audit log records the granularity and secrets do not leak.
    let reasons = audit_reasons(&env.pool, &env.root_admin_id, &target).await;
    assert_eq!(reasons.len(), 1, "one audit row: {reasons:?}");
    assert!(reasons[0].contains("totp=removed"), "{}", reasons[0]);
    assert!(reasons[0].contains("passkeys=2"), "{}", reasons[0]);
    assert!(
        !reasons[0].contains("test-ciphertext"),
        "secrets must not leak into the audit log: {}",
        reasons[0]
    );

    // ── The second time succeeds with "nothing removed" (admins operate without knowing whether it is set up).
    let res = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["totp_removed"], false);
    assert_eq!(body["passkeys_removed"], 0);
}

#[tokio::test]
async fn mfa_reset_rejects_self_and_unknown_users() {
    let Some(env) = support::setup("admin mfa reset guards").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // One cannot reset oneself (use self-service; prevents lockout by mistake).
    let self_uri = format!(
        "/{}/admin/users/{}/mfa-reset",
        env.root_tenant_id, env.root_admin_id
    );
    let res = send(&env.app, post(&admin_tok, &self_uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "self -> 403");

    // Nonexistent and invalid UUID are both 404 (prevents existence guessing).
    for target in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_string()] {
        let uri = format!("/{}/admin/users/{target}/mfa-reset", env.root_tenant_id);
        let res = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "target={target}");
    }
}
