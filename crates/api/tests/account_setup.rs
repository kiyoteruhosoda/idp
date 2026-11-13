//! One-time account setup links (ADR-0062).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test account_setup
//!
//! When an admin creates a user, a **link to hand to the user** is returned instead of a generated password. Guarantees checked:
//!
//! 1. **Creation no longer returns a password.** A link is returned instead, and it points at the user.
//! 2. ⚠ **Merely opening it does not consume it.** A preview bot fetches a link pasted in chat first,
//!    so reading (`describe`) must not consume it.
//! 3. **The link lets the user set a password** (through the same endpoint as the forgotten-password reset). Once set,
//!    the link is dead.
//! 4. ⚠ **A forgotten-password reset link cannot register a passkey** (split by purpose; ADR-0062 decision 2).

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_json, create_sso_session, exchange_admin_token, get, post, post_internal, send,
    setup as support_setup, unique, TestEnv, SERVICE_TOKEN,
};

/// "Provisional or not" as read by the members screen (ADR-0064).
async fn pending_setup(env: &TestEnv, admin_tok: &str, user_id: &str) -> bool {
    let res = send(
        &env.app,
        get(
            admin_tok,
            &format!("/{}/admin/members/{user_id}", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await["pending_setup"]
        .as_bool()
        .expect("pending_setup is always present")
}

async fn setup() -> Option<TestEnv> {
    support_setup("account setup").await
}

async fn tok(env: &TestEnv, sso: &str, tenant_id: &str) -> String {
    exchange_admin_token(&env.app, tenant_id, sso).await
}

/// An admin creates a user in the root tenant and returns `(user_id, setup_url, token)`.
async fn create_user(env: &TestEnv, admin_tok: &str) -> (String, String, String) {
    let res = send(
        &env.app,
        post(
            admin_tok,
            &format!("/{}/admin/users", env.root_tenant_id),
            json!({ "email": format!("setup-{}@example.com", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "admin creates a user");
    let created = body_json(res).await;
    assert!(
        created.get("generated_password").is_none(),
        "creating a user no longer hands the admin a password: {created}"
    );
    let setup_url = created["setup_url"]
        .as_str()
        .expect("setup url")
        .to_string();
    let token = setup_url
        .split("token=")
        .nth(1)
        .expect("the link carries the token")
        .to_string();
    (
        created["user_id"].as_str().expect("user id").to_string(),
        setup_url,
        token,
    )
}

async fn describe(env: &TestEnv, token: &str) -> serde_json::Value {
    let res = send(
        &env.app,
        post_internal(
            "/internal/account-setup/describe",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": env.root_tenant_id, "token": token }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "describe answers");
    body_json(res).await
}

#[tokio::test]
async fn creating_a_user_hands_out_a_setup_link_instead_of_a_password() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;

    let (_user_id, setup_url, token) = create_user(&env, &admin_tok).await;

    assert!(
        setup_url.contains("/account-setup?token="),
        "the link lands on the setup screen: {setup_url}"
    );
    let view = describe(&env, &token).await;
    assert_eq!(view["result"], "ok", "the link can be read: {view}");
    assert_eq!(
        view["allows_passkey"], true,
        "a link the admin issued may register a passkey"
    );
    assert!(
        view["email"].as_str().is_some_and(|e| e.contains('@')),
        "the screen can say whose link it is: {view}"
    );
}

/// ⚠ Reading does not consume it (so preview bots cannot eat it).
#[tokio::test]
async fn reading_the_link_does_not_use_it_up() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;
    let (_user_id, _url, token) = create_user(&env, &admin_tok).await;

    for _ in 0..3 {
        assert_eq!(describe(&env, &token).await["result"], "ok");
    }
}

/// The link lets the user set a password. Once set, the link is dead.
///
/// ADR-0064: provisional right after creation, cleared once the user sets it.
#[tokio::test]
async fn the_link_sets_a_password_once() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;
    let (user_id, _url, token) = create_user(&env, &admin_tok).await;
    assert!(
        pending_setup(&env, &admin_tok, &user_id).await,
        "a user the admin just created is pending until they set it up"
    );

    let complete = json!({
        "tenant_id": env.root_tenant_id,
        "token": token,
        "new_password": format!("SetupByTheUser-{}!", unique()),
    });
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/complete",
            Some(SERVICE_TOKEN),
            complete.clone(),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        body_json(res).await["result"],
        "ok",
        "the setup link goes through the same door as a forgotten-password reset"
    );

    // A used-up link can no longer be read.
    assert_eq!(describe(&env, &token).await["result"], "invalid_or_expired");
    assert!(
        !pending_setup(&env, &admin_tok, &user_id).await,
        "setting a password ends the pending state"
    );
}

/// An admin reissue also returns **only a link** (nobody knows the replaced password).
#[tokio::test]
async fn reissuing_a_password_also_hands_out_only_a_link() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;
    let (user_id, _url, first_token) = create_user(&env, &admin_tok).await;

    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{user_id}/password-reset",
                env.root_tenant_id
            ),
            json!({}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "admin reissues");
    let body = body_json(res).await;
    assert!(
        body.get("generated_password").is_none(),
        "the admin never receives a usable password: {body}"
    );
    assert!(body["setup_url"]
        .as_str()
        .is_some_and(|u| u.contains("token=")));

    // ⚠ **Reissuing kills the previous link** (with two live links nobody knows which was handed over).
    assert_eq!(
        describe(&env, &first_token).await["result"],
        "invalid_or_expired"
    );
}

/// ⚠ A forgotten-password reset link cannot add a passkey (split by purpose).
#[tokio::test]
async fn a_forgotten_password_link_may_not_add_a_passkey() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;
    let (user_id, _url, setup_token) = create_user(&env, &admin_tok).await;
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&env.pool)
        .await
        .expect("the created user");
    let request_reset = || {
        post_internal(
            "/internal/password-reset/request",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": env.root_tenant_id, "email": email }),
        )
    };
    let reset_tokens = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ? AND purpose = 'reset'",
        )
        .bind(&user_id)
        .fetch_one(&env.pool)
        .await
        .expect("count reset tokens")
    };

    // ⚠ ADR-0064: while provisional, "Forgot password" issues no reset link
    //   (the user has the setup link; do not let someone who can read the mail finish the provisional signup).
    let res = send(&env.app, request_reset()).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the answer never reveals the state"
    );
    assert_eq!(reset_tokens().await, 0, "no reset link for a pending user");

    // After the user finishes setup, press "Forgot password" (one reset-purpose token is created).
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/complete",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "token": setup_token,
                "new_password": format!("SetupByTheUser-{}!", unique()),
            }),
        ),
    )
    .await;
    assert_eq!(body_json(res).await["result"], "ok", "setup finished");
    let res = send(&env.app, request_reset()).await;
    assert_eq!(res.status(), StatusCode::OK, "reset requested");

    // ⚠ The token plaintext appears only in the mail (or startup log), so this test checks from the DB row
    //   that the "purpose" is `reset`. Refusing passkeys is decided by that column.
    let purpose: String = sqlx::query_scalar(
        "SELECT purpose FROM password_reset_tokens \
         WHERE user_id = ? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&user_id)
    .fetch_one(&env.pool)
    .await
    .expect("a live token");
    assert_eq!(
        purpose, "reset",
        "a link the user asked for is not a setup link"
    );
}
