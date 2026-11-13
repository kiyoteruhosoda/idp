//! Integration tests running authenticator self-management (AP9) against a real DB.
//!
//! The screen (web) calls api after passing the step-up gate. Because this was not tested,
//! **that TOTP registration had never once succeeded in production** could only be noticed from the screen
//! (api returned `internal`, and web returned 500 without logging).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test mfa_totp_self_registration

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{body_json, post_internal, send, SERVICE_TOKEN};

/// The step-up gate (the screen passes it first).
async fn step_up_check(app: &axum::Router, tenant: &str, sso: &str) -> serde_json::Value {
    let response = send(
        app,
        post_internal(
            "/internal/step-up/check",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "sso_session_id": sso,
                "operation": "manage_authenticators",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "step-up check status");
    body_json(response).await
}

/// A user who just signed in can start TOTP registration.
///
/// **Looks into the QR content.** The `otpauth://` URI separates `{issuer}:{account}` with `:`, so if the
/// issuer contains the OIDC issuer URL (`https://…`) the URI cannot be built and registration fails entirely.
/// "200 was returned" alone does not catch this failure.
#[tokio::test]
async fn a_signed_in_user_can_start_a_totp_registration() {
    let Some(env) = support::setup("totp self registration").await else {
        return;
    };
    let (app, pool, tenant) = (env.app, env.pool, env.root_tenant_id);

    let user_id = support::create_plain_user(&pool, &tenant).await;
    let sso = support::create_sso_session(&pool, &user_id).await;

    let check = step_up_check(&app, &tenant, &sso).await;
    assert_eq!(
        check["result"], "satisfied",
        "satisfied right after sign-in"
    );

    let response = send(
        &app,
        post_internal(
            "/internal/mfa/totp/setup",
            Some(SERVICE_TOKEN),
            json!({ "sso_session_id": sso }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "totp setup status");
    let setup = body_json(response).await;
    assert_eq!(
        setup["result"], "ok",
        "TOTP provisional registration can start: {setup}"
    );

    let uri = setup["totp_uri"].as_str().expect("totp_uri");
    assert!(uri.starts_with("otpauth://totp/"), "{uri}");
    // The label is the host name, not the URL. If the scheme's `:` remained, totp-rs would reject it.
    assert!(
        !uri.contains("https%3A") && !uri.contains("http%3A"),
        "{uri}"
    );
    // The account name is looked up from the user by api (empty would be indistinguishable in authenticator app lists).
    let account: String = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .expect("read user email");
    let encoded_account = account.replace('@', "%40");
    assert!(
        uri.contains(&encoded_account) || uri.contains(&account),
        "the QR carries the account name: uri={uri} account={account}"
    );

    let secret = setup["secret_base32"].as_str().expect("secret_base32");
    assert!(
        !secret.is_empty(),
        "raw code for users who cannot use the QR"
    );
}

/// Recovery code issuance (AP9). Sits next to TOTP in "authenticator self-management" and likewise had no test.
#[tokio::test]
async fn a_signed_in_user_can_issue_recovery_codes() {
    let Some(env) = support::setup("recovery codes").await else {
        return;
    };
    let (app, pool, tenant) = (env.app, env.pool, env.root_tenant_id);

    let user_id = support::create_plain_user(&pool, &tenant).await;
    let sso = support::create_sso_session(&pool, &user_id).await;

    let response = send(
        &app,
        post_internal(
            "/internal/account/recovery-codes",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": tenant, "sso_session_id": sso }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "recovery codes status");
    let issued = body_json(response).await;
    assert_eq!(issued["result"], "ok", "can be issued: {issued}");
    let codes = issued["codes"].as_array().expect("codes");
    assert!(!codes.is_empty(), "the batch is not empty: {issued}");

    // Reflected in the "n remaining" the screen shows.
    let response = send(
        &app,
        post_internal(
            "/internal/account/authenticators",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": tenant, "sso_session_id": sso }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "authenticators status");
    let list = body_json(response).await;
    assert_eq!(
        list["result"], "ok",
        "the authenticator list can be fetched: {list}"
    );
    assert_eq!(
        list["recovery_codes_remaining"],
        codes.len() as u64,
        "the remaining count equals the number issued: {list}"
    );
}
