//! Integration tests for the endpoint that lets machines set only the mail (SMTP) settings (ADR-0051).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_smtp_settings
//!
//! Key points checked:
//! - A **machine** with `idp.smtp:write` can set only the mail route without touching other parts of
//!   system settings (SMS, runtime, restart). Without this endpoint the SMTP password could only be
//!   pasted into the screen by hand.
//! - **The plaintext password is not returned**. Only whether it is set is returned.
//! - `idp.tenant.admin` does not reach it. If it did, root's tenant admins could change the global
//!   mail route.
//! - It can be granted in tenants other than root (ADR-0058 §8), but it reaches **only that tenant's route**, and
//!   the global route endpoint stays 403 unless root.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::json;
use support::{
    admin_token, body_json, create_plain_user, create_sso_session, exchange_admin_token, get, post,
    put, restore_smtp_settings, send, snapshot_smtp_settings, unique, SmtpSettingsLock,
};

fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// Gets an admin token via `client_credentials` + `resource={issuer}/{tenant}/admin`.
async fn machine_token(
    env: &support::TestEnv,
    tenant_id: &str,
    client_id: &str,
    secret: &str,
) -> String {
    let resource = format!("{}/{}/admin", env.issuer, tenant_id);
    let body = format!(
        "grant_type=client_credentials&resource={}",
        percent_encoding::utf8_percent_encode(&resource, percent_encoding::NON_ALPHANUMERIC)
    );
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(client_id, secret))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "management token");
    body_json(res).await["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

#[tokio::test]
async fn a_machine_with_the_smtp_code_sets_the_mail_route_and_never_reads_the_password_back() {
    let Some(env) = support::setup("admin smtp settings").await else {
        return;
    };
    // ⚠ **There is only one SMTP configuration in the system.** It is actually rewritten, so serialize with other tests
    //   touching the same settings (`password_reset`) **across binaries**, and restore it afterwards.
    let smtp_lock = SmtpSettingsLock::acquire(&env.pool).await;
    let saved = snapshot_smtp_settings(&env.pool).await;

    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/clients/{client_id}/permissions",
                env.root_tenant_id
            ),
            json!({ "permission_code": "idp.smtp:write" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.smtp:write");

    let machine_tok = machine_token(&env, &env.root_tenant_id, &client_id, &secret).await;
    let smtp_uri = format!("/{}/admin/system-settings/smtp", env.root_tenant_id);
    let host = format!("smtp-{}.example.com", unique());

    let res = send(
        &env.app,
        put(
            &machine_tok,
            &smtp_uri,
            json!({
                "smtp_host": host,
                "smtp_port": 587,
                "smtp_username": "AKIA_EXAMPLE",
                "smtp_password": "s3cret-derived-password",
                "smtp_from_address": "noreply@example.com",
                "smtp_use_tls": true,
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "machine can set SMTP");
    let updated = body_json(res).await;
    assert_eq!(updated["smtp_host"], json!(host));
    assert_eq!(updated["smtp_password_set"], json!(true));
    assert!(
        updated.get("smtp_password").is_none(),
        "the plaintext password must never come back: {updated}"
    );

    // Reading is implied by `:write` (implication 4 of ADR-0037). It can be read without adding another code.
    let res = send(&env.app, get(&machine_tok, &smtp_uri)).await;
    assert_eq!(res.status(), StatusCode::OK, "write implies read");
    let fetched = body_json(res).await;
    assert_eq!(fetched["smtp_host"], json!(host));
    assert_eq!(fetched["smtp_username"], json!("AKIA_EXAMPLE"));
    assert_eq!(fetched["smtp_password_set"], json!(true));
    assert!(fetched.get("smtp_password").is_none());

    // ⚠ **Also check it did not spread.** It does not reach anything other than the mail route.
    let res = send(
        &env.app,
        get(
            &machine_tok,
            &format!("/{}/admin/system-settings", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.smtp:write must not reach the whole system settings"
    );

    restore_smtp_settings(&env.pool, &saved).await;
    smtp_lock.release().await;
}

#[tokio::test]
async fn a_tenant_admin_cannot_reach_the_smtp_settings() {
    let Some(env) = support::setup("smtp tenant admin").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/users/{user}/permissions", env.root_tenant_id),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.tenant.admin");

    let sso = create_sso_session(&env.pool, &user).await;
    let tok = exchange_admin_token(&env.app, &env.root_tenant_id, &sso).await;
    let smtp_uri = format!("/{}/admin/system-settings/smtp", env.root_tenant_id);

    let res = send(&env.app, get(&tok, &smtp_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.tenant.admin must not imply idp.smtp:read"
    );
    let res = send(
        &env.app,
        put(&tok, &smtp_uri, json!({ "smtp_host": "nope.example.com" })),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.tenant.admin must not imply idp.smtp:write"
    );
}

/// ADR-0058 §8: `idp.smtp:*` can be granted inside a tenant too. It reaches **only that tenant's route**, and
/// the global route endpoint stays 403 unless root. Responses for tenants without a route do not show global values.
#[tokio::test]
async fn a_child_tenant_machine_sets_only_its_own_mail_route() {
    let Some(env) = support::setup("smtp tenant route").await else {
        return;
    };
    let admin_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let root_tok = exchange_admin_token(&env.app, &env.root_tenant_id, &admin_sso).await;
    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("child-{}", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create a child tenant");
    let child = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();
    let child_tok = exchange_admin_token(&env.app, &child, &admin_sso).await;
    let (client_id, secret) = support::insert_m2m_client(&env.pool, &child, &["openid"]).await;

    let res = send(
        &env.app,
        post(
            &child_tok,
            &format!("/{child}/admin/clients/{client_id}/permissions"),
            json!({ "permission_code": "idp.smtp:write" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the SMTP code is grantable inside a tenant (ADR-0058 §8)"
    );
    let machine_tok = machine_token(&env, &child, &client_id, &secret).await;
    let own_uri = format!("/{child}/admin/settings/smtp");

    // Until it has a route it follows the global one. ⚠ Global values are not shown to the tenant (fields are empty).
    let res = send(&env.app, get(&machine_tok, &own_uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let before = body_json(res).await;
    assert_eq!(before["inherited"], json!(true));
    assert_eq!(before["smtp_host"], json!(""));

    let host = format!("smtp-{}.tenant.example", unique());
    let res = send(
        &env.app,
        put(
            &machine_tok,
            &own_uri,
            json!({
                "smtp_host": host,
                "smtp_port": 587,
                "smtp_username": "tenant-user",
                "smtp_password": "tenant-secret",
                "smtp_from_address": "noreply@tenant.example",
                "smtp_use_tls": true,
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "a tenant sets its own route");
    let updated = body_json(res).await;
    assert_eq!(updated["inherited"], json!(false));
    assert_eq!(updated["smtp_host"], json!(host));

    // Destinations pointing at the home network / loopback are rejected on save (task #740).
    for internal in ["mariadb", "10.10.2.11", "127.0.0.1", "169.254.169.254"] {
        let res = send(
            &env.app,
            put(
                &machine_tok,
                &own_uri,
                json!({ "smtp_host": internal, "smtp_from_address": "noreply@tenant.example" }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{internal}");
    }
    assert_eq!(updated["smtp_password_set"], json!(true));
    assert!(
        updated.get("smtp_password").is_none(),
        "the plaintext password must never come back: {updated}"
    );

    // ⚠ It does not reach the global route endpoint (the root gate on the using side).
    let whole_uri = format!("/{child}/admin/system-settings/smtp");
    let res = send(&env.app, get(&machine_tok, &whole_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a tenant-scoped SMTP code must not reach the whole-IdP route"
    );

    // Deleting it reverts to following the global one.
    let res = send(&env.app, support::delete(&machine_tok, &own_uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["inherited"], json!(true));
}

/// ⚠ `idp.tenant.admin` does not reach even the tenant route (granting is one explicit code).
#[tokio::test]
async fn a_tenant_admin_does_not_reach_its_own_mail_route_without_the_code() {
    let Some(env) = support::setup("smtp tenant admin").await else {
        return;
    };
    let admin_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let root_tok = exchange_admin_token(&env.app, &env.root_tenant_id, &admin_sso).await;

    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("child-{}", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create a child tenant");
    let child = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();

    // The creator is the new tenant's bootstrap admin (ADR-0009 §5) = holds `idp.tenant.admin`.
    // ⚠ `idp.system.admin` exists only in root's scope, so it is not in child tenant tokens.
    let child_tok = exchange_admin_token(&env.app, &child, &admin_sso).await;
    let own_uri = format!("/{child}/admin/settings/smtp");

    let res = send(&env.app, get(&child_tok, &own_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.tenant.admin must not imply idp.smtp:read"
    );
    let res = send(
        &env.app,
        put(
            &child_tok,
            &own_uri,
            json!({ "smtp_host": "smtp.example.com", "smtp_from_address": "a@example.com" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.tenant.admin must not imply idp.smtp:write"
    );
}
