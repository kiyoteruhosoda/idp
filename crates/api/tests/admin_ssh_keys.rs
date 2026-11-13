//! Integration tests for the list of SSH keys read by the distributing machine (`GET /{tenant_id}/admin/ssh-keys`; task #885, ADR-0072).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_ssh_keys
//!
//! - Only **machine clients** with `idp.ssh-keys:read` can read it. People's admin tokens (`idp.tenant.admin`),
//!   machines without the code and requests without a token are refused
//! - Empty when `SSH_KEYS_ENABLED` is disabled for the organization. When enabled, active keys appear
//! - Keys of suspended users and revoked (deleted) keys do not appear

mod support;

use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{json, Value};
use support::{
    body_json, create_sso_session, delete, exchange_admin_token, get, post, put, send, unique,
    TestEnv,
};

/// A test sk-ssh-ed25519 public key (base64 body) and its fingerprint (same format as `ssh-keygen -l`).
fn sample_key(seed: u8) -> (String, String) {
    use sha2::Digest;
    fn put_string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut blob = Vec::new();
    put_string(&mut blob, b"sk-ssh-ed25519@openssh.com");
    put_string(&mut blob, &[seed; 32]);
    put_string(&mut blob, b"ssh:");
    let fingerprint = format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(&blob))
    );
    (
        base64::engine::general_purpose::STANDARD.encode(&blob),
        fingerprint,
    )
}

/// root creates an organization and returns the SSO session of that organization's admin (`idp.tenant.admin`).
async fn create_tenant(env: &TestEnv) -> (String, String) {
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let root_tok = exchange_admin_token(&env.app, &env.root_tenant_id, &root_sso).await;
    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("SshKeys-{}", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create tenant");
    let tenant_id = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();

    let res = send(
        &env.app,
        post(
            &exchange_admin_token(&env.app, &tenant_id, &root_sso).await,
            &format!("/{tenant_id}/admin/users"),
            json!({ "email": format!("ssh-admin-{}@example.com", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create tenant admin");
    let admin_id = body_json(res).await["user_id"]
        .as_str()
        .expect("user id")
        .to_string();
    let res = send(
        &env.app,
        post(
            &exchange_admin_token(&env.app, &tenant_id, &root_sso).await,
            &format!("/{tenant_id}/admin/users/{admin_id}/permissions"),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant tenant admin");
    support::finish_setup(&env.pool, &admin_id).await;
    (tenant_id, create_sso_session(&env.pool, &admin_id).await)
}

/// Creates a machine client of the organization, has the org admin grant `codes`, and returns the admin token.
async fn machine(env: &TestEnv, tenant_id: &str, admin_tok: &str, codes: &[&str]) -> String {
    let (client_id, secret) = support::insert_m2m_client(&env.pool, tenant_id, &["openid"]).await;
    for code in codes {
        let res = send(
            &env.app,
            post(
                admin_tok,
                &format!("/{tenant_id}/admin/clients/{client_id}/permissions"),
                json!({ "permission_code": code }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "grant {code} to the machine");
    }
    let res =
        support::request_management_token(&env.app, &env.issuer, tenant_id, &client_id, &secret)
            .await;
    assert_eq!(res.status(), StatusCode::OK, "machine management token");
    body_json(res).await["access_token"]
        .as_str()
        .expect("access token")
        .to_string()
}

async fn list(env: &TestEnv, tok: &str, tenant_id: &str) -> (StatusCode, Value) {
    let res = send(&env.app, get(tok, &format!("/{tenant_id}/admin/ssh-keys"))).await;
    let status = res.status();
    (status, body_json(res).await)
}

#[tokio::test]
async fn only_the_distribution_machine_reads_the_active_keys_of_an_enabled_tenant() {
    let Some(env) = support::setup("admin ssh keys").await else {
        return;
    };
    let (tenant_id, admin_sso) = create_tenant(&env).await;
    let admin_tok = exchange_admin_token(&env.app, &tenant_id, &admin_sso).await;
    // The tenant admin implies `idp.ssh-keys:read`, so it can grant it to the machine.
    let reader = machine(&env, &tenant_id, &admin_tok, &["idp.ssh-keys:read"]).await;
    let other = machine(&env, &tenant_id, &admin_tok, &["idp.users:read"]).await;

    // A user with a key (with a username) and the key.
    let owner = support::create_plain_user(&env.pool, &tenant_id).await;
    let username = format!("kyon{}", unique());
    // The username is the registry's primary identifier (`users` has no column for it).
    sqlx::query(
        "INSERT INTO user_login_identifiers \
         (id, tenant_id, user_id, identifier_type, display_value, normalized_value, \
          is_active, primary_of_user) \
         VALUES (?, ?, ?, 'username', ?, ?, 1, ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&tenant_id)
    .bind(&owner)
    .bind(&username)
    .bind(username.to_lowercase())
    .bind(&owner)
    .execute(&env.pool)
    .await
    .unwrap();
    let (blob, fingerprint) = sample_key(1);
    let key_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO user_ssh_keys \
         (id, tenant_id, user_id, name, key_type, key_blob, fingerprint, created_at) \
         VALUES (?, ?, ?, 'kyon-pc', 'sk-ssh-ed25519@openssh.com', ?, ?, UTC_TIMESTAMP(6))",
    )
    .bind(&key_id)
    .bind(&tenant_id)
    .bind(&owner)
    .bind(&blob)
    .bind(&fingerprint)
    .execute(&env.pool)
    .await
    .unwrap();

    // Empty in an organization where it is disabled (the default).
    let (status, body) = list(&env, &reader, &tenant_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "keys": [] }));

    // Enabling it makes them appear.
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("/{tenant_id}/admin/settings/tenant/keys/SSH_KEYS_ENABLED"),
            json!({ "value": "true" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "enable ssh keys");
    let (status, body) = list(&env, &reader, &tenant_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let keys = body["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1, "{body}");
    assert_eq!(keys[0]["username"], json!(username));
    assert_eq!(keys[0]["name"], json!("kyon-pc"));
    assert_eq!(
        keys[0]["public_key"],
        json!(format!("sk-ssh-ed25519@openssh.com {blob}"))
    );
    assert_eq!(keys[0]["fingerprint"], json!(fingerprint));
    assert!(keys[0]["created_at"].as_str().unwrap().ends_with('Z'));

    // People's admin tokens (idp.tenant.admin), machines without the code and no token cannot read.
    assert_eq!(
        list(&env, &admin_tok, &tenant_id).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        list(&env, &other, &tenant_id).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(list(&env, "", &tenant_id).await.0, StatusCode::UNAUTHORIZED);
    // Another organization's token does not pass (iss and aud are per organization).
    assert_eq!(
        list(&env, &reader, &env.root_tenant_id).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Keys of suspended users do not appear.
    sqlx::query("UPDATE users SET status = 'DISABLED' WHERE id = ?")
        .bind(&owner)
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        list(&env, &reader, &tenant_id).await.1,
        json!({ "keys": [] })
    );
    sqlx::query("UPDATE users SET status = 'ACTIVE' WHERE id = ?")
        .bind(&owner)
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        list(&env, &reader, &tenant_id).await.1["keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Revoked (deleted) keys do not appear.
    sqlx::query("DELETE FROM user_ssh_keys WHERE id = ?")
        .bind(&key_id)
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        list(&env, &reader, &tenant_id).await.1,
        json!({ "keys": [] })
    );

    // Cleanup (restore the setting to the default).
    let res = send(
        &env.app,
        delete(
            &admin_tok,
            &format!("/{tenant_id}/admin/settings/tenant/keys/SSH_KEYS_ENABLED"),
        ),
    )
    .await;
    assert!(res.status().is_success(), "clear setting");
}
