//! 配る機械が読む SSH の鍵の一覧（`GET /{tenant_id}/admin/ssh-keys`。task #885・ADR-0072）の統合テスト。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_ssh_keys
//!
//! - `idp.ssh-keys:read` を持つ**機械クライアント**だけが読める。人の管理トークン（`idp.tenant.admin`）・
//!   コードを持たない機械・トークン無しは断る
//! - 組織で `SSH_KEYS_ENABLED` が無効なら空。有効にすると有効な鍵が出る
//! - 止めた利用者の鍵・取り消した（消した）鍵は出ない

mod support;

use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{json, Value};
use support::{
    body_json, create_sso_session, delete, exchange_admin_token, get, post, put, send, unique,
    TestEnv,
};

/// 試験用の sk-ssh-ed25519 の公開鍵（本体 base64）と、その指紋（`ssh-keygen -l` と同じ形）。
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

/// root が組織を作り、その組織の管理者（`idp.tenant.admin`）の SSO セッションを返す。
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

/// 組織の機械クライアントを作り、`codes` を組織の管理者が付けて、管理トークンを返す。
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
    // テナント管理者は `idp.ssh-keys:read` を含意するので、機械へ付けられる。
    let reader = machine(&env, &tenant_id, &admin_tok, &["idp.ssh-keys:read"]).await;
    let other = machine(&env, &tenant_id, &admin_tok, &["idp.users:read"]).await;

    // 鍵を持つ利用者（利用者名つき）と、その鍵。
    let owner = support::create_plain_user(&env.pool, &tenant_id).await;
    let username = format!("kyon{}", unique());
    sqlx::query("UPDATE users SET preferred_username = ? WHERE id = ?")
        .bind(&username)
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

    // 無効（既定）の組織では空。
    let (status, body) = list(&env, &reader, &tenant_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "keys": [] }));

    // 有効にすると出る。
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

    // 人の管理トークン（idp.tenant.admin）・コードを持たない機械・トークン無しは読めない。
    assert_eq!(
        list(&env, &admin_tok, &tenant_id).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        list(&env, &other, &tenant_id).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(list(&env, "", &tenant_id).await.0, StatusCode::UNAUTHORIZED);
    // 別の組織のトークンは通らない（iss・aud が組織ごと）。
    assert_eq!(
        list(&env, &reader, &env.root_tenant_id).await.0,
        StatusCode::UNAUTHORIZED
    );

    // 止めた利用者の鍵は出ない。
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

    // 取り消した（消した）鍵は出ない。
    sqlx::query("DELETE FROM user_ssh_keys WHERE id = ?")
        .bind(&key_id)
        .execute(&env.pool)
        .await
        .unwrap();
    assert_eq!(
        list(&env, &reader, &tenant_id).await.1,
        json!({ "keys": [] })
    );

    // 後片付け（設定を既定へ戻す）。
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
