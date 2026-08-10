//! AP11: 認証器の秘密を登録簿へ集約する移行（AP9 の contract フェーズ 前半）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test authenticator_secret_migration
//!
//! この移行の失敗は「利用者が MFA を通れなくなり自力で復旧できない」形で出る。ここで固定するのは
//! **移行中に両方が読める**という一点で、具体的には:
//!
//! 1. 元の表にしか秘密が無い行（移送前・古いプロセスが書いた行）も読める。
//! 2. 新しく書いた秘密は**両方**に載る（古いプロセスから見ても設定済みに見える）。
//! 3. 消したときは**両方**から消える（失効させた鍵が片側に残らない）。

mod support;

use idp_api::domain::repositories::{TotpSecretRepository, WebAuthnCredentialRepository};
use idp_api::domain::totp_secret::TotpSecret;
use idp_api::domain::webauthn_credential::WebAuthnCredential;
use idp_api::infrastructure::repositories::totp_secret::SqlxTotpSecretRepository;
use idp_api::infrastructure::repositories::webauthn_credential::SqlxWebAuthnCredentialRepository;
use sqlx::MySqlPool;
use uuid::Uuid;

/// 登録簿に載っている TOTP の秘密（無ければ `None`）。
async fn registry_totp_secret(pool: &MySqlPool, user_id: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT secret_encrypted FROM user_authenticators \
         WHERE user_id = ? AND authenticator_type = 'totp' AND status <> 'revoked' LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .expect("read registry")
    .flatten()
}

async fn legacy_totp_secret(pool: &MySqlPool, user_id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT secret_encrypted FROM user_totp_secrets WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .expect("read legacy table")
}

/// 元の表にしか秘密が無い状態でも読める（移送前の行・古いプロセスが書いた行）。
#[tokio::test]
async fn a_secret_that_only_exists_in_the_legacy_table_is_still_readable() {
    let Some(env) = support::setup("ap11 totp fallback").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("uuid");

    // 古いプロセスの書き込みを模す（登録簿には触れない）。
    sqlx::query(
        "INSERT INTO user_totp_secrets (user_id, secret_encrypted, confirmed_at) \
         VALUES (?, 'legacy-only-secret', UTC_TIMESTAMP(6))",
    )
    .bind(&user_id)
    .execute(&env.pool)
    .await
    .expect("insert legacy secret");
    assert_eq!(registry_totp_secret(&env.pool, &user_id).await, None);

    let repo = SqlxTotpSecretRepository::new(env.pool.clone());
    let found = repo
        .find_by_user_id(user_uuid)
        .await
        .expect("find")
        .expect("the legacy row must still be readable");
    assert_eq!(found.secret_encrypted, "legacy-only-secret");
}

/// 新しく書いた秘密は両方に載り、削除では両方から消える。
#[tokio::test]
async fn totp_secrets_are_written_to_and_cleared_from_both_places() {
    let Some(env) = support::setup("ap11 totp dual write").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("uuid");

    // 登録簿の行（`register_totp_pending` 相当）を用意する。
    sqlx::query(
        "INSERT INTO user_authenticators (id, user_id, authenticator_type, status, created_at) \
         VALUES (?, ?, 'totp', 'pending', UTC_TIMESTAMP(6))",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(&user_id)
    .execute(&env.pool)
    .await
    .expect("insert registry row");

    let repo = SqlxTotpSecretRepository::new(env.pool.clone());
    let now = chrono::Utc::now();
    repo.upsert(&TotpSecret {
        user_id: user_uuid,
        secret_encrypted: "fresh-secret".to_string(),
        confirmed_at: Some(now),
        created_at: now,
        updated_at: now,
    })
    .await
    .expect("upsert");

    assert_eq!(
        registry_totp_secret(&env.pool, &user_id).await.as_deref(),
        Some("fresh-secret"),
        "登録簿（新しい単一の出所）へ載る"
    );
    assert_eq!(
        legacy_totp_secret(&env.pool, &user_id).await.as_deref(),
        Some("fresh-secret"),
        "元の表へも載る（古いプロセスがこちらを読むため）"
    );

    repo.delete(user_uuid).await.expect("delete");
    assert_eq!(
        registry_totp_secret(&env.pool, &user_id).await,
        None,
        "失効させた共有鍵が登録簿に残らない"
    );
    assert_eq!(legacy_totp_secret(&env.pool, &user_id).await, None);
}

/// パスキーは credential ID からの逆引きが要（認証レスポンスが持ってくるのはこの値だけ）。
/// 登録簿からも元の表からも引けること、削除で逆引きが両方から消えることを確かめる。
#[tokio::test]
async fn passkeys_are_reachable_by_credential_id_from_either_place() {
    let Some(env) = support::setup("ap11 webauthn lookup").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("uuid");
    let credential_row_id = Uuid::now_v7();
    let credential_id = format!("cred-{}", Uuid::new_v4());

    // 登録簿の行（`register_webauthn` 相当）を先に作る。
    sqlx::query(
        "INSERT INTO user_authenticators \
         (id, user_id, authenticator_type, status, label, credential_ref, created_at) \
         VALUES (?, ?, 'webauthn', 'active', 'Test key', ?, UTC_TIMESTAMP(6))",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(&user_id)
    .bind(credential_row_id.to_string())
    .execute(&env.pool)
    .await
    .expect("insert registry row");

    let repo = SqlxWebAuthnCredentialRepository::new(env.pool.clone());
    let now = chrono::Utc::now();
    repo.create(&WebAuthnCredential {
        id: credential_row_id,
        user_id: user_uuid,
        credential_id: credential_id.clone(),
        passkey_json: "{\"fake\":\"passkey\"}".to_string(),
        name: "Test key".to_string(),
        created_at: now,
        last_used_at: None,
    })
    .await
    .expect("create credential");

    // 秘密と credential ID が登録簿にも載る。
    let registry: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT secret_encrypted, credential_id FROM user_authenticators \
         WHERE credential_ref = ?",
    )
    .bind(credential_row_id.to_string())
    .fetch_one(&env.pool)
    .await
    .expect("read registry");
    assert_eq!(registry.0.as_deref(), Some("{\"fake\":\"passkey\"}"));
    assert_eq!(registry.1.as_deref(), Some(credential_id.as_str()));

    // 逆引きが通る（登録簿が先に当たる）。
    let found = repo
        .find_by_credential_id(&credential_id)
        .await
        .expect("lookup")
        .expect("the passkey must be reachable by its credential id");
    assert_eq!(found.user_id, user_uuid);
    assert_eq!(found.passkey_json, "{\"fake\":\"passkey\"}");

    // 削除すると逆引きに当たらなくなる（片側に残ると、消したはずの鍵で認証が通る）。
    repo.delete(found.id, user_uuid).await.expect("delete");
    assert!(
        repo.find_by_credential_id(&credential_id)
            .await
            .expect("lookup")
            .is_none(),
        "deleted passkeys must not remain reachable in either place"
    );
}
