//! AP11b: 認証器の秘密を登録簿へ一本化し終えた状態の統合テスト（AP9 の contract フェーズ 後半）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test authenticator_secret_migration
//!
//! 前半（0035）は「登録簿と元の表の両方が読める」ことを固定していた。後半で元の表を落とした
//! ので、ここで固定するのは**登録簿だけで完結している**という一点である。具体的には:
//!
//! 1. 秘密は登録簿の行に載り、そこから読める。
//! 2. 置き場所となる行が無ければ**黙って捨てずに失敗する**（登録できたのに設定されていない、
//!    という状態を作らない）。
//! 3. 消したときは登録簿からも消える（失効させた鍵が残らない）。
//! 4. 失効した行の秘密は読まない（再登録で古い行が `revoked` になるため）。

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

/// `register_totp_pending` 相当の行を用意して、その行 id を返す。
async fn insert_pending_totp_row(pool: &MySqlPool, user_id: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_authenticators (id, user_id, authenticator_type, status, created_at) \
         VALUES (?, ?, 'totp', 'pending', UTC_TIMESTAMP(6))",
    )
    .bind(id.to_string())
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert registry row");
    id
}

/// 秘密は登録簿の行に載り、そこから読める。消せば登録簿からも消える。
#[tokio::test]
async fn a_totp_secret_lives_on_the_registry_row_and_is_cleared_from_it() {
    let Some(env) = support::setup("ap11b totp registry only").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("uuid");
    insert_pending_totp_row(&env.pool, &user_id).await;

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
        Some("fresh-secret")
    );
    let found = repo
        .find_by_user_id(user_uuid)
        .await
        .expect("find")
        .expect("the secret must be readable");
    assert_eq!(found.secret_encrypted, "fresh-secret");

    repo.delete(user_uuid).await.expect("delete");
    assert_eq!(
        registry_totp_secret(&env.pool, &user_id).await,
        None,
        "失効させた共有鍵が登録簿に残らない"
    );
    assert!(repo
        .find_by_user_id(user_uuid)
        .await
        .expect("find")
        .is_none());
}

/// **置き場所が無ければ失敗する。** 秘密の置き場所が登録簿だけになった以上、行が無いときに
/// 黙って何もしないと「登録できたのに設定されていない」利用者ができる（本人は QR を読み取り
/// 終えており、次のログインで初めて気づく）。
#[tokio::test]
async fn storing_a_secret_without_a_registry_row_fails_instead_of_vanishing() {
    let Some(env) = support::setup("ap11b totp requires row").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("uuid");

    let repo = SqlxTotpSecretRepository::new(env.pool.clone());
    let now = chrono::Utc::now();
    let result = repo
        .upsert(&TotpSecret {
            user_id: user_uuid,
            secret_encrypted: "orphan-secret".to_string(),
            confirmed_at: None,
            created_at: now,
            updated_at: now,
        })
        .await;
    assert!(
        result.is_err(),
        "a secret with nowhere to go must not be silently dropped"
    );
    assert_eq!(registry_totp_secret(&env.pool, &user_id).await, None);
}

/// 失効した行の秘密は読まない。再登録すると古い行は `revoked` になるので、ここを見てしまうと
/// **取り消したはずの共有鍵で認証が通る**。
#[tokio::test]
async fn a_revoked_rows_secret_is_not_readable() {
    let Some(env) = support::setup("ap11b totp revoked").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("uuid");
    let row_id = insert_pending_totp_row(&env.pool, &user_id).await;

    let repo = SqlxTotpSecretRepository::new(env.pool.clone());
    let now = chrono::Utc::now();
    repo.upsert(&TotpSecret {
        user_id: user_uuid,
        secret_encrypted: "old-secret".to_string(),
        confirmed_at: Some(now),
        created_at: now,
        updated_at: now,
    })
    .await
    .expect("upsert");

    sqlx::query("UPDATE user_authenticators SET status = 'revoked' WHERE id = ?")
        .bind(row_id.to_string())
        .execute(&env.pool)
        .await
        .expect("revoke");

    assert!(
        repo.find_by_user_id(user_uuid)
            .await
            .expect("find")
            .is_none(),
        "a revoked authenticator's secret must not be usable"
    );
}

/// パスキーは credential ID からの逆引きが要（認証レスポンスが持ってくるのはこの値だけ）。
/// 登録簿の 1 行がパスキー 1 本であり、削除すると逆引きに当たらなくなる。
#[tokio::test]
async fn a_passkey_is_one_registry_row_reachable_by_its_credential_id() {
    let Some(env) = support::setup("ap11b webauthn lookup").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("uuid");
    let row_id = Uuid::now_v7();
    let credential_id = format!("cred-{}", Uuid::new_v4());

    let repo = SqlxWebAuthnCredentialRepository::new(env.pool.clone());
    let now = chrono::Utc::now();
    repo.create(&WebAuthnCredential {
        id: row_id,
        user_id: user_uuid,
        credential_id: credential_id.clone(),
        passkey_json: "{\"fake\":\"passkey\"}".to_string(),
        name: "Test key".to_string(),
        created_at: now,
        last_used_at: None,
    })
    .await
    .expect("create credential");

    // 登録簿に「使える」行として 1 行だけ在る。
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_authenticators \
         WHERE user_id = ? AND authenticator_type = 'webauthn' AND status = 'active' \
           AND secret_encrypted IS NOT NULL",
    )
    .bind(&user_id)
    .fetch_one(&env.pool)
    .await
    .expect("count rows");
    assert_eq!(rows, 1, "a passkey must be exactly one registry row");

    let found = repo
        .find_by_credential_id(&credential_id)
        .await
        .expect("lookup")
        .expect("the passkey must be reachable by its credential id");
    assert_eq!(found.id, row_id, "the id handed out is the registry row id");
    assert_eq!(found.user_id, user_uuid);
    assert_eq!(found.passkey_json, "{\"fake\":\"passkey\"}");
    assert_eq!(found.name, "Test key");

    // 署名カウンタの更新は同じ行へ効く（進まないとクローン検知が働かない）。
    repo.update_passkey(row_id, "{\"fake\":\"passkey2\"}", now)
        .await
        .expect("update");
    assert_eq!(
        repo.find_by_id(row_id)
            .await
            .expect("find")
            .expect("still there")
            .passkey_json,
        "{\"fake\":\"passkey2\"}"
    );

    // 削除すると逆引きに当たらなくなる（残ると、消したはずの鍵で認証が通る）。
    repo.delete(row_id, user_uuid).await.expect("delete");
    assert!(
        repo.find_by_credential_id(&credential_id)
            .await
            .expect("lookup")
            .is_none(),
        "deleted passkeys must not remain reachable"
    );
    assert!(repo
        .list_by_user_id(user_uuid)
        .await
        .expect("list")
        .is_empty());
}

/// 同じ credential ID の二重登録は DB の一意制約で弾く（アプリ層の事前チェックに頼らない）。
#[tokio::test]
async fn registering_the_same_credential_twice_is_rejected() {
    let Some(env) = support::setup("ap11b webauthn duplicate").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("uuid");
    let credential_id = format!("cred-{}", Uuid::new_v4());
    let repo = SqlxWebAuthnCredentialRepository::new(env.pool.clone());
    let now = chrono::Utc::now();
    let credential = |id: Uuid| WebAuthnCredential {
        id,
        user_id: user_uuid,
        credential_id: credential_id.clone(),
        passkey_json: "{}".to_string(),
        name: String::new(),
        created_at: now,
        last_used_at: None,
    };

    repo.create(&credential(Uuid::now_v7()))
        .await
        .expect("first registration");
    let err = repo
        .create(&credential(Uuid::now_v7()))
        .await
        .expect_err("the same credential must not register twice");
    assert!(
        matches!(err, idp_api::domain::error::DomainError::Conflict(_)),
        "expected a conflict, got {err:?}"
    );
}
