//! AP11b: integration tests for the state after authenticator secrets were unified into the registry (second half of AP9's contract phase).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test authenticator_secret_migration
//!
//! The first half (0035) pinned "both the registry and the original tables are readable". The second half dropped the
//! original tables, so what is pinned here is the single point that **the registry alone is self-contained**. Specifically:
//!
//! 1. Secrets are on registry rows and read from there.
//! 2. Without a row to hold it, it **fails instead of silently dropping** (never creating the state
//!    "registered but not configured").
//! 3. Deleting also removes it from the registry (revoked keys do not remain).
//! 4. Secrets of revoked rows are not read (re-registration marks old rows `revoked`).

mod support;

use assay_api::domain::repositories::{TotpSecretRepository, WebAuthnCredentialRepository};
use assay_api::domain::totp_secret::TotpSecret;
use assay_api::domain::webauthn_credential::WebAuthnCredential;
use assay_api::infrastructure::repositories::totp_secret::SqlxTotpSecretRepository;
use assay_api::infrastructure::repositories::webauthn_credential::SqlxWebAuthnCredentialRepository;
use sqlx::MySqlPool;
use uuid::Uuid;

/// The TOTP secret on the registry (`None` if absent).
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

/// Prepares a row equivalent to `register_totp_pending` and returns its row id.
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

/// Secrets are on registry rows and read from there. Deleting also removes them from the registry.
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
        "the revoked shared key does not remain in the registry"
    );
    assert!(repo
        .find_by_user_id(user_uuid)
        .await
        .expect("find")
        .is_none());
}

/// **Fails if there is nowhere to put it.** Now that the registry is the only place for secrets, silently doing nothing
/// when there is no row would create users who are "registered but not configured" (the user has already scanned
/// the QR code and first notices at the next sign-in).
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

/// Secrets of revoked rows are not read. Re-registration marks old rows `revoked`, so looking at them would let
/// **authentication pass with a shared key that should have been revoked**.
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

/// Passkeys hinge on reverse lookup from the credential ID (the only value the authentication response carries).
/// One registry row is one passkey, and deleting it makes the reverse lookup miss.
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

    // Exactly one row exists in the registry as "usable".
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

    // Sign counter updates apply to the same row (if it does not advance, clone detection does not work).
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

    // Deleting makes the reverse lookup miss (if it remained, authentication would pass with a deleted key).
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

/// Duplicate registration of the same credential ID is rejected by a DB unique constraint (not relying on app-layer pre-checks).
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
        matches!(err, assay_api::domain::error::DomainError::Conflict(_)),
        "expected a conflict, got {err:?}"
    );
}
