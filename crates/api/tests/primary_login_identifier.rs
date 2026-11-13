//! AP15b: the state after moving primary login identifiers into the registry (second half of AP8's contract phase).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test primary_login_identifier
//!
//! A failure of this migration shows up as "users can no longer sign in with their username". The first half pinned
//! "present in both". The second half dropped `users.preferred_username`, so what is pinned here is the single point
//! that **the registry alone is self-contained**:
//!
//! 1. Creating a user makes the primary identifier a registry row, and it resolves by that value.
//! 2. Changing the name in the profile makes the registry follow, and the old name no longer resolves.
//! 3. The primary identifier cannot be disabled or deleted per identifier (otherwise sign-in would break).
//! 4. Values used by someone else are **rejected** (the first half gave up and kept resolving on the `users` side).

mod support;

use assay_api::domain::login_identifier::{LoginIdentifierType, UserLoginIdentifier};
use assay_api::domain::repositories::{UserLoginIdentifierRepository, UserRepository};
use assay_api::domain::tenant::TenantId;
use assay_api::domain::user::User;
use assay_api::domain::values::UserStatus;
use assay_api::infrastructure::repositories::user::SqlxUserRepository;
use assay_api::infrastructure::repositories::user_login_identifier::SqlxUserLoginIdentifierRepository;
use sqlx::MySqlPool;
use uuid::Uuid;

/// The primary identifier on the registry (display value).
async fn registry_primary(pool: &MySqlPool, user_id: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT display_value FROM user_login_identifiers WHERE user_id = ? AND primary_of_user IS NOT NULL",
    )
    .bind(user_id.to_string())
    .fetch_optional(pool)
    .await
    .expect("read registry")
}

fn new_user(tenant_id: TenantId, username: &str) -> User {
    let now = chrono::Utc::now();
    User {
        id: Uuid::now_v7(),
        tenant_id,
        sub: Uuid::now_v7(),
        email: format!("{username}@example.com"),
        email_verified: true,
        preferred_username: Some(username.to_string()),
        name: None,
        language: None,
        theme: None,
        password_hash: "x".to_string(),
        must_change_password: false,
        password_changed_at: None,
        status: UserStatus::Active,
        pending_setup: false,
        failed_login_count: 0,
        locked_until: None,
        created_at: now,
        updated_at: now,
    }
}

/// Both on creation and profile edit, the registry's primary identifier row becomes "the value usable for sign-in now".
#[tokio::test]
async fn the_primary_identifier_is_a_registry_row_that_follows_profile_edits() {
    let Some(env) = support::setup("ap15b primary registry").await else {
        return;
    };
    let tenant_id: TenantId = Uuid::parse_str(&env.root_tenant_id).expect("uuid").into();
    let users = SqlxUserRepository::new(env.pool.clone());

    let username = format!("ap15-{}", Uuid::new_v4().simple());
    let user = new_user(tenant_id, &username);
    users.create(&user).await.expect("create user");

    assert_eq!(
        registry_primary(&env.pool, user.id).await.as_deref(),
        Some(username.as_str()),
        "the primary identifier exists as a registry row"
    );
    // The fetched user carries the same value (the `preferred_username` claim and list display look here).
    assert_eq!(
        users
            .find_by_id(user.id)
            .await
            .expect("find")
            .expect("user")
            .preferred_username
            .as_deref(),
        Some(username.as_str())
    );

    // Renaming makes the registry follow. Otherwise either the old name could still sign in,
    // or the new name could not.
    let renamed = format!("{username}-renamed");
    users
        .update_profile(user.id, &user.email, Some(&renamed), Some("Renamed"))
        .await
        .expect("update profile");
    assert_eq!(
        registry_primary(&env.pool, user.id).await.as_deref(),
        Some(renamed.as_str()),
        "the registry does not keep pointing at the old name"
    );

    // With either name, "only the new name resolves".
    let resolved = users
        .find_by_login_identifier(tenant_id, &renamed)
        .await
        .expect("resolve");
    assert_eq!(resolved.into_user().map(|u| u.id), Some(user.id));
    assert!(
        !users
            .find_by_login_identifier(tenant_id, &username)
            .await
            .expect("resolve")
            .is_taken(),
        "the old name does not resolve and leaves no reservation (if left, it would block someone else's registration)"
    );

    // Removing the primary identifier also removes it from the registry.
    users
        .update_profile(user.id, &user.email, None, None)
        .await
        .expect("clear preferred_username");
    assert_eq!(registry_primary(&env.pool, user.id).await, None);
}

/// The primary identifier cannot be stopped or deleted per identifier (to stop it, disable the account).
#[tokio::test]
async fn the_primary_identifier_cannot_be_disabled_or_deleted_as_an_identifier() {
    let Some(env) = support::setup("ap15b primary is protected").await else {
        return;
    };
    let tenant_id: TenantId = Uuid::parse_str(&env.root_tenant_id).expect("uuid").into();
    let users = SqlxUserRepository::new(env.pool.clone());
    let identifiers = SqlxUserLoginIdentifierRepository::new(env.pool.clone());

    let username = format!("ap15-guard-{}", Uuid::new_v4().simple());
    let user = new_user(tenant_id, &username);
    users.create(&user).await.expect("create user");

    let primary = identifiers
        .list_for_user(user.id)
        .await
        .expect("list")
        .into_iter()
        .find(|i| i.is_primary)
        .expect("the primary row must exist in the registry");

    assert!(
        !identifiers
            .set_active(primary.id, user.id, false)
            .await
            .expect("set_active"),
        "the primary identifier cannot be disabled"
    );
    assert!(
        !identifiers
            .delete(primary.id, user.id)
            .await
            .expect("delete"),
        "the primary identifier cannot be deleted"
    );
    assert_eq!(
        registry_primary(&env.pool, user.id).await.as_deref(),
        Some(username.as_str()),
        "rejected operations do not delete or disable the row"
    );

    // Additional identifiers can be stopped and deleted as before.
    let now = chrono::Utc::now();
    let extra_value = format!("ap15-extra-{}", Uuid::new_v4().simple());
    let extra = UserLoginIdentifier {
        id: Uuid::now_v7(),
        tenant_id,
        user_id: user.id,
        identifier_type: LoginIdentifierType::Username,
        display_value: extra_value.clone(),
        normalized_value: LoginIdentifierType::Username.normalize(&extra_value),
        is_active: true,
        is_primary: false,
        is_primary_email: false,
        created_at: now,
        updated_at: now,
    };
    identifiers.create(&extra).await.expect("create extra");
    assert!(identifiers
        .set_active(extra.id, user.id, false)
        .await
        .expect("set_active"));
    assert!(identifiers.delete(extra.id, user.id).await.expect("delete"));
}

/// A value someone else already uses cannot become a primary identifier.
///
/// The first half (expand) gave up here and treated `users.preferred_username` as authoritative. Now that the column is
/// gone, giving up would **silently create a user who cannot sign in with that username**, so the whole operation
/// fails with `Conflict`. Collision detection reaches the DB unique constraint (tenant × normalized value; independent
/// of kind since migration 0041).
#[tokio::test]
async fn a_value_another_user_already_owns_is_rejected() {
    let Some(env) = support::setup("ap15b primary conflict").await else {
        return;
    };
    let tenant_id: TenantId = Uuid::parse_str(&env.root_tenant_id).expect("uuid").into();
    let users = SqlxUserRepository::new(env.pool.clone());
    let identifiers = SqlxUserLoginIdentifierRepository::new(env.pool.clone());

    let taken = format!("ap15b-taken-{}", Uuid::new_v4().simple());
    let owner = new_user(
        tenant_id,
        &format!("ap15b-owner-{}", Uuid::new_v4().simple()),
    );
    users.create(&owner).await.expect("create owner");
    // The owner holds this value as an **additional** identifier (a shape the primary identifier's unique constraint alone cannot prevent).
    let now = chrono::Utc::now();
    identifiers
        .create(&UserLoginIdentifier {
            id: Uuid::now_v7(),
            tenant_id,
            user_id: owner.id,
            identifier_type: LoginIdentifierType::Username,
            display_value: taken.clone(),
            normalized_value: LoginIdentifierType::Username.normalize(&taken),
            is_active: true,
            is_primary: false,
            is_primary_email: false,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create extra identifier");

    // On a collision at creation, the user is not created at all.
    let newcomer = new_user(tenant_id, &taken);
    let err = users
        .create(&newcomer)
        .await
        .expect_err("a taken value must not become someone else's primary identifier");
    assert!(
        matches!(err, assay_api::domain::error::DomainError::Conflict(_)),
        "expected a conflict, got {err:?}"
    );
    assert!(
        users.find_by_id(newcomer.id).await.expect("find").is_none(),
        "no leftovers from the failed creation remain"
    );

    // The same for renaming an existing user.
    let other = new_user(
        tenant_id,
        &format!("ap15b-other-{}", Uuid::new_v4().simple()),
    );
    users.create(&other).await.expect("create other");
    let err = users
        .update_profile(other.id, &other.email, Some(&taken), None)
        .await
        .expect_err("renaming onto a taken value must fail");
    assert!(
        matches!(err, assay_api::domain::error::DomainError::Conflict(_)),
        "expected a conflict, got {err:?}"
    );

    // The owner's side is intact (not silently rewritten).
    assert_eq!(
        users
            .find_by_login_identifier(tenant_id, &taken)
            .await
            .expect("resolve")
            .into_user()
            .map(|u| u.id),
        Some(owner.id)
    );
}
