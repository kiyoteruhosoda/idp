//! AP15b: 主たるログイン識別子を登録簿へ移し終えた状態（AP8 の contract フェーズ 後半）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test primary_login_identifier
//!
//! この移行の失敗は「利用者がユーザー名でログインできなくなる」形で出る。前半は「両方に在る」
//! ことを固定していた。後半で `users.preferred_username` を落としたので、ここで固定するのは
//! **登録簿だけで完結している**という一点である:
//!
//! 1. 利用者を作ると主識別子が登録簿の行になり、その値で解決できる。
//! 2. プロフィールで名前を変えると登録簿が追随し、古い名前では解決しない。
//! 3. 主識別子は識別子単位で無効化・削除できない（できるとログインできなくなる）。
//! 4. 他人が使っている値は**拒否される**（前半は諦めて `users` 側で解決し続けていた）。

mod support;

use idp_api::domain::login_identifier::{LoginIdentifierType, UserLoginIdentifier};
use idp_api::domain::repositories::{UserLoginIdentifierRepository, UserRepository};
use idp_api::domain::tenant::TenantId;
use idp_api::domain::user::User;
use idp_api::domain::values::UserStatus;
use idp_api::infrastructure::repositories::user::SqlxUserRepository;
use idp_api::infrastructure::repositories::user_login_identifier::SqlxUserLoginIdentifierRepository;
use sqlx::MySqlPool;
use uuid::Uuid;

/// 登録簿に載っている主識別子（表示値）。
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
        password_hash: "x".to_string(),
        must_change_password: false,
        password_changed_at: None,
        status: UserStatus::Active,
        failed_login_count: 0,
        locked_until: None,
        created_at: now,
        updated_at: now,
    }
}

/// 作成とプロフィール編集のどちらでも、登録簿の主識別子行が「今ログインに使える値」になる。
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
        "主識別子は登録簿の行として在る"
    );
    // 読み出した利用者にも同じ値が載る（`preferred_username` クレーム・一覧の表示はここを見る）。
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

    // 名前を変えると登録簿が追随する。追随しないと、古い名前でログインできてしまうか、
    // 新しい名前でログインできないかのどちらかになる。
    let renamed = format!("{username}-renamed");
    users
        .update_profile(user.id, &user.email, Some(&renamed), Some("Renamed"))
        .await
        .expect("update profile");
    assert_eq!(
        registry_primary(&env.pool, user.id).await.as_deref(),
        Some(renamed.as_str()),
        "登録簿が古い名前を指したままにならない"
    );

    // どちらの名前でも「新しい名前だけが解決する」。
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
        "古い名前は解決せず、予約も残さない（残っていると別人の登録を邪魔する）"
    );

    // 主識別子を外すと登録簿からも消える。
    users
        .update_profile(user.id, &user.email, None, None)
        .await
        .expect("clear preferred_username");
    assert_eq!(registry_primary(&env.pool, user.id).await, None);
}

/// 主識別子は識別子単位で止められない・消せない（止めるならアカウントの無効化）。
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
        "主識別子は無効化できない"
    );
    assert!(
        !identifiers
            .delete(primary.id, user.id)
            .await
            .expect("delete"),
        "主識別子は削除できない"
    );
    assert_eq!(
        registry_primary(&env.pool, user.id).await.as_deref(),
        Some(username.as_str()),
        "弾かれた操作で行が消えたり無効になったりしない"
    );

    // 追加の識別子は従来どおり止められる・消せる。
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

/// 他人が既に使っている値は主識別子にできない。
///
/// 前半（expand）はここで諦めて `users.preferred_username` 側を正としていた。列を落とした今、
/// 諦めると**そのユーザー名でログインできない利用者を黙って作る**ことになるので、`Conflict` で
/// 操作ごと失敗させる。衝突の検出は DB の一意制約（tenant × 種別 × 正規化値）まで届く。
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
    // 所有者は**追加の**識別子としてこの値を持つ（主識別子の一意制約だけでは防げない形）。
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
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create extra identifier");

    // 作成でぶつかると、利用者ごと作られない。
    let newcomer = new_user(tenant_id, &taken);
    let err = users
        .create(&newcomer)
        .await
        .expect_err("a taken value must not become someone else's primary identifier");
    assert!(
        matches!(err, idp_api::domain::error::DomainError::Conflict(_)),
        "expected a conflict, got {err:?}"
    );
    assert!(
        users.find_by_id(newcomer.id).await.expect("find").is_none(),
        "失敗した作成の残骸が残らない"
    );

    // 既存利用者の改名でも同じ。
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
        matches!(err, idp_api::domain::error::DomainError::Conflict(_)),
        "expected a conflict, got {err:?}"
    );

    // 所有者の側は無傷（黙って書き換えられていない）。
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
