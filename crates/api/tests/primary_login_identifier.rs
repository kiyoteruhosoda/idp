//! AP15: 主たるログイン識別子を登録簿へ移す移行（AP8 の contract フェーズ 前半）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test primary_login_identifier
//!
//! この移行の失敗は「利用者がユーザー名でログインできなくなる」形で出る。ここで固定するのは
//! **移行中に両方が正しい**という一点で、具体的には:
//!
//! 1. 利用者を作ると、主識別子が `users.preferred_username` と登録簿の**両方**に載る。
//! 2. プロフィールで名前を変えると、**両方**が新しい値になる（登録簿が古い名前を指し続けない）。
//! 3. 主識別子は識別子単位で無効化・削除できない（できるとログインできなくなる）。
//! 4. 登録簿に主識別子が無い利用者（移送前の行）も、従来どおり `users` 側で解決できる。

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

async fn stored_preferred_username(pool: &MySqlPool, user_id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT preferred_username FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .fetch_one(pool)
        .await
        .expect("read user")
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

/// 作成とプロフィール編集の両方で、`users` と登録簿が同じ値を指す。
#[tokio::test]
async fn the_primary_identifier_is_written_to_both_places_and_stays_in_step() {
    let Some(env) = support::setup("ap15 primary dual write").await else {
        return;
    };
    let tenant_id: TenantId = Uuid::parse_str(&env.root_tenant_id).expect("uuid").into();
    let users = SqlxUserRepository::new(env.pool.clone());

    let username = format!("ap15-{}", Uuid::new_v4().simple());
    let user = new_user(tenant_id, &username);
    users.create(&user).await.expect("create user");

    assert_eq!(
        stored_preferred_username(&env.pool, user.id)
            .await
            .as_deref(),
        Some(username.as_str())
    );
    assert_eq!(
        registry_primary(&env.pool, user.id).await.as_deref(),
        Some(username.as_str()),
        "主識別子は登録簿にも載る（新しい経路はこちらを見る）"
    );

    // 名前を変えると両方が追随する。片方だけだと、古い名前でログインできてしまうか、
    // 新しい名前でログインできないかのどちらかになる。
    let renamed = format!("{username}-renamed");
    users
        .update_profile(user.id, &user.email, Some(&renamed), Some("Renamed"))
        .await
        .expect("update profile");
    assert_eq!(
        stored_preferred_username(&env.pool, user.id)
            .await
            .as_deref(),
        Some(renamed.as_str())
    );
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
    assert_eq!(resolved.map(|u| u.id), Some(user.id));
    assert!(
        users
            .find_by_login_identifier(tenant_id, &username)
            .await
            .expect("resolve")
            .is_none(),
        "古い名前は解決しない（登録簿に残していると別人の予約を邪魔する）"
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
    let Some(env) = support::setup("ap15 primary is protected").await else {
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

/// 登録簿に主識別子が無い利用者（移送前の行・古いプロセスが作った行）も解決できる。
/// フォールバックは `users.preferred_username` を落とす次のリリースまで残る。
#[tokio::test]
async fn a_user_whose_primary_is_only_in_the_users_table_still_resolves() {
    let Some(env) = support::setup("ap15 legacy fallback").await else {
        return;
    };
    let tenant_id: TenantId = Uuid::parse_str(&env.root_tenant_id).expect("uuid").into();
    let users = SqlxUserRepository::new(env.pool.clone());

    let username = format!("ap15-legacy-{}", Uuid::new_v4().simple());
    let user = new_user(tenant_id, &username);
    users.create(&user).await.expect("create user");

    // 移送前の状態を作る（登録簿の主識別子行だけを落とす）。
    sqlx::query(
        "DELETE FROM user_login_identifiers WHERE user_id = ? AND primary_of_user IS NOT NULL",
    )
    .bind(user.id.to_string())
    .execute(&env.pool)
    .await
    .expect("drop registry primary");
    assert_eq!(registry_primary(&env.pool, user.id).await, None);

    let resolved = users
        .find_by_login_identifier(tenant_id, &username)
        .await
        .expect("resolve");
    assert_eq!(
        resolved.map(|u| u.id),
        Some(user.id),
        "登録簿に無くても `users.preferred_username` で解決できる"
    );
}
