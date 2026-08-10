//! AP6: 段階的ロックと管理者によるロック解除。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test account_lockout
//!
//! 段階的ロックは「失敗の記録とロック判定を 1 文の UPDATE で行う」（SEC13）制約のため、
//! ロック時間の選択が SQL の中に落ちる。ドメインの計算式（`lock_duration_secs_for`）と
//! SQL が選ぶ段が**一致していること**をここで固定する。片方だけ直しても気づけるようにする。

mod support;

use axum::http::StatusCode;
use idp_api::domain::authentication_policy::LockoutPolicy;
use idp_api::domain::repositories::UserRepository;
use idp_api::infrastructure::repositories::user::SqlxUserRepository;
use support::{body_json, create_plain_user, create_sso_session, post_empty, send};
use uuid::Uuid;

/// 3 回失敗でロック、上限は初回の 4 倍（＝ 3 段）。
fn escalating_policy() -> LockoutPolicy {
    LockoutPolicy {
        max_failed_attempts: 3,
        lock_duration_secs: 60,
        max_lock_duration_secs: 240,
    }
}

/// ロック時間が段ごとに伸び、SQL が選ぶ段がドメインの計算式と一致する。
#[tokio::test]
async fn the_lock_window_grows_with_each_repeated_lockout() {
    let Some(env) = support::setup("account lockout escalation").await else {
        return;
    };
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("user id is a UUID");
    let users = SqlxUserRepository::new(env.pool.clone());
    let policy = escalating_policy();
    let now = chrono::Utc::now();

    // 閾値に届くまではロックされない。
    for _ in 0..(policy.max_failed_attempts - 1) {
        let record = users
            .record_login_failure(user_uuid, policy, now)
            .await
            .expect("record login failure");
        assert!(!record.is_locked(), "閾値未満ではロックしない");
    }

    // 閾値到達以降、失敗するたびに段が 1 つ進む。SQL が選んだロック期限を、ドメインの
    // 計算式が返す秒数と突き合わせる。
    for step in 0..4 {
        let record = users
            .record_login_failure(user_uuid, policy, now)
            .await
            .expect("record login failure");
        let locked_until = record.locked_until.expect("locked after the threshold");
        let expected_secs = policy.lock_duration_secs_for(record.failed_login_count);
        let actual_secs = (locked_until - now).num_seconds();
        assert_eq!(
            actual_secs, expected_secs as i64,
            "step {step}: SQL の選んだ段（{actual_secs}s）がドメインの計算式（{expected_secs}s）と食い違う \
             （failed_login_count = {}）",
            record.failed_login_count
        );
    }

    // 上限を超えて伸び続けないこと。
    let record = users
        .record_login_failure(user_uuid, policy, now)
        .await
        .expect("record login failure");
    let locked_until = record.locked_until.expect("locked");
    assert_eq!(
        (locked_until - now).num_seconds(),
        policy.max_lock_duration_secs as i64
    );
}

/// 管理者の解除は、ロック期限のクリアと**失敗回数のリセットを同時に**行う。
/// 期限だけ消すと、次の 1 回の失敗で即座に再ロックされ、しかも段が 1 つ進む（前より長くなる）。
#[tokio::test]
async fn an_administrator_unlock_also_clears_the_failure_counter() {
    let Some(env) = support::setup("account lockout admin unlock").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (&env.app, &env.pool, &env.root_tenant_id);
    let admin_cookie = create_sso_session(pool, &env.root_admin_id).await;
    let user_id = create_plain_user(pool, root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("user id is a UUID");

    let users = SqlxUserRepository::new(pool.clone());
    let policy = escalating_policy();
    let now = chrono::Utc::now();
    for _ in 0..policy.max_failed_attempts {
        users
            .record_login_failure(user_uuid, policy, now)
            .await
            .expect("record login failure");
    }
    let locked = users
        .find_by_id(user_uuid)
        .await
        .expect("load user")
        .expect("user exists");
    assert!(locked.is_locked_at(now), "前提: ロックされている");

    let res = send(
        app,
        post_empty(
            &admin_cookie,
            &format!("/{root_tenant_id}/admin/users/{user_id}/unlock"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["was_locked"], serde_json::json!(true));

    let unlocked = users
        .find_by_id(user_uuid)
        .await
        .expect("load user")
        .expect("user exists");
    assert!(!unlocked.is_locked_at(now), "ロック期限が消えている");
    assert_eq!(
        unlocked.failed_login_count, 0,
        "失敗回数もリセットする（残すと次の 1 回で再ロックされ、段も進む）"
    );

    // 解除後は初回の段からやり直しになる（段が引き継がれない）。
    for _ in 0..(policy.max_failed_attempts - 1) {
        let record = users
            .record_login_failure(user_uuid, policy, now)
            .await
            .expect("record login failure");
        assert!(!record.is_locked(), "解除後は閾値からやり直し");
    }
    let record = users
        .record_login_failure(user_uuid, policy, now)
        .await
        .expect("record login failure");
    let locked_until = record.locked_until.expect("locked again");
    assert_eq!(
        (locked_until - now).num_seconds(),
        policy.lock_duration_secs as i64,
        "解除後の再ロックは初回の長さに戻る"
    );
}

/// ロックされていない利用者への解除も成功する（冪等）。`was_locked = false` で区別できる。
#[tokio::test]
async fn unlocking_an_account_that_is_not_locked_succeeds_and_says_so() {
    let Some(env) = support::setup("account lockout idempotent unlock").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (&env.app, &env.pool, &env.root_tenant_id);
    let admin_cookie = create_sso_session(pool, &env.root_admin_id).await;
    let user_id = create_plain_user(pool, root_tenant_id).await;

    let res = send(
        app,
        post_empty(
            &admin_cookie,
            &format!("/{root_tenant_id}/admin/users/{user_id}/unlock"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["was_locked"], serde_json::json!(false));
}
