//! SEC13: ログイン失敗カウンタの加算が原子的であることの検証。
//!
//! 従来は「`failed_login_count` を読む → +1 して書き戻す」だったため、並行して届いた N 件の
//! 試行が同じ値を読み、N 回失敗しても行が 1 しか進まずロック閾値へ届かないことがあった。
//! ここでは実 DB に対して同時に失敗を記録し、**取りこぼしが無い**ことを確かめる。
//!
//! 実行方法は `schema.rs` と同じ（`TEST_DATABASE_URL` が必須）。

mod support;

use idp_api::domain::authentication_policy::LockoutPolicy;
use idp_api::domain::repositories::UserRepository;
use idp_api::infrastructure::repositories::user::SqlxUserRepository;
use std::sync::Arc;
use uuid::Uuid;

const CONCURRENCY: usize = 8;

#[tokio::test]
async fn concurrent_failures_all_count_and_reach_the_lock_threshold() {
    let Some(env) = support::setup("login_failure_counter").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("user id is a UUID");

    let users = Arc::new(SqlxUserRepository::new(env.pool.clone()));
    // 閾値を同時実行数ちょうどに置く。取りこぼしがあれば「ロックされない」で落ちる。
    let lockout = LockoutPolicy {
        max_failed_attempts: CONCURRENCY as i32,
        lock_duration_secs: 900,
        // 段階化しない設定（上限 = 初回時間）。ここで見たいのは加算の原子性だけで、
        // ロック時間の伸びは AP6 のテストが見る。
        max_lock_duration_secs: 900,
    };
    let now = chrono::Utc::now();

    let mut handles = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let users = Arc::clone(&users);
        handles.push(tokio::spawn(async move {
            users
                .record_login_failure(user_uuid, lockout, now)
                .await
                .expect("record login failure")
        }));
    }
    // spawn した時点で並行して走っている。ここでは全件の完了を待つだけ。
    for handle in handles {
        handle.await.expect("task did not panic");
    }

    let (count, locked_until): (i32, Option<chrono::NaiveDateTime>) =
        sqlx::query_as("SELECT failed_login_count, locked_until FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_one(&env.pool)
            .await
            .expect("read login state");

    assert_eq!(
        count, CONCURRENCY as i32,
        "並行した失敗をすべて数える（read-modify-write だとここが 1〜{CONCURRENCY} の間で揺れる）"
    );
    assert!(
        locked_until.is_some(),
        "閾値に達したらロックが掛かる（多層防御の一枚を取りこぼさない）"
    );

    // 最後に記録した側は必ず「ロック済み」を観測する（呼び出し側の Locked 判定の根拠）。
    let last = users
        .record_login_failure(user_uuid, lockout, now)
        .await
        .expect("record login failure");
    assert!(last.is_locked(), "ロック後の失敗も Locked を返す");
    assert_eq!(last.failed_login_count, CONCURRENCY as i32 + 1);
}

/// 期限切れのロックは「掛かっていない」として返す（利用者が待てば解ける。恒久ロックはしない）。
#[tokio::test]
async fn an_expired_lock_is_not_reported_as_locked() {
    let Some(env) = support::setup("login_failure_counter_expired").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("user id is a UUID");
    let users = SqlxUserRepository::new(env.pool.clone());

    let now = chrono::Utc::now();
    // 1 秒だけロックされる設定で閾値に達しさせ、その 1 時間後の視点で読む。
    let lockout = LockoutPolicy {
        max_failed_attempts: 1,
        lock_duration_secs: 1,
        max_lock_duration_secs: 1,
    };
    let locked = users
        .record_login_failure(user_uuid, lockout, now)
        .await
        .expect("record login failure");
    assert!(locked.is_locked());

    let later = now + chrono::Duration::hours(1);
    let after = users
        .record_login_failure(user_uuid, lockout, later)
        .await
        .expect("record login failure");
    assert!(
        after.is_locked(),
        "later 時点で新しいロックが掛かり直す（閾値 1 のため）"
    );

    // 閾値に届かない設定なら、過去のロックは復活しない。
    let lenient = LockoutPolicy {
        max_failed_attempts: 1_000,
        lock_duration_secs: 1,
        max_lock_duration_secs: 1,
    };
    let much_later = now + chrono::Duration::hours(2);
    let relaxed = users
        .record_login_failure(user_uuid, lenient, much_later)
        .await
        .expect("record login failure");
    assert!(!relaxed.is_locked(), "期限切れのロックは掛かっていない扱い");
}
