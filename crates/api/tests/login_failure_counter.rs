//! SEC13: checks that incrementing the login failure counter is atomic.
//!
//! It used to "read `failed_login_count` → write back +1", so N concurrent attempts could read the same value
//! and after N failures the row advanced only by 1, never reaching the lock threshold.
//! Here failures are recorded concurrently against a real DB to confirm **nothing is lost**.
//!
//! Run the same way as `schema.rs` (`TEST_DATABASE_URL` is required).

mod support;

use assay_api::domain::authentication_policy::LockoutPolicy;
use assay_api::domain::repositories::UserRepository;
use assay_api::infrastructure::repositories::user::SqlxUserRepository;
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
    // Set the threshold to exactly the concurrency. If anything is lost, it fails with "not locked".
    let lockout = LockoutPolicy {
        max_failed_attempts: CONCURRENCY as i32,
        lock_duration_secs: 900,
        // A non-progressive setting (cap = first duration). We only want to see increment atomicity here;
        // lock duration growth is covered by the AP6 tests.
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
    // They are already running in parallel once spawned. Here we only wait for all to complete.
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
        "counts every concurrent failure (with read-modify-write this would vary between 1 and {CONCURRENCY})"
    );
    assert!(
        locked_until.is_some(),
        "the lock applies once the threshold is reached (do not lose one layer of defence in depth)"
    );

    // The last recorder always observes "locked" (the basis for the caller's Locked decision).
    let last = users
        .record_login_failure(user_uuid, lockout, now)
        .await
        .expect("record login failure");
    assert!(
        last.is_locked(),
        "failures after locking also return Locked"
    );
    assert_eq!(last.failed_login_count, CONCURRENCY as i32 + 1);
}

/// An expired lock is returned as "not locked" (waiting releases it; no permanent lock).
#[tokio::test]
async fn an_expired_lock_is_not_reported_as_locked() {
    let Some(env) = support::setup("login_failure_counter_expired").await else {
        return;
    };
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let user_uuid = Uuid::parse_str(&user_id).expect("user id is a UUID");
    let users = SqlxUserRepository::new(env.pool.clone());

    let now = chrono::Utc::now();
    // Reach the threshold with a 1-second lock and read from the viewpoint of 1 hour later.
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
        "a new lock applies again at the later point (threshold is 1)"
    );

    // With a setting that does not reach the threshold, a past lock does not come back.
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
    assert!(!relaxed.is_locked(), "an expired lock counts as not locked");
}
