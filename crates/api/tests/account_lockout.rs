//! AP6: progressive lockout and unlock by an admin.
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test account_lockout
//!
//! Progressive lockout is constrained to "record the failure and decide the lock in one UPDATE" (SEC13),
//! so the choice of lock duration happens inside SQL. This pins down that the domain formula
//! (`lock_duration_secs_for`) and the step SQL picks **agree**, so fixing only one side gets noticed.

mod support;

use assay_api::domain::authentication_policy::LockoutPolicy;
use assay_api::domain::repositories::UserRepository;
use assay_api::infrastructure::repositories::user::SqlxUserRepository;
use axum::http::StatusCode;
use support::{admin_token, body_json, create_plain_user, post_empty, send};
use uuid::Uuid;

/// Rounds "how many seconds from now" of a lock expiry to seconds.
///
/// `chrono::Utc::now()` has nanosecond precision, but it is **truncated to microseconds** when stored in
/// `DATETIME(6)`. Looking at the difference with `num_seconds()` (truncation toward 0) gives 59 for exactly 60.
/// What we want to check is "which step was chosen", so we round to the nearest second and compare.
fn lock_seconds(
    locked_until: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> i64 {
    (locked_until - now).num_milliseconds().div_euclid(1_000)
        + i64::from((locked_until - now).num_milliseconds().rem_euclid(1_000) >= 500)
}

/// Lock after 3 failures; the cap is 4x the first (= 3 steps).
fn escalating_policy() -> LockoutPolicy {
    LockoutPolicy {
        max_failed_attempts: 3,
        lock_duration_secs: 60,
        max_lock_duration_secs: 240,
    }
}

/// The lock duration grows per step, and the step SQL picks agrees with the domain formula.
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

    // No lock until the threshold is reached.
    for _ in 0..(policy.max_failed_attempts - 1) {
        let record = users
            .record_login_failure(user_uuid, policy, now)
            .await
            .expect("record login failure");
        assert!(!record.is_locked(), "no lock below the threshold");
    }

    // From the threshold on, each failure advances one step. Compare the lock expiry SQL chose with
    // the seconds the domain formula returns.
    for step in 0..4 {
        let record = users
            .record_login_failure(user_uuid, policy, now)
            .await
            .expect("record login failure");
        let locked_until = record.locked_until.expect("locked after the threshold");
        let expected_secs = policy.lock_duration_secs_for(record.failed_login_count);
        let actual_secs = lock_seconds(locked_until, now);
        assert_eq!(
            actual_secs, expected_secs as i64,
            "step {step}: the step SQL chose ({actual_secs}s) disagrees with the domain formula ({expected_secs}s) \
             (failed_login_count = {})",
            record.failed_login_count
        );
    }

    // It must not keep growing past the cap.
    let record = users
        .record_login_failure(user_uuid, policy, now)
        .await
        .expect("record login failure");
    let locked_until = record.locked_until.expect("locked");
    assert_eq!(
        lock_seconds(locked_until, now),
        policy.max_lock_duration_secs as i64
    );
}

/// An admin unlock clears the lock expiry and **resets the failure count at the same time**.
/// Clearing only the expiry would re-lock on the next single failure, one step further (longer than before).
#[tokio::test]
async fn an_administrator_unlock_also_clears_the_failure_counter() {
    let Some(env) = support::setup("account lockout admin unlock").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (&env.app, &env.pool, &env.root_tenant_id);
    let admin_tok = admin_token(&env.app, pool, &env.root_tenant_id, &env.root_admin_id).await;
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
    assert!(locked.is_locked_at(now), "precondition: locked");

    let res = send(
        app,
        post_empty(
            &admin_tok,
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
    assert!(!unlocked.is_locked_at(now), "the lock expiry is cleared");
    assert_eq!(
        unlocked.failed_login_count, 0,
        "the failure count is reset too (keeping it re-locks on the next failure and advances the step)"
    );

    // After unlocking, it starts again from the first step (the step is not carried over).
    for _ in 0..(policy.max_failed_attempts - 1) {
        let record = users
            .record_login_failure(user_uuid, policy, now)
            .await
            .expect("record login failure");
        assert!(
            !record.is_locked(),
            "after unlock, counting restarts from the threshold"
        );
    }
    let record = users
        .record_login_failure(user_uuid, policy, now)
        .await
        .expect("record login failure");
    let locked_until = record.locked_until.expect("locked again");
    assert_eq!(
        lock_seconds(locked_until, now),
        policy.lock_duration_secs as i64,
        "re-lock after unlock goes back to the first duration"
    );
}

/// Unlocking a user who is not locked also succeeds (idempotent). Distinguishable by `was_locked = false`.
#[tokio::test]
async fn unlocking_an_account_that_is_not_locked_succeeds_and_says_so() {
    let Some(env) = support::setup("account lockout idempotent unlock").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (&env.app, &env.pool, &env.root_tenant_id);
    let admin_tok = admin_token(&env.app, pool, &env.root_tenant_id, &env.root_admin_id).await;
    let user_id = create_plain_user(pool, root_tenant_id).await;

    let res = send(
        app,
        post_empty(
            &admin_tok,
            &format!("/{root_tenant_id}/admin/users/{user_id}/unlock"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["was_locked"], serde_json::json!(false));
}
