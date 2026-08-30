//! パスワードポリシー（AP7。仕様 §11.2）の統合テスト。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test password_policy
//!
//! 単体テスト（`assay_core::application::password_policy`）が見るのは判定そのもので、ここで見るのは
//! **判定に使う材料が実際に DB へ載るか**である。履歴の行が積まれ剪定されること、パスワード設定
//! 時刻が記録されること、そして期限切れがログインで強制変更に化けることは、フェイクの
//! リポジトリでは確かめられない。
//!
//! 有効期限は設定値（`PASSWORD_MAX_AGE_DAYS`）で決まるため、本ファイルは専用のテストバイナリとして
//! 起動時に環境変数を立てる。同じ値を全テストで立てるので、並行実行しても食い違わない。

mod support;

use serde_json::json;
use support::{body_json, create_sso_session, post_internal, send, SERVICE_TOKEN};

/// 本バイナリのポリシー設定。履歴は「現行 + 退役 2 件」、有効期限は 30 日。
fn apply_policy_env() {
    std::env::set_var("PASSWORD_HISTORY_COUNT", "3");
    std::env::set_var("PASSWORD_MAX_AGE_DAYS", "30");
}

/// セルフサービスのパスワード変更（`/internal/account/change-password`）を 1 回叩く。
async fn change_password(
    app: &axum::Router,
    sso_session_id: &str,
    current: &str,
    new: &str,
) -> serde_json::Value {
    let response = send(
        app,
        post_internal(
            "/internal/account/change-password",
            Some(SERVICE_TOKEN),
            json!({
                "sso_session_id": sso_session_id,
                "current_password": current,
                "new_password": new,
            }),
        ),
    )
    .await;
    body_json(response).await
}

#[tokio::test]
async fn rejects_reused_passwords_and_prunes_history_to_the_policy_depth() {
    apply_policy_env();
    let Some(env) = support::setup("password_policy_reuse").await else {
        return;
    };
    let username = format!("pw-reuse-{}", support::unique());
    let p1 = "initial-password-1";
    support::register_user(&env.app, &env.root_tenant_id, &username, p1).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    let user_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("registered user");
    let sso = create_sso_session(&env.pool, &user_id).await;

    // 自己登録の時点で設定時刻が入っている（有効期限の起点。NULL のままだと作成時刻へ落ちる）。
    let changed_at: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT password_changed_at FROM users WHERE id = ?")
            .bind(&user_id)
            .fetch_one(&env.pool)
            .await
            .expect("read password_changed_at");
    assert!(
        changed_at.is_some(),
        "self-registration must record when the password was set"
    );

    // 現行と同じ値は再利用として拒否する（履歴の深さ 1 の部分）。
    let body = change_password(&env.app, &sso, p1, p1).await;
    assert_eq!(body["result"], "weak_password");
    assert_eq!(body["reason"], "reused");

    // 別の値へは変えられる。
    let p2 = "second-password-2";
    let body = change_password(&env.app, &sso, p1, p2).await;
    assert_eq!(body["result"], "ok", "unexpected response: {body}");

    // 退役したハッシュが 1 件積まれる。
    let history: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_password_history WHERE user_id = ?")
            .bind(&user_id)
            .fetch_one(&env.pool)
            .await
            .expect("count history");
    assert_eq!(history, 1);

    // 退役したパスワードへは戻せない。
    let body = change_password(&env.app, &sso, p2, p1).await;
    assert_eq!(body["result"], "weak_password");
    assert_eq!(body["reason"], "reused");

    // さらに 2 回変えると、退役側は深さ（3 - 現行 1 = 2 件）で剪定される。
    let p3 = "third-password-333";
    let p4 = "fourth-password-44";
    assert_eq!(
        change_password(&env.app, &sso, p2, p3).await["result"],
        "ok"
    );
    assert_eq!(
        change_password(&env.app, &sso, p3, p4).await["result"],
        "ok"
    );
    let history: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_password_history WHERE user_id = ?")
            .bind(&user_id)
            .fetch_one(&env.pool)
            .await
            .expect("count history");
    assert_eq!(history, 2, "history must be pruned to the policy depth");

    // 剪定で落ちた最古のパスワードは再び使える（保持していないものは判定できない、を明示する）。
    let body = change_password(&env.app, &sso, p4, p1).await;
    assert_eq!(
        body["result"], "ok",
        "a password older than the retained depth is accepted again: {body}"
    );
}

#[tokio::test]
async fn expired_password_sends_the_user_to_the_forced_change_form() {
    apply_policy_env();
    let Some(env) = support::setup("password_policy_expiry").await else {
        return;
    };
    let username = format!("pw-expiry-{}", support::unique());
    let password = "expiring-password-1";
    support::register_user(&env.app, &env.root_tenant_id, &username, password).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    let login = json!({
        "tenant_id": env.root_tenant_id,
        "username": username,
        "password": password,
    });

    // 設定した直後は期限内。
    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            login.clone(),
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["result"], "success", "unexpected response: {body}");

    // 設定時刻を 31 日前へ戻すと（= 有効日数 30 を超える）、次のログインで変更を要求する。
    let aged_user_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("registered user");
    sqlx::query(
        "UPDATE users SET password_changed_at = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 31 DAY) \
         WHERE id = ?",
    )
    .bind(&aged_user_id)
    .execute(&env.pool)
    .await
    .expect("age the password");

    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            login.clone(),
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(
        body["result"], "password_change_required",
        "an expired password must not sign in directly: {body}"
    );

    // 変更フォーム（強制変更経路）は `must_change_password` が立っていなくても受け付ける。
    let new_password = "renewed-password-22";
    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal/change-password",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "username": username,
                "current_password": password,
                "new_password": new_password,
            }),
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["result"], "success", "unexpected response: {body}");

    // 変更で設定時刻が更新され、期限内へ戻る。
    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "username": username,
                "password": new_password,
            }),
        ),
    )
    .await;
    let body = body_json(response).await;
    assert_eq!(body["result"], "success", "unexpected response: {body}");
}
