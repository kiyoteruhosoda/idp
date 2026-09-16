//! テナントの設定で動くこと（ADR-0058。#109）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test tenant_settings_consumers
//!
//! ⚠ **どの試験もテナントを 2 つ以上使い、違う値を入れる。** 1 テナントだけだと、全体の値を読んで
//! いても通ってしまう。あわせて **行の無いテナントが全体に従う**ことも確かめる。
//!
//! 行は `tenant_settings` へ直接入れる（書き込みの口は別のタスクで入る）。テナントは毎回新しく
//! 作るので、解決器のキャッシュに古い値が残っていることはない。

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{
    body_json, mark_email_verified, post_internal, register_user, send, unique, TestEnv,
    SERVICE_TOKEN,
};

/// 自己登録を有効にしたテナントを 1 つ作る。
async fn create_tenant(env: &TestEnv, label: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, self_registration_enabled) \
         VALUES (?, ?, ?, 1)",
    )
    .bind(&id)
    .bind(&env.root_tenant_id)
    .bind(format!("{label}-{}", unique()))
    .execute(&env.pool)
    .await
    .expect("create tenant");
    id
}

/// テナントの行を入れる（そのテナントでの上書き）。
async fn set_tenant_setting(env: &TestEnv, tenant_id: &str, key: &str, value: &str) {
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
         VALUES (?, ?, ?, 0)",
    )
    .bind(tenant_id)
    .bind(key)
    .bind(value)
    .execute(&env.pool)
    .await
    .expect("insert tenant setting");
}

/// 全体の行（`system_settings`）にそのキーがあれば値を返す。行の無いテナントの期待値に使う。
async fn global_value(env: &TestEnv, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT setting_value FROM system_settings WHERE setting_key = ? AND setting_value <> ''",
    )
    .bind(key)
    .fetch_optional(&env.pool)
    .await
    .expect("read system setting")
}

async fn register(env: &TestEnv, tenant: &str, password: &str) -> StatusCode {
    let username = format!("ts{}", unique());
    let response = send(
        &env.app,
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": format!("{username}@example.com"),
                    "preferred_username": username,
                    "password": password,
                    "name": "Tenant Settings Tester",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    response.status()
}

/// 所属元 `tenant` に、パスワードの分かっている検証済みの利用者を作る。`(user_id, username, password)`。
async fn create_user(env: &TestEnv, tenant: &str) -> (String, String, String) {
    let username = format!("ts{}", unique());
    let password = format!("tenant-settings-{}", unique());
    register_user(&env.app, tenant, &username, &password).await;
    mark_email_verified(&env.pool, tenant, &username).await;
    let user_id = support::find_user_id_by_username(&env.pool, tenant, &username)
        .await
        .expect("registered user");
    (user_id, username, password)
}

/// ポータルのログインを 1 回試し、応答の JSON を返す。
///
/// `ip` は試行ごとに変える（IP 単位のレート制限はプロセス内で共有され、同じバイナリの試験どうしで
/// バケツを取り合うため）。
async fn portal_login(
    env: &TestEnv,
    tenant: &str,
    ip: &str,
    username: &str,
    password: &str,
) -> Value {
    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "username": username,
                "password": password,
                "ip_address": ip,
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

/// パスワードの最小長は登録するテナントの値で判定する。行の無いテナントは全体に従う。
#[tokio::test]
async fn self_registration_is_judged_by_the_registering_tenants_password_policy() {
    let Some(env) = support::setup("tenant settings: password policy").await else {
        return;
    };
    let strict = create_tenant(&env, "strict").await;
    let lenient = create_tenant(&env, "lenient").await;
    let follower = create_tenant(&env, "follower").await;
    set_tenant_setting(&env, &strict, "PASSWORD_MIN_LENGTH", "16").await;
    set_tenant_setting(&env, &lenient, "PASSWORD_MIN_LENGTH", "6").await;

    // 12 文字: strict だけが弾く。
    let twelve = "abcdefghijkl";
    assert_eq!(
        register(&env, &strict, twelve).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(register(&env, &lenient, twelve).await, StatusCode::CREATED);
    assert_eq!(register(&env, &follower, twelve).await, StatusCode::CREATED);

    // 7 文字: lenient は通す。行の無い follower は全体の最小長に従う。
    let seven = "abcdefg";
    assert_eq!(register(&env, &lenient, seven).await, StatusCode::CREATED);
    let global_min: usize = global_value(&env, "PASSWORD_MIN_LENGTH")
        .await
        .map(|v| v.parse().expect("numeric PASSWORD_MIN_LENGTH"))
        .unwrap_or(8);
    let expected = if seven.len() < global_min {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::CREATED
    };
    assert_eq!(register(&env, &follower, seven).await, expected);
}

/// ロックの閾値は利用者の所属元テナントの値。⚠ ゲストが参加先の画面から失敗しても、参加先の
/// 値ではなく所属元の値で数える（ロックの状態は利用者の行にあり、所属元が管理する）。
#[tokio::test]
async fn lockout_counts_against_the_users_home_tenant_threshold() {
    let Some(env) = support::setup("tenant settings: lockout").await else {
        return;
    };
    let quick = create_tenant(&env, "quick-lock").await;
    let follower = create_tenant(&env, "follower-lock").await;
    let host = create_tenant(&env, "host-lock").await;
    set_tenant_setting(&env, &quick, "LOGIN_MAX_FAILED_ATTEMPTS", "2").await;
    // 参加先は緩い値を決めているが、ゲストには効かない。
    set_tenant_setting(&env, &host, "LOGIN_MAX_FAILED_ATTEMPTS", "50").await;

    let (quick_user, quick_name, _) = create_user(&env, &quick).await;
    let (_, follower_name, _) = create_user(&env, &follower).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&host)
    .bind(&quick_user)
    .execute(&env.pool)
    .await
    .expect("make the quick-lock user a guest of the host");

    // quick の利用者: 参加先（host）の画面から 2 回失敗 → 所属元の閾値 2 でロック。
    let first = portal_login(&env, &host, "203.0.113.201", &quick_name, "wrong-password").await;
    assert_eq!(first["result"], "invalid_credentials", "{first}");
    let second = portal_login(&env, &host, "203.0.113.202", &quick_name, "wrong-password").await;
    assert_eq!(second["result"], "locked", "{second}");

    // 行の無いテナントの利用者: 2 回では全体の閾値（既定 10）に届かない。
    let global_threshold: u32 = global_value(&env, "LOGIN_MAX_FAILED_ATTEMPTS")
        .await
        .map(|v| v.parse().expect("numeric LOGIN_MAX_FAILED_ATTEMPTS"))
        .unwrap_or(10);
    if global_threshold > 2 {
        for ip in ["203.0.113.203", "203.0.113.204"] {
            let outcome = portal_login(&env, &follower, ip, &follower_name, "wrong-password").await;
            assert_eq!(outcome["result"], "invalid_credentials", "{outcome}");
        }
    }
}

/// SSO セッションの寿命（web が Cookie の `Max-Age` に使う値）は利用者の所属元テナントの値。
/// 行の無いテナントは全体に従う。
#[tokio::test]
async fn the_sso_cookie_lives_as_long_as_the_home_tenant_says() {
    let Some(env) = support::setup("tenant settings: sso lifetime").await else {
        return;
    };
    let short = create_tenant(&env, "short-sso").await;
    let follower = create_tenant(&env, "follower-sso").await;
    let host = create_tenant(&env, "host-sso").await;
    set_tenant_setting(&env, &short, "SSO_ABSOLUTE_TTL_SECS", "1234").await;
    set_tenant_setting(&env, &host, "SSO_ABSOLUTE_TTL_SECS", "999").await;

    let (short_user, short_name, short_password) = create_user(&env, &short).await;
    let (_, follower_name, follower_password) = create_user(&env, &follower).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&host)
    .bind(&short_user)
    .execute(&env.pool)
    .await
    .expect("make the short-sso user a guest of the host");

    let home = portal_login(&env, &short, "203.0.113.211", &short_name, &short_password).await;
    assert_eq!(home["result"], "success", "{home}");
    assert_eq!(home["sso_absolute_ttl_secs"], 1234);

    // 参加先の画面から入っても、SSO セッションは全テナントで共有されるので所属元の値で決まる。
    let as_guest = portal_login(&env, &host, "203.0.113.212", &short_name, &short_password).await;
    assert_eq!(as_guest["result"], "success", "{as_guest}");
    assert_eq!(as_guest["sso_absolute_ttl_secs"], 1234);

    let expected: u64 = global_value(&env, "SSO_ABSOLUTE_TTL_SECS")
        .await
        .map(|v| v.parse().expect("numeric SSO_ABSOLUTE_TTL_SECS"))
        .unwrap_or(86_400);
    let followed = portal_login(
        &env,
        &follower,
        "203.0.113.213",
        &follower_name,
        &follower_password,
    )
    .await;
    assert_eq!(followed["result"], "success", "{followed}");
    assert_eq!(followed["sso_absolute_ttl_secs"], expected);
}
