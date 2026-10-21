//! リフレッシュのたびに、利用者がアプリをまだ使ってよいかを見直す（task #582。ADR-0054）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test refresh_rechecks_application_access
//!
//! 以前はアプリの利用の判定が **code を出すときだけ**だったので、利用者をアプリから外しても・
//! アプリを止めても、持っているリフレッシュトークンで寿命（既定 30 日）まで新しいトークンが出ていた。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::Value;
use sqlx::MySqlPool;
use support::{body_json, create_plain_user, send, TestEnv};

/// root の下にテナントを 1 つ作り、割り当ての判定を `enforce` にする。
/// ⚠ 全体の行と root テナントには触らない（並走する他のテストの前提）。
async fn enforcing_tenant(pool: &MySqlPool, root_tenant_id: &str) -> String {
    let tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status, self_registration_enabled) \
         VALUES (?, ?, ?, 'ACTIVE', 0)",
    )
    .bind(&tenant)
    .bind(root_tenant_id)
    .bind(format!("refresh-assignment-{}", &tenant[..8]))
    .execute(pool)
    .await
    .expect("create tenant");
    sqlx::query(
        "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
         VALUES (?, 'APPLICATION_ASSIGNMENT_ENFORCEMENT', 'enforce', 0)",
    )
    .bind(&tenant)
    .execute(pool)
    .await
    .expect("insert tenant setting");
    tenant
}

/// 「個別に割り当てた人だけ」のアプリを作り、client を OIDC の名乗りとして結ぶ。アプリの id を返す。
async fn individual_application(pool: &MySqlPool, tenant: &str, client_id: &str) -> String {
    let client_row_id: String =
        sqlx::query_scalar("SELECT id FROM clients WHERE tenant_id = ? AND client_id = ?")
            .bind(tenant)
            .bind(client_id)
            .fetch_one(pool)
            .await
            .expect("the client must exist");
    let application_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO applications (id, tenant_id, display_name, status, assignment_mode) \
         VALUES (?, ?, 'Refresh Recheck', 'ACTIVE', 'INDIVIDUAL')",
    )
    .bind(&application_id)
    .bind(tenant)
    .execute(pool)
    .await
    .expect("insert application");
    sqlx::query(
        "INSERT INTO application_bindings (id, application_id, kind, client_id) \
         VALUES (?, ?, 'oidc', ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&application_id)
    .bind(&client_row_id)
    .execute(pool)
    .await
    .expect("insert oidc binding");
    application_id
}

async fn assign(pool: &MySqlPool, application_id: &str, user_id: &str) {
    sqlx::query(
        "INSERT INTO application_assignments (id, application_id, kind, user_id) \
         VALUES (?, ?, 'USER', ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(application_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("assign user");
}

/// 有効なリフレッシュトークンを 1 本入れて、平文を返す。
async fn insert_refresh_token(
    pool: &MySqlPool,
    tenant: &str,
    user_id: &str,
    client_id: &str,
) -> String {
    let plain = format!("rt-{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, client_id, scope, expires_at) \
         VALUES (?, ?, ?, ?, '[\"openid\"]', DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))",
    )
    .bind(assay_api::infrastructure::crypto::sha256_hex(&plain))
    .bind(tenant)
    .bind(user_id)
    .bind(client_id)
    .execute(pool)
    .await
    .expect("insert refresh token");
    plain
}

async fn refresh(
    env: &TestEnv,
    tenant: &str,
    client_id: &str,
    secret: &str,
    token: &str,
) -> (StatusCode, Value) {
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic}"))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    let status = res.status();
    (status, body_json(res).await)
}

async fn active_tokens(pool: &MySqlPool, user_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("count refresh tokens")
}

#[tokio::test]
async fn a_user_removed_from_the_application_can_no_longer_refresh() {
    let Some(env) = support::setup("refresh rechecks assignment").await else {
        return;
    };
    let tenant = enforcing_tenant(&env.pool, &env.root_tenant_id).await;
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &tenant, &["openid"]).await;
    let application_id = individual_application(&env.pool, &tenant, &client_id).await;
    let user_id = create_plain_user(&env.pool, &tenant).await;
    assign(&env.pool, &application_id, &user_id).await;

    // 割り当てがあるうちは今までどおり更新できる。
    let token = insert_refresh_token(&env.pool, &tenant, &user_id, &client_id).await;
    let (status, body) = refresh(&env, &tenant, &client_id, &secret, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rotated = body["refresh_token"]
        .as_str()
        .expect("rotated refresh token")
        .to_string();

    // アプリから外す。
    sqlx::query("DELETE FROM application_assignments WHERE application_id = ? AND user_id = ?")
        .bind(&application_id)
        .bind(&user_id)
        .execute(&env.pool)
        .await
        .expect("unassign");
    let (status, body) = refresh(&env, &tenant, &client_id, &secret, &rotated).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // その許可で出したトークンは家族ごと止まる。
    assert_eq!(active_tokens(&env.pool, &user_id).await, 0);
}

#[tokio::test]
async fn a_disabled_application_stops_its_refresh_tokens() {
    let Some(env) = support::setup("refresh rechecks disabled app").await else {
        return;
    };
    let tenant = enforcing_tenant(&env.pool, &env.root_tenant_id).await;
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &tenant, &["openid"]).await;
    let application_id = individual_application(&env.pool, &tenant, &client_id).await;
    let user_id = create_plain_user(&env.pool, &tenant).await;
    assign(&env.pool, &application_id, &user_id).await;
    let token = insert_refresh_token(&env.pool, &tenant, &user_id, &client_id).await;

    sqlx::query("UPDATE applications SET status = 'DISABLED' WHERE id = ?")
        .bind(&application_id)
        .execute(&env.pool)
        .await
        .expect("disable application");
    let (status, body) = refresh(&env, &tenant, &client_id, &secret, &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
}
