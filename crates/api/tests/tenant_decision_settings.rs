//! 判定そのものを決める 2 キーがテナントごとに効くことの統合テスト（ADR-0058 §4・§10）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test tenant_decision_settings
//!
//! 検証すること（どれも **2 テナントに違う値を入れて**確かめる。1 テナントだけだと、全体の値を
//! 読んでいても通ってしまう）:
//! - `AUTH_POLICY_DEFAULT_EFFECT`: 一致するポリシーが無いとき、`deny` のテナントはログインを断り、
//!   `allow` のテナントは通す。管理 API の一覧はそれぞれのテナントの値を返す
//! - `APPLICATION_ASSIGNMENT_ENFORCEMENT`: 割り当ての無い人を、`enforce` のテナントは断り、
//!   `record_only` のテナントは通して記録だけ残す。管理 API のアプリ一覧はそれぞれの値を返す
//!
//! ⚠ 値は**このテスト用に作ったテナント**の `tenant_settings` にだけ入れる。全体の行
//! （`system_settings`）と root テナントには触らない ——並走する他のテストの前提を変えないため。

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{
    admin_token, authorize_uri_openid_only, begin_login, body_json, create_plain_user, get, send,
    TestEnv, SERVICE_TOKEN, SERVICE_TOKEN_HEADER,
};

const PASSWORD: &str = "CorrectHorse9!";

/// root の下にテナントを 1 つ作り、`settings` をそのテナントの行として入れる。
async fn tenant_with_settings(env: &TestEnv, settings: &[(&str, &str)]) -> String {
    let tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status, self_registration_enabled) \
         VALUES (?, ?, ?, 'ACTIVE', 1)",
    )
    .bind(&tenant)
    .bind(&env.root_tenant_id)
    .bind(format!("decision-settings-{}", &tenant[..8]))
    .execute(&env.pool)
    .await
    .expect("create tenant");
    for (key, value) in settings {
        sqlx::query(
            "INSERT INTO tenant_settings (tenant_id, setting_key, setting_value, is_secret) \
             VALUES (?, ?, ?, 0)",
        )
        .bind(&tenant)
        .bind(key)
        .bind(value)
        .execute(&env.pool)
        .await
        .expect("insert tenant setting");
    }
    tenant
}

/// 自己登録でユーザーを作り、メール検証まで済ませる（ログインできる状態にする）。
async fn register_verified_user(env: &TestEnv, tenant: &str) -> String {
    let username = format!("decision-{}", support::unique());
    let payload = json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": PASSWORD,
    });
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
    support::mark_email_verified(&env.pool, tenant, &username).await;
    username
}

/// `/authorize` から始めてパスワードで認証し、内部認証の応答を返す。
async fn log_in(env: &TestEnv, tenant: &str, client_id: &str, username: &str) -> Value {
    let auth_session = begin_login(
        &env.app,
        tenant,
        &authorize_uri_openid_only(tenant, client_id),
    )
    .await;
    let csrf = assay_api::application::login::csrf_token(&auth_session, &env.csrf_secret);
    let body = json!({
        "tenant_id": tenant,
        "auth_session_id": auth_session,
        "username": username,
        "password": PASSWORD,
        "csrf_token": csrf,
    });
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/internal/authenticate")
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "internal authenticate");
    body_json(response).await
}

/// そのテナントの管理者の管理トークン。
async fn tenant_admin_token(env: &TestEnv, tenant: &str) -> String {
    let admin = create_plain_user(&env.pool, tenant).await;
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, ?, ?)",
    )
    .bind(&admin)
    .bind("idp.tenant.admin")
    .bind(tenant)
    .execute(&env.pool)
    .await
    .expect("grant idp.tenant.admin");
    admin_token(&env.app, &env.pool, tenant, &admin).await
}

async fn get_json(env: &TestEnv, token: &str, uri: &str) -> Value {
    let response = send(&env.app, get(token, uri)).await;
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    body_json(response).await
}

/// 割り当ての判定の監査行（`application.access_denied`）の `result`。
async fn access_denied_results(pool: &MySqlPool, tenant: &str) -> Vec<String> {
    sqlx::query(
        "SELECT result FROM audit_log WHERE tenant_id = ? AND event_type = 'application.access_denied' \
         ORDER BY occurred_at",
    )
    .bind(tenant)
    .fetch_all(pool)
    .await
    .expect("read audit")
    .iter()
    .map(|row| row.get::<String, _>("result"))
    .collect()
}

#[tokio::test]
async fn each_tenant_decides_what_happens_when_no_policy_matches() {
    let Some(env) = support::setup("tenant policy default effect").await else {
        return;
    };
    let strict = tenant_with_settings(&env, &[("AUTH_POLICY_DEFAULT_EFFECT", "deny")]).await;
    let lenient = tenant_with_settings(&env, &[("AUTH_POLICY_DEFAULT_EFFECT", "allow")]).await;

    // どちらのテナントにもポリシーは 1 件も無い ——結果を分けるのは既定動作だけである。
    for (tenant, expected) in [(&strict, "policy_denied"), (&lenient, "success")] {
        let client_id = support::insert_public_client(&env.pool, tenant, &["openid"]).await;
        let username = register_verified_user(&env, tenant).await;
        let body = log_in(&env, tenant, &client_id, &username).await;
        assert_eq!(body["result"], expected, "tenant {tenant}: {body}");
    }

    // 管理コンソールが描く値も、そのテナントの値である（web は値を持たない）。
    for (tenant, expected) in [(&strict, "deny"), (&lenient, "allow")] {
        let token = tenant_admin_token(&env, tenant).await;
        let listed = get_json(
            &env,
            &token,
            &format!("/{tenant}/admin/authentication-policies"),
        )
        .await;
        assert_eq!(
            listed["default_effect"], expected,
            "tenant {tenant}: {listed}"
        );
    }
}

#[tokio::test]
async fn each_tenant_decides_whether_to_enforce_application_assignments() {
    let Some(env) = support::setup("tenant assignment enforcement").await else {
        return;
    };
    let enforcing =
        tenant_with_settings(&env, &[("APPLICATION_ASSIGNMENT_ENFORCEMENT", "enforce")]).await;
    let recording = tenant_with_settings(
        &env,
        &[("APPLICATION_ASSIGNMENT_ENFORCEMENT", "record_only")],
    )
    .await;

    // 「個別」のアプリで、利用者は名簿に載っていない。
    for (tenant, expected, audited) in [
        (&enforcing, "application_not_permitted", "failure"),
        (&recording, "success", "success"),
    ] {
        let client_id = support::insert_public_client(&env.pool, tenant, &["openid"]).await;
        let application_id =
            support::open_client_as_application(&env.pool, tenant, &client_id).await;
        sqlx::query("UPDATE applications SET assignment_mode = 'INDIVIDUAL' WHERE id = ?")
            .bind(&application_id)
            .execute(&env.pool)
            .await
            .expect("make the application individual");
        let username = register_verified_user(&env, tenant).await;

        let body = log_in(&env, tenant, &client_id, &username).await;
        assert_eq!(body["result"], expected, "tenant {tenant}: {body}");
        assert_eq!(
            access_denied_results(&env.pool, tenant).await,
            vec![audited.to_string()],
            "tenant {tenant}"
        );
    }

    for (tenant, expected) in [(&enforcing, "enforce"), (&recording, "record_only")] {
        let token = tenant_admin_token(&env, tenant).await;
        let listed = get_json(&env, &token, &format!("/{tenant}/admin/applications")).await;
        assert_eq!(listed["enforcement"], expected, "tenant {tenant}: {listed}");
    }
}
