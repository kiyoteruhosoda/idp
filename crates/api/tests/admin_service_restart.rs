//! 設定画面からの再起動と、DB 管理になった `ISSUER` の統合テスト（DB あり。ADR-0017）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_service_restart
//!
//! 検証するのは:
//!
//! 1. `ISSUER` が設定画面から編集できる（`DB_MANAGED` / `editable` / web とも共有）。
//! 2. 壊れた `ISSUER` は保存させない（保存できてしまうと次回起動から全 RP のトークン検証が落ちる）。
//! 3. 再起動は `idp.system.admin` を持つ root 管理者だけが要求できる。
//! 4. 要求は受理（202）を返し、監査ログに残る。
//!
//! **`system_settings` の `ISSUER` 行は書き換えない。** このテーブルはテナント列を持たない IdP 全体の
//! 共有テーブルで、テストバイナリは並列に走る。`ISSUER` は `Config` の広範囲（Cookie の Secure 判定・
//! 本番シークレットの fail-fast・公開 URL）に効くため、書き換えると同時実行中の別テストの `Config`
//! まで巻き添えにする。保存経路は「不正値が弾かれること」＝ DB を変えない側で確認し、DB 上書きが
//! `Config` へ届くことは `idp-core` の単体テスト（`config::tests::issuer_is_overridden_by_db_settings`）
//! で固定している。
//!
//! 再起動の要求はテスト内で `ServiceRestart` のフラグを立てるだけで、待っている `axum::serve` が
//! 居ないためテストプロセスは止まらない。

mod support;

use axum::http::StatusCode;
use idp_api::config::Config;
use idp_api::domain::clock::Clock;
use idp_api::presentation::{router, state::AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use support::{body_json, create_plain_user, create_sso_session, get, post, put, send};

async fn start_api(pool: &sqlx::MySqlPool) -> axum::Router {
    let db_settings = idp_api::load_db_managed_settings(pool)
        .await
        .expect("load DB-managed settings");
    let config = Config::from_env_and_db_settings(&db_settings).expect("resolve api config");
    let clock: Arc<dyn Clock> = Arc::new(support::SystemClock);
    router::build(AppState::build(pool.clone(), Arc::new(config), clock))
}

async fn runtime_setting(app: &axum::Router, cookie: &str, tenant_id: &str, key: &str) -> Value {
    let response = send(
        app,
        get(cookie, &format!("/{tenant_id}/admin/system-settings")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "system settings");
    body_json(response).await["runtime_settings"]
        .as_array()
        .expect("runtime_settings array")
        .iter()
        .find(|item| item["key"] == key)
        .unwrap_or_else(|| panic!("{key} not present in runtime settings"))
        .clone()
}

#[tokio::test]
async fn issuer_is_editable_from_the_settings_screen_but_rejects_broken_values() {
    let Some(env) = support::setup("admin issuer setting").await else {
        return;
    };
    let pool = env.pool.clone();
    let admin_cookie = create_sso_session(&pool, &env.root_admin_id).await;
    let app = start_api(&pool).await;

    // 1. 画面から編集できるキーとして出る（ENV 管理のままだと行は出るのに保存できない）。
    let item = runtime_setting(&app, &admin_cookie, &env.root_tenant_id, "ISSUER").await;
    assert_eq!(item["owner"], "DB_MANAGED", "{item}");
    assert_eq!(item["editable"], true, "{item}");
    assert_eq!(item["restart_required"], true, "{item}");
    assert_eq!(
        item["shared_with_web"], true,
        "web も消費するので両方の再起動が要ることが画面に出る: {item}"
    );

    // 2. 壊れた値は保存させない（DB は変わらない）。
    for broken in ["idp.example.com", "ftp://idp.example.com", "not a url"] {
        let response = send(
            &app,
            put(
                &admin_cookie,
                &format!("/{}/admin/system-settings/runtime", env.root_tenant_id),
                json!({ "key": "ISSUER", "value": broken }),
            ),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "`{broken}` must be rejected"
        );
    }
    let item = runtime_setting(&app, &admin_cookie, &env.root_tenant_id, "ISSUER").await;
    assert!(
        item["db_value"].is_null(),
        "拒否した値は保存されない: {item}"
    );
}

#[tokio::test]
async fn restarting_requires_the_system_admin_and_is_audited() {
    let Some(env) = support::setup("admin service restart").await else {
        return;
    };
    let pool = env.pool.clone();
    let app = start_api(&pool).await;
    let path = format!("/{}/admin/restart", env.root_tenant_id);

    // 権限なしの一般利用者は要求できない（プロセスを落とす操作なので root 限定）。
    let plain_user_id = create_plain_user(&pool, &env.root_tenant_id).await;
    let plain_cookie = create_sso_session(&pool, &plain_user_id).await;
    let response = send(&app, post(&plain_cookie, &path, json!({}))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 未認証も同様。
    let response = send(&app, post("", &path, json!({}))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // root の system 管理者なら受理される（停止は応答後なので 202 が返る）。
    let admin_cookie = create_sso_session(&pool, &env.root_admin_id).await;
    let response = send(&app, post(&admin_cookie, &path, json!({}))).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = body_json(response).await;
    assert_eq!(body["service"], "api");
    assert_eq!(body["restarting"], true);

    // 全リクエストを打ち切る操作なので、誰が要求したかが監査に残る。
    let recorded: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE event_type = 'service.restart_requested' \
         AND user_id = ?",
    )
    .bind(&env.root_admin_id)
    .fetch_one(&pool)
    .await
    .expect("count audit rows");
    assert!(recorded >= 1, "restart request must be audited");
}
