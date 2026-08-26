//! 「保存済みだが未反映」の可視化（`GET /{tenant_id}/admin/system-settings`。MT27）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_pending_restart
//!
//! ランタイム設定は `restart_required` で、保存しただけでは稼働中のプロセスの挙動が変わらない。
//! それが画面から見えないと、運用者は「保存したのに直らない」と誤った結論に至る。検証するのは:
//!
//! 1. 起動時の値と保存値が一致していれば未反映ではない。
//! 2. 保存値を変えると未反映になる（api を再起動していないため）。
//! 3. **上書きを解除しても未反映**（起動時は DB から採っていたので、まだ既定値に戻っていない）。
//! 4. その状態で api を起動し直すと未反映が解消する。
//! 5. 共有キー（`shared_with_web`）はその旨が応答に載る（反映に web の再起動も要るため）。
//! 6. 出所区分が `DbManaged` から `EnvLocked` へ変わったキーの残存行は未反映にしない
//!    （`EnvLocked` は DB を見ないので、突き合わせると再起動しても消えない警告になる）。
//!
//! `system_settings` はテナント列を持たない IdP 全体の共有テーブルで、テストバイナリは並列に走る。
//! 他のテストと同じキーを書き換えると互いに競合するため、本テスト専用のキー
//! （`TENANT_CACHE_TTL_SECS`）を 1 つのテスト関数の中だけで扱う。共有キーの確認は**書き換えずに**
//! フラグの有無だけを見る。

mod support;

use axum::http::StatusCode;
use idp_api::config::Config;
use idp_api::domain::clock::Clock;
use idp_api::presentation::{router, state::AppState};
use serde_json::Value;
use std::sync::Arc;
use support::{admin_token, body_json, get, send};

/// 本テスト専用のキー（`DB_MANAGED` / 非 secret / `restart_required`。web とは共有しない）。
const KEY: &str = "TENANT_CACHE_TTL_SECS";
/// 共有キーの代表。値は書き換えず `shared_with_web` フラグの確認にだけ使う。
const SHARED_KEY: &str = "COOKIE_SECURE";
/// `EnvLocked` のキー（ADR-0012 で `DbManaged` から移した）。残存行があっても未反映にしないことの確認用。
/// `EnvLocked` は解決時に DB を参照しないため、この行を入れても設定の解決には影響しない。
const ENV_LOCKED_KEY: &str = "PUBLIC_WEB_BASE_URL";

async fn upsert_setting(pool: &sqlx::MySqlPool, key: &str, value: &str) {
    sqlx::query(
        "INSERT INTO system_settings (setting_key, setting_value, is_secret) VALUES (?, ?, 0) \
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    .expect("upsert system setting");
}

async fn delete_setting(pool: &sqlx::MySqlPool, key: &str) {
    sqlx::query("DELETE FROM system_settings WHERE setting_key = ?")
        .bind(key)
        .execute(pool)
        .await
        .expect("delete system setting");
}

/// api の起動シーケンス（DB 管理設定の読み出し → `Config` 解決 → ルータ組立）を再現する。
/// 「起動時スナップショット」と現在の DB 値のずれを見る本テストでは、再起動を表現する要になる。
async fn start_api(pool: &sqlx::MySqlPool) -> axum::Router {
    let db_settings = idp_api::load_db_managed_settings(pool)
        .await
        .expect("load DB-managed settings");
    let config = Config::from_env_and_db_settings(&db_settings).expect("resolve api config");
    let clock: Arc<dyn Clock> = Arc::new(support::SystemClock);
    router::build(AppState::build(pool.clone(), Arc::new(config), clock))
}

/// 設定画面が読む応答から、対象キーの 1 件を取り出す。
async fn runtime_setting(app: &axum::Router, cookie: &str, tenant_id: &str, key: &str) -> Value {
    let response = send(
        app,
        get(cookie, &format!("/{tenant_id}/admin/system-settings")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "system settings");
    let body = body_json(response).await;
    body["runtime_settings"]
        .as_array()
        .expect("runtime_settings array")
        .iter()
        .find(|item| item["key"] == key)
        .unwrap_or_else(|| panic!("{key} not present in runtime settings"))
        .clone()
}

#[tokio::test]
async fn saved_settings_are_reported_as_pending_until_the_api_restarts() {
    let Some(env) = support::setup("admin pending restart").await else {
        return;
    };
    let pool = env.pool.clone();
    let admin_tok = admin_token(&env.app, &pool, &env.root_tenant_id, &env.root_admin_id).await;

    // ── 1. 上書きを保存した状態で api を「起動」する → 反映済み。
    upsert_setting(&pool, KEY, "120").await;
    let app = start_api(&pool).await;
    let item = runtime_setting(&app, &admin_tok, &env.root_tenant_id, KEY).await;
    assert_eq!(item["source"], "DB");
    assert_eq!(item["value"], "120");
    assert_eq!(item["db_value"], "120");
    assert_eq!(
        item["pending_restart"], false,
        "起動時の値と保存値が同じなら未反映ではない: {item}"
    );

    // ── 2. 保存値を変える（api は再起動していない）→ 未反映。
    upsert_setting(&pool, KEY, "300").await;
    let item = runtime_setting(&app, &admin_tok, &env.root_tenant_id, KEY).await;
    assert_eq!(item["value"], "120", "稼働中の api は起動時の値のまま");
    assert_eq!(item["db_value"], "300", "保存値は新しい");
    assert_eq!(
        item["pending_restart"], true,
        "保存しただけでは効いていないことが分かる: {item}"
    );

    // ── 3. 上書きを解除する → **これも未反映**（まだ既定値に戻っていない）。
    delete_setting(&pool, KEY).await;
    let item = runtime_setting(&app, &admin_tok, &env.root_tenant_id, KEY).await;
    assert!(item["db_value"].is_null(), "保存値は無くなった: {item}");
    assert_eq!(item["value"], "120", "稼働中の api は起動時の値のまま");
    assert_eq!(
        item["pending_restart"], true,
        "解除の未反映を取りこぼすと「解除したのに戻らない」が見えない: {item}"
    );

    // ── 4. 再起動すると解消する。
    let restarted = start_api(&pool).await;
    let item = runtime_setting(&restarted, &admin_tok, &env.root_tenant_id, KEY).await;
    assert_ne!(item["source"], "DB", "DB 上書きは解除済み: {item}");
    assert_eq!(item["pending_restart"], false, "再起動で解消する: {item}");

    // ── 5. 共有キーは「web の再起動も要る」ことが応答から分かる（値は書き換えない）。
    let shared = runtime_setting(&restarted, &admin_tok, &env.root_tenant_id, SHARED_KEY).await;
    assert_eq!(shared["shared_with_web"], true, "{shared}");
    let own = runtime_setting(&restarted, &admin_tok, &env.root_tenant_id, KEY).await;
    assert_eq!(own["shared_with_web"], false, "{own}");

    // ── 6. 出所区分が `DbManaged` から `EnvLocked` へ変わったキーの残存行は未反映にしない。
    // `EnvLocked` は解決時に DB を見ないので `source` が `DB` になり得ず、突き合わせると
    // **再起動しても消えない**警告が出続ける。しかも `editable` が false で画面から消せない。
    upsert_setting(&pool, ENV_LOCKED_KEY, "https://legacy.example.com").await;
    let legacy = start_api(&pool).await;
    let item = runtime_setting(&legacy, &admin_tok, &env.root_tenant_id, ENV_LOCKED_KEY).await;
    assert_ne!(item["source"], "DB", "EnvLocked は DB を参照しない: {item}");
    assert_eq!(
        item["editable"], false,
        "画面から消せないキーであることの確認: {item}"
    );
    assert_eq!(
        item["pending_restart"], false,
        "残存行は設定の解決に影響しないので未反映ではない: {item}"
    );
    delete_setting(&pool, ENV_LOCKED_KEY).await;
}
