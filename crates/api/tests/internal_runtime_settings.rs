//! 共有ランタイム設定（`GET /internal/runtime-settings`。MT26 / ADR-0013）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test internal_runtime_settings
//!
//! web は DB を持たないため、api/web の両方が消費する DB 管理設定（`COOKIE_SECURE` 等）はこの
//! エンドポイントが唯一の出所になる。検証するのは次の 4 点:
//!
//! 1. `/internal/*` 共通のサービストークンで保護されている（未提示・不一致は 401）。
//! 2. `shared_with_web` のキーの DB 上書き値**だけ**を返す（api 専用のキーは漏らさない）。
//! 3. **DB → api（実サーバ）→ HTTP → web の `Config`** がつながっている。ここが切れていると
//!    api だけ新しい値で動き web は古い値のまま、という静かな不一致になる。
//!    web を dev-dependency として使う理由は `e2e_domain_split.rs` と同じ（web の sqlx 非依存という
//!    crate 境界は侵さない）。
//! 4. 上書き解除（空文字列）は「未設定」として返さない（web は自分の ENV へフォールバックする）。
//!
//! `system_settings` はテナント列を持たない IdP 全体の共有テーブルで、テストバイナリは並列に走る。
//! 同じキーを書き換えるケースを複数のテスト関数へ分けると互いに競合するため、**1 つのテスト関数**に
//! 直列化してある。

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use idp_contracts::runtime_settings::{
    SharedRuntimeSettingsResponse, SHARED_RUNTIME_SETTINGS_PATH,
};
use std::collections::HashMap;
use std::future::IntoFuture;
use support::{send, SERVICE_TOKEN, SERVICE_TOKEN_HEADER};

/// このテストが書き換える共有キー（＝ web へ渡ることを期待するキー）。
const SHARED_KEYS: [&str; 3] = ["COOKIE_SECURE", "HSTS_MAX_AGE", "AUTH_SESSION_TTL_SECS"];

/// 共有ランタイム設定 API を叩く（`token` が `Some` のときだけサービストークンを付ける）。
fn get_shared_settings(token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(SHARED_RUNTIME_SETTINGS_PATH);
    if let Some(t) = token {
        builder = builder.header(SERVICE_TOKEN_HEADER, t);
    }
    builder.body(Body::empty()).unwrap()
}

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

async fn fetch_settings(app: &axum::Router) -> SharedRuntimeSettingsResponse {
    let response = send(app, get_shared_settings(Some(SERVICE_TOKEN))).await;
    assert_eq!(response.status(), StatusCode::OK, "shared runtime settings");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&body).expect("decode shared runtime settings")
}

#[tokio::test]
async fn shared_runtime_settings_are_protected_scoped_and_reach_the_web_configuration() {
    let Some(env) = support::setup("internal runtime settings").await else {
        return;
    };
    let pool = env.pool.clone();
    let app = env.app.clone();

    // ── 1. サービストークンが無ければ 401（本文まで到達しない）。
    let response = send(&app, get_shared_settings(None)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "missing token");
    let response = send(&app, get_shared_settings(Some("wrong-token"))).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "wrong token");

    // ── 2. 共有キーと api 専用キーを並べて投入し、共有キーだけが返ることを見る。
    upsert_setting(&pool, "COOKIE_SECURE", "true").await;
    upsert_setting(&pool, "HSTS_MAX_AGE", "31536000").await;
    upsert_setting(&pool, "AUTH_SESSION_TTL_SECS", "1200").await;

    let body = fetch_settings(&app).await;
    assert_eq!(
        body.settings.get("COOKIE_SECURE").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        body.settings.get("HSTS_MAX_AGE").map(String::as_str),
        Some("31536000")
    );
    assert_eq!(
        body.settings
            .get("AUTH_SESSION_TTL_SECS")
            .map(String::as_str),
        Some("1200")
    );
    // 共有キー以外（api 専用の TTL・SMTP 設定・secret）は 1 つも載せない。他テストが並行して
    // 別のキーを書いていても、部分集合であることを見れば取りこぼしなく確認できる。
    for key in body.settings.keys() {
        assert!(
            SHARED_KEYS.contains(&key.as_str()),
            "only web-shared settings may be exposed, got {key}"
        );
    }

    // ── 3. api を実サーバとして起動し、web の起動手順（bootstrap → 取得 → 再解決）を辿る。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind api listener");
    let api_base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    // ENV には DB と**異なる**値を置き、DB が勝つことまで確かめる。環境変数はプロセス共有だが、
    // 本バイナリのテストはこの 1 関数だけなので競合しない。
    std::env::set_var("API_BASE_URL", &api_base);
    std::env::set_var("COOKIE_SECURE", "false");
    std::env::set_var("HSTS_MAX_AGE", "1");
    std::env::set_var("AUTH_SESSION_TTL_SECS", "60");

    let bootstrap = idp_web::config::Config::from_env().expect("bootstrap web config");
    let client = idp_web::api_client::ApiClient::new(
        bootstrap.api_base_url(),
        bootstrap.internal_service_token(),
    );
    let shared: HashMap<String, String> = client
        .fetch_shared_runtime_settings()
        .await
        .expect("fetch shared runtime settings from api");
    let web_config =
        idp_web::config::Config::from_env_and_shared_settings(&shared).expect("resolve web config");

    assert!(web_config.cookie_secure(), "DB value must win over ENV");
    assert_eq!(web_config.hsts_max_age(), 31_536_000);
    assert_eq!(web_config.auth_session_ttl_secs(), 1_200);
    let mut applied = web_config.shared_settings_from_api().to_vec();
    applied.sort();
    assert_eq!(
        applied,
        ["AUTH_SESSION_TTL_SECS", "COOKIE_SECURE", "HSTS_MAX_AGE"],
        "web must report which keys came from the DB"
    );

    // ── 4. 上書き解除（空文字列）は「未設定」として返さない → web は自分の ENV へ戻る。
    upsert_setting(&pool, "HSTS_MAX_AGE", "").await;
    let shared = client
        .fetch_shared_runtime_settings()
        .await
        .expect("refetch shared runtime settings");
    assert!(
        !shared.contains_key("HSTS_MAX_AGE"),
        "cleared overrides must be absent, not empty: {shared:?}"
    );
    let web_config =
        idp_web::config::Config::from_env_and_shared_settings(&shared).expect("resolve web config");
    assert_eq!(web_config.hsts_max_age(), 1, "falls back to the web ENV");

    for key in SHARED_KEYS {
        std::env::remove_var(key);
        delete_setting(&pool, key).await;
    }
    std::env::remove_var("API_BASE_URL");
}
