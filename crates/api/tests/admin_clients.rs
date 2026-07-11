//! クライアント（RP）登録・管理 API の E2E 統合テスト（Progress A1、設計仕様 §9.3）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_clients
//!
//! 認可は `RequirePerms<IdpAdmin>`（`idp.tenant.admin`。`idp.system.admin` は代替として許可）。
//! 初期管理者（seed 0002 で root テナントへ `idp.system.admin` 付与済み）の SSO セッションを
//! 直接作成し、その Cookie で管理 API を叩く。権限の無い利用者は 403 になることも検証する。

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE};
use axum::http::{Request, StatusCode};
use idp_api::config::Config;
use idp_api::domain::clock::Clock;
use idp_api::infrastructure::crypto;
use idp_api::presentation::router;
use idp_api::presentation::state::AppState;
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use std::sync::Arc;
use tower::ServiceExt;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const REDIRECT_URI: &str = "https://app.example.com/callback";

struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

struct TestEnv {
    app: axum::Router,
    pool: MySqlPool,
    /// 過渡期（MT9 まで）の既定テナント = seed 済み root テナントの UUID。
    root_tenant_id: String,
    /// seed 0002 の初期管理者（root 所属・idp.system.admin 保有）。UUID は動的採番のため DB から引く。
    admin_id: String,
}

async fn setup() -> Option<TestEnv> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping admin clients integration test");
        return None;
    };
    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");
    MIGRATOR.run(&pool).await.expect("run migrations");

    let root_tenant_id: String =
        sqlx::query_scalar("SELECT id FROM tenants WHERE parent_tenant_id IS NULL")
            .fetch_one(&pool)
            .await
            .expect("root tenant seeded");
    let admin_id: String =
        sqlx::query_scalar("SELECT id FROM users WHERE tenant_id = ? AND email = 'admin@example.com'")
            .bind(&root_tenant_id)
            .fetch_one(&pool)
            .await
            .expect("initial admin seeded");
    let root = idp_api::domain::tenant::TenantId::from(
        uuid::Uuid::parse_str(&root_tenant_id).expect("root UUID"),
    );

    let config = Arc::new(Config::from_env().expect("load config"));
    let state = AppState::build(pool.clone(), config, Arc::new(SystemClock), root);
    Some(TestEnv {
        app: router::build(state),
        pool,
        root_tenant_id,
        admin_id,
    })
}

/// 指定ユーザーの有効な SSO セッションを作成し、Cookie 用の平文 session_id を返す。
async fn create_sso_session(pool: &MySqlPool, user_id: &str) -> String {
    let session_id = crypto::random_hex(32);
    let session_hash = crypto::sha256_hex(&session_id);
    sqlx::query(
        "INSERT INTO sso_sessions \
         (session_hash, user_id, auth_time, idle_expires_at, absolute_expires_at) \
         VALUES (?, ?, UTC_TIMESTAMP(6), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 HOUR), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 8 HOUR))",
    )
    .bind(&session_hash)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert sso session");
    session_id
}

async fn send(app: &axum::Router, request: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(request).await.expect("send request")
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn admin_post(cookie: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .header(COOKIE, format!("sso_session_id={cookie}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn admin_can_manage_clients_but_others_cannot() {
    let Some(env) = setup().await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.admin_id).await;

    // 未認証（Cookie 無し）→ 401。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/admin/clients", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(json!({}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // 権限の無い利用者 → 403。
    let plain_user_id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, 'x', 'ACTIVE')",
    )
    .bind(&plain_user_id)
    .bind(&env.root_tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!(
        "plain-{}@example.com",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ))
    .execute(&env.pool)
    .await
    .expect("insert plain user");
    let plain_cookie = create_sso_session(&env.pool, &plain_user_id).await;
    let res = send(
        &env.app,
        admin_post(
            &plain_cookie,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": "X",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // バリデーション: フラグメント付き redirect_uri → 400。
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": "Bad",
                "client_type": "public",
                "redirect_uris": ["https://app.example.com/cb#frag"],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "fragment uri -> 400");

    // public クライアント登録 → 201・secret 無し。
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": "Public App",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid", "profile"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "public create -> 201");
    let created = body_json(res).await;
    let public_client_id = created["client_id"].as_str().unwrap().to_string();
    assert!(
        created.get("client_secret").is_none(),
        "public has no secret"
    );
    assert_eq!(created["token_endpoint_auth_method"], "none");

    // public のシークレット再発行 → 400。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/admin/clients/{public_client_id}/secret", env.root_tenant_id))
            .header(COOKIE, format!("sso_session_id={admin_cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "public secret -> 400"
    );

    // confidential クライアント登録 → 201・secret 平文あり。
    let res = send(
        &env.app,
        admin_post(
            &admin_cookie,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": "Confidential App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "confidential create -> 201"
    );
    let created = body_json(res).await;
    let conf_client_id = created["client_id"].as_str().unwrap().to_string();
    let first_secret = created["client_secret"]
        .as_str()
        .expect("confidential returns secret")
        .to_string();
    assert!(!first_secret.is_empty());
    assert_eq!(created["token_endpoint_auth_method"], "client_secret_basic");

    // 一覧に両クライアントが含まれる。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(format!("/{}/admin/clients", env.root_tenant_id))
            .header(COOKIE, format!("sso_session_id={admin_cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let list = body_json(res).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["client_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&public_client_id.as_str()));
    assert!(ids.contains(&conf_client_id.as_str()));

    // 更新: status を DISABLED に。
    let res = send(
        &env.app,
        Request::builder()
            .method("PATCH")
            .uri(format!("/{}/admin/clients/{public_client_id}", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/json")
            .header(COOKIE, format!("sso_session_id={admin_cookie}"))
            .body(Body::from(
                json!({ "client_status": "DISABLED" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["client_status"], "DISABLED");

    // confidential のシークレット再発行 → 200・新しい値（旧値と異なる）。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/admin/clients/{conf_client_id}/secret", env.root_tenant_id))
            .header(COOKIE, format!("sso_session_id={admin_cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let rotated = body_json(res).await["client_secret"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!rotated.is_empty());
    assert_ne!(rotated, first_secret, "rotation changes the secret");

    // 不存在の取得 → 404。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(format!("/{}/admin/clients/does-not-exist", env.root_tenant_id))
            .header(COOKIE, format!("sso_session_id={admin_cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing client -> 404");
}
