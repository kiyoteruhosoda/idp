//! 内部認証 API（`/internal/authenticate*`、ADR-0007 §3・§5）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test internal_auth
//!
//! web →api のサービス間 I/F を検証する。web は資格情報・auth_session 参照・接続元情報を
//! JSON で転送し、api は SSO/code を発行して `result` タグ付き JSON を返す。サービス認証トークン
//! （`X-Internal-Auth-Token`）が無ければ 401 で遮断される。

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use idp_api::application::login::csrf_token;
use serde_json::json;
use support::{
    body_json, cookie_value, post_internal, send, CODE_CHALLENGE, REDIRECT_URI, SERVICE_TOKEN,
};

async fn register_user(app: &axum::Router, tenant: &str, username: &str, password: &str) {
    let payload = json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": password,
        "name": "Internal Auth Tester",
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
}

/// `/authorize` を開始して `auth_session_id` Cookie を得る（未ログインなので /login へ 302）。
async fn start_authorize(app: &axum::Router, tenant: &str, client_id: &str) -> String {
    let uri = format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid%20profile%20email&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
        "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
    );
    let response = send(
        app,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "authorize -> login");
    cookie_value(&response, "auth_session_id").expect("auth_session_id cookie")
}

#[tokio::test]
async fn authenticate_requires_service_token_and_issues_sso_and_code() {
    let Some(env) = support::setup("internal auth").await else {
        return;
    };
    let (app, pool, root_tenant_id, csrf_secret) =
        (env.app, env.pool, env.root_tenant_id, env.csrf_secret);

    let client_id =
        support::insert_public_client(&pool, &root_tenant_id, &["openid", "profile", "email"])
            .await;
    let username = format!("int{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let password = "correct-horse-battery";
    register_user(&app, &root_tenant_id, &username, password).await;
    support::mark_email_verified(&pool, &root_tenant_id, &username).await;

    // サービストークンが無ければ 401（本文まで到達しない）。
    let auth_session = start_authorize(&app, &root_tenant_id, &client_id).await;
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            None,
            json!({
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session, &csrf_secret),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "missing token");

    // 誤ったトークンも 401。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some("wrong-token"),
            json!({
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session, &csrf_secret),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "wrong token");

    // CSRF 不一致（正しいトークンだが csrf が違う）→ result=csrf_mismatch。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": root_tenant_id,
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": "0".repeat(64),
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["result"], "csrf_mismatch");

    // 正常系: 認証成功。初回は profile/email が未同意のため同意ステップへ（F3）。
    // SSO セッション id はこの時点で発行される。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": root_tenant_id,
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session, &csrf_secret),
                "ip_address": "203.0.113.7",
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "authenticate success");
    let body = body_json(response).await;
    assert_eq!(body["result"], "consent_required");
    let consent_session = body["auth_session_id"]
        .as_str()
        .expect("auth_session_id")
        .to_string();
    assert!(!body["sso_session_id"].as_str().unwrap().is_empty());
    assert!(body["sso_absolute_ttl_secs"].as_u64().unwrap() > 0);

    // 同意を承諾すると code 付き redirect を返す。
    let response = send(
        &app,
        post_internal(
            "/internal/consent/approve",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": root_tenant_id, "auth_session_id": consent_session }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "consent approve");
    let body = body_json(response).await;
    assert_eq!(body["result"], "success");
    assert!(
        body["redirect_to"]
            .as_str()
            .unwrap()
            .starts_with(REDIRECT_URI),
        "redirect_to should point at the RP: {body}"
    );

    // SSO セッションが DB に作成され、web から転送された接続元 IP が記録されている
    // （並行する他テストと干渉しないよう、この試行に固有の IP で絞り込む）。
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE ip_address = ?")
        .bind("203.0.113.7")
        .fetch_one(&pool)
        .await
        .expect("query sso_sessions");
    assert!(count >= 1, "an SSO session recorded with the forwarded IP");
}

#[tokio::test]
async fn admin_authenticate_rejects_unknown_user() {
    let Some(env) = support::setup("internal auth").await else {
        return;
    };
    let (app, root_tenant_id) = (env.app, env.root_tenant_id);

    // 認証情報が誤り（未登録ユーザー）→ result=invalid_credentials。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate/admin",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": root_tenant_id,
                "username": format!("nobody-{}", uuid::Uuid::new_v4()),
                "password": "whatever",
                "ip_address": "203.0.113.9",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["result"], "invalid_credentials");

    // サービストークンが無ければ 401。
    let response = send(
        &app,
        post_internal(
            "/internal/authenticate/admin",
            None,
            json!({ "username": "x", "password": "y" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // tenant_id が無い・不正な内部リクエストは 400（fail-closed。SEC4）。
    for bad in [
        json!({ "username": "x", "password": "y" }),
        json!({ "tenant_id": "not-a-uuid", "username": "x", "password": "y" }),
    ] {
        let response = send(
            &app,
            post_internal("/internal/authenticate/admin", Some(SERVICE_TOKEN), bad),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "missing/invalid tenant_id -> 400"
        );
    }
}
