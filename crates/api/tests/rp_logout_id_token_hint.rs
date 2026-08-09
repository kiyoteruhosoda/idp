//! RP-initiated Logout の `id_token_hint` の統合テスト（G12。OIDC RP-Initiated Logout 1.0 §2）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test rp_logout_id_token_hint
//!
//! 検証の要:
//! - 検証済み hint の `aud` が `post_logout_redirect_uri` の照合先になること（`client_id`
//!   パラメータが無くても、その RP に登録された URI だけが通る）。
//! - 署名・issuer が確かめられない hint では**リダイレクトを返さない**こと（確かめられない相手へ
//!   ブラウザを送り返さない）。セッションの終了自体は続けること（ログアウトは冪等）。
//! - hint の `sub` が現在ログイン中の利用者と違うなら、そのセッションを**終了しない**こと。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use sqlx::MySqlPool;
use support::{
    body_json, handoff_handle, post_internal, query_param, resume_authorize, send, TestEnv,
    CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

const POST_LOGOUT_URI: &str = "https://app.example.com/after-logout";

/// ログイン 1 回ぶんの成果物（ID Token と、そのログインで発行された SSO Cookie）。
struct LoggedIn {
    id_token: String,
    sso_cookie: String,
}

/// クライアントへ `post_logout_redirect_uris` を設定する（support の挿入ヘルパーは持たない）。
async fn set_post_logout_uri(pool: &MySqlPool, client_id: &str, uri: &str) {
    sqlx::query("UPDATE clients SET post_logout_redirect_uris = ? WHERE client_id = ?")
        .bind(json!([uri]).to_string())
        .bind(client_id)
        .execute(pool)
        .await
        .expect("set post_logout_redirect_uris");
}

async fn register_user(app: &axum::Router, tenant: &str, username: &str, password: &str) {
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "email": format!("{username}@example.com"),
                    "preferred_username": username,
                    "password": password,
                    "name": "Logout Tester",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
}

/// `/authorize` → ログイン → 同意 → `/token` を通し、ID Token と SSO Cookie を得る。
async fn log_in(env: &TestEnv, client_id: &str, secret: &str, username: &str) -> LoggedIn {
    let password = "correct-horse-battery";
    register_user(&env.app, &env.root_tenant_id, username, password).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, username).await;

    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st&nonce=nc&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode("openid", NON_ALPHANUMERIC)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to /login");
    let handle = handoff_handle(&response);

    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], "login_required");
    let auth_session = body["auth_session_id"].as_str().unwrap().to_string();
    let csrf = idp_api::application::login::csrf_token(&auth_session, &env.csrf_secret);

    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let sso_cookie = body["sso_session_id"].as_str().unwrap().to_string();

    // 初回ログインは同意ステップを挟む場合がある（scope 構成による）。挟むなら承諾する。
    let callback = match body["result"].as_str() {
        Some("consent_required") => {
            let consent_session = body["auth_session_id"].as_str().unwrap().to_string();
            let response = send(
                &env.app,
                post_internal(
                    "/internal/consent/approve",
                    Some(SERVICE_TOKEN),
                    json!({
                        "tenant_id": env.root_tenant_id,
                        "auth_session_id": consent_session,
                    }),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = body_json(response).await;
            assert_eq!(body["result"], "success");
            body["redirect_to"].as_str().unwrap().to_string()
        }
        _ => body["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string(),
    };
    assert!(callback.starts_with(REDIRECT_URI));
    let code = query_param(&callback, "code").expect("authorization code");

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{client_id}:{secret}"))
                ),
            )
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "token endpoint");
    let tokens = body_json(response).await;
    LoggedIn {
        id_token: tokens["id_token"].as_str().expect("id_token").to_string(),
        sso_cookie,
    }
}

/// `POST /internal/logout/rp` を叩く。
async fn rp_logout(env: &TestEnv, payload: Value) -> Value {
    let response = send(
        &env.app,
        post_internal("/internal/logout/rp", Some(SERVICE_TOKEN), payload),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "rp logout");
    body_json(response).await
}

async fn sso_session_exists(pool: &MySqlPool, sso_cookie: &str) -> bool {
    let hash = idp_api::infrastructure::crypto::sha256_hex(sso_cookie);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE session_hash = ?")
        .bind(hash)
        .fetch_one(pool)
        .await
        .expect("count sso sessions");
    count > 0
}

fn unique_username() -> String {
    format!("lo{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

/// 検証済み hint の `aud` が `post_logout_redirect_uri` の照合先になる（`client_id` 不要）。
#[tokio::test]
async fn a_verified_id_token_hint_authorizes_the_post_logout_redirect() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "id_token_hint": session.id_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
            "state": "xyz",
        }),
    )
    .await;

    assert_eq!(result["result"], "ok");
    let redirect = result["redirect_to"].as_str().expect("redirect_to");
    assert!(redirect.starts_with(POST_LOGOUT_URI), "{redirect}");
    assert_eq!(query_param(redirect, "state").as_deref(), Some("xyz"));
    assert!(
        !sso_session_exists(&env.pool, &session.sso_cookie).await,
        "the sso session must be terminated"
    );
}

/// 検証を通らない hint ではリダイレクトを返さない。セッションの終了自体は続ける。
#[tokio::test]
async fn an_unverifiable_id_token_hint_suppresses_the_redirect_but_still_logs_out() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    // 署名部分を差し替えた ID Token（ヘッダ・ペイロードは本物）。
    let mut parts: Vec<&str> = session.id_token.split('.').collect();
    parts[2] = "AAAA";
    let tampered = parts.join(".");

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "id_token_hint": tampered,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    assert_eq!(result["result"], "ok");
    assert!(
        result["redirect_to"].is_null(),
        "an unverifiable hint must not produce a redirect: {result}"
    );
    assert!(
        !sso_session_exists(&env.pool, &session.sso_cookie).await,
        "logout itself is idempotent and must still happen"
    );
}

/// Access Token（`typ=at+jwt`）は hint として受け付けない。
#[tokio::test]
async fn an_access_token_is_not_accepted_as_an_id_token_hint() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["reports.read"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{client_id}:{secret}"))
                ),
            )
            .body(Body::from("grant_type=client_credentials"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let access_token = body_json(response).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "id_token_hint": access_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;
    assert!(
        result["redirect_to"].is_null(),
        "an access token must not authorize the redirect: {result}"
    );
}

/// hint の `sub` が現在ログイン中の利用者と違うなら、そのセッションは終了しない。
#[tokio::test]
async fn a_hint_for_another_user_does_not_terminate_the_current_session() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    // 利用者 A の ID Token を取り、そのあと同じブラウザで利用者 B がログインした状況を作る。
    let first = log_in(&env, &client_id, &secret, &unique_username()).await;
    let second = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": second.sso_cookie,
            "id_token_hint": first.id_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    // `ok` ではなく `subject_mismatch` を返す。web はこれを見て **Cookie を消さない**
    // （消すと DB にだけセッションが生きた宙ぶらりんの状態になる）。
    assert_eq!(result["result"], "subject_mismatch", "{result}");
    assert!(
        result["redirect_to"].is_null(),
        "a mismatched hint must not produce a redirect: {result}"
    );
    assert!(
        sso_session_exists(&env.pool, &second.sso_cookie).await,
        "another user's session must survive"
    );
}

/// `client_id` パラメータと hint の `aud` が食い違う場合はどちらも信用しない。
#[tokio::test]
async fn a_client_id_that_contradicts_the_hint_suppresses_the_redirect() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;
    let (other_client_id, _) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &other_client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "client_id": other_client_id,
            "id_token_hint": session.id_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    assert!(
        result["redirect_to"].is_null(),
        "contradicting client_id and aud must not produce a redirect: {result}"
    );
}

/// hint の `aud` に登録されていない URI は通らない（別 RP に登録された URI でも同じ）。
#[tokio::test]
async fn the_redirect_must_be_registered_for_the_client_named_by_the_hint() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    // hint を出す RP には別の URI を登録し、要求する URI は**他の RP**にだけ登録する。
    set_post_logout_uri(&env.pool, &client_id, "https://app.example.com/own").await;
    let (other_client_id, _) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &other_client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "id_token_hint": session.id_token,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    assert!(
        result["redirect_to"].is_null(),
        "a URI registered for another RP must not be honoured: {result}"
    );
}

/// hint も `client_id` も無い従来の要求は、これまでどおりテナント内の登録 URI で通る。
#[tokio::test]
async fn a_request_without_any_hint_keeps_the_previous_behaviour() {
    let Some(env) = support::setup("rp logout id_token_hint").await else {
        return;
    };
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    set_post_logout_uri(&env.pool, &client_id, POST_LOGOUT_URI).await;

    let session = log_in(&env, &client_id, &secret, &unique_username()).await;

    let result = rp_logout(
        &env,
        json!({
            "tenant_id": env.root_tenant_id,
            "sso_session_id": session.sso_cookie,
            "post_logout_redirect_uri": POST_LOGOUT_URI,
        }),
    )
    .await;

    let redirect = result["redirect_to"].as_str().expect("redirect_to");
    assert!(redirect.starts_with(POST_LOGOUT_URI), "{redirect}");
}
