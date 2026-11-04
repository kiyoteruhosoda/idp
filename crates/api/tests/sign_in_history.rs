//! 本人が見るログイン履歴（task #879。ADR-0073）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test sign_in_history
//!
//! 単体テストでは繋がりを証明できない。履歴は 3 か所（web の応答・監査ログの書き込み・`/token`）で
//! 写され、`sid` で突き合わせて 1 行にまとまる。ログイン → 失敗 → コードの交換 → 更新 → 使い回し
//! までを実 DB で通し、画面へ渡る形（`/internal/account/sign-in-history`）で確かめる。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use support::{
    body_json, handoff_handle, post_internal, query_param, resume_authorize, send, TestEnv,
    CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

const PASSWORD: &str = "correct-horse-battery";

fn basic_auth(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

fn unique_username() -> String {
    format!("sh{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

/// `/authorize` から始めて、ログインの欄を開いたところ（`auth_session_id`）まで進める。
async fn begin(env: &TestEnv, client_id: &str, scope: &str) -> String {
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st&nonce=nc&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode(scope, NON_ALPHANUMERIC)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to /login");
    let handle = handoff_handle(&response);
    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], "login_required");
    body["auth_session_id"].as_str().unwrap().to_string()
}

async fn authenticate(env: &TestEnv, auth_session: &str, username: &str, password: &str) -> Value {
    let csrf = assay_api::application::login::csrf_token(auth_session, &env.csrf_secret);
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
                "ip_address": "203.0.113.10",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
            }),
        ),
    )
    .await;
    body_json(response).await
}

/// web がログイン状態の Cookie を置いた応答で呼ぶ口（端末の判定と同じ）。
async fn observe(env: &TestEnv, sso_cookie: &str, country: Option<&str>) {
    let response = send(
        &env.app,
        post_internal(
            "/internal/devices/observe",
            Some(SERVICE_TOKEN),
            json!({
                "sso_session_id": sso_cookie,
                "device_token": null,
                "country": country,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "device observation");
}

/// 同意を挟まれたら承諾し、戻り先の code を返す。
async fn code_from(env: &TestEnv, body: &Value) -> String {
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
            body_json(response).await["redirect_to"]
                .as_str()
                .unwrap()
                .to_string()
        }
        _ => body["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string(),
    };
    assert!(callback.starts_with(REDIRECT_URI));
    query_param(&callback, "code").expect("authorization code")
}

async fn token(env: &TestEnv, client_id: &str, secret: &str, form: String) -> (StatusCode, Value) {
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(form))
            .unwrap(),
    )
    .await;
    let status = response.status();
    (status, body_json(response).await)
}

async fn refresh(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    refresh_token: &str,
) -> (StatusCode, Value) {
    token(
        env,
        client_id,
        secret,
        format!(
            "grant_type=refresh_token&refresh_token={}",
            utf8_percent_encode(refresh_token, NON_ALPHANUMERIC)
        ),
    )
    .await
}

async fn history(env: &TestEnv, sso_cookie: &str) -> Value {
    let response = send(
        &env.app,
        post_internal(
            "/internal/account/sign-in-history",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": sso_cookie,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "sign-in history");
    body_json(response).await
}

/// **ログイン・失敗・アプリでの更新・使い回しが、本人の履歴に分けて並ぶ。他人には見えない。**
#[tokio::test]
async fn sign_ins_failures_and_refreshes_appear_in_the_owners_history_only() {
    let Some(env) = support::setup("sign-in history").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();
    support::register_user(&env.app, &env.root_tenant_id, &username, PASSWORD).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    // 1. パスワード違い（失敗の行になる）。
    let auth_session = begin(&env, &client_id, "openid offline_access").await;
    let failed = authenticate(&env, &auth_session, &username, "wrong-password-123").await;
    assert!(
        failed["sso_session_id"].is_null(),
        "wrong password must not sign in: {failed}"
    );

    // 2. 正しいパスワードでログインし、web と同じく Cookie を置いた応答で写す（国は JP）。
    let auth_session = begin(&env, &client_id, "openid offline_access").await;
    let body = authenticate(&env, &auth_session, &username, PASSWORD).await;
    let sso_cookie = body["sso_session_id"]
        .as_str()
        .expect("sso session")
        .to_string();
    observe(&env, &sso_cookie, Some("JP")).await;
    // 同じログインの 2 回目の頼みは行を増やさない。
    observe(&env, &sso_cookie, Some("KP")).await;

    // 3. アプリがコードを交換し、リフレッシュトークンで 2 回更新する。
    let code = code_from(&env, &body).await;
    let (status, tokens) = token(
        &env,
        &client_id,
        &secret,
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token endpoint: {tokens}");
    let first = tokens["refresh_token"].as_str().unwrap().to_string();
    let (status, rotated) = refresh(&env, &client_id, &secret, &first).await;
    assert_eq!(status, StatusCode::OK);
    let second = rotated["refresh_token"].as_str().unwrap().to_string();
    let (status, _) = refresh(&env, &client_id, &secret, &second).await;
    assert_eq!(status, StatusCode::OK);

    let page = history(&env, &sso_cookie).await;
    assert_eq!(page["result"], "ok", "{page}");
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "1 success + 1 failure: {page}");

    // 新しい順: 先頭が成功、次が失敗。
    let ok = &entries[0];
    assert_eq!(ok["outcome"], "succeeded");
    assert_eq!(ok["current"], true);
    assert_eq!(ok["country"], "JP", "the first observation wins: {ok}");
    assert_eq!(ok["methods"], json!(["password"]));
    let apps = ok["apps"].as_array().unwrap();
    assert_eq!(apps.len(), 1, "{ok}");
    assert_eq!(apps[0]["client_id"], client_id);
    let usage = &apps[0]["refresh"];
    assert_eq!(usage["use_count"], 2, "{usage}");
    assert!(usage["last_used_at"].is_string(), "{usage}");
    assert_eq!(usage["state"], "active");
    assert!(usage["reuse_detected_at"].is_null());

    let ng = &entries[1];
    assert_eq!(ng["outcome"], "failed");
    assert_eq!(ng["failure_kind"], "wrong_password");
    assert_eq!(ng["ip_address"], "203.0.113.10");
    assert!(ng["apps"].as_array().unwrap().is_empty());

    // 4. 使い終えたトークンをもう一度出す → 使い回しの検知と、取り消し。
    let (status, _) = refresh(&env, &client_id, &secret, &first).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let page = history(&env, &sso_cookie).await;
    let usage = &page["entries"][0]["apps"][0]["refresh"];
    assert!(usage["reuse_detected_at"].is_string(), "{usage}");
    assert_eq!(usage["state"], "revoked", "{usage}");

    // 5. 別の利用者のログイン状態では、この利用者の行は 1 つも出ない。
    let other = unique_username();
    support::register_user(&env.app, &env.root_tenant_id, &other, PASSWORD).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &other).await;
    let auth_session = begin(&env, &client_id, "openid").await;
    let body = authenticate(&env, &auth_session, &other, PASSWORD).await;
    let other_cookie = body["sso_session_id"].as_str().unwrap().to_string();
    observe(&env, &other_cookie, None).await;
    let page = history(&env, &other_cookie).await;
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "only the other user's own sign-in: {page}"
    );
    assert!(
        entries[0]["country"].is_null(),
        "no country header, no country"
    );
    assert_eq!(
        entries[0]["outcome"], "succeeded",
        "the first user's failed attempt must not appear here: {page}"
    );
    assert!(
        entries[0]["apps"].as_array().unwrap().is_empty(),
        "the first user's app usage must not leak: {page}"
    );
}

/// ログイン状態が無い（切れた）なら、履歴は返さない。
#[tokio::test]
async fn an_unknown_session_gets_no_history() {
    let Some(env) = support::setup("sign-in history without a session").await else {
        return;
    };
    let page = history(&env, "not-a-session").await;
    assert_eq!(page["result"], "session_expired", "{page}");
}
