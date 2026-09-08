//! セッションを終えたら、そのセッションの refresh token も使えなくなる（ADR-0044）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' \
//!     cargo test --test session_end_revokes_refresh_tokens
//!
//! これは**単体テストでは証明できない**。`sid` は発行時に持ち回られ rotation で引き継がれる
//! 値で、失効はその `sid` に対する 1 本の UPDATE である。つまり「発行 → 更新 → セッション終了
//! → 更新が断られる」までを実 DB で通さないと、経路が繋がっている確証にならない。
//!
//! 何を守っているか:
//!
//! アクセストークンは既定 15 分で切れる。だがログアウトが refresh token を落とさないと、
//! **その端末は 15 分ごとに新しいアクセストークンを取り直せる**（rotation は期限を延ばさないので
//! 最初の発行から 30 日が上限だが、ログアウトしたはずの端末が 30 日動く時点で「ログアウト」に
//! なっていない）。短命アクセストークンは、失効が効くことを前提にして初めて意味を持つ。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::json;
use support::{
    body_json, handoff_handle, post_internal, query_param, resume_authorize, send, TestEnv,
    CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

/// ログイン 1 回ぶんの成果物。
struct LoggedIn {
    refresh_token: String,
    sso_cookie: String,
}

fn basic_auth(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

fn unique_username() -> String {
    format!("sr{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
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
                    "name": "Session Revoke Tester",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
}

/// `offline_access` 付きで一通り通し、refresh token と SSO Cookie を得る。
async fn log_in_with_offline_access(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    username: &str,
) -> LoggedIn {
    let password = "correct-horse-battery";
    register_user(&env.app, &env.root_tenant_id, username, password).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, username).await;

    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st&nonce=nc&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode("openid offline_access", NON_ALPHANUMERIC)
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
    let csrf = assay_api::application::login::csrf_token(&auth_session, &env.csrf_secret);

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

    // `offline_access` は同意を挟む。挟まれたら承諾する。
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
    let code = query_param(&callback, "code").expect("authorization code");

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "token endpoint");
    let tokens = body_json(response).await;
    LoggedIn {
        refresh_token: tokens["refresh_token"]
            .as_str()
            .expect("refresh_token（offline_access を要求している）")
            .to_string(),
        sso_cookie,
    }
}

/// refresh grant を 1 回叩く。成功したら回転後の refresh token を返す。
async fn refresh(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    refresh_token: &str,
) -> (StatusCode, Option<String>) {
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(refresh_token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    let rotated = body["refresh_token"].as_str().map(|s| s.to_string());
    (status, rotated)
}

/// **ログアウトすると、そのセッションの refresh token は使えなくなる。**
#[tokio::test]
async fn logging_out_stops_the_refresh_grant() {
    let Some(env) = support::setup("logout revokes refresh tokens").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let logged_in = log_in_with_offline_access(&env, &client_id, &secret, &unique_username()).await;

    // ログアウト前は更新が通る（この前提が崩れていると、以降の assert は何も証明しない）。
    let (status, rotated) = refresh(&env, &client_id, &secret, &logged_in.refresh_token).await;
    assert_eq!(status, StatusCode::OK, "ログアウト前の更新は通る");
    let rotated = rotated.expect("回転後の refresh token");

    let response = send(
        &env.app,
        post_internal(
            "/internal/logout/rp",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": logged_in.sso_cookie,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "rp logout");

    // **回転後のトークン**で試す。rotation を引き継いだ子まで落ちていないと、
    // 「ログアウト直前に一度更新した端末」だけが生き残る。
    let (status, _) = refresh(&env, &client_id, &secret, &rotated).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "ログアウト後の更新は断られる（断られないなら、その端末は最長 30 日動き続ける）"
    );
}

/// **セルフサービスで他端末を切ると、その端末の refresh token も使えなくなる。**
///
/// 画面は「この端末をアカウントからログアウトしますか？」と訊く。`sso_sessions` の行を
/// 消すだけでは、その問いに答えたことにならない。
#[tokio::test]
async fn revoking_a_session_from_the_security_screen_stops_its_refresh_grant() {
    let Some(env) = support::setup("self-service revoke revokes refresh tokens").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();

    // 端末 A: 切られる側（refresh token を持つ）。
    let device_a = log_in_with_offline_access(&env, &client_id, &secret, &username).await;
    // 端末 B: 操作する側。同じ利用者でもう 1 セッション作る。
    let device_b = log_in_again(&env, &client_id, &secret, &username).await;

    let (status, rotated) = refresh(&env, &client_id, &secret, &device_a.refresh_token).await;
    assert_eq!(status, StatusCode::OK, "切る前の更新は通る");
    let rotated = rotated.expect("回転後の refresh token");

    // 端末 B から、端末 A のセッションを切る。
    let overview = send(
        &env.app,
        post_internal(
            "/internal/account/security",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": device_b,
            }),
        ),
    )
    .await;
    assert_eq!(overview.status(), StatusCode::OK, "security overview");
    let body = body_json(overview).await;
    let target = body["sessions"]
        .as_array()
        .expect("sessions")
        .iter()
        .find(|s| s["current"] == false)
        .expect("端末 A のセッションが一覧に出る")["id"]
        .as_str()
        .expect("session id")
        .to_string();

    let response = send(
        &env.app,
        post_internal(
            "/internal/account/security/revoke-session",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": device_b,
                "session_id": target,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "revoke session");

    let (status, _) = refresh(&env, &client_id, &secret, &rotated).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "切った端末の更新は断られる"
    );
}

/// 既に登録済みの利用者でもう一度ログインし、SSO Cookie だけを得る。
async fn log_in_again(env: &TestEnv, client_id: &str, secret: &str, username: &str) -> String {
    let password = "correct-horse-battery";
    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st2&nonce=nc2&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode("openid", NON_ALPHANUMERIC)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let handle = handoff_handle(&response);
    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    let auth_session = body["auth_session_id"].as_str().unwrap().to_string();
    let csrf = assay_api::application::login::csrf_token(&auth_session, &env.csrf_secret);

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
    let _ = (client_id, secret);
    body["sso_session_id"].as_str().unwrap().to_string()
}
