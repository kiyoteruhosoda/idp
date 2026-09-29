//! 認可セッションの上で「認証し直し」たとき、前の認証が残らないことの統合テスト。
//!
//! 同意待ち（＝認証済み）の認可セッションで、別の利用者としてパスワードだけを通し、第二段
//! （パスワードの強制変更・MFA）の手前で止まった場合、その認可セッションはもう**誰の認証も
//! 完了していない**。前の利用者の `auth_time` / `sid` が残っていると、同意の承諾がそれを
//! 「認証済み」と読み、第二段を済ませていない利用者に code を発行してしまう。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行する。

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use support::{
    body_json, handoff_handle, resume_authorize, send, CODE_CHALLENGE, REDIRECT_URI_ENC,
    SERVICE_TOKEN, SERVICE_TOKEN_HEADER,
};

async fn internal_post(app: &axum::Router, uri: &str, body: Value) -> Value {
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    body_json(response).await
}

async fn authenticate(
    env: &support::TestEnv,
    auth_session: &str,
    username: &str,
    password: &str,
) -> Value {
    internal_post(
        &env.app,
        "/internal/authenticate",
        json!({
            "tenant_id": env.root_tenant_id,
            "auth_session_id": auth_session,
            "username": username,
            "password": password,
            "csrf_token": assay_api::application::login::csrf_token(auth_session, &env.csrf_secret),
        }),
    )
    .await
}

#[tokio::test]
async fn password_only_reauthentication_does_not_inherit_the_previous_login() {
    let Some(env) = support::setup("auth_session_reauthentication").await else {
        return;
    };
    let tenant = env.root_tenant_id.clone();
    // profile を要求して、最初の利用者を同意画面で止める。
    let client_id = support::insert_public_client(&env.pool, &tenant, &["openid", "profile"]).await;

    // 1 人目（自分のアカウント）: 普通にログインして同意待ちになる。
    let first = format!("reauth-a-{}", support::unique());
    support::register_user(&env.app, &tenant, &first, "first-password-1").await;
    support::mark_email_verified(&env.pool, &tenant, &first).await;

    // 2 人目（パスワードだけ知られている相手）: 強制変更の状態にしておく。
    let second = format!("reauth-b-{}", support::unique());
    support::register_user(&env.app, &tenant, &second, "second-password-1").await;
    support::mark_email_verified(&env.pool, &tenant, &second).await;
    let second_id = support::find_user_id_by_username(&env.pool, &tenant, &second)
        .await
        .expect("second user");
    support::force_password_change(&env.pool, &second_id, "second-password-1").await;

    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope=openid%20profile&state=s&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let handle = handoff_handle(&response);
    let body = resume_authorize(&env.app, &tenant, &handle, None).await;
    assert_eq!(body["result"], "login_required");
    let session = body["auth_session_id"].as_str().unwrap().to_string();

    let body = authenticate(&env, &session, &first, "first-password-1").await;
    assert_eq!(body["result"], "consent_required", "{body}");
    let session = body["auth_session_id"].as_str().unwrap().to_string();

    // 同じ認可セッションで 2 人目としてパスワードだけ通す（強制変更の手前で止まる）。
    let body = authenticate(&env, &session, &second, "second-password-1").await;
    assert_eq!(body["result"], "password_change_required", "{body}");
    let session = body["auth_session_id"].as_str().unwrap().to_string();

    // ⚠ ここで同意を承諾しても、code は出てはならない。2 人目は認証を終えておらず、
    //   1 人目の認証はもう、この認可セッションの持ち主ではない。
    let body = internal_post(
        &env.app,
        "/internal/consent/approve",
        json!({ "tenant_id": tenant, "auth_session_id": session }),
    )
    .await;
    assert_ne!(
        body["result"], "success",
        "consent must not issue a code for a login that stopped half-way: {body}"
    );
}
