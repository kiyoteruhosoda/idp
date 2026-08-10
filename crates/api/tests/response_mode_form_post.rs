//! G12: `response_mode=form_post`。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test response_mode_form_post
//!
//! 検証するのは 3 点:
//!
//! 1. 未知の `response_mode` は**既定へ丸めず**エラーにする。丸めると、RP は `form_post` を
//!    要求したつもりで認可コードが URL に載って返り、しかもそれに気づけない。
//! 2. 要求が `/authorize` から**別リクエストの応答時点まで**運ばれる（`auth_sessions` へ保存する）。
//! 3. 応答は「送信先＋パラメータ」で返り、**送信先に認可コードが載らない**。

mod support;

use axum::http::StatusCode;
use support::{
    anonymous, handoff_handle, insert_public_client, location, resume_authorize, send, setup,
    CODE_CHALLENGE, REDIRECT_URI_ENC,
};

fn authorize_uri(tenant: &str, client_id: &str, response_mode: &str) -> String {
    let mode = if response_mode.is_empty() {
        String::new()
    } else {
        format!("&response_mode={response_mode}")
    };
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}\
         &scope=openid&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256{mode}"
    )
}

/// 未知の値は `invalid_request` として RP へ返す（既定の `query` へ丸めない）。
#[tokio::test]
async fn an_unsupported_response_mode_is_rejected_instead_of_being_defaulted() {
    let Some(env) = setup("response_mode rejection").await else {
        return;
    };
    let client_id = insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = send(
        &env.app,
        anonymous(
            axum::http::Method::GET,
            &authorize_uri(&env.root_tenant_id, &client_id, "fragment"),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = location(&response);
    assert!(
        location.contains("error=invalid_request"),
        "unsupported response_mode must be an error, got {location}"
    );
    // エラーそのものは RP へ返る（リダイレクト可能な段階の失敗のため）。
    assert!(
        location.starts_with("http://localhost:3000/callback"),
        "{location}"
    );
}

/// `query` は従来どおり受け付ける（明示指定でも既定でも同じ）。
#[tokio::test]
async fn an_explicit_query_response_mode_is_accepted() {
    let Some(env) = setup("response_mode query").await else {
        return;
    };
    let client_id = insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = send(
        &env.app,
        anonymous(
            axum::http::Method::GET,
            &authorize_uri(&env.root_tenant_id, &client_id, "query"),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = location(&response);
    assert!(
        !location.contains("error="),
        "`query` must be accepted, got {location}"
    );
}

/// 要求が `/authorize` から応答時点まで運ばれ、`resume` の応答が
/// 「送信先＋フォームフィールド」で返る。**送信先に認可コードが載らない**ことも確かめる。
#[tokio::test]
async fn form_post_is_carried_to_the_authorization_response() {
    let Some(env) = setup("response_mode form_post").await else {
        return;
    };
    let client_id = insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let sso_cookie = support::create_sso_session(&env.pool, &user_id).await;

    // 1. `/authorize` で `form_post` を要求し、web へのハンドオフを受け取る。
    let response = send(
        &env.app,
        anonymous(
            axum::http::Method::GET,
            &authorize_uri(&env.root_tenant_id, &client_id, "form_post"),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let handle = handoff_handle(&response);

    // 2. 要求は `auth_sessions` に残る（応答を組み立てるのは別リクエストのため）。
    let stored: Option<String> =
        sqlx::query_scalar("SELECT response_mode FROM auth_sessions WHERE handle_hash IS NOT NULL")
            .fetch_optional(&env.pool)
            .await
            .expect("read auth session")
            .flatten();
    assert_eq!(
        stored.as_deref(),
        Some("form_post"),
        "the requested response_mode must survive until the response is built"
    );

    // 3. SSO 済みなので resume がそのまま認可応答を返す。
    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, Some(&sso_cookie)).await;
    assert_eq!(body["result"], serde_json::json!("redirect"));

    let redirect_to = body["redirect_to"].as_str().expect("redirect_to");
    let form_post = body["form_post"].as_array().expect("form_post fields");

    // 送信先には認可応答のパラメータが載らない（載せると URL に code が残る）。
    assert_eq!(redirect_to, "http://localhost:3000/callback");
    assert!(!redirect_to.contains("code="), "{redirect_to}");

    let names: Vec<&str> = form_post
        .iter()
        .map(|pair| pair[0].as_str().expect("field name"))
        .collect();
    assert!(names.contains(&"code"), "{form_post:?}");
    assert!(names.contains(&"state"), "{form_post:?}");
}
