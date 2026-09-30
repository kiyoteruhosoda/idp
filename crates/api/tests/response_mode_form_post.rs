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
    //    テストは同じ DB を共有し並行して走るので、**このテストが作ったクライアント**で絞る。
    //    絞らないと隣のテストの認可セッション（`query`）を読んでしまう。
    let stored: Option<String> =
        sqlx::query_scalar("SELECT response_mode FROM auth_sessions WHERE client_id = ?")
            .bind(&client_id)
            .fetch_one(&env.pool)
            .await
            .expect("read auth session");
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

/// 失敗も成功と同じ返し方で返す（RP は同じ受け口で待っている）。`prompt=none` で SSO が無いときの
/// `login_required` は、`form_post` を要求されていれば hidden フィールドで返る。
#[tokio::test]
async fn a_resume_failure_follows_the_requested_response_mode() {
    let Some(env) = setup("response_mode form_post error").await else {
        return;
    };
    let client_id = insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let response = send(
        &env.app,
        anonymous(
            axum::http::Method::GET,
            &format!(
                "{}&prompt=none",
                authorize_uri(&env.root_tenant_id, &client_id, "form_post")
            ),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let handle = handoff_handle(&response);

    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    assert_eq!(
        body["result"],
        serde_json::json!("error_redirect"),
        "{body}"
    );
    assert_eq!(
        body["redirect_to"], "http://localhost:3000/callback",
        "{body}"
    );
    let fields: Vec<(String, String)> = body["form_post"]
        .as_array()
        .expect("form_post fields")
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_string(),
                pair[1].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert!(
        fields.contains(&("error".to_string(), "login_required".to_string())),
        "{fields:?}"
    );
    assert!(
        fields.contains(&("state".to_string(), "st".to_string())),
        "{fields:?}"
    );

    // `query` のままの要求では従来どおり URL に載る。
    let response = send(
        &env.app,
        anonymous(
            axum::http::Method::GET,
            &format!(
                "{}&prompt=none",
                authorize_uri(&env.root_tenant_id, &client_id, "")
            ),
            None,
        ),
    )
    .await;
    let handle = handoff_handle(&response);
    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], serde_json::json!("error_redirect"));
    assert!(body["form_post"].is_null(), "{body}");
    let redirect_to = body["redirect_to"].as_str().unwrap();
    assert!(
        redirect_to.contains("error=login_required"),
        "{redirect_to}"
    );
    assert!(redirect_to.contains("state=st"), "{redirect_to}");
}
