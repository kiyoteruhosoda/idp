//! G12: `response_mode=form_post`.
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test response_mode_form_post
//!
//! Three things are checked:
//!
//! 1. An unknown `response_mode` is an error, **not rounded to the default**. If rounded, an RP believing it requested
//!    `form_post` would get the authorization code back in the URL, without noticing.
//! 2. The request is carried from `/authorize` **to the time of the response in another request** (stored in `auth_sessions`).
//! 3. The response comes back as "destination + parameters", and **the destination carries no authorization code**.

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

/// Unknown values are returned to the RP as `invalid_request` (not rounded to the default `query`).
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
    // The error itself goes back to the RP (a failure at a stage where redirecting is possible).
    assert!(
        location.starts_with("http://localhost:3000/callback"),
        "{location}"
    );
}

/// `query` is accepted as before (same whether explicit or default).
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

/// The request is carried from `/authorize` to response time, and the `resume` response comes back as
/// "destination + form fields". Also checks that **the destination carries no authorization code**.
#[tokio::test]
async fn form_post_is_carried_to_the_authorization_response() {
    let Some(env) = setup("response_mode form_post").await else {
        return;
    };
    let client_id = insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let sso_cookie = support::create_sso_session(&env.pool, &user_id).await;

    // 1. Request `form_post` at `/authorize` and receive the handoff to web.
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

    // 2. The request remains in `auth_sessions` (the response is built by another request).
    //    Tests share the same DB and run in parallel, so filter by **the client this test created**.
    //    Otherwise it would read a neighbouring test's authorization session (`query`).
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

    // 3. Already SSO-signed-in, so resume returns the authorization response directly.
    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, Some(&sso_cookie)).await;
    assert_eq!(body["result"], serde_json::json!("redirect"));

    let redirect_to = body["redirect_to"].as_str().expect("redirect_to");
    let form_post = body["form_post"].as_array().expect("form_post fields");

    // The destination carries no authorization response parameters (otherwise the code would remain in the URL).
    assert_eq!(redirect_to, "http://localhost:3000/callback");
    assert!(!redirect_to.contains("code="), "{redirect_to}");

    let names: Vec<&str> = form_post
        .iter()
        .map(|pair| pair[0].as_str().expect("field name"))
        .collect();
    assert!(names.contains(&"code"), "{form_post:?}");
    assert!(names.contains(&"state"), "{form_post:?}");
}

/// Failures come back the same way as successes (the RP waits at the same endpoint). The `login_required` of
/// `prompt=none` without SSO comes back in hidden fields when `form_post` was requested.
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

    // A request staying with `query` puts it in the URL as before.
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
