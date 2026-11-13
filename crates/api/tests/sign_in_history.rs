//! Sign-in history the user sees about themselves (task #879, ADR-0073).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test sign_in_history
//!
//! Unit tests cannot prove the wiring. History is copied in 3 places (web's response, the audit log
//! write, `/token`) and matched by `sid` into one row. This runs login -> failure -> code exchange ->
//! refresh -> reuse against a real DB and checks the shape handed to the screen (`/internal/account/sign-in-history`).

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

/// Starts at `/authorize` and proceeds to the opened login form (`auth_session_id`).
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

/// The route web calls with the response that sets the login cookie (same as device detection).
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

/// Accepts consent if interposed and returns the code from the redirect target.
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

/// **Logins, failures, refreshes in apps and reuse are listed separately in the user's history. Others cannot see them.**
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

    // 1. Wrong password (becomes a failure row).
    let auth_session = begin(&env, &client_id, "openid offline_access").await;
    let failed = authenticate(&env, &auth_session, &username, "wrong-password-123").await;
    assert!(
        failed["sso_session_id"].is_null(),
        "wrong password must not sign in: {failed}"
    );

    // 2. Log in with the correct password and copy with a response that sets the cookie as web does (country JP).
    let auth_session = begin(&env, &client_id, "openid offline_access").await;
    let body = authenticate(&env, &auth_session, &username, PASSWORD).await;
    let sso_cookie = body["sso_session_id"]
        .as_str()
        .expect("sso session")
        .to_string();
    observe(&env, &sso_cookie, Some("JP")).await;
    // A second request for the same login does not add a row.
    observe(&env, &sso_cookie, Some("KP")).await;

    // 3. The app exchanges the code and refreshes twice with the refresh token.
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

    // Newest first: success first, then failure.
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

    // 4. Present a used token again -> reuse detection and revocation.
    let (status, _) = refresh(&env, &client_id, &secret, &first).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let page = history(&env, &sso_cookie).await;
    let usage = &page["entries"][0]["apps"][0]["refresh"];
    assert!(usage["reuse_detected_at"].is_string(), "{usage}");
    assert_eq!(usage["state"], "revoked", "{usage}");

    // 5. Another user's login state shows none of this user's rows.
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

/// With no (expired) login state, no history is returned.
#[tokio::test]
async fn an_unknown_session_gets_no_history() {
    let Some(env) = support::setup("sign-in history without a session").await else {
        return;
    };
    let page = history(&env, "not-a-session").await;
    assert_eq!(page["result"], "session_expired", "{page}");
}

/// Sends a refused login to `/internal/authenticate`. `country` is the header web adds (task #895).
async fn fail_with_country(
    env: &TestEnv,
    client_id: &str,
    username: &str,
    country: Option<&str>,
    service_token: Option<&str>,
) -> StatusCode {
    let auth_session = begin(env, client_id, "openid").await;
    let csrf = assay_api::application::login::csrf_token(&auth_session, &env.csrf_secret);
    let mut request = post_internal(
        "/internal/authenticate",
        service_token,
        json!({
            "tenant_id": env.root_tenant_id,
            "auth_session_id": auth_session,
            "username": username,
            "password": "wrong-password-895",
            "csrf_token": csrf,
            "ip_address": "198.51.100.95",
        }),
    );
    if let Some(country) = country {
        request.headers_mut().insert(
            assay_contracts::auth::CLIENT_COUNTRY_HEADER,
            country.parse().unwrap(),
        );
    }
    send(&env.app, request).await.status()
}

/// **Refused login rows also carry the country web added. A request without a service token gets no country.** (task #895)
#[tokio::test]
async fn failed_sign_ins_carry_the_country_the_web_vouched_for() {
    let Some(env) = support::setup("sign-in history failure country").await else {
        return;
    };
    let (client_id, _secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let username = unique_username();
    support::register_user(&env.app, &env.root_tenant_id, &username, PASSWORD).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;

    // 1. web added a country (JP).
    assert_eq!(
        fail_with_country(&env, &client_id, &username, Some("JP"), Some(SERVICE_TOKEN)).await,
        StatusCode::OK
    );
    // 2. No country (the home entrance removed it / configured not to trust it).
    assert_eq!(
        fail_with_country(&env, &client_id, &username, None, Some(SERVICE_TOKEN)).await,
        StatusCode::OK
    );
    // 3. Send directly with a country but no service token -> refused, no row added.
    assert_eq!(
        fail_with_country(&env, &client_id, &username, Some("KP"), None).await,
        StatusCode::UNAUTHORIZED
    );

    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT h.outcome, h.country FROM sign_in_history h \
         JOIN user_login_identifiers i ON i.user_id = h.user_id \
         WHERE i.normalized_value = ? ORDER BY h.id",
    )
    .bind(&username)
    .fetch_all(&env.pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![
            ("failed".to_string(), Some("JP".to_string())),
            ("failed".to_string(), None),
        ],
        "the vouched country is recorded, a missing one stays unknown, an unauthenticated one is never recorded"
    );
}
