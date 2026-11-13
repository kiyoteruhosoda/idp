//! E2E integration tests for the OIDC authorization code flow (MVP completion conditions 1–13, design spec §10).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test oidc_flow
//!
//! Test data (client / user) is created with random identifiers per run and does not interfere with existing data.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{
    body_json, handoff_handle, location, query_param, resume_authorize, send, CODE_CHALLENGE,
    CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN, SERVICE_TOKEN_HEADER,
};

/// Registers a unique public client (openid/profile/email) and returns its client_id.
async fn insert_public_client(pool: &MySqlPool, tenant_id: &str) -> String {
    support::insert_public_client(pool, tenant_id, &["openid", "profile", "email"]).await
}

/// Registers a unique confidential client (openid only) and returns `(client_id, client_secret)`.
async fn insert_confidential_client(pool: &MySqlPool, tenant_id: &str) -> (String, String) {
    support::insert_confidential_client(pool, tenant_id, &["openid"]).await
}

async fn register_user(app: &axum::Router, tenant: &str, username: &str, password: &str) -> String {
    let payload = json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": password,
        "name": "E2E Tester",
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
    body_json(response).await["sub"]
        .as_str()
        .unwrap()
        .to_string()
}

fn authorize_uri(tenant: &str, client_id: &str, state: &str, nonce: &str) -> String {
    authorize_uri_with_scope(tenant, client_id, "openid profile email", state, nonce)
}

/// ⚠ An authorization request **without `nonce`** (ADR-0049). Mimics counterparts like Forgejo that
/// omit it as the spec allows. **`state` and PKCE are sent.**
fn authorize_uri_without_nonce(tenant: &str, client_id: &str, state: &str) -> String {
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope=openid&state={state}&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
    )
}

fn authorize_uri_with_scope(
    tenant: &str,
    client_id: &str,
    scope: &str,
    state: &str,
    nonce: &str,
) -> String {
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state={state}&nonce={nonce}&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
        utf8_percent_encode(scope, NON_ALPHANUMERIC)
    )
}

fn basic_auth(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// Login CSRF token derived from `auth_session_id` (the contract: web renders it, api's LoginService verifies it).
fn login_csrf(auth_session: &str, csrf_secret: &[u8; 32]) -> String {
    assay_api::application::login::csrf_token(auth_session, csrf_secret)
}

/// Drives credential verification via api's internal authentication (`POST /internal/authenticate`) (the login screen is in the web crate).
/// Passing `X-Forwarded-For` is reflected in audit and rate limiting. The result is JSON with a `result` tag.
async fn internal_authenticate(
    app: &axum::Router,
    tenant: &str,
    auth_session: &str,
    username: &str,
    password: &str,
    csrf: &str,
) -> (StatusCode, Value) {
    let body = json!({
        "tenant_id": tenant,
        "auth_session_id": auth_session,
        "username": username,
        "password": password,
        "csrf_token": csrf,
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri("/internal/authenticate")
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    let status = response.status();
    (status, body_json(response).await)
}

async fn audit_count(pool: &MySqlPool, client_id: &str, event_type: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM audit_log WHERE client_id = ? AND event_type = ?")
        .bind(client_id)
        .bind(event_type)
        .fetch_one(pool)
        .await
        .expect("query audit_log")
        .get("c")
}

#[tokio::test]
async fn full_authorization_code_flow_with_sso_and_audit() {
    let Some(env) = support::setup("OIDC flow").await else {
        return;
    };
    let support::TestEnv {
        app,
        pool,
        issuer,
        root_tenant_id,
        ..
    } = env;

    let client_id = insert_public_client(&pool, &root_tenant_id).await;
    let username = format!("e2e{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let password = "correct-horse-battery";
    let sub = register_user(&app, &root_tenant_id, &username, password).await; // condition 1
    support::mark_email_verified(&pool, &root_tenant_id, &username).await;

    // Conditions 2, 3: start /authorize → hand off to web's /login (ADR-0018 decision 2: a one-time handle in the URL
    // rather than a cookie; an absolute URL based on PUBLIC_WEB_BASE_URL; ADR-0012 §4).
    let response = send(
        &app,
        Request::builder()
            .uri(authorize_uri(
                &root_tenant_id,
                &client_id,
                "state-abc",
                "nonce-xyz",
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to /login");
    assert!(
        location(&response).starts_with(&format!(
            "{}/{root_tenant_id}/login?auth_session=",
            env.public_web_base_url
        )),
        "handoff URL: {}",
        location(&response)
    );
    let handle = handoff_handle(&response);

    // As web would: exchange the handle via resume to get auth_session_id (no SSO → login_required).
    let body = resume_authorize(&app, &root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], "login_required");
    let auth_session = body["auth_session_id"]
        .as_str()
        .expect("auth_session_id")
        .to_string();

    // The handle is single-use (ADR-0018 decision 3): reuse is rejected.
    let body = resume_authorize(&app, &root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], "expired_handle", "handle reuse is rejected");

    // CSRF derives from auth_session (web renders it, api's LoginService verifies it).
    let csrf = login_csrf(&auth_session, &env.csrf_secret);

    // A CSRF token mismatch is rejected (result=csrf_mismatch).
    let (status, body) = internal_authenticate(
        &app,
        &root_tenant_id,
        &auth_session,
        &username,
        password,
        &"0".repeat(64),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"], "csrf_mismatch", "csrf mismatch");

    // Conditions 4, 5, 7: login succeeds. The first time, profile/email are not consented, so it goes to the consent step (F3).
    let (status, body) = internal_authenticate(
        &app,
        &root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login success");
    assert_eq!(
        body["result"], "consent_required",
        "first login needs consent"
    );
    let sso_cookie = body["sso_session_id"]
        .as_str()
        .expect("sso_session_id")
        .to_string();
    let consent_session = body["auth_session_id"]
        .as_str()
        .expect("auth_session_id")
        .to_string();

    // Accepting consent redirects to the RP with a code.
    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/internal/consent/approve")
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(
                json!({ "tenant_id": root_tenant_id, "auth_session_id": consent_session })
                    .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "consent approve");
    let body = body_json(response).await;
    assert_eq!(body["result"], "success", "consent approved");
    let callback = body["redirect_to"]
        .as_str()
        .expect("redirect_to")
        .to_string();
    assert!(callback.starts_with(REDIRECT_URI));
    assert_eq!(
        query_param(&callback, "state").as_deref(),
        Some("state-abc")
    );
    let code = query_param(&callback, "code").expect("authorization code");

    // Conditions 8, 10: PKCE S256 verification at /token, issuance of RS256-signed tokens.
    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={}&code_verifier={CODE_VERIFIER}&client_id={client_id}",
                "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "token endpoint");
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(response.headers().get("pragma").unwrap(), "no-cache");
    let tokens = body_json(response).await;
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "openid profile email");
    let id_token = tokens["id_token"].as_str().unwrap().to_string();
    let access_token = tokens["access_token"].as_str().unwrap().to_string();

    // Condition 11: Discovery / JWKS.
    let response = send(
        &app,
        Request::builder()
            .uri(format!(
                "/{root_tenant_id}/.well-known/openid-configuration"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let discovery = body_json(response).await;
    // Per-tenant issuer (ADR-0009 §6): during the transition, `<base>/<root_uuid>` is built for the root tenant.
    let tenant_issuer = format!("{issuer}/{root_tenant_id}");
    assert_eq!(discovery["issuer"], tenant_issuer.as_str());
    // Only values that can be guaranteed are published (ADR-0043 decision 5). RPs look here to learn what they can send.
    assert_eq!(
        discovery["acr_values_supported"],
        json!(["urn:assay:ac:mfa", "urn:assay:ac:single"])
    );
    for claim in ["acr", "amr"] {
        assert!(
            discovery["claims_supported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == claim),
            "claims_supported must advertise {claim}"
        );
    }
    assert_eq!(
        discovery["authorization_endpoint"],
        format!("{tenant_issuer}/authorize").as_str()
    );

    let response = send(
        &app,
        Request::builder()
            .uri(format!("/{root_tenant_id}/.well-known/jwks.json"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let jwks = body_json(response).await;

    // Condition 10 check: verify the ID Token with the JWKS public key and check the claims.
    let header = jsonwebtoken::decode_header(&id_token).expect("id token header");
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    let kid = header.kid.expect("kid");
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == kid.as_str())
        .expect("signing key in JWKS");
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(
        jwk["n"].as_str().unwrap(),
        jwk["e"].as_str().unwrap(),
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[client_id.as_str()]);
    let id_claims = jsonwebtoken::decode::<Value>(&id_token, &decoding_key, &validation)
        .expect("verify id token");
    assert_eq!(id_claims.claims["iss"], tenant_issuer.as_str());
    assert_eq!(id_claims.claims["sub"], sub.as_str());
    assert_eq!(id_claims.claims["nonce"], "nonce-xyz");
    assert!(id_claims.claims["auth_time"].is_i64());
    assert_eq!(id_claims.claims["preferred_username"], username.as_str());
    // Authentication strength and method (ADR-0043). Password only, so it claims single factor.
    // Without this, RPs cannot check whether their `acr_values` request took effect.
    assert_eq!(id_claims.claims["acr"], "urn:assay:ac:single");
    assert_eq!(id_claims.claims["amr"], json!(["pwd"]));

    // The Access Token has typ=at+jwt.
    let at_header = jsonwebtoken::decode_header(&access_token).expect("access token header");
    assert_eq!(at_header.typ.as_deref(), Some("at+jwt"));

    // Condition 9: an authorization code can be used only once (reuse is invalid_grant).
    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={}&code_verifier={CODE_VERIFIER}&client_id={client_id}",
                "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "code reuse");
    assert_eq!(body_json(response).await["error"], "invalid_grant");

    // Condition 12: /userinfo returns claims according to scope (openid profile email).
    let response = send(
        &app,
        Request::builder()
            .uri(format!("/{root_tenant_id}/userinfo"))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "userinfo");
    let claims = body_json(response).await;
    assert_eq!(claims["sub"], sub.as_str());
    assert_eq!(claims["email"], format!("{username}@example.com"));
    assert_eq!(claims["email_verified"], true);
    assert_eq!(claims["preferred_username"], username.as_str());
    assert_eq!(claims["name"], "E2E Tester");

    // An invalid token is 401.
    let response = send(
        &app,
        Request::builder()
            .uri(format!("/{root_tenant_id}/userinfo"))
            .header(AUTHORIZATION, "Bearer not-a-jwt")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Condition 6: the second /authorize returns a code via SSO without signing in again (ADR-0018 decision 2:
    // api does not read the SSO cookie, so sso_session_id is put in the web-equivalent resume call).
    let response = send(
        &app,
        Request::builder()
            .uri(authorize_uri(
                &root_tenant_id,
                &client_id,
                "state-2nd",
                "nonce-2nd",
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to /login");
    let second_handle = handoff_handle(&response);
    let body = resume_authorize(&app, &root_tenant_id, &second_handle, Some(&sso_cookie)).await;
    assert_eq!(body["result"], "redirect", "SSO resume issues a code");
    let callback = body["redirect_to"]
        .as_str()
        .expect("redirect_to")
        .to_string();
    assert!(
        callback.starts_with(REDIRECT_URI),
        "expected direct redirect to client, got {callback}"
    );
    assert_eq!(
        query_param(&callback, "state").as_deref(),
        Some("state-2nd")
    );
    let second_code = query_param(&callback, "code").expect("code via SSO");

    // A code obtained via SSO can also be exchanged at /token, and auth_time keeps the first login time.
    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=authorization_code&code={second_code}&redirect_uri={}&code_verifier={CODE_VERIFIER}&client_id={client_id}",
                "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "token via SSO code");
    let second_tokens = body_json(response).await;
    let second_id_token = second_tokens["id_token"].as_str().unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[client_id.as_str()]);
    let second_claims =
        jsonwebtoken::decode::<Value>(second_id_token, &decoding_key, &validation).unwrap();
    assert_eq!(second_claims.claims["nonce"], "nonce-2nd");
    // Even on SSO restore, it claims the method that established the session as is (not recomputed).
    assert_eq!(second_claims.claims["acr"], "urn:assay:ac:single");
    assert_eq!(second_claims.claims["amr"], json!(["pwd"]));
    assert_eq!(
        second_claims.claims["auth_time"], id_claims.claims["auth_time"],
        "auth_time keeps the first login time on SSO resume"
    );

    // `prompt=none` (silent authentication, iframe path): with SSO, a code without interaction; without SSO,
    // a `login_required` error goes back to the RP (an ADR-0018 regression condition; decided in resume).
    let prompt_none_uri = format!(
        "{}&prompt=none",
        authorize_uri(&root_tenant_id, &client_id, "state-silent", "nonce-silent")
    );
    let response = send(
        &app,
        Request::builder()
            .uri(&prompt_none_uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let handle = handoff_handle(&response);
    let body = resume_authorize(&app, &root_tenant_id, &handle, Some(&sso_cookie)).await;
    assert_eq!(body["result"], "redirect", "prompt=none with SSO: {body}");
    assert!(query_param(body["redirect_to"].as_str().unwrap(), "code").is_some());

    let response = send(
        &app,
        Request::builder()
            .uri(&prompt_none_uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let handle = handoff_handle(&response);
    let body = resume_authorize(&app, &root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], "error_redirect", "prompt=none without SSO");
    let error_callback = body["redirect_to"].as_str().unwrap();
    assert_eq!(
        query_param(error_callback, "error").as_deref(),
        Some("login_required")
    );

    // `prompt=select_account` (G12): even with a valid SSO, **do not silently continue with the current account**.
    // assay has only one SSO session per browser, so it cannot show a list of accounts,
    // but returning to the login screen lets the user sign in again with the same account or switch.
    let select_account_uri = format!(
        "{}&prompt=select_account",
        authorize_uri(&root_tenant_id, &client_id, "state-select", "nonce-select")
    );
    let response = send(
        &app,
        Request::builder()
            .uri(&select_account_uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let handle = handoff_handle(&response);
    let body = resume_authorize(&app, &root_tenant_id, &handle, Some(&sso_cookie)).await;
    assert_eq!(
        body["result"], "login_required",
        "prompt=select_account must not resume the existing SSO session: {body}"
    );
    assert_eq!(
        query_param(error_callback, "state").as_deref(),
        Some("state-silent")
    );

    // Condition 13: audit log (login / code issuance and use / token issuance / SSO).
    assert!(audit_count(&pool, &client_id, "login.succeeded").await >= 1);
    assert!(audit_count(&pool, &client_id, "sso_session.created").await >= 1);
    assert!(audit_count(&pool, &client_id, "authorization_code.issued").await >= 2);
    assert!(audit_count(&pool, &client_id, "authorization_code.used").await >= 2);
    assert!(audit_count(&pool, &client_id, "authorization_code.reuse_detected").await >= 1);
    assert!(audit_count(&pool, &client_id, "token.issued").await >= 2);

    // A correlation_id is attached.
    let correlation: Option<String> =
        sqlx::query("SELECT correlation_id FROM audit_log WHERE client_id = ? LIMIT 1")
            .bind(&client_id)
            .fetch_optional(&pool)
            .await
            .unwrap()
            .map(|r| r.get("correlation_id"));
    assert!(correlation.map(|c| !c.is_empty()).unwrap_or(false));
}

#[tokio::test]
async fn refresh_token_rotation_introspection_and_revocation_e2e() {
    let Some(env) = support::setup("OIDC refresh/revoke/introspect flow").await else {
        return;
    };
    let support::TestEnv {
        app,
        pool,
        root_tenant_id,
        ..
    } = env;

    let (client_id, secret) =
        support::insert_confidential_client(&pool, &root_tenant_id, &["openid", "offline_access"])
            .await;
    let username = format!("e2ert{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let password = "correct-horse-battery";
    register_user(&app, &root_tenant_id, &username, password).await;
    support::mark_email_verified(&pool, &root_tenant_id, &username).await;

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        &authorize_uri_with_scope(
            &root_tenant_id,
            &client_id,
            "openid offline_access",
            "state-refresh",
            "nonce-refresh",
        ),
    )
    .await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);

    let (status, body) = internal_authenticate(
        &app,
        &root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login with offline_access scope");

    let callback = if body["result"] == "consent_required" {
        let consent_session = body["auth_session_id"].as_str().expect("auth_session_id");
        let response = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/internal/consent/approve")
                .header(CONTENT_TYPE, "application/json")
                .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
                .body(Body::from(
                    json!({ "tenant_id": root_tenant_id, "auth_session_id": consent_session })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "consent approve");
        body_json(response).await["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string()
    } else {
        assert_eq!(body["result"], "success", "login result");
        body["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string()
    };
    let code = query_param(&callback, "code").expect("authorization code");

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(&client_id, &secret))
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "token with offline_access"
    );
    let tokens = body_json(response).await;
    let access_token = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    assert_eq!(tokens["scope"], "openid offline_access");

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/introspect"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(&client_id, &secret))
            .body(Body::from(format!(
                "token={}&token_type_hint=access_token",
                utf8_percent_encode(&access_token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "introspect access token");
    let body = body_json(response).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["client_id"], client_id);
    assert_eq!(body["token_type"], "Bearer");

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(&client_id, &secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(&refresh_token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "refresh token rotation");
    let rotated = body_json(response).await;
    let rotated_refresh = rotated["refresh_token"]
        .as_str()
        .expect("rotated refresh token");
    assert_ne!(rotated_refresh, refresh_token);

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(&client_id, &secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(&refresh_token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "refresh token reuse"
    );
    assert_eq!(body_json(response).await["error"], "invalid_grant");

    // SEC8: on detecting reuse, revoke down to the child tokens rotated from it.
    // Revoking only the parent would let child tokens an attacker obtained by exchanging first survive.
    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(&client_id, &secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(rotated_refresh, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "descendant of a reused refresh token must be revoked too"
    );
    assert_eq!(body_json(response).await["error"], "invalid_grant");

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/revoke"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(&client_id, &secret))
            .body(Body::from(format!(
                "token={}&token_type_hint=access_token",
                utf8_percent_encode(&access_token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "revoke access token");

    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/introspect"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(&client_id, &secret))
            .body(Body::from(format!(
                "token={}&token_type_hint=access_token",
                utf8_percent_encode(&access_token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "introspect revoked access token"
    );
    assert_eq!(body_json(response).await["active"], false);

    assert!(audit_count(&pool, &client_id, "refresh_token.issued").await >= 2);
    assert!(audit_count(&pool, &client_id, "refresh_token.used").await >= 1);
    assert!(audit_count(&pool, &client_id, "refresh_token.reuse_detected").await >= 1);
}

#[tokio::test]
async fn invalid_authorize_and_client_auth_failures() {
    let Some(env) = support::setup("OIDC flow").await else {
        return;
    };
    let support::TestEnv {
        app,
        pool,
        root_tenant_id,
        ..
    } = env;

    let client_id = insert_public_client(&pool, &root_tenant_id).await;

    // An unregistered client gets 400 without a redirect.
    let response = send(
        &app,
        Request::builder()
            .uri(authorize_uri(&root_tenant_id, "no-such-client", "s", "n"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_client");

    // An unregistered redirect_uri does not redirect either.
    let response = send(
        &app,
        Request::builder()
            .uri(format!(
                "/{root_tenant_id}/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fevil.example.com%2Fcb&scope=openid&state=s&nonce=n&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Exceeding scope returns invalid_scope to the redirect_uri (using a client registered with openid only).
    let (conf_client_id, secret) = insert_confidential_client(&pool, &root_tenant_id).await;
    let response = send(
        &app,
        Request::builder()
            .uri(authorize_uri(&root_tenant_id, &conf_client_id, "s", "n")) // scope=openid profile email
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let callback = location(&response);
    assert_eq!(
        query_param(&callback, "error").as_deref(),
        Some("invalid_scope")
    );
    assert_eq!(query_param(&callback, "state").as_deref(), Some("s"));

    // Condition 13: confidential client authentication failure (Basic secret mismatch → 401 + audit log).
    let bad_basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{conf_client_id}:wrong-secret"));
    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {bad_basic}"))
            .body(Body::from(format!(
                "grant_type=authorization_code&code=whatever&redirect_uri={}&code_verifier={CODE_VERIFIER}",
                "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("www-authenticate"));
    assert_eq!(body_json(response).await["error"], "invalid_client");
    assert!(audit_count(&pool, &conf_client_id, "client.authentication_failed").await >= 1);

    // With the correct secret client authentication passes (the code is fake, so it gets as far as invalid_grant).
    let good_basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{conf_client_id}:{secret}"));
    let response = send(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/{root_tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {good_basic}"))
            .body(Body::from(format!(
                "grant_type=authorization_code&code=whatever&redirect_uri={}&code_verifier={CODE_VERIFIER}",
                "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_grant");
}

#[tokio::test]
async fn login_lockout_after_repeated_failures() {
    let Some(env) = support::setup("OIDC flow").await else {
        return;
    };
    let support::TestEnv {
        app,
        pool,
        root_tenant_id,
        ..
    } = env;

    let client_id = insert_public_client(&pool, &root_tenant_id).await;
    let username = format!("lock{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let password = "correct-horse-battery";
    register_user(&app, &root_tenant_id, &username, password).await;
    support::mark_email_verified(&pool, &root_tenant_id, &username).await;

    // Create an AuthSession and go to the login screen (handoff → resume).
    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        &authorize_uri(&root_tenant_id, &client_id, "st", "no"),
    )
    .await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);

    // 9 failures → invalid_credentials, locked on the 10th (locked).
    for attempt in 1..=10 {
        let (status, body) = internal_authenticate(
            &app,
            &root_tenant_id,
            &auth_session,
            &username,
            "wrong-password",
            &csrf,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "attempt {attempt}");
        let expected = if attempt < 10 {
            "invalid_credentials"
        } else {
            "locked"
        };
        assert_eq!(body["result"], expected, "attempt {attempt}");
    }

    // While locked, even the correct password is rejected.
    let (_, body) = internal_authenticate(
        &app,
        &root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(body["result"], "locked", "locked account");

    // Audit log: 10+ login.failed and 2+ login.locked (at locking + attempts while locked).
    assert!(audit_count(&pool, &client_id, "login.failed").await >= 10);
    assert!(audit_count(&pool, &client_id, "login.locked").await >= 2);
}

/// ⚠ **Authorization starts even without `nonce`** (ADR-0049; `nonce` is optional for the code flow in
/// OIDC Core 3.1.2.1).
///
/// ⚠ **It stopped being required because it rejected spec-compliant counterparts** — Forgejo does not
/// send `nonce` (not implemented), so it could not even reach the login screen.
/// **`state` and PKCE (S256) remain required.**
#[tokio::test]
async fn authorize_without_nonce_is_accepted() {
    let Some(env) = support::setup("authorize without nonce").await else {
        return;
    };
    let support::TestEnv {
        app,
        pool,
        root_tenant_id,
        ..
    } = env;
    let client_id = insert_public_client(&pool, &root_tenant_id).await;

    let response = send(
        &app,
        Request::builder()
            .uri(authorize_uri_without_nonce(
                &root_tenant_id,
                &client_id,
                "state-no-nonce",
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    // ⚠ **Not rejected; proceeds as far as the handoff to the login screen.**
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        location(&response).contains("/login?auth_session="),
        "handoff URL: {}",
        location(&response)
    );

    // ⚠ **`state` remains required.** Invalid requests are **sent back to the client**
    //   (302 to `redirect_uri` with `error=`), so **tell them apart by destination**
    //   — it must not be the handoff to the login screen.
    let without_state = format!(
        "/{root_tenant_id}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope=openid&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
    );
    let response = send(
        &app,
        Request::builder()
            .uri(without_state)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let back = location(&response);
    assert!(back.contains("error=invalid_request"), "location: {back}");
    assert!(!back.contains("/login?auth_session="), "location: {back}");

    // ⚠ **PKCE remains required too.**
    let without_pkce = format!(
        "/{root_tenant_id}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope=openid&state=s"
    );
    let response = send(
        &app,
        Request::builder()
            .uri(without_pkce)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let back = location(&response);
    assert!(back.contains("error=invalid_request"), "location: {back}");
    assert!(!back.contains("/login?auth_session="), "location: {back}");
}
