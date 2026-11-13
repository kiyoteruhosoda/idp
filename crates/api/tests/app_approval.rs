//! "Continue with the app" and authenticator app keys (task #892; ADR-0077).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test app_approval
//!
//! The test plays the authenticator app: it signs with an aws-lc-rs P-256 key instead of a Keystore key. Key Attestation
//! verification itself is covered by the domain tests (`key_attestation/tests.rs`), so here an enrollment in the stage
//! after key attestation passed is put in the DB, then registration confirmation, activation, approval, completion and revocation are run.

mod support;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use axum::http::{Method, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{
    anonymous, body_json, create_plain_user, post_internal, send, unique, TestEnv, SERVICE_TOKEN,
};

const PACKAGE: &str = "com.nolumia.auth";

/// Opens the authenticator app endpoints (decided by env vars only; once per test binary).
fn enable_app_approver() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let digest = hex::encode(Sha256::digest(b"authapp-test-signer"));
        let roots = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../core/src/domain/key_attestation/fixtures/root.pem"
        );
        std::env::set_var("APP_APPROVER_PACKAGE_NAME", PACKAGE);
        std::env::set_var("APP_APPROVER_SIGNING_CERT_SHA256", digest);
        std::env::set_var("APP_APPROVER_EXTRA_ATTESTATION_ROOTS_FILE", roots);
    });
}

async fn setup(name: &str) -> Option<TestEnv> {
    enable_app_approver();
    support::setup(name).await
}

/// Stand-in for the app's key.
struct AppKey {
    pair: EcdsaKeyPair,
    spki: Vec<u8>,
}

impl AppKey {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        // SubjectPublicKeyInfo (id-ecPublicKey, prime256v1) + uncompressed point.
        let mut spki = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
        spki.extend_from_slice(pair.public_key().as_ref());
        Self { pair, spki }
    }

    fn key_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(&self.spki))
    }

    fn sign(&self, action: &str, tenant: &str, target: &str, nonce: &str) -> String {
        let message = format!("assay-app-approver-v1\n{action}\n{tenant}\n{target}\n{nonce}");
        let signature = self
            .pair
            .sign(&SystemRandom::new(), message.as_bytes())
            .unwrap();
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    }
}

/// An SSO session that just signed in with a passkey (the condition for confirming registration).
async fn passkey_session(env: &TestEnv, user_id: &str, method: &str) -> String {
    let session_id = assay_api::domain::crypto::random_hex(32);
    sqlx::query(
        "INSERT INTO sso_sessions \
         (session_hash, user_id, auth_time, idle_expires_at, absolute_expires_at, authentication_methods) \
         VALUES (?, ?, UTC_TIMESTAMP(6), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 HOUR), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 8 HOUR), ?)",
    )
    .bind(assay_api::domain::crypto::sha256_hex(&session_id))
    .bind(user_id)
    .bind(json!([method]).to_string())
    .execute(&env.pool)
    .await
    .expect("insert sso session");
    session_id
}

async fn internal(env: &TestEnv, uri: &str, payload: Value) -> Value {
    let res = send(&env.app, post_internal(uri, Some(SERVICE_TOKEN), payload)).await;
    assert_eq!(res.status(), StatusCode::OK, "{uri}");
    body_json(res).await
}

async fn public(
    env: &TestEnv,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let uri = format!("/{}/app-approver/{path}", env.root_tenant_id);
    let res = send(&env.app, anonymous(method, &uri, body)).await;
    let status = res.status();
    let text = support::body_text(res).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// Starts enrollment and puts the stage after key attestation passed in the DB (Key Attestation checks are in the domain tests).
async fn enrollment_awaiting_confirmation(env: &TestEnv, key: &AppKey) -> String {
    let (status, body) = public(env, Method::POST, "enrollments", None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["enrollment_id"].as_str().unwrap().to_string();
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(body["challenge"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    sqlx::query(
        "UPDATE app_approver_enrollments SET stage = 'awaiting_confirmation', public_key_spki = ?, \
         security_level = 'tee', device_name = 'Pixel test' WHERE id = ?",
    )
    .bind(&key.spki)
    .bind(&id)
    .execute(&env.pool)
    .await
    .unwrap();
    id
}

/// Creates a user, registers a key and activates it. Returns `(user_id, key)`.
async fn registered_key(env: &TestEnv) -> (String, AppKey) {
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let key = AppKey::new();
    let enrollment = enrollment_awaiting_confirmation(env, &key).await;
    let sso = passkey_session(env, &user_id, "webauthn").await;
    let confirmed = internal(
        env,
        "/internal/account/app-approver/confirm",
        json!({ "tenant_id": env.root_tenant_id, "sso_session_id": sso, "enrollment_id": enrollment }),
    )
    .await;
    assert_eq!(confirmed["result"], "confirmed", "{confirmed}");
    let code = confirmed["code"].as_str().unwrap().to_string();
    let (status, body) = public(
        env,
        Method::POST,
        &format!("enrollments/{enrollment}/activate"),
        Some(json!({
            "code": code,
            "signature": key.sign("activate", &env.root_tenant_id, &enrollment, &code),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key_id"], key.key_id());
    (user_id, key)
}

/// Starts a request (in place of web). `(request_id, browser_binding)`.
async fn start_request(env: &TestEnv, auth_session_id: Option<&str>) -> (String, String) {
    let body = internal(
        env,
        "/internal/app-approval/start",
        json!({ "tenant_id": env.root_tenant_id, "auth_session_id": auth_session_id, "ip_address": "203.0.113.9" }),
    )
    .await;
    assert_eq!(body["result"], "started", "{body}");
    (
        body["request_id"].as_str().unwrap().to_string(),
        body["browser_binding"].as_str().unwrap().to_string(),
    )
}

/// The app reads the request and approves it. Returns the code of continue_url.
async fn approve(env: &TestEnv, key: &AppKey, request_id: &str) -> String {
    let (status, view) = public(env, Method::GET, &format!("requests/{request_id}"), None).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["state"], "pending");
    assert_eq!(view["ip_address"], "203.0.113.9");
    let challenge = view["challenge"].as_str().unwrap();
    let (status, body) = public(
        env,
        Method::POST,
        &format!("requests/{request_id}/approve"),
        Some(json!({
            "key_id": key.key_id(),
            "signature": key.sign("approve", &env.root_tenant_id, request_id, challenge),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let url = body["continue_url"].as_str().unwrap();
    assert!(
        url.contains(&format!(
            "/{}/login/app/complete?request={request_id}&code=",
            env.root_tenant_id
        )),
        "{url}"
    );
    support::query_param(url, "code").unwrap()
}

async fn complete(env: &TestEnv, request_id: &str, code: &str, binding: Option<&str>) -> Value {
    internal(
        env,
        "/internal/app-approval/complete",
        json!({
            "tenant_id": env.root_tenant_id,
            "request_id": request_id,
            "code": code,
            "browser_binding": binding,
        }),
    )
    .await
}

async fn session_lifetime_secs(env: &TestEnv, sso_session_id: &str) -> (i64, i64) {
    sqlx::query_as(
        "SELECT TIMESTAMPDIFF(SECOND, created_at, idle_expires_at), \
                TIMESTAMPDIFF(SECOND, created_at, absolute_expires_at) \
         FROM sso_sessions WHERE session_hash = ?",
    )
    .bind(assay_api::domain::crypto::sha256_hex(sso_session_id))
    .fetch_one(&env.pool)
    .await
    .expect("sso session exists")
}

#[tokio::test]
async fn an_approval_completes_only_in_the_browser_that_started_it() {
    let Some(env) = setup("app_approval_browser").await else {
        return;
    };
    let (_user, key) = registered_key(&env).await;

    // Approved a request started on another device: the code reaches this phone's browser, but there is no mark.
    let (request_id, binding) = start_request(&env, None).await;
    let code = approve(&env, &key, &request_id).await;
    let refused = complete(&env, &request_id, &code, None).await;
    assert_eq!(refused["result"], "another_browser", "{refused}");
    // The refused request is finished (issuing the same code again with another mark does not pass).
    let other = complete(&env, &request_id, &code, Some("not-the-binding")).await;
    assert_eq!(other["result"], "invalid", "{other}");
    // The first attempt with a different mark also counts as "another browser".
    let (request_id2, _) = start_request(&env, None).await;
    let code2 = approve(&env, &key, &request_id2).await;
    let wrong = complete(&env, &request_id2, &code2, Some("not-the-binding")).await;
    assert_eq!(wrong["result"], "another_browser", "{wrong}");
    // A request refused once does not complete even if the correct mark comes later.
    let late = complete(&env, &request_id, &code, Some(&binding)).await;
    assert_eq!(late["result"], "invalid", "{late}");

    // In the same browser (mark matches) it completes, and the sign-in lasts 30 days (the idle expiry is the same).
    let (request_id, binding) = start_request(&env, None).await;
    let code = approve(&env, &key, &request_id).await;
    let done = complete(&env, &request_id, &code, Some(&binding)).await;
    assert_eq!(done["result"], "success", "{done}");
    assert!(
        done["redirect_to"].is_null(),
        "outside an authorization: {done}"
    );
    let sso = done["sso_session_id"].as_str().unwrap();
    assert_eq!(done["sso_absolute_ttl_secs"], 2_592_000);
    let (idle, absolute) = session_lifetime_secs(&env, sso).await;
    // created_at is set by the DB (off by a few milliseconds), so allow for second truncation.
    assert!((2_591_998..=2_592_000).contains(&idle), "{idle}");
    assert!((2_591_998..=2_592_000).contains(&absolute), "{absolute}");
    let linked: Option<String> = sqlx::query_scalar(
        "SELECT approver_key_id FROM sso_session_contexts WHERE session_hash = ?",
    )
    .bind(assay_api::domain::crypto::sha256_hex(sso))
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert!(linked.is_some());
}

#[tokio::test]
async fn an_approval_continues_the_authorization_it_started_from() {
    let Some(env) = setup("app_approval_authorize").await else {
        return;
    };
    let (_user, key) = registered_key(&env).await;
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let auth_session_id = support::begin_login(
        &env.app,
        &env.root_tenant_id,
        &support::authorize_uri_openid_only(&env.root_tenant_id, &client_id),
    )
    .await;
    let (request_id, binding) = start_request(&env, Some(&auth_session_id)).await;
    let (_, view) = public(&env, Method::GET, &format!("requests/{request_id}"), None).await;
    assert_eq!(view["client_name"], "Integration Test App");
    let code = approve(&env, &key, &request_id).await;
    let done = complete(&env, &request_id, &code, Some(&binding)).await;
    assert_eq!(done["result"], "success", "{done}");
    let redirect = done["redirect_to"].as_str().expect("back to the RP");
    assert!(redirect.starts_with(support::REDIRECT_URI), "{redirect}");
    assert!(
        support::query_param(redirect, "code").is_some(),
        "{redirect}"
    );
}

#[tokio::test]
async fn the_code_is_single_use_and_lasts_30_seconds() {
    let Some(env) = setup("app_approval_code").await else {
        return;
    };
    let (_user, key) = registered_key(&env).await;

    let (request_id, binding) = start_request(&env, None).await;
    let code = approve(&env, &key, &request_id).await;
    let expires_in: i64 = sqlx::query_scalar(
        "SELECT TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(6), code_expires_at) FROM app_approval_requests WHERE id = ?",
    )
    .bind(&request_id)
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert!((25..=30).contains(&expires_in), "{expires_in}");
    assert_eq!(
        complete(&env, &request_id, &code, Some(&binding)).await["result"],
        "success"
    );
    assert_eq!(
        complete(&env, &request_id, &code, Some(&binding)).await["result"],
        "invalid"
    );

    // A code past 30 seconds.
    let (request_id, binding) = start_request(&env, None).await;
    let code = approve(&env, &key, &request_id).await;
    sqlx::query(
        "UPDATE app_approval_requests SET code_expires_at = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND) WHERE id = ?",
    )
    .bind(&request_id)
    .execute(&env.pool)
    .await
    .unwrap();
    assert_eq!(
        complete(&env, &request_id, &code, Some(&binding)).await["result"],
        "invalid"
    );

    // A wrong code.
    let (request_id, binding) = start_request(&env, None).await;
    let _ = approve(&env, &key, &request_id).await;
    assert_eq!(
        complete(&env, &request_id, &format!("x{}", unique()), Some(&binding)).await["result"],
        "invalid"
    );
}

#[tokio::test]
async fn revoking_the_key_ends_the_sessions_it_approved() {
    let Some(env) = setup("app_approval_revoke").await else {
        return;
    };
    let (user_id, key) = registered_key(&env).await;
    let (request_id, binding) = start_request(&env, None).await;
    let code = approve(&env, &key, &request_id).await;
    let done = complete(&env, &request_id, &code, Some(&binding)).await;
    let approved_session = done["sso_session_id"].as_str().unwrap().to_string();

    // It is listed in the "Devices" section as "Authenticator app".
    let account = passkey_session(&env, &user_id, "webauthn").await;
    let listed = internal(
        &env,
        "/internal/account/app-approver/keys",
        json!({ "tenant_id": env.root_tenant_id, "sso_session_id": account }),
    )
    .await;
    assert_eq!(listed["result"], "listed", "{listed}");
    assert_eq!(listed["enabled"], true);
    assert_eq!(listed["keys"][0]["device_name"], "Pixel test");
    assert_eq!(listed["keys"][0]["security_level"], "tee");
    assert!(listed["keys"][0]["last_used_at"].is_string());

    // Revoke from the app (signature over the time).
    let signed_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let (status, _) = public(
        &env,
        Method::POST,
        &format!("keys/{}/revoke", key.key_id()),
        Some(json!({
            "signed_at": signed_at,
            "signature": key.sign("revoke", &env.root_tenant_id, &key.key_id(), &signed_at),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE session_hash = ?")
            .bind(assay_api::domain::crypto::sha256_hex(&approved_session))
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "the approved session ended");
    let (status, _) = public(&env, Method::GET, &format!("keys/{}", key.key_id()), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A revoked key can no longer approve.
    let (request_id, _) = start_request(&env, None).await;
    let (_, view) = public(&env, Method::GET, &format!("requests/{request_id}"), None).await;
    let challenge = view["challenge"].as_str().unwrap();
    let (status, body) = public(
        &env,
        Method::POST,
        &format!("requests/{request_id}/approve"),
        Some(json!({
            "key_id": key.key_id(),
            "signature": key.sign("approve", &env.root_tenant_id, &request_id, challenge),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "key_revoked");
}

#[tokio::test]
async fn revoking_from_the_account_page_also_ends_the_sessions() {
    let Some(env) = setup("app_approval_account_revoke").await else {
        return;
    };
    let (user_id, key) = registered_key(&env).await;
    let (request_id, binding) = start_request(&env, None).await;
    let code = approve(&env, &key, &request_id).await;
    let done = complete(&env, &request_id, &code, Some(&binding)).await;
    let approved_session = done["sso_session_id"].as_str().unwrap().to_string();
    let account = passkey_session(&env, &user_id, "webauthn").await;
    let listed = internal(
        &env,
        "/internal/account/app-approver/keys",
        json!({ "tenant_id": env.root_tenant_id, "sso_session_id": account }),
    )
    .await;
    let id = listed["keys"][0]["id"].as_str().unwrap();
    let revoked = internal(
        &env,
        "/internal/account/app-approver/keys/revoke",
        json!({ "tenant_id": env.root_tenant_id, "sso_session_id": account, "key_id": id }),
    )
    .await;
    assert_eq!(revoked["result"], "revoked", "{revoked}");
    assert_eq!(revoked["sessions"], 1);
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sso_sessions WHERE session_hash = ?")
            .bind(assay_api::domain::crypto::sha256_hex(&approved_session))
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn signatures_must_come_from_the_registered_key_for_this_request() {
    let Some(env) = setup("app_approval_signature").await else {
        return;
    };
    let (_user, key) = registered_key(&env).await;
    let stranger = AppKey::new();
    let (request_id, _) = start_request(&env, None).await;
    let (_, view) = public(&env, Method::GET, &format!("requests/{request_id}"), None).await;
    let challenge = view["challenge"].as_str().unwrap().to_string();

    // Registered key's number with another key's signature.
    let (status, body) = public(
        &env,
        Method::POST,
        &format!("requests/{request_id}/approve"),
        Some(json!({
            "key_id": key.key_id(),
            "signature": stranger.sign("approve", &env.root_tenant_id, &request_id, &challenge),
        })),
    )
    .await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("signature_invalid"))
    );
    // Reusing a refusal signature for approval.
    let (status, _) = public(
        &env,
        Method::POST,
        &format!("requests/{request_id}/approve"),
        Some(json!({
            "key_id": key.key_id(),
            "signature": key.sign("deny", &env.root_tenant_id, &request_id, &challenge),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // An unknown key.
    let (status, body) = public(
        &env,
        Method::POST,
        &format!("requests/{request_id}/approve"),
        Some(json!({
            "key_id": stranger.key_id(),
            "signature": stranger.sign("approve", &env.root_tenant_id, &request_id, &challenge),
        })),
    )
    .await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("key_revoked"))
    );
    // Once refused, it can no longer be approved.
    let (status, _) = public(
        &env,
        Method::POST,
        &format!("requests/{request_id}/deny"),
        Some(json!({
            "key_id": key.key_id(),
            "signature": key.sign("deny", &env.root_tenant_id, &request_id, &challenge),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = public(
        &env,
        Method::POST,
        &format!("requests/{request_id}/approve"),
        Some(json!({
            "key_id": key.key_id(),
            "signature": key.sign("approve", &env.root_tenant_id, &request_id, &challenge),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn registration_needs_a_recent_passkey_and_a_matching_attestation() {
    let Some(env) = setup("app_approval_registration").await else {
        return;
    };
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let key = AppKey::new();
    let enrollment = enrollment_awaiting_confirmation(&env, &key).await;
    // A session signed in with a password cannot confirm.
    let password_session = passkey_session(&env, &user_id, "password").await;
    let refused = internal(
        &env,
        "/internal/account/app-approver/confirm",
        json!({ "tenant_id": env.root_tenant_id, "sso_session_id": password_session, "enrollment_id": enrollment }),
    )
    .await;
    assert_eq!(refused["result"], "passkey_required", "{refused}");
    // Activation without a code before confirmation does not pass.
    let (status, _) = public(
        &env,
        Method::POST,
        &format!("enrollments/{enrollment}/activate"),
        Some(json!({ "code": "nothing", "signature": key.sign("activate", &env.root_tenant_id, &enrollment, "nothing") })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Even a correctly shaped chain made with the test root is not accepted if the challenge is not this enrollment's.
    let (status, body) = public(&env, Method::POST, "enrollments", None).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = body["enrollment_id"].as_str().unwrap();
    let pem = include_str!("../../core/src/domain/key_attestation/fixtures/good.pem");
    let chain: Vec<String> = pem
        .split("-----END CERTIFICATE-----")
        .filter_map(|block| {
            let b64: String = block
                .lines()
                .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
                .collect();
            (!b64.is_empty()).then(|| STANDARD.encode(STANDARD.decode(b64).unwrap()))
        })
        .collect();
    assert_eq!(chain.len(), 3);
    let (status, body) = public(
        &env,
        Method::PUT,
        &format!("enrollments/{id}/key"),
        Some(json!({ "certificate_chain": chain, "device_name": "Pixel test" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "attestation_rejected");
    assert_eq!(body["reason"], "wrong_challenge");
    // A refused enrollment is discarded (cannot be reissued with the same challenge).
    let (status, _) = public(
        &env,
        Method::PUT,
        &format!("enrollments/{id}/key"),
        Some(json!({ "certificate_chain": chain, "device_name": "Pixel test" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn asset_links_name_the_authenticator_app() {
    let Some(env) = setup("app_approval_asset_links").await else {
        return;
    };
    let res = send(
        &env.app,
        anonymous(Method::GET, "/.well-known/assetlinks.json", None),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body[0]["target"]["package_name"], PACKAGE);
    let fingerprint = body[0]["target"]["sha256_cert_fingerprints"][0]
        .as_str()
        .unwrap()
        .to_string();
    let expected = hex::encode_upper(Sha256::digest(b"authapp-test-signer"))
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    assert_eq!(fingerprint, expected);
}
