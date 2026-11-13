//! Binds mobile app tokens to the device key with DPoP (ADR-0075; task #893).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test dpop_binding
//!
//! - Refreshing with a proof puts `cnf.jkt` on the access token and the same key on the refresh token
//! - A bound refresh token cannot be used without the key or with another key (nothing is revoked)
//! - A bound access token cannot be used at `/userinfo` either without a key proof
//! - Apps that attach no proof work as before (AC3)

mod support;

use assay_api::domain::crypto::{base64url, sha256_hex};
use assay_api::domain::dpop::{access_token_hash, jwk_thumbprint_p256};
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::elliptic_curve::Generate as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use support::{body_json, create_plain_user, send, TestEnv};

/// Stand-in for the app (plays the Keystore key).
struct DeviceKey(SigningKey);

impl DeviceKey {
    fn generate() -> Self {
        Self(SigningKey::generate_from_rng(&mut rand::rng()))
    }

    fn jwk(&self) -> Value {
        let point = p256::PublicKey::from(self.0.verifying_key()).to_sec1_point(false);
        json!({
            "kty": "EC", "crv": "P-256",
            "x": base64url(point.x().unwrap()),
            "y": base64url(point.y().unwrap()),
        })
    }

    fn thumbprint(&self) -> String {
        let jwk = self.jwk();
        jwk_thumbprint_p256(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap())
    }

    fn proof(&self, method: &str, uri: &str, access_token: Option<&str>) -> String {
        let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()});
        let mut claims = json!({
            "jti": uuid::Uuid::now_v7().to_string(),
            "htm": method,
            "htu": uri,
            "iat": chrono::Utc::now().timestamp(),
        });
        if let Some(at) = access_token {
            claims["ath"] = Value::String(access_token_hash(at));
        }
        let input = format!(
            "{}.{}",
            base64url(header.to_string().as_bytes()),
            base64url(claims.to_string().as_bytes())
        );
        let signature: Signature = self.0.sign(input.as_bytes());
        format!("{input}.{}", base64url(&signature.to_bytes()))
    }
}

struct App<'a> {
    env: &'a TestEnv,
    client_id: String,
    secret: String,
}

impl App<'_> {
    fn token_uri(&self) -> String {
        format!("{}/{}/token", self.env.issuer, self.env.root_tenant_id)
    }

    fn userinfo_uri(&self) -> String {
        format!("{}/{}/userinfo", self.env.issuer, self.env.root_tenant_id)
    }

    async fn refresh(&self, refresh_token: &str, proof: Option<String>) -> (StatusCode, Value) {
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.client_id, self.secret));
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/{}/token", self.env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic}"));
        if let Some(proof) = proof {
            request = request.header("DPoP", proof);
        }
        let res = send(
            &self.env.app,
            request
                .body(Body::from(format!(
                    "grant_type=refresh_token&refresh_token={}",
                    utf8_percent_encode(refresh_token, NON_ALPHANUMERIC)
                )))
                .unwrap(),
        )
        .await;
        let status = res.status();
        (status, body_json(res).await)
    }

    async fn userinfo(&self, authorization: String, proof: Option<String>) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("GET")
            .uri(format!("/{}/userinfo", self.env.root_tenant_id))
            .header(AUTHORIZATION, authorization);
        if let Some(proof) = proof {
            request = request.header("DPoP", proof);
        }
        let res = send(&self.env.app, request.body(Body::empty()).unwrap()).await;
        let status = res.status();
        let body = if status == StatusCode::OK || status == StatusCode::UNAUTHORIZED {
            body_json(res).await
        } else {
            Value::Null
        };
        (status, body)
    }
}

async fn insert_refresh_token(env: &TestEnv, client_id: &str, user_id: &str) -> String {
    let plain = format!("rt-{}", uuid::Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (token_hash, tenant_id, user_id, client_id, scope, auth_time, expires_at) \
         VALUES (?, ?, ?, ?, '[\"openid\"]', UTC_TIMESTAMP(6), \
                 DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))",
    )
    .bind(sha256_hex(&plain))
    .bind(&env.root_tenant_id)
    .bind(user_id)
    .bind(client_id)
    .execute(&env.pool)
    .await
    .expect("insert refresh token");
    plain
}

async fn bound_key_of(env: &TestEnv, refresh_token: &str) -> Option<String> {
    sqlx::query_scalar("SELECT dpop_jkt FROM refresh_tokens WHERE token_hash = ?")
        .bind(sha256_hex(refresh_token))
        .fetch_one(&env.pool)
        .await
        .expect("dpop_jkt")
}

async fn is_revoked(env: &TestEnv, refresh_token: &str) -> bool {
    let revoked: Option<chrono::NaiveDateTime> =
        sqlx::query_scalar("SELECT revoked_at FROM refresh_tokens WHERE token_hash = ?")
            .bind(sha256_hex(refresh_token))
            .fetch_one(&env.pool)
            .await
            .expect("revoked_at");
    revoked.is_some()
}

/// The access token body (the signature is not checked).
fn claims_of(access_token: &str) -> Value {
    let payload = access_token.split('.').nth(1).expect("payload");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url"),
    )
    .expect("claims")
}

async fn app(env: &TestEnv) -> (App<'_>, String) {
    let (client_id, secret) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    (
        App {
            env,
            client_id,
            secret,
        },
        user_id,
    )
}

#[tokio::test]
async fn a_proof_binds_the_tokens_and_only_that_key_can_use_them() {
    let Some(env) = support::setup("dpop binding").await else {
        return;
    };
    let (app, user_id) = app(&env).await;
    let device = DeviceKey::generate();
    let thief = DeviceKey::generate();

    // An app updated to the DPoP version: attaching a proof to an unbound token binds it from there.
    let unbound = insert_refresh_token(&env, &app.client_id, &user_id).await;
    let (status, first) = app
        .refresh(&unbound, Some(device.proof("POST", &app.token_uri(), None)))
        .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["token_type"], "DPoP");
    let access_token = first["access_token"].as_str().unwrap().to_string();
    assert_eq!(claims_of(&access_token)["cnf"]["jkt"], device.thumbprint());
    let bound = first["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(bound_key_of(&env, &bound).await, Some(device.thumbprint()));

    // Someone who copied only the token (no key) cannot use it, and the owner's token does not stop.
    let (status, body) = app.refresh(&bound, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_dpop_proof");
    // A proof made with another key does not work either.
    let (status, body) = app
        .refresh(&bound, Some(thief.proof("POST", &app.token_uri(), None)))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        !is_revoked(&env, &bound).await,
        "a stranger without the key must not end the owner's sign-in"
    );

    // /userinfo: a bound access token cannot be used as Bearer.
    let (status, _) = app.userinfo(format!("Bearer {access_token}"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Even sent as DPoP, it cannot be used without a proof or with another key.
    let (status, body) = app.userinfo(format!("DPoP {access_token}"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_dpop_proof");
    let (status, _) = app
        .userinfo(
            format!("DPoP {access_token}"),
            Some(thief.proof("GET", &app.userinfo_uri(), Some(&access_token))),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A proof with the owner's key works.
    let (status, body) = app
        .userinfo(
            format!("DPoP {access_token}"),
            Some(device.proof("GET", &app.userinfo_uri(), Some(&access_token))),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sub"], claims_of(&access_token)["sub"]);

    // The owner's app can keep using it (refreshing with a proof of the same key; the binding carries over).
    let (status, second) = app
        .refresh(&bound, Some(device.proof("POST", &app.token_uri(), None)))
        .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["token_type"], "DPoP");
    let next = second["refresh_token"].as_str().unwrap();
    assert_eq!(bound_key_of(&env, next).await, Some(device.thumbprint()));

    // Reuse detection still works (if the key holder presents a used token again, the whole family stops).
    let (status, body) = app
        .refresh(&bound, Some(device.proof("POST", &app.token_uri(), None)))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(
        is_revoked(&env, next).await,
        "the family is revoked on reuse"
    );
}

#[tokio::test]
async fn a_proof_is_used_only_once_and_only_at_its_endpoint() {
    let Some(env) = support::setup("dpop proof once").await else {
        return;
    };
    let (app, user_id) = app(&env).await;
    let device = DeviceKey::generate();

    let token = insert_refresh_token(&env, &app.client_id, &user_id).await;
    let proof = device.proof("POST", &app.token_uri(), None);
    let (status, first) = app.refresh(&token, Some(proof.clone())).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    // Using the same proof again is refused (`jti` once per key).
    let next = first["refresh_token"].as_str().unwrap();
    let (status, body) = app.refresh(next, Some(proof)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_dpop_proof");
    // A proof for another endpoint (/userinfo) cannot be used at the token endpoint.
    let (status, body) = app
        .refresh(next, Some(device.proof("POST", &app.userinfo_uri(), None)))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_dpop_proof");
    // Refusing a broken proof does not revoke the token (it can be rebuilt and resent).
    assert!(!is_revoked(&env, next).await);
}

#[tokio::test]
async fn apps_without_dpop_keep_working_as_before() {
    let Some(env) = support::setup("dpop absent").await else {
        return;
    };
    let (app, user_id) = app(&env).await;

    let token = insert_refresh_token(&env, &app.client_id, &user_id).await;
    let (status, body) = app.refresh(&token, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    let access_token = body["access_token"].as_str().unwrap();
    assert!(claims_of(access_token).get("cnf").is_none());
    let next = body["refresh_token"].as_str().unwrap();
    assert_eq!(bound_key_of(&env, next).await, None);

    let (status, _) = app.userinfo(format!("Bearer {access_token}"), None).await;
    assert_eq!(status, StatusCode::OK);
    // Sending an unbound token as DPoP is a mismatch.
    let (status, _) = app.userinfo(format!("DPoP {access_token}"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discovery_names_the_dpop_algorithms() {
    let Some(env) = support::setup("dpop discovery").await else {
        return;
    };
    let res = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/.well-known/openid-configuration",
                env.root_tenant_id
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["dpop_signing_alg_values_supported"], json!(["ES256"]));
}
