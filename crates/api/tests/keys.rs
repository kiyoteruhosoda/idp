//! Integration tests (with DB) from signing key bootstrap through signing to JWKS verification.
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test keys

mod support;

use assay_api::application::key_service::KeyService;
use assay_api::domain::clock::Clock;
use assay_api::infrastructure::jwt;
use assay_api::infrastructure::repositories::signing_key::SqlxSigningKeyRepository;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;

struct FixedClock(DateTime<Utc>);
impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: usize,
}

/// Number of concurrent bootstraps (tasks to actually race into the exclusive section of `insert_if_no_active`).
const CONCURRENT_BOOTSTRAPS: usize = 8;

/// Pool size is "concurrent bootstraps + spare for verification queries". `insert_if_no_active` occupies one
/// connection while holding the advisory lock, so a pool smaller than the concurrency gets stuck waiting to acquire.
const POOL_MAX_CONNECTIONS: u32 = CONCURRENT_BOOTSTRAPS as u32 + 2;

// Only one worker thread (regression guard). RSA key generation is CPU-bound but offloaded to the blocking pool,
// so even with more concurrent tasks than workers the runtime can progress other tasks (DB I/O, tasks holding the
// exclusive section). If key generation went back to running directly on worker threads, 8 generations would occupy
// the one worker, the exclusive section would not progress, and this test would stall holding connections and fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn ensure_key_is_idempotent_and_token_verifies_against_jwks() {
    let Some(pool) =
        support::connect_pool_with_max_connections("key service", POOL_MAX_CONNECTIONS).await
    else {
        return;
    };

    let repo = Arc::new(SqlxSigningKeyRepository::new(pool.clone()));
    let clock = Arc::new(FixedClock(Utc::now()));
    // Match the encryption key to the app default. If mixed with another key on the shared test DB,
    // other tests (going through server assembly) could not decrypt the ACTIVE key.
    let kek = *assay_api::config::Config::from_env()
        .expect("config")
        .key_encryption_key();
    let service = Arc::new(KeyService::new(repo, clock, kek));

    // To actually cause the race, empty the key table before bootstrapping concurrently
    // (this test binary alone handles this table, and cargo runs binaries sequentially).
    sqlx::query("DELETE FROM signing_keys")
        .execute(&pool)
        .await
        .expect("clear signing keys");

    // Concurrency safety (SEC5): even with simultaneous bootstraps from several instances there is one ACTIVE key
    // (exclusive section via the advisory lock of `insert_if_no_active`).
    let mut tasks = Vec::new();
    for _ in 0..CONCURRENT_BOOTSTRAPS {
        let svc = service.clone();
        tasks.push(tokio::spawn(async move { svc.ensure_active_key().await }));
    }
    for task in tasks {
        task.await.expect("join").expect("concurrent ensure");
    }

    // Idempotency: calling again does not add ACTIVE keys.
    service.ensure_active_key().await.expect("ensure again");

    let active_count: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM signing_keys WHERE status = 'ACTIVE'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("c");
    assert_eq!(active_count, 1, "exactly one ACTIVE signing key must exist");

    // Sign with the ACTIVE key and verify with the public key from JWKS.
    let active = service.active_signing_key().await.expect("active key");
    let claims = Claims {
        sub: "user-1".to_string(),
        iss: "https://idp.example.com".to_string(),
        exp: 9_999_999_999,
    };
    let token = jwt::sign(
        &active.private_pem,
        &active.kid,
        "at+jwt",
        &active.algorithm,
        &claims,
    )
    .expect("sign");

    let jwks = service.jwks().await.expect("jwks");
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == active.kid)
        .expect("jwk for active kid present in JWKS");

    let decoding_key = jwt::decoding_key_from_jwk(jwk).expect("decoding key");
    let alg = match active.algorithm.as_str() {
        "ES256" => jsonwebtoken::Algorithm::ES256,
        _ => jsonwebtoken::Algorithm::RS256,
    };
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp"]);

    let data =
        jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).expect("verify token");
    assert_eq!(data.claims.sub, "user-1");
}
