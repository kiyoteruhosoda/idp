//! 署名鍵ブートストラップ〜署名〜JWKS 検証の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test keys

use chrono::{DateTime, Utc};
use idp::application::key_service::KeyService;
use idp::domain::clock::Clock;
use idp::infrastructure::jwt;
use idp::infrastructure::repositories::signing_key::SqlxSigningKeyRepository;
use serde::{Deserialize, Serialize};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::Row;
use std::sync::Arc;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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

#[tokio::test]
async fn ensure_key_is_idempotent_and_token_verifies_against_jwks() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping key service integration test");
        return;
    };

    let pool = MySqlPoolOptions::new()
        .connect(&url)
        .await
        .expect("connect to test database");
    MIGRATOR.run(&pool).await.expect("run migrations");

    let repo = Arc::new(SqlxSigningKeyRepository::new(pool.clone()));
    let clock = Arc::new(FixedClock(Utc::now()));
    // 暗号化キーはアプリ既定値と揃える。共有テスト DB 上で別の鍵と混在すると
    // 他テスト（サーバ組み立て経由）が ACTIVE 鍵を復号できなくなるため。
    let kek = *idp::config::Config::from_env()
        .expect("config")
        .key_encryption_key();
    let service = KeyService::new(repo, clock, kek);

    // 冪等性: 2 回呼んでも ACTIVE 鍵は増えない。
    service.ensure_active_key().await.expect("ensure #1");
    service.ensure_active_key().await.expect("ensure #2");

    let active_count: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM signing_keys WHERE status = 'ACTIVE'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("c");
    assert_eq!(active_count, 1, "exactly one ACTIVE signing key must exist");

    // ACTIVE 鍵で署名し、JWKS 由来の公開鍵で検証できる。
    let active = service.active_signing_key().await.expect("active key");
    let claims = Claims {
        sub: "user-1".to_string(),
        iss: "https://idp.example.com".to_string(),
        exp: 9_999_999_999,
    };
    let token = jwt::sign(&active.private_pem, &active.kid, "at+jwt", &claims).expect("sign");

    let jwks = service.jwks().await.expect("jwks");
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == active.kid)
        .expect("jwk for active kid present in JWKS");

    let decoding_key = jwt::decoding_key_from_jwk(jwk).expect("decoding key");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp"]);

    let data =
        jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation).expect("verify token");
    assert_eq!(data.claims.sub, "user-1");
}
