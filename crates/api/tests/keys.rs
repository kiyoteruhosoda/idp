//! 署名鍵ブートストラップ〜署名〜JWKS 検証の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test keys

mod support;

use chrono::{DateTime, Utc};
use idp_api::application::key_service::KeyService;
use idp_api::domain::clock::Clock;
use idp_api::infrastructure::jwt;
use idp_api::infrastructure::repositories::signing_key::SqlxSigningKeyRepository;
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

// RSA 鍵生成は同期 CPU 処理のため、並走ブートストラップの検証にはマルチスレッドランタイムを使う
// （current_thread だと keygen がリアクタをブロックし、他タスクの DB I/O が進まない）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ensure_key_is_idempotent_and_token_verifies_against_jwks() {
    let Some(pool) = support::connect_pool("key service").await else {
        return;
    };

    let repo = Arc::new(SqlxSigningKeyRepository::new(pool.clone()));
    let clock = Arc::new(FixedClock(Utc::now()));
    // 暗号化キーはアプリ既定値と揃える。共有テスト DB 上で別の鍵と混在すると
    // 他テスト（サーバ組み立て経由）が ACTIVE 鍵を復号できなくなるため。
    let kek = *idp_api::config::Config::from_env()
        .expect("config")
        .key_encryption_key();
    let service = Arc::new(KeyService::new(repo, clock, kek));

    // 並走レースを実際に起こすため、鍵テーブルを空にしてから同時ブートストラップする
    // （本テストバイナリは単独でこのテーブルを扱い、cargo はバイナリを逐次実行する）。
    sqlx::query("DELETE FROM signing_keys")
        .execute(&pool)
        .await
        .expect("clear signing keys");

    // 並走安全性（SEC5）: 複数インスタンスの同時ブートストラップでも ACTIVE 鍵は 1 本
    // （`insert_if_no_active` の advisory lock による排他区間）。
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let svc = service.clone();
        tasks.push(tokio::spawn(async move { svc.ensure_active_key().await }));
    }
    for task in tasks {
        task.await.expect("join").expect("concurrent ensure");
    }

    // 冪等性: さらに呼んでも ACTIVE 鍵は増えない。
    service.ensure_active_key().await.expect("ensure again");

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
