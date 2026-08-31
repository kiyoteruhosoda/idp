//! `private_key_jwt` クライアント認証の統合テスト（ADR-0030。RFC 7523）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test private_key_jwt
//!
//! 検証の要:
//! - 署名済み assertion だけでトークンが取れること（共有秘密を一切流さない）。
//! - 同じ assertion の**再利用が拒まれる**こと（`jti` の再生防止）。これが無いと、傍受した
//!   相手は `exp` までの間その assertion を使い回せる。
//! - 他人の鍵・他テナント宛・期限切れ・`jti` 無しが通らないこと。
//! - `private_key_jwt` で登録したクライアントが、secret 方式へ「落ちない」こと。

mod support;

use assay_api::domain::client_assertion::JWT_BEARER_ASSERTION_TYPE;
use assay_api::domain::jwt::{generate_rsa_keypair, sign};
use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Serialize;
use serde_json::Value;
use support::{body_json, send};

#[derive(Serialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    jti: String,
}

struct AssertionSpec<'a> {
    client_id: &'a str,
    private_pem: &'a str,
    kid: &'a str,
    audience: String,
    expires_in_seconds: i64,
    jti: String,
}

impl<'a> AssertionSpec<'a> {
    /// 素直に通るはずの assertion（`aud` はテナント issuer のトークンエンドポイント）。
    fn valid(
        env: &support::TestEnv,
        client_id: &'a str,
        private_pem: &'a str,
        kid: &'a str,
    ) -> Self {
        Self {
            client_id,
            private_pem,
            kid,
            audience: format!("{}/{}/token", env.issuer, env.root_tenant_id),
            expires_in_seconds: 120,
            jti: support::unique(),
        }
    }

    fn build(&self) -> String {
        let now = Utc::now().timestamp();
        sign(
            self.private_pem,
            self.kid,
            "JWT",
            "RS256",
            &AssertionClaims {
                iss: self.client_id.to_string(),
                sub: self.client_id.to_string(),
                aud: self.audience.clone(),
                exp: now + self.expires_in_seconds,
                iat: now,
                jti: self.jti.clone(),
            },
        )
        .expect("sign client assertion")
    }
}

/// `/token` へ `client_credentials` + client assertion を投げる。
async fn request_token(
    app: &axum::Router,
    tenant_id: &str,
    assertion: &str,
) -> axum::response::Response {
    request_token_with_type(app, tenant_id, assertion, JWT_BEARER_ASSERTION_TYPE).await
}

async fn request_token_with_type(
    app: &axum::Router,
    tenant_id: &str,
    assertion: &str,
    assertion_type: &str,
) -> axum::response::Response {
    let body = format!(
        "grant_type=client_credentials&client_assertion_type={}&client_assertion={}",
        utf8_percent_encode(assertion_type, NON_ALPHANUMERIC),
        utf8_percent_encode(assertion, NON_ALPHANUMERIC),
    );
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// 署名済み assertion だけでアクセストークンが取れる。`client_id` は body に載せない
/// （RFC 7521 §4.2 が認める省略形。対象クライアントは assertion の `sub` から決まる）。
#[tokio::test]
async fn issues_a_token_for_a_signed_assertion_without_any_shared_secret() {
    let Some(env) = support::setup("private_key_jwt").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    let response = request_token(&env.app, &env.root_tenant_id, &spec.build()).await;
    assert_eq!(response.status(), StatusCode::OK);

    let tokens = body_json(response).await;
    assert_eq!(tokens["token_type"], "Bearer");
    // 登録できる scope は OIDC の 4 値だけで、そのすべてが利用者前提か offline_access のため、
    // このトークンに載る scope は無い（ADR-0033）。
    assert_eq!(tokens["scope"], "");
    assert!(tokens["access_token"]
        .as_str()
        .is_some_and(|t| !t.is_empty()));
    // client_credentials なので利用者主体のトークンは返らない（G4）。
    assert_eq!(tokens["id_token"], Value::Null);
    assert_eq!(tokens["refresh_token"], Value::Null);
}

/// テナント issuer そのものを `aud` に入れる実装も受け入れる（ADR-0030 決定 6）。
#[tokio::test]
async fn the_tenant_issuer_is_also_accepted_as_the_audience() {
    let Some(env) = support::setup("private_key_jwt_aud_issuer").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let mut spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    spec.audience = format!("{}/{}", env.issuer, env.root_tenant_id);
    let response = request_token(&env.app, &env.root_tenant_id, &spec.build()).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// **同じ assertion は 2 回使えない**（ADR-0030 決定 5）。1 回目は通り、2 回目は拒まれる。
#[tokio::test]
async fn the_same_assertion_cannot_be_replayed() {
    let Some(env) = support::setup("private_key_jwt_replay").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    let assertion = spec.build();

    let first = request_token(&env.app, &env.root_tenant_id, &assertion).await;
    assert_eq!(first.status(), StatusCode::OK, "1 回目は通る");

    let second = request_token(&env.app, &env.root_tenant_id, &assertion).await;
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "同じ assertion の使い回しは拒む"
    );
    assert_eq!(body_json(second).await["error"], "invalid_client");

    // `jti` を変えれば（＝新しく署名すれば）通る。止めているのは再生であって連続利用ではない。
    let mut fresh = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    fresh.jti = support::unique();
    let third = request_token(&env.app, &env.root_tenant_id, &fresh.build()).await;
    assert_eq!(third.status(), StatusCode::OK);
}

/// 登録されていない鍵で署名した assertion は通らない（＝鍵を差し替えれば旧鍵は失効する）。
#[tokio::test]
async fn an_assertion_signed_by_another_key_is_rejected() {
    let Some(env) = support::setup("private_key_jwt_other_key").await else {
        return;
    };
    let (client_id, _private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let (attacker_pem, _) = generate_rsa_keypair().expect("generate attacker key");

    let spec = AssertionSpec::valid(&env, &client_id, &attacker_pem, &kid);
    let response = request_token(&env.app, &env.root_tenant_id, &spec.build()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "invalid_client");
}

/// 別の宛先向けに署名させた assertion を転送しても通らない。
#[tokio::test]
async fn an_assertion_for_another_audience_is_rejected() {
    let Some(env) = support::setup("private_key_jwt_bad_aud").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let mut spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    spec.audience = "https://someone-else.example.com/token".to_string();
    let response = request_token(&env.app, &env.root_tenant_id, &spec.build()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 期限切れ、および有効期間が長すぎる assertion は通らない（ADR-0030 決定 5）。
#[tokio::test]
async fn expired_and_overlong_assertions_are_rejected() {
    let Some(env) = support::setup("private_key_jwt_lifetime").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let mut expired = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    // 時計ずれの許容幅（60 秒）より確実に過去へ置く。
    expired.expires_in_seconds = -300;
    assert_eq!(
        request_token(&env.app, &env.root_tenant_id, &expired.build())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let mut overlong = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    overlong.expires_in_seconds = 60 * 60;
    assert_eq!(
        request_token(&env.app, &env.root_tenant_id, &overlong.build())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

/// `client_assertion_type` が `jwt-bearer` でなければ受け付けない（RFC 7523 §2.2）。
#[tokio::test]
async fn an_unsupported_assertion_type_is_rejected() {
    let Some(env) = support::setup("private_key_jwt_type").await else {
        return;
    };
    let (client_id, private_pem, kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let spec = AssertionSpec::valid(&env, &client_id, &private_pem, &kid);
    let response = request_token_with_type(
        &env.app,
        &env.root_tenant_id,
        &spec.build(),
        "urn:example:some-other-assertion",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// `private_key_jwt` で登録したクライアントは、secret 方式へ落ちない（ADR-0030 決定 2）。
/// この方式のクライアントは secret を持たないので、Basic を送っても照合対象が無い。
#[tokio::test]
async fn a_private_key_jwt_client_cannot_authenticate_with_a_secret() {
    let Some(env) = support::setup("private_key_jwt_no_fallback").await else {
        return;
    };
    let (client_id, _private_pem, _kid) =
        support::insert_private_key_jwt_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    let credentials = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{client_id}:whatever"),
    );
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Basic {credentials}"),
            )
            .body(Body::from("grant_type=client_credentials"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Discovery が `private_key_jwt` と対応署名アルゴリズムを広告する。
#[tokio::test]
async fn discovery_advertises_private_key_jwt() {
    let Some(env) = support::setup("private_key_jwt_discovery").await else {
        return;
    };
    let response = send(
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
    assert_eq!(response.status(), StatusCode::OK);
    let doc = body_json(response).await;
    let methods = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .expect("auth methods");
    assert!(methods.iter().any(|m| m == "private_key_jwt"));
    assert_eq!(
        doc["token_endpoint_auth_signing_alg_values_supported"],
        serde_json::json!(["RS256", "ES256"])
    );
}
