//! OIDC 認可コードフローの E2E 統合テスト（MVP 完了条件 1〜13、設計仕様 §10）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test oidc_flow
//!
//! テストデータ（client / user）は実行ごとにランダムな識別子で作成し、既存データと干渉しない。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{
    body_json, cookie_value, location, query_param, send, CODE_CHALLENGE, CODE_VERIFIER,
    REDIRECT_URI, SERVICE_TOKEN, SERVICE_TOKEN_HEADER,
};

/// 一意な public client（openid/profile/email）を登録して client_id を返す。
async fn insert_public_client(pool: &MySqlPool, tenant_id: &str) -> String {
    support::insert_public_client(pool, tenant_id, &["openid", "profile", "email"]).await
}

/// 一意な confidential client（openid のみ）を登録して `(client_id, client_secret)` を返す。
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
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid%20profile%20email&state={state}&nonce={nonce}&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
        "http%3A%2F%2Flocalhost%3A3000%2Fcallback"
    )
}

/// `auth_session_id` 由来のログイン CSRF トークン（web が描画し api の LoginService が検証する契約）。
fn login_csrf(auth_session: &str) -> String {
    idp_api::application::login::csrf_token(auth_session, idp_api::config::DEV_CSRF_SECRET)
}

/// api の内部認証（`POST /internal/authenticate`）で資格情報検証を駆動する（ログイン画面は web crate）。
/// `X-Forwarded-For` を渡すと監査・レート制限に反映される。結果は `result` タグ付き JSON。
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
    let sub = register_user(&app, &root_tenant_id, &username, password).await; // 条件 1

    // 条件 2, 3: /authorize 開始 → 未ログインなので /login へ。
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
    assert_eq!(response.status(), StatusCode::FOUND, "redirect to /login");
    // api は未ログイン時に /{tenant_id}/login（web が描画）へ 302 する（ADR-0009 §6、MT13）。
    assert_eq!(location(&response), format!("/{root_tenant_id}/login"));
    let auth_session = cookie_value(&response, "auth_session_id").expect("auth_session_id cookie");

    // CSRF は auth_session 由来（web が描画・api の LoginService が検証）。
    let csrf = login_csrf(&auth_session);

    // CSRF トークン不一致は拒否される（result=csrf_mismatch）。
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

    // 条件 4, 5, 7: ログイン成功。初回は profile/email が未同意のため同意ステップへ（F3）。
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

    // 同意を承諾すると code 付きで RP へリダイレクトされる。
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

    // 条件 8, 10: /token で PKCE S256 検証、RS256 署名のトークン発行。
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

    // 条件 11: Discovery / JWKS。
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
    // per-tenant issuer（ADR-0009 §6）: 過渡期は root テナントで `<基底>/<root_uuid>` を合成する。
    let tenant_issuer = format!("{issuer}/{root_tenant_id}");
    assert_eq!(discovery["issuer"], tenant_issuer.as_str());
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

    // 条件 10 検証: ID Token を JWKS の公開鍵で検証し、クレームを確認する。
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

    // Access Token は typ=at+jwt。
    let at_header = jsonwebtoken::decode_header(&access_token).expect("access token header");
    assert_eq!(at_header.typ.as_deref(), Some("at+jwt"));

    // 条件 9: authorization code は一度しか使えない（再利用は invalid_grant）。
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

    // 条件 12: /userinfo は scope（openid profile email）に応じたクレームを返す。
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
    assert_eq!(claims["email_verified"], false);
    assert_eq!(claims["preferred_username"], username.as_str());
    assert_eq!(claims["name"], "E2E Tester");

    // 不正なトークンは 401。
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

    // 条件 6: 2 回目の /authorize は SSO により再ログインなしで code が返る。
    let response = send(
        &app,
        Request::builder()
            .uri(authorize_uri(
                &root_tenant_id,
                &client_id,
                "state-2nd",
                "nonce-2nd",
            ))
            .header(COOKIE, format!("sso_session_id={sso_cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "SSO resume");
    let callback = location(&response);
    assert!(
        callback.starts_with(REDIRECT_URI),
        "expected direct redirect to client, got {callback}"
    );
    assert_eq!(
        query_param(&callback, "state").as_deref(),
        Some("state-2nd")
    );
    let second_code = query_param(&callback, "code").expect("code via SSO");

    // SSO 経由の code も /token で交換でき、auth_time は初回ログイン時刻を維持する。
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
    assert_eq!(
        second_claims.claims["auth_time"], id_claims.claims["auth_time"],
        "auth_time keeps the first login time on SSO resume"
    );

    // 条件 13: 監査ログ（login / code 発行・使用 / token 発行 / SSO）。
    assert!(audit_count(&pool, &client_id, "login.succeeded").await >= 1);
    assert!(audit_count(&pool, &client_id, "sso_session.created").await >= 1);
    assert!(audit_count(&pool, &client_id, "authorization_code.issued").await >= 2);
    assert!(audit_count(&pool, &client_id, "authorization_code.used").await >= 2);
    assert!(audit_count(&pool, &client_id, "authorization_code.reuse_detected").await >= 1);
    assert!(audit_count(&pool, &client_id, "token.issued").await >= 2);

    // correlation_id が付与されている。
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

    // 未登録 client はリダイレクトせず 400。
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

    // 未登録 redirect_uri もリダイレクトしない。
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

    // scope 超過は redirect_uri へ invalid_scope を返す（openid のみ登録の client を使用）。
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

    // 条件 13: confidential client の認証失敗（Basic の secret 不一致 → 401 + 監査ログ）。
    use base64::Engine as _;
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

    // 正しい secret なら client 認証は通る（code が偽物なので invalid_grant まで進む）。
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

    // AuthSession を作ってログイン画面へ。
    let response = send(
        &app,
        Request::builder()
            .uri(authorize_uri(&root_tenant_id, &client_id, "st", "no"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let auth_session = cookie_value(&response, "auth_session_id").expect("auth_session cookie");
    let csrf = login_csrf(&auth_session);

    // 9 回失敗 → invalid_credentials、10 回目でロック（locked）。
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

    // ロック中は正しいパスワードでも拒否される。
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

    // 監査ログ: login.failed が 10 件以上、login.locked が 2 件以上（ロック時 + ロック中の試行）。
    assert!(audit_count(&pool, &client_id, "login.failed").await >= 10);
    assert!(audit_count(&pool, &client_id, "login.locked").await >= 2);
}
