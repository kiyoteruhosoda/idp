//! リソース指標（RFC 8707）の統合テスト（ADR-0042）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test resource_indicators
//!
//! 検証の要:
//! - 登録され、かつ**そのクライアントへ貸してある**宛名だけが `aud` に載ること。
//! - 未登録・停止中・未許可を**応答で区別しない**こと（区別すると登録の有無を総当たりで探れる）。
//! - 宛名のトークンに `perms` が載らないこと。何をしてよいかはリソースサーバが決める（ADR-0033）。
//! - 管理 API 向けのトークン（ADR-0037）が従来どおりであること。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{json, Value};
use support::{admin_token, body_json, delete, post, send, unique};

/// `ACCESS_TOKEN_TTL_SECS` の既定。宛名のトークンは通常のアクセストークンと同じ寿命で出る。
const ACCESS_TOKEN_TTL_SECS: u64 = 900;
/// `MANAGEMENT_TOKEN_TTL_SECS` の既定（ADR-0037）。
const MANAGEMENT_TOKEN_TTL_SECS: u64 = 300;

fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

async fn request_token(
    app: &axum::Router,
    tenant_id: &str,
    client_id: &str,
    secret: &str,
    resource: Option<&str>,
) -> axum::response::Response {
    let mut body = "grant_type=client_credentials".to_string();
    if let Some(r) = resource {
        body.push_str(&format!(
            "&resource={}",
            percent_encoding::utf8_percent_encode(r, percent_encoding::NON_ALPHANUMERIC)
        ));
    }
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(client_id, secret))
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// アクセストークン（JWT）のクレームを読む。署名は他のテストが見ているので、ここでは載る値だけを見る。
fn claims(access_token: &str) -> Value {
    let payload = access_token.split('.').nth(1).expect("payload segment");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&decoded).expect("claims json")
}

#[tokio::test]
async fn only_a_registered_and_granted_audience_reaches_the_token() {
    let Some(env) = support::setup("resource indicators").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let audience = format!("api://wiki-{}", unique());
    let resources_uri = format!("/{}/admin/resources", env.root_tenant_id);
    let lending_uri = format!(
        "/{}/admin/clients/{client_id}/resources",
        env.root_tenant_id
    );

    // 登録前は断る。
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_target");

    // 宛名を登録する。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &resources_uri,
            json!({ "resource_uri": audience, "display_name": "wiki machine API" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register the audience");
    let resource_id = body_json(res).await["id"].as_str().unwrap().to_string();

    // 登録しただけでは出ない。**貸してあることまで**が条件である。
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "registered but not granted must not be issued"
    );
    assert_eq!(body_json(res).await["error"], "invalid_target");

    // このクライアントへ貸す。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &lending_uri,
            json!({ "resource_uri": audience }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "lend the audience");

    // 宛名が `aud` に載る。
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let issued = body_json(res).await;
    assert_eq!(issued["expires_in"].as_u64(), Some(ACCESS_TOKEN_TTL_SECS));
    let claims = claims(issued["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["aud"], json!(audience), "aud is the registered name");
    assert_eq!(claims["client_id"], json!(client_id));
    assert_eq!(claims["sub_type"], json!("client"));
    // 何をしてよいかは載らない（ADR-0033）。ここに権限が載り始めると、アプリの権限モデルを
    // 直すたびに idp を触ることになる。
    assert!(
        claims.get("perms").is_none_or(Value::is_null),
        "a resource token must not carry perms: {claims}"
    );

    // 取り消すと、次のトークンからは出なくなる（発行済みは TTL まで有効）。
    let res = send(
        &env.app,
        delete(&admin_tok, &format!("{lending_uri}/{resource_id}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke the lending");
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_target");
}

#[tokio::test]
async fn a_disabled_audience_stops_new_tokens_without_losing_the_lending() {
    let Some(env) = support::setup("resource indicators disabled").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let audience = format!("api://blob-{}", unique());

    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/resources", env.root_tenant_id),
            json!({ "resource_uri": audience, "display_name": "blob machine API" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let resource_id = body_json(res).await["id"].as_str().unwrap().to_string();
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/clients/{client_id}/resources",
                env.root_tenant_id
            ),
            json!({ "resource_uri": audience }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    // 停止する。
    let res = send(
        &env.app,
        support::patch(
            &admin_tok,
            &format!("/{}/admin/resources/{resource_id}", env.root_tenant_id),
            json!({ "status": "DISABLED" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "DISABLED");

    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a disabled audience must not be issued"
    );

    // 貸し出しは消えていない——再開すればそのまま出る（停止は削除の代わりに使える）。
    let res = send(
        &env.app,
        support::patch(
            &admin_tok,
            &format!("/{}/admin/resources/{resource_id}", env.root_tenant_id),
            json!({ "status": "ACTIVE" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "re-enabling restores issuing");
}

#[tokio::test]
async fn the_management_audience_stays_separate_from_registered_ones() {
    let Some(env) = support::setup("resource indicators management").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let management_aud = format!("{}/{}/admin", env.issuer, env.root_tenant_id);

    // 管理 API の `aud` は登録できない。登録できると、`perms` の付かない管理宛のトークンを
    // 誰にでも出せてしまう（`aud` だけを見る相手はそれを通す）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/resources", env.root_tenant_id),
            json!({ "resource_uri": management_aud, "display_name": "management" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "the management audience must be reserved"
    );

    // 完全一致だけを拒むと `…/admin/` のような紛らわしい名前が登録できてしまう。issuer 配下は
    // 丸ごと予約する（いま実害があるからではなく、貸してよい理由が無いため）。
    for near_miss in [
        format!("{management_aud}/"),
        format!("{}/{}/userinfo", env.issuer, env.root_tenant_id),
        format!("{}/anything", env.issuer),
    ] {
        let res = send(
            &env.app,
            post(
                &admin_tok,
                &format!("/{}/admin/resources", env.root_tenant_id),
                json!({ "resource_uri": near_miss, "display_name": "near miss" }),
            ),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "names inside our own issuer must be reserved: {near_miss}"
        );
    }

    // 従来どおり、権限を付けたクライアントには短命の管理トークンが出る。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/clients/{client_id}/permissions",
                env.root_tenant_id
            ),
            json!({ "permission_code": "idp.users:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&management_aud),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let issued = body_json(res).await;
    assert_eq!(
        issued["expires_in"].as_u64(),
        Some(MANAGEMENT_TOKEN_TTL_SECS)
    );
    let claims = claims(issued["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["aud"], json!(management_aud));
    assert_eq!(claims["perms"], json!("idp.users:read"));
}
