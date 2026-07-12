//! クライアント（RP）登録・管理 API の E2E 統合テスト（Progress A1、設計仕様 §9.3）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_clients
//!
//! 認可は `RequirePerms<IdpAdmin>`（`idp.tenant.admin`。`idp.system.admin` は代替として許可）。
//! 初期管理者（seed で root テナントへ `idp.system.admin` 付与済み）の SSO セッションを
//! 直接作成し、その Cookie で管理 API を叩く。権限の無い利用者は 403 になることも検証する。

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::json;
use support::{body_json, create_plain_user, create_sso_session, get, patch, post, send};

const REDIRECT_URI: &str = "https://app.example.com/callback";

#[tokio::test]
async fn admin_can_manage_clients_but_others_cannot() {
    let Some(env) = support::setup("admin clients").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);

    // 未認証（Cookie 無し）→ 401。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(&clients_uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(json!({}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // 権限の無い利用者 → 403。
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_cookie = create_sso_session(&env.pool, &plain_user_id).await;
    let res = send(
        &env.app,
        post(
            &plain_cookie,
            &clients_uri,
            json!({
                "app_name": "X",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // バリデーション: フラグメント付き redirect_uri → 400。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &clients_uri,
            json!({
                "app_name": "Bad",
                "client_type": "public",
                "redirect_uris": ["https://app.example.com/cb#frag"],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "fragment uri -> 400");

    // public クライアント登録 → 201・secret 無し。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &clients_uri,
            json!({
                "app_name": "Public App",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid", "profile"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "public create -> 201");
    let created = body_json(res).await;
    let public_client_id = created["client_id"].as_str().unwrap().to_string();
    assert!(
        created.get("client_secret").is_none(),
        "public has no secret"
    );
    assert_eq!(created["token_endpoint_auth_method"], "none");

    // public のシークレット再発行 → 400。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &format!("{clients_uri}/{public_client_id}/secret"),
            json!({}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "public secret -> 400");

    // confidential クライアント登録 → 201・secret 平文あり。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &clients_uri,
            json!({
                "app_name": "Confidential App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "confidential create -> 201"
    );
    let created = body_json(res).await;
    let conf_client_id = created["client_id"].as_str().unwrap().to_string();
    let first_secret = created["client_secret"]
        .as_str()
        .expect("confidential returns secret")
        .to_string();
    assert!(!first_secret.is_empty());
    assert_eq!(created["token_endpoint_auth_method"], "client_secret_basic");

    // 一覧に両クライアントが含まれる。
    let res = send(&env.app, get(&admin_cookie, &clients_uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let list = body_json(res).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["client_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&public_client_id.as_str()));
    assert!(ids.contains(&conf_client_id.as_str()));

    // 更新: status を DISABLED に。
    let res = send(
        &env.app,
        patch(
            &admin_cookie,
            &format!("{clients_uri}/{public_client_id}"),
            json!({ "client_status": "DISABLED" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["client_status"], "DISABLED");

    // confidential のシークレット再発行 → 200・新しい値（旧値と異なる）。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &format!("{clients_uri}/{conf_client_id}/secret"),
            json!({}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let rotated = body_json(res).await["client_secret"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!rotated.is_empty());
    assert_ne!(rotated, first_secret, "rotation changes the secret");

    // 不存在の取得 → 404。
    let res = send(
        &env.app,
        get(&admin_cookie, &format!("{clients_uri}/does-not-exist")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing client -> 404");
}
