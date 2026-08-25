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
use support::{body_json, create_plain_user, create_sso_session, delete, get, patch, post, send};

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
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "public secret -> 400"
    );

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
    // 一覧はページング付きのオブジェクト（`{clients, total, limit, offset}`）を返す（G7）。
    let list = body_json(res).await;
    let ids: Vec<&str> = list["clients"]
        .as_array()
        .expect("clients array")
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

/// クライアント認証方式（G3）。confidential は `client_secret_post` を選べ、あとから切り替えられる。
/// `none`（＝認証なし）と public への指定は拒否する。
#[tokio::test]
async fn confidential_clients_can_choose_the_client_authentication_method() {
    let Some(env) = support::setup("admin clients auth method").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);

    // 登録時に client_secret_post を選べる。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &clients_uri,
            json!({
                "app_name": "Post Auth App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "token_endpoint_auth_method": "client_secret_post",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    assert_eq!(created["token_endpoint_auth_method"], "client_secret_post");
    let client_id = created["client_id"].as_str().unwrap().to_string();

    // あとから client_secret_basic へ戻せる（secret はそのまま。提示場所だけが変わる）。
    let res = send(
        &env.app,
        patch(
            &admin_cookie,
            &format!("{clients_uri}/{client_id}"),
            json!({ "token_endpoint_auth_method": "client_secret_basic" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        body_json(res).await["token_endpoint_auth_method"],
        "client_secret_basic"
    );

    // `none` は confidential では選べない（secret を持ったまま認証が外れるため）。
    let res = send(
        &env.app,
        patch(
            &admin_cookie,
            &format!("{clients_uri}/{client_id}"),
            json!({ "token_endpoint_auth_method": "none" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 未知の値も拒否する。
    let res = send(
        &env.app,
        patch(
            &admin_cookie,
            &format!("{clients_uri}/{client_id}"),
            json!({ "token_endpoint_auth_method": "private_key_jwt" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // public クライアントには設定できない。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &clients_uri,
            json!({
                "app_name": "Public App",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let public_client_id = body_json(res).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let res = send(
        &env.app,
        patch(
            &admin_cookie,
            &format!("{clients_uri}/{public_client_id}"),
            json!({ "token_endpoint_auth_method": "client_secret_post" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// ADR-0032 より前に登録されたクライアントは `authorization_code` が無条件に付いたため、
/// `client_credentials` を許可したものは「両方」の姿で保存されている。
/// その姿を無条件に拒むと、漏洩したクライアントを DISABLED にすることすらできなくなる。
#[tokio::test]
async fn a_client_registered_before_the_usage_split_can_still_be_disabled() {
    let Some(env) = support::setup("admin clients legacy usage").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    // `authorization_code` + `client_credentials` + redirect_uri を持つ旧来の姿。
    let (client_id, _) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let client_uri = format!("/{}/admin/clients/{client_id}", env.root_tenant_id);

    let res = send(
        &env.app,
        patch(
            &admin_cookie,
            &client_uri,
            json!({ "client_status": "DISABLED" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "両用途を持つ既存クライアントを停止できること"
    );
    assert_eq!(body_json(res).await["client_status"], "DISABLED");

    // 一方、これから両立させる登録は拒む（ADR-0032 決定 3）。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": "Both Usages App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "allow_client_credentials": true,
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// ADR-0035: 削除は論理削除。実体は残るが、一覧から消え、管理操作も認可経路も通らなくなる。
#[tokio::test]
async fn a_deleted_client_disappears_from_the_console_but_stays_in_the_database() {
    let Some(env) = support::setup("admin clients delete").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let base = format!("/{}/admin/clients", env.root_tenant_id);

    let created = body_json(
        send(
            &env.app,
            post(
                &admin_cookie,
                &base,
                json!({
                    "app_name": "Doomed App",
                    "client_type": "confidential",
                    "redirect_uris": [REDIRECT_URI],
                    "scopes": ["openid"],
                }),
            ),
        )
        .await,
    )
    .await;
    let client_id = created["client_id"].as_str().expect("client_id");
    let client_uri = format!("{base}/{client_id}");

    // 削除は専用経路だけが行う。更新で状態を DELETED に倒せると、`client.deleted` の監査記録を
    // 残さないまま取り消せない削除ができてしまう（ADR-0035）。
    let res = send(
        &env.app,
        patch(
            &admin_cookie,
            &client_uri,
            json!({ "client_status": "DELETED" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "更新経路では削除できない"
    );

    let res = send(&env.app, delete(&admin_cookie, &client_uri)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "admin delete -> 204");

    // 一覧から消える。
    let listed = body_json(send(&env.app, get(&admin_cookie, &base)).await).await;
    let ids: Vec<&str> = listed["clients"]
        .as_array()
        .expect("clients")
        .iter()
        .filter_map(|c| c["client_id"].as_str())
        .collect();
    assert!(!ids.contains(&client_id), "削除済みは一覧に出ない: {ids:?}");

    // 取得・更新・再削除はいずれも 404（`load` が削除済みを「無い」ものとして扱う）。
    for res in [
        send(&env.app, get(&admin_cookie, &client_uri)).await,
        send(
            &env.app,
            patch(&admin_cookie, &client_uri, json!({ "app_name": "Revived" })),
        )
        .await,
        send(&env.app, delete(&admin_cookie, &client_uri)).await,
    ] {
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    // **実体は残っている**（監査で client_id を引いたときに追えるようにするため）。
    let status: String =
        sqlx::query_scalar("SELECT client_status FROM clients WHERE client_id = ?")
            .bind(client_id)
            .fetch_one(&env.pool)
            .await
            .expect("row still exists");
    assert_eq!(status, "DELETED");
}
