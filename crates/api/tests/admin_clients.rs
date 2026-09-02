//! クライアント（RP）登録・管理 API の E2E 統合テスト（Progress A1、設計仕様 §9.3）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_clients
//!
//! 認可は権限コード（`idp.clients:read` / `:write`。`idp.tenant.admin`・`idp.system.admin` は
//! 含意により許可。ADR-0037）。
//! 初期管理者（seed で root テナントへ `idp.system.admin` 付与済み）の SSO セッションを
//! 直接作成し、管理トークンへ交換して管理 API を叩く。権限の無い利用者は 403 になることも検証する。

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::json;
use support::{admin_token, body_json, create_plain_user, delete, get, patch, post, send};

const REDIRECT_URI: &str = "https://app.example.com/callback";

#[tokio::test]
async fn admin_can_manage_clients_but_others_cannot() {
    let Some(env) = support::setup("admin clients").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);

    // 未認証（トークン無し）→ 401。
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
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(
        &env.app,
        post(
            &plain_token,
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
            &admin_tok,
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
            &admin_tok,
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
            &admin_tok,
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
    // 既定は `private_key_jwt`（ADR-0036）なので、secret を受け取るには方式を明示する。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "Confidential App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "token_endpoint_auth_method": "client_secret_basic",
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
    let res = send(&env.app, get(&admin_tok, &clients_uri)).await;
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
            &admin_tok,
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
            &admin_tok,
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
        get(&admin_tok, &format!("{clients_uri}/does-not-exist")),
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
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);

    // 登録時に client_secret_post を選べる。
    let res = send(
        &env.app,
        post(
            &admin_tok,
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
            &admin_tok,
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
            &admin_tok,
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
            &admin_tok,
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
            &admin_tok,
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
            &admin_tok,
            &format!("{clients_uri}/{public_client_id}"),
            json!({ "token_endpoint_auth_method": "client_secret_post" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// `?grant_type=` で一覧を系統ごとに分ける（ADR-0038）。
///
/// **絞り込みはページングと同じ層で行う必要がある。** web が 1 ページ受け取ってから間引くと、
/// `total` もページャも実際の件数と合わなくなる。ここでは、返る中身と `total` の両方が
/// 絞り込み後の値になっていることを見る。
///
/// ⚠ **専用のテナントを作ってその中で数える。** root テナントで数えると、同じ DB で他のテストが
/// 作ったクライアントが積み上がり、1 ページ（50 件）に収まらなくなった時点で `total` と返却件数が
/// 食い違って落ちる（実際に踏んだ。DB を作り直すまで再現し続ける）。テナントを分ければ件数は
/// このテストが作った 2 件だけになり、`total` を**実数と突き合わせて**検証できる。
#[tokio::test]
async fn the_client_list_can_be_split_by_grant_type() {
    let Some(env) = support::setup("admin clients grant filter").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("grant-filter-{}", support::unique()) }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "create an isolated tenant"
    );
    let tenant_id = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();
    // 作成者（root）は新テナントの ACTIVE GUEST 管理者になる（ADR-0009 §4）。管理トークンは
    // テナント毎なので取り直す。
    let admin_tok = admin_token(&env.app, &env.pool, &tenant_id, &env.root_admin_id).await;
    let clients_uri = format!("/{tenant_id}/admin/clients");

    // 連携先（redirect_uri を持つ）とサービスアカウント（持たない）を 1 つずつ。
    for body in [
        json!({
            "app_name": "Relying Party App",
            "client_type": "confidential",
            "redirect_uris": [REDIRECT_URI],
            "scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic",
        }),
        json!({
            "app_name": "Service Account App",
            "client_type": "confidential",
            "redirect_uris": [],
            "scopes": ["openid"],
            "allow_client_credentials": true,
            "token_endpoint_auth_method": "client_secret_basic",
        }),
    ] {
        let res = send(&env.app, post(&admin_tok, &clients_uri, body)).await;
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    let names_for = |uri: String| {
        let app = env.app.clone();
        let tok = admin_tok.clone();
        async move {
            let res = send(&app, get(&tok, &uri)).await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = body_json(res).await;
            let names: Vec<String> = body["clients"]
                .as_array()
                .expect("clients")
                .iter()
                .map(|c| c["app_name"].as_str().unwrap_or_default().to_string())
                .collect();
            (names, body["total"].as_i64().expect("total"))
        }
    };

    let (all, all_total) = names_for(clients_uri.clone()).await;
    assert!(all.iter().any(|n| n == "Relying Party App"));
    assert!(all.iter().any(|n| n == "Service Account App"));

    let (rps, rp_total) = names_for(format!("{clients_uri}?grant_type=authorization_code")).await;
    assert!(rps.iter().any(|n| n == "Relying Party App"));
    assert!(
        !rps.iter().any(|n| n == "Service Account App"),
        "連携先の一覧にサービスアカウントが混ざってはならない"
    );

    let (sas, sa_total) = names_for(format!("{clients_uri}?grant_type=client_credentials")).await;
    assert!(sas.iter().any(|n| n == "Service Account App"));
    assert!(!sas.iter().any(|n| n == "Relying Party App"));

    // total も絞り込み後の値であること（ページャがこの値で「次へ」を出す）。テナントを分けて
    // あるので、期待値は「このテストが作った 2 件」で確定する。
    assert_eq!((all.len(), all_total), (2, 2), "作った 2 件だけが見える");
    assert_eq!((rps.len(), rp_total), (1, 1));
    assert_eq!((sas.len(), sa_total), (1, 1));
    assert_eq!(
        rp_total + sa_total,
        all_total,
        "両立は作れないので排他に分かれる"
    );

    // 未知の値は黙って無視せず 400。無視すると、絞り込みの失敗が画面上は成功に見える。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{clients_uri}?grant_type=nonsense")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// 「両方」の姿（`authorization_code` + `client_credentials` + redirect_uri）は、登録でも更新でも拒む
/// （ADR-0032 決定 3・Revised）。
///
/// ADR-0032 は当初 `update` に猶予を置いていた——その姿で保存された既存行を無条件に拒むと、
/// 漏洩したクライアントを DISABLED にすることすらできなくなるため。2026-08-27 に猶予を外したのは、
/// **`delete` がこの検証を通らない**からである。DB を直接触るなどしてその姿の行が生まれても、
/// 論理削除で必ず止められる（ADR-0035。DELETED は `is_active()` が false なので認可・トークン経路も
/// 通らない）。止める手段が残っていることが猶予を外す条件なので、ここで一緒に検証する。
#[tokio::test]
async fn a_dual_usage_client_is_refused_on_update_but_can_still_be_stopped() {
    let Some(env) = support::setup("admin clients dual usage").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    // api では作れない姿なので、DB へ直接入れる。
    let (client_id, _) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let client_uri = format!("/{}/admin/clients/{client_id}", env.root_tenant_id);

    // 更新は拒む（猶予を外した本体）。
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &client_uri,
            json!({ "client_status": "DISABLED" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "両用途の姿を温存する更新は通さない"
    );

    // それでも止められること。ここが通らなくなったら猶予を戻す必要がある。
    let res = send(&env.app, delete(&admin_tok, &client_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "論理削除は用途の検証を通らないので、必ず止められる"
    );

    // これから両立させる登録も拒む。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": "Both Usages App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "allow_client_credentials": true,
                "token_endpoint_auth_method": "client_secret_basic",
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
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let base = format!("/{}/admin/clients", env.root_tenant_id);

    let created = body_json(
        send(
            &env.app,
            post(
                &admin_tok,
                &base,
                json!({
                    "app_name": "Doomed App",
                    "client_type": "confidential",
                    "redirect_uris": [REDIRECT_URI],
                    "scopes": ["openid"],
                    "token_endpoint_auth_method": "client_secret_basic",
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
            &admin_tok,
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

    let res = send(&env.app, delete(&admin_tok, &client_uri)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "admin delete -> 204");

    // 一覧から消える。
    let listed = body_json(send(&env.app, get(&admin_tok, &base)).await).await;
    let ids: Vec<&str> = listed["clients"]
        .as_array()
        .expect("clients")
        .iter()
        .filter_map(|c| c["client_id"].as_str())
        .collect();
    assert!(!ids.contains(&client_id), "削除済みは一覧に出ない: {ids:?}");

    // 取得・更新・再削除はいずれも 404（`load` が削除済みを「無い」ものとして扱う）。
    for res in [
        send(&env.app, get(&admin_tok, &client_uri)).await,
        send(
            &env.app,
            patch(&admin_tok, &client_uri, json!({ "app_name": "Revived" })),
        )
        .await,
        send(&env.app, delete(&admin_tok, &client_uri)).await,
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

/// ADR-0036: 認証方式を省略した登録は `private_key_jwt` になる。
///
/// OIDC Registration 1.0 の既定（`client_secret_basic`）から意図的に外している。既定は「選ぶ人が
/// 何も書かなかったとき」に置かれる値なので、共有秘密ではなく公開鍵のほうへ倒す。弱いほうを
/// 選ぶときだけ明示させる。
#[tokio::test]
async fn omitting_the_authentication_method_registers_a_private_key_jwt_client() {
    let Some(env) = support::setup("admin clients default auth method").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);

    // 方式も検証鍵も無い登録は拒む。既定が `private_key_jwt` である以上、通せば「どの資格情報でも
    // 認証できないクライアント」ができてしまう。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "No Method App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // 本文は既定が何かまで伝える。「検証鍵が必要」だけでは、`private_key_jwt` と書いた覚えの
    // 無い呼び出し元に理由が伝わらない。
    let message = body_json(res).await["message"]
        .as_str()
        .expect("message")
        .to_string();
    assert!(
        message.contains("token_endpoint_auth_method") && message.contains("private_key_jwt"),
        "既定と省略された項目名が本文に出ていない: {message}"
    );

    // 検証鍵だけを送れば、方式を書かなくても `private_key_jwt` として登録できる。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "Default Method App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "jwks": support::sample_client_jwks(),
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    assert_eq!(created["token_endpoint_auth_method"], "private_key_jwt");
    // この方式のクライアントは共有秘密を持たない（ADR-0030）。
    assert!(
        created["client_secret"].is_null(),
        "private_key_jwt で secret が発行されている: {created}"
    );
}
