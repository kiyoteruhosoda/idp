//! IdP 自身を機械から操作する管理 API の統合テスト（ADR-0037）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test management_api
//!
//! 検証の要:
//! - システム用クライアントが `client_credentials` + `resource` で**管理トークン**を得て、
//!   付与された細粒度権限の範囲だけを操作できること。
//! - `resource` を付けずに得たトークン（`aud` が `/userinfo`）で管理 API を叩けないこと。
//!   ここが通ると、利用者ログイン用のトークンが管理面へ持ち込めることになる。
//! - 包括的な管理権限（`idp.tenant.admin` / `idp.system.admin`）をクライアントへ付与できないこと。
//! - 管理トークンがテナントを跨がないこと。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::json;
use support::{admin_token, body_json, delete, get, post, send, unique};

/// `MANAGEMENT_TOKEN_TTL_SECS` の既定（`domain::system_setting` の定義と対）。
const MANAGEMENT_TOKEN_TTL_SECS: u64 = 300;
/// `ACCESS_TOKEN_TTL_SECS` の既定。
const ACCESS_TOKEN_TTL_SECS: u64 = 900;

fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// `client_credentials` で `/token` を叩く（`resource` は任意）。
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

/// この IdP の管理 API を指すリソース指標（`{issuer}/{tenant_id}/admin`）。
fn management_resource(env: &support::TestEnv, tenant_id: &str) -> String {
    format!("{}/{}/admin", env.issuer, tenant_id)
}

#[tokio::test]
async fn a_system_client_operates_the_idp_within_the_permissions_it_was_granted() {
    let Some(env) = support::setup("management api").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let perms_uri = format!(
        "/{}/admin/clients/{client_id}/permissions",
        env.root_tenant_id
    );

    // 権限が 1 つも無いうちは、管理 API を要求しても管理トークンは出ない（取れたのに何も
    // 通らないトークンを作らない）。
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&management_resource(&env, &env.root_tenant_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["error"],
        "invalid_target",
        "no permissions -> invalid_target"
    );

    // 読み取りだけを付与する。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &perms_uri,
            json!({ "permission_code": "idp.users:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.users:read");
    assert_eq!(
        body_json(res).await["permission_codes"],
        json!(["idp.users:read"])
    );

    // 管理トークンを取得する。
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&management_resource(&env, &env.root_tenant_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let issued = body_json(res).await;
    // 管理トークンは通常のアクセストークンより短命（ADR-0037 決定 2）。`perms` はトークンから
    // 読むので、この寿命がそのまま「権限を剥奪してから実際に効くまで」の上限になる。既定の
    // ACCESS_TOKEN_TTL_SECS（900）が使われていると、剥奪が 3 倍長く効かないまま残る。
    assert_eq!(
        issued["expires_in"].as_u64(),
        Some(MANAGEMENT_TOKEN_TTL_SECS),
        "a management token must use MANAGEMENT_TOKEN_TTL_SECS, not ACCESS_TOKEN_TTL_SECS"
    );
    let machine_tok = issued["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // 読み取りは通る。
    let user_uri = format!("/{}/admin/users/{}", env.root_tenant_id, env.root_admin_id);
    let res = send(&env.app, get(&machine_tok, &user_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "idp.users:read allows reading"
    );

    // 書き込みは通らない（`:read` は `:write` を含意しない）。
    let res = send(
        &env.app,
        post(
            &machine_tok,
            &format!("/{}/admin/users", env.root_tenant_id),
            json!({ "email": format!("machine-{}@example.com", support::unique()) }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.users:read must not allow writing"
    );

    // 別リソースにも及ばない。
    let res = send(
        &env.app,
        get(
            &machine_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.users:read must not reach clients"
    );

    // 剥奪すると、次に取るトークンには載らない（発行済みトークンは TTL まで有効）。
    let res = send(
        &env.app,
        delete(&admin_tok, &format!("{perms_uri}/idp.users:read")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["permission_codes"], json!([]));
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&management_resource(&env, &env.root_tenant_id)),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a revoked client can no longer get a management token"
    );
}

/// `resource` を付けずに得たトークンは `/userinfo` 向けであり、管理 API では 401。
///
/// これが通ると、RP が利用者ログインで受け取ったトークンも同じ `aud` で管理面へ届くことになる。
#[tokio::test]
async fn a_token_minted_for_userinfo_cannot_reach_the_management_api() {
    let Some(env) = support::setup("management api audience").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
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

    // `resource` 無し → `aud` は `/userinfo`。寿命も通常のアクセストークンのまま
    // （管理トークンの短い寿命を、関係の無いトークンにまで広げない）。
    let res = request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await;
    assert_eq!(res.status(), StatusCode::OK);
    let issued = body_json(res).await;
    assert_eq!(
        issued["expires_in"].as_u64(),
        Some(ACCESS_TOKEN_TTL_SECS),
        "a userinfo-audience token keeps the ordinary access token lifetime"
    );
    let userinfo_tok = issued["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let res = send(
        &env.app,
        get(
            &userinfo_tok,
            &format!("/{}/admin/users/{}", env.root_tenant_id, env.root_admin_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "audience mismatch -> 401"
    );

    // 利用者を認証した grant では `resource` を受け付けない（黙って無視すると、管理トークンを
    // 頼んだつもりの呼び出し元が管理 API で 401 になる理由に辿り着けない）。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(&client_id, &secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token=whatever&resource={}",
                percent_encoding::utf8_percent_encode(
                    &management_resource(&env, &env.root_tenant_id),
                    percent_encoding::NON_ALPHANUMERIC
                )
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["error"],
        "invalid_target",
        "resource is only meaningful for client_credentials"
    );

    // 知らないリソースの要求は `invalid_target`（RFC 8707 §2）。
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some("https://someone-elses.example.com/api"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_target");
}

/// 包括的な管理権限はクライアントへ付与できない（アプリ層と DB の CHECK の二重防御）。
#[tokio::test]
async fn blanket_admin_permissions_cannot_be_granted_to_a_client() {
    let Some(env) = support::setup("management api blanket").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, _secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let perms_uri = format!(
        "/{}/admin/clients/{client_id}/permissions",
        env.root_tenant_id
    );

    for code in ["idp.tenant.admin", "idp.system.admin"] {
        let res = send(
            &env.app,
            post(&admin_tok, &perms_uri, json!({ "permission_code": code })),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "{code} must not be grantable to a client"
        );
    }

    // 未知のコードも拒む（マスタに無い＝FK 違反）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &perms_uri,
            json!({ "permission_code": "idp.made-up:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// 細粒度コードだけを持つ**利用者**も、管理コンソール経由（管理トークン）で同じ境界に従う。
/// 既存の `idp.tenant.admin` 保有者が今までどおり全部通ることも併せて確かめる。
#[tokio::test]
async fn fine_grained_codes_bound_a_user_while_tenant_admin_still_implies_everything() {
    let Some(env) = support::setup("management api user scope").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // 既存の包括コード保有者（seed の root 管理者は idp.system.admin）は全部通る。
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    // `idp.audit:read` だけを持つ利用者を作る。
    let target = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/users/{target}/permissions", env.root_tenant_id),
            json!({ "permission_code": "idp.audit:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let scoped_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &target).await;
    let res = send(
        &env.app,
        get(
            &scoped_tok,
            &format!("/{}/admin/audit-logs", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "idp.audit:read allows reading audit logs"
    );

    let res = send(
        &env.app,
        get(
            &scoped_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.audit:read must not reach clients"
    );

    // コンソールの入口（whoami）は包括コードを要求したままなので通らない（ADR-0037 積み残し）。
    let res = send(
        &env.app,
        get(
            &scoped_tok,
            &format!("/{}/admin/whoami", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// 付与候補の絞り込みは api が行う（`?grantable_to=client`。ADR-0037）。
///
/// web は core に依存しないので、この判定を web 側にも書くと**マスタが増えたときに片方だけ
/// 古くなる**。管理コンソールの選択肢がこの応答そのものなので、包括コードが混ざれば画面から
/// 「付けられない権限」を選べてしまう。
#[tokio::test]
async fn the_grantable_to_client_filter_removes_the_blanket_admin_codes() {
    let Some(env) = support::setup("management api grantable filter").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/permissions", env.root_tenant_id);

    // 絞り込み無しはマスタ全件（包括コードを含む）。
    let res = send(&env.app, get(&admin_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let all = body_json(res).await;
    let all: Vec<String> = serde_json::from_value(all["codes"].clone()).expect("codes");
    assert!(all.iter().any(|c| c == "idp.tenant.admin"));
    assert!(all.iter().any(|c| c == "idp.system.admin"));
    assert!(all.iter().any(|c| c == "idp.users:read"));

    // `grantable_to=client` は包括コードだけを落とし、細粒度コードは残す。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{uri}?grantable_to=client")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let filtered = body_json(res).await;
    let filtered: Vec<String> = serde_json::from_value(filtered["codes"].clone()).expect("codes");
    assert!(
        !filtered.iter().any(|c| c == "idp.tenant.admin"),
        "blanket tenant admin must not be offered as a client grant"
    );
    assert!(
        !filtered.iter().any(|c| c == "idp.system.admin"),
        "blanket system admin must not be offered as a client grant"
    );
    assert!(filtered.iter().any(|c| c == "idp.users:read"));
    assert_eq!(filtered.len(), all.len() - 2);

    // 未知の値は絞り込まない（支援 API なので綴り違いを 400 にはしない）。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{uri}?grantable_to=nonsense")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let unfiltered = body_json(res).await;
    let unfiltered: Vec<String> =
        serde_json::from_value(unfiltered["codes"].clone()).expect("codes");
    assert_eq!(unfiltered.len(), all.len());
}


/// 非 root テナントでは `idp.system.admin` を**付与できない**ので、付与候補にも出さない。
///
/// この権限は root scope でしか存在できず（`user_permissions_system_admin_scope_chk`。ADR-0009 §4）、
/// 実行者が誰であっても非 root では付与が通らない。候補に残すと、管理コンソールの付与フォームに
/// **選べるのに必ず 403 になる選択肢**が並ぶ（ADR-0032「選べないものを見せない」）。
///
/// 検証は 2 段で、候補から消えていることと、**api を直接叩けば依然 403 であること**の両方を見る。
/// 前者だけだと、画面から消しただけで api を緩めた変更を通してしまう。
#[tokio::test]
async fn system_admin_is_neither_offered_nor_grantable_outside_the_root_tenant() {
    let Some(env) = support::setup("management api system admin scope").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // root が子テナントを作る。作成者 root はその子テナントの ACTIVE GUEST 管理者として残る
    // （ADR-0009 §4 のブートストラップ）ので、以降は「ゲスト管理者」としての操作になる。
    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("SystemAdminScope{}", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create child tenant");
    let child = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();
    let guest_tok = admin_token(&env.app, &env.pool, &child, &env.root_admin_id).await;

    // 1. 付与候補に idp.system.admin が出ない（root テナントでは出る。上のテストが押さえている）。
    let res = send(
        &env.app,
        get(&guest_tok, &format!("/{child}/admin/permissions")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let codes = body_json(res).await;
    let codes: Vec<String> = serde_json::from_value(codes["codes"].clone()).expect("codes");
    assert!(
        !codes.iter().any(|c| c == "idp.system.admin"),
        "system admin must not be offered outside the root tenant"
    );
    assert!(
        codes.iter().any(|c| c == "idp.tenant.admin"),
        "tenant admin remains grantable in a child tenant"
    );

    // 2. 候補から消しただけで api を緩めていないこと。
    let res = send(
        &env.app,
        post(
            &guest_tok,
            &format!("/{child}/admin/users"),
            json!({ "email": format!("scope-{}@example.com", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create target user");
    let target = body_json(res).await["user_id"]
        .as_str()
        .expect("user id")
        .to_string();

    let res = send(
        &env.app,
        post(
            &guest_tok,
            &format!("/{child}/admin/users/{target}/permissions"),
            json!({ "permission_code": "idp.system.admin" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "granting system admin outside root must stay refused"
    );
}
