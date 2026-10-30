//! 細粒度コードから管理者へ昇格できないことの統合テスト（task #579。脆弱性確認 2026-10-20 の高-1）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_escalation
//!
//! 細粒度コードは「テナントの中の分担」のためのもので、集めても `idp.tenant.admin` /
//! `idp.system.admin` には届かない（ADR-0037）。以前は次の 3 つで届いてしまっていた。
//!
//! - (a) `idp.users:write` だけで、管理者のパスワード再発行・MFA 解除・プロフィール変更ができた
//! - (b) `idp.permissions:write` だけで、自分の持たないコード（`idp.tenant.admin` など）を付けられた
//! - (c) `idp.clients:write` だけで、クライアントへ自分の持たないコードを付けられた
//!
//! 加えて、管理者の口座を扱うこと自体を仕事にする機械（break-glass）は `idp.admins:write` で
//! 今までどおり続けられることを確かめる。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::json;
use support::{admin_token, body_json, delete, get, patch, post, post_empty, send, TestEnv};

/// root の管理者（`idp.system.admin`）として、利用者へ権限を付ける。
async fn grant_user(env: &TestEnv, root_tok: &str, user_id: &str, code: &str) {
    let res = send(
        &env.app,
        post(
            root_tok,
            &format!("/{}/admin/users/{user_id}/permissions", env.root_tenant_id),
            json!({ "permission_code": code }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant {code} to {user_id}");
}

/// 指定の権限だけを持つ利用者を作り、その管理トークンを返す。
async fn delegate(env: &TestEnv, root_tok: &str, codes: &[&str]) -> (String, String) {
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    for code in codes {
        grant_user(env, root_tok, &user_id, code).await;
    }
    let tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &user_id).await;
    (user_id, tok)
}

/// 指定の権限だけを持つシステム用クライアントを作り、その管理トークンを返す。
async fn machine(env: &TestEnv, root_tok: &str, codes: &[&str]) -> (String, String) {
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    for code in codes {
        let res = send(
            &env.app,
            post(
                root_tok,
                &format!(
                    "/{}/admin/clients/{client_id}/permissions",
                    env.root_tenant_id
                ),
                json!({ "permission_code": code }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "grant {code} to the machine");
    }
    let resource = format!("{}/{}/admin", env.issuer, env.root_tenant_id);
    let body = format!(
        "grant_type=client_credentials&resource={}",
        percent_encoding::utf8_percent_encode(&resource, percent_encoding::NON_ALPHANUMERIC)
    );
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic}"))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "machine management token");
    let tok = body_json(res).await["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    (client_id, tok)
}

fn users_uri(env: &TestEnv, user_id: &str, rest: &str) -> String {
    format!("/{}/admin/users/{user_id}{rest}", env.root_tenant_id)
}

/// (a) `idp.users:write` だけでは、管理者の口座を扱えない。普通の利用者は今までどおり扱える。
#[tokio::test]
async fn users_writer_cannot_take_over_an_administrator() {
    let Some(env) = support::setup("admin escalation users").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_, writer) = delegate(&env, &root_tok, &["idp.users:write"]).await;
    let (admin_id, _) = delegate(&env, &root_tok, &["idp.tenant.admin"]).await;
    let plain = support::create_plain_user(&env.pool, &env.root_tenant_id).await;

    for target in [admin_id.as_str(), env.root_admin_id.as_str()] {
        for request in [
            post_empty(&writer, &users_uri(&env, target, "/password-reset")),
            post_empty(&writer, &users_uri(&env, target, "/mfa-reset")),
            patch(
                &writer,
                &users_uri(&env, target, "/profile"),
                json!({ "email": format!("taken-{}@example.com", support::unique()) }),
            ),
            patch(
                &writer,
                &users_uri(&env, target, ""),
                json!({ "status": "DISABLED" }),
            ),
            post(
                &writer,
                &users_uri(&env, target, "/login-identifiers"),
                json!({ "identifier_type": "username", "value": format!("x{}", support::unique()) }),
            ),
            delete(&writer, &users_uri(&env, target, "")),
        ] {
            let uri = request.uri().to_string();
            let res = send(&env.app, request).await;
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "{uri}");
        }
    }

    // 普通の利用者は今までどおり扱える（設定リンクが返る）。
    let res = send(
        &env.app,
        post_empty(&writer, &users_uri(&env, &plain, "/password-reset")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "reset a plain user");
    assert!(body_json(res).await["setup_url"].is_string());

    // 管理者自身（idp.tenant.admin）は、今までどおり他の管理者の口座を扱える。
    let (_, tenant_admin) = delegate(&env, &root_tok, &["idp.tenant.admin"]).await;
    let res = send(
        &env.app,
        post_empty(&tenant_admin, &users_uri(&env, &admin_id, "/mfa-reset")),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "tenant admin resets an admin's MFA"
    );
    // ⚠ ただし idp.system.admin の持ち主には届かない。
    let res = send(
        &env.app,
        post_empty(
            &tenant_admin,
            &users_uri(&env, &env.root_admin_id, "/password-reset"),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "system admin is out of reach"
    );
}

/// (b) `idp.permissions:write` だけでは、自分の持たないコードを付けも外しもできない。
#[tokio::test]
async fn permissions_writer_cannot_grant_what_it_does_not_hold() {
    let Some(env) = support::setup("admin escalation permissions").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (writer_id, writer) = delegate(&env, &root_tok, &["idp.permissions:write"]).await;
    let (admin_id, _) = delegate(&env, &root_tok, &["idp.tenant.admin"]).await;

    for (target, code) in [
        (writer_id.as_str(), "idp.tenant.admin"),
        (writer_id.as_str(), "idp.smtp:write"),
        (writer_id.as_str(), "idp.users:write"),
        (writer_id.as_str(), "idp.admins:write"),
    ] {
        let res = send(
            &env.app,
            post(
                &writer,
                &users_uri(&env, target, "/permissions"),
                json!({ "permission_code": code }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "grant {code}");
    }
    let res = send(
        &env.app,
        delete(
            &writer,
            &users_uri(&env, &admin_id, "/permissions/idp.tenant.admin"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "revoke tenant admin");

    // 自分が持つ範囲（:write は :read を含む）は今までどおり配れる。
    let res = send(
        &env.app,
        post(
            &writer,
            &users_uri(&env, &admin_id, "/permissions"),
            json!({ "permission_code": "idp.permissions:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant a code it implies");

    // 付与フォームの候補にも、配れないコードは出ない。
    let res = send(
        &env.app,
        get(
            &writer,
            &format!("/{}/admin/permissions", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let codes: Vec<String> =
        serde_json::from_value(body_json(res).await["codes"].clone()).expect("codes");
    assert!(
        codes.iter().any(|c| c == "idp.permissions:read"),
        "{codes:?}"
    );
    assert!(!codes.iter().any(|c| c == "idp.tenant.admin"), "{codes:?}");
    assert!(!codes.iter().any(|c| c == "idp.users:write"), "{codes:?}");
}

/// (c) `idp.clients:write` だけでは、クライアントへ自分の持たないコードを付けられない。
#[tokio::test]
async fn clients_writer_cannot_grant_a_client_what_it_does_not_hold() {
    let Some(env) = support::setup("admin escalation clients").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_, writer) = delegate(&env, &root_tok, &["idp.clients:write"]).await;
    let (client_id, _) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let uri = format!(
        "/{}/admin/clients/{client_id}/permissions",
        env.root_tenant_id
    );

    for code in [
        "idp.users:write",
        "idp.permissions:write",
        "idp.admins:write",
    ] {
        let res = send(
            &env.app,
            post(&writer, &uri, json!({ "permission_code": code })),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "grant {code} to a client"
        );
    }
    let res = send(
        &env.app,
        post(
            &writer,
            &uri,
            json!({ "permission_code": "idp.clients:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant a code it implies");
}

/// `idp.clients:write` だけでは、自分の持たない権限を持つクライアントを乗っ取れない（task #756）。
///
/// 秘密を作り直す・公開鍵を差し替える・認証方式を変えれば、そのクライアントの権限を行使できる。
/// 消すのも同じ判定（口座の削除と揃える）。⚠ 権限の無いクライアントは今までどおり扱える。
#[tokio::test]
async fn clients_writer_cannot_take_over_a_stronger_client() {
    let Some(env) = support::setup("admin escalation client takeover").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_, writer) = machine(&env, &root_tok, &["idp.clients:write"]).await;

    // 自分の持たない権限を持つクライアント
    let (strong, _) = support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let granted = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/clients/{strong}/permissions", env.root_tenant_id),
            json!({ "permission_code": "idp.users:write" }),
        ),
    )
    .await;
    assert_eq!(granted.status(), StatusCode::OK);
    let strong_uri = format!("/{}/admin/clients/{strong}", env.root_tenant_id);

    let rotate = send(
        &env.app,
        post_empty(&writer, &format!("{strong_uri}/secret")),
    )
    .await;
    assert_eq!(rotate.status(), StatusCode::FORBIDDEN, "rotate the secret");
    let swap_key = send(
        &env.app,
        patch(
            &writer,
            &strong_uri,
            json!({
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": "{\"keys\":[]}",
            }),
        ),
    )
    .await;
    assert_eq!(swap_key.status(), StatusCode::FORBIDDEN, "swap the key");
    let removed = send(&env.app, delete(&writer, &strong_uri)).await;
    assert_eq!(removed.status(), StatusCode::FORBIDDEN, "delete");

    // 権限の無いクライアントは今までどおり
    let (plain, _) = support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let plain_uri = format!("/{}/admin/clients/{plain}", env.root_tenant_id);
    let rotate = send(
        &env.app,
        post_empty(&writer, &format!("{plain_uri}/secret")),
    )
    .await;
    assert_eq!(rotate.status(), StatusCode::OK, "rotate a plain client");

    // 同じ権限を持つ者（ここでは管理者）は扱える
    let rotate = send(
        &env.app,
        post_empty(&root_tok, &format!("{strong_uri}/secret")),
    )
    .await;
    assert_eq!(
        rotate.status(),
        StatusCode::OK,
        "the administrator can still rotate"
    );

    // 他のテナントや無いクライアントは 404 のまま（居るかどうかを 403 で教えない）
    let missing = send(
        &env.app,
        post_empty(
            &writer,
            &format!(
                "/{}/admin/clients/no-such-client/secret",
                env.root_tenant_id
            ),
        ),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND, "missing client");
}

/// break-glass の機械（`idp.users:write` ＋ `idp.permissions:write` ＋ `idp.admins:write`）は、
/// 非常用口座へ `idp.tenant.admin` を付け、そのパスワードを作り直せる。⚠ system 管理者には届かない。
#[tokio::test]
async fn admins_write_lets_the_break_glass_machine_keep_working() {
    let Some(env) = support::setup("admin escalation break-glass").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_, breakglass) = machine(
        &env,
        &root_tok,
        &[
            "idp.users:write",
            "idp.permissions:write",
            "idp.admins:write",
        ],
    )
    .await;
    let account = support::create_plain_user(&env.pool, &env.root_tenant_id).await;

    // create: 非常用口座へ idp.tenant.admin を付ける。
    let res = send(
        &env.app,
        post(
            &breakglass,
            &users_uri(&env, &account, "/permissions"),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant tenant admin");
    // rotate: 管理者になった非常用口座のパスワードを設定リンクで作り直す。
    let res = send(
        &env.app,
        post_empty(&breakglass, &users_uri(&env, &account, "/password-reset")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "reset an admin account");

    // ⚠ system 管理者の口座と、その権限には届かない。
    let res = send(
        &env.app,
        post_empty(
            &breakglass,
            &users_uri(&env, &env.root_admin_id, "/password-reset"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "system admin account");
    let res = send(
        &env.app,
        post(
            &breakglass,
            &users_uri(&env, &account, "/permissions"),
            json!({ "permission_code": "idp.smtp:write" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "root-only code beyond tenant admin"
    );
}

/// 指定のテナントの ACTIVE なゲストにし、そのテナントの権限を付ける（本番の口座と同じ形を DB で作る）。
async fn make_guest_with(env: &TestEnv, user_id: &str, tenant_id: &str, code: &str) {
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(tenant_id)
    .bind(user_id)
    .execute(&env.pool)
    .await
    .expect("insert guest membership");
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, ?, ?)",
    )
    .bind(user_id)
    .bind(code)
    .bind(tenant_id)
    .execute(&env.pool)
    .await
    .expect("insert guest permission");
}

/// root の管理者がテナントを作り、その ID を返す（作成者はそのテナントの管理者になる）。
async fn create_child_tenant(env: &TestEnv, root_tok: &str) -> String {
    let res = send(
        &env.app,
        post(
            root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("child-{}", support::unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create child tenant");
    body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string()
}

/// 子テナントの管理者は、root のゲスト管理者の口座を扱えない（task #757・ADR-0070）。
///
/// 口座を作り直せば root の管理に届くので、所属元の管理者でも断る。⚠ 他の子テナントのゲスト管理者は
/// 今までどおり所属元の管理者が扱える（ADR-0009 §3）。root を所属元にすれば root の機械が扱える
/// （break-glass の形）。
#[tokio::test]
async fn a_child_tenant_cannot_take_over_a_guest_administrator_of_the_root() {
    let Some(env) = support::setup("admin escalation root guest").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let child = create_child_tenant(&env, &root_tok).await;
    let other_child = create_child_tenant(&env, &root_tok).await;
    let child_tok = admin_token(&env.app, &env.pool, &child, &env.root_admin_id).await;
    let child_uri = |user: &str, rest: &str| format!("/{child}/admin/users/{user}{rest}");

    let root_guest = support::create_plain_user(&env.pool, &child).await;
    make_guest_with(&env, &root_guest, &env.root_tenant_id, "idp.tenant.admin").await;
    for request in [
        post_empty(&child_tok, &child_uri(&root_guest, "/password-reset")),
        post_empty(&child_tok, &child_uri(&root_guest, "/mfa-reset")),
        patch(
            &child_tok,
            &child_uri(&root_guest, "/profile"),
            json!({ "email": format!("taken-{}@example.com", support::unique()) }),
        ),
        patch(
            &child_tok,
            &child_uri(&root_guest, ""),
            json!({ "status": "DISABLED" }),
        ),
        delete(&child_tok, &child_uri(&root_guest, "")),
    ] {
        let uri = request.uri().to_string();
        let res = send(&env.app, request).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{uri}");
    }

    // 他の子テナントのゲスト管理者は、今までどおり所属元の管理者が扱える。
    let child_guest = support::create_plain_user(&env.pool, &child).await;
    make_guest_with(&env, &child_guest, &other_child, "idp.tenant.admin").await;
    let res = send(
        &env.app,
        post_empty(&child_tok, &child_uri(&child_guest, "/password-reset")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "guest of another child");

    // root を所属元にした非常用口座は、子テナントのゲスト管理者を兼ねても root の機械が扱える。
    let (_, breakglass) = machine(
        &env,
        &root_tok,
        &[
            "idp.users:write",
            "idp.permissions:write",
            "idp.admins:write",
        ],
    )
    .await;
    let account = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    grant_user(&env, &root_tok, &account, "idp.tenant.admin").await;
    make_guest_with(&env, &account, &child, "idp.tenant.admin").await;
    let res = send(
        &env.app,
        post_empty(&breakglass, &users_uri(&env, &account, "/password-reset")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "break-glass homed in root");
}
