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
