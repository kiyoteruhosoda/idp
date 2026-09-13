//! メール送信（SMTP）設定だけを機械から入れる口の統合テスト（ADR-0051）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_smtp_settings
//!
//! 検証の要:
//! - `idp.smtp:write` を持つ**機械**が、システム設定の他の面（SMS・ランタイム・再起動）へ
//!   触れないまま、メールの経路だけを入れられること。この口が無いと SMTP パスワードは
//!   人が画面へ手で貼るしかない。
//! - **パスワードの平文が返らない**こと。設定済みか否かだけを返す。
//! - `idp.tenant.admin` からは届かないこと。届くと、テナントの中の人がシステム全体の
//!   メール経路を変えられる。
//! - root 以外のテナントでは、そもそもこのコードを**配れない**こと。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::json;
use support::{
    admin_token, body_json, create_plain_user, create_sso_session, exchange_admin_token, get, post,
    put, restore_smtp_settings, send, snapshot_smtp_settings, unique, SmtpSettingsLock,
};

fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// `client_credentials` + `resource={issuer}/{tenant}/admin` で管理トークンを得る。
async fn machine_token(
    env: &support::TestEnv,
    tenant_id: &str,
    client_id: &str,
    secret: &str,
) -> String {
    let resource = format!("{}/{}/admin", env.issuer, tenant_id);
    let body = format!(
        "grant_type=client_credentials&resource={}",
        percent_encoding::utf8_percent_encode(&resource, percent_encoding::NON_ALPHANUMERIC)
    );
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(client_id, secret))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "management token");
    body_json(res).await["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

#[tokio::test]
async fn a_machine_with_the_smtp_code_sets_the_mail_route_and_never_reads_the_password_back() {
    let Some(env) = support::setup("admin smtp settings").await else {
        return;
    };
    // ⚠ **SMTP の設定はシステムに 1 組しか無い。** 実際に書き換えるので、同じ設定を触る
    //   他のテスト（`password_reset`）と**バイナリを跨いで**直列化し、終わったら元に戻す。
    let smtp_lock = SmtpSettingsLock::acquire(&env.pool).await;
    let saved = snapshot_smtp_settings(&env.pool).await;

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
            json!({ "permission_code": "idp.smtp:write" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.smtp:write");

    let machine_tok = machine_token(&env, &env.root_tenant_id, &client_id, &secret).await;
    let smtp_uri = format!("/{}/admin/system-settings/smtp", env.root_tenant_id);
    let host = format!("smtp-{}.example.com", unique());

    let res = send(
        &env.app,
        put(
            &machine_tok,
            &smtp_uri,
            json!({
                "smtp_host": host,
                "smtp_port": 587,
                "smtp_username": "AKIA_EXAMPLE",
                "smtp_password": "s3cret-derived-password",
                "smtp_from_address": "noreply@example.com",
                "smtp_use_tls": true,
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "machine can set SMTP");
    let updated = body_json(res).await;
    assert_eq!(updated["smtp_host"], json!(host));
    assert_eq!(updated["smtp_password_set"], json!(true));
    assert!(
        updated.get("smtp_password").is_none(),
        "the plaintext password must never come back: {updated}"
    );

    // 読み取りは `:write` が含意する（ADR-0037 の含意 4）。別のコードを足さずに読める。
    let res = send(&env.app, get(&machine_tok, &smtp_uri)).await;
    assert_eq!(res.status(), StatusCode::OK, "write implies read");
    let fetched = body_json(res).await;
    assert_eq!(fetched["smtp_host"], json!(host));
    assert_eq!(fetched["smtp_username"], json!("AKIA_EXAMPLE"));
    assert_eq!(fetched["smtp_password_set"], json!(true));
    assert!(fetched.get("smtp_password").is_none());

    // ⚠ **広がっていないことまで見る。** メールの経路以外へは届かない。
    let res = send(
        &env.app,
        get(
            &machine_tok,
            &format!("/{}/admin/system-settings", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.smtp:write must not reach the whole system settings"
    );

    restore_smtp_settings(&env.pool, &saved).await;
    smtp_lock.release().await;
}

#[tokio::test]
async fn a_tenant_admin_cannot_reach_the_smtp_settings() {
    let Some(env) = support::setup("smtp tenant admin").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/users/{user}/permissions", env.root_tenant_id),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.tenant.admin");

    let sso = create_sso_session(&env.pool, &user).await;
    let tok = exchange_admin_token(&env.app, &env.root_tenant_id, &sso).await;
    let smtp_uri = format!("/{}/admin/system-settings/smtp", env.root_tenant_id);

    let res = send(&env.app, get(&tok, &smtp_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.tenant.admin must not imply idp.smtp:read"
    );
    let res = send(
        &env.app,
        put(&tok, &smtp_uri, json!({ "smtp_host": "nope.example.com" })),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.tenant.admin must not imply idp.smtp:write"
    );
}

#[tokio::test]
async fn the_smtp_code_cannot_be_granted_outside_the_root_tenant() {
    let Some(env) = support::setup("smtp grant scope").await else {
        return;
    };
    let admin_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let root_tok = exchange_admin_token(&env.app, &env.root_tenant_id, &admin_sso).await;

    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("child-{}", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create a child tenant");
    let child = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();

    // 作成者は新テナントのブートストラップ管理者（ADR-0009 §5）。そのテナントの
    // トークンへ交換して、その中からクライアントへ配ろうとする。
    let child_tok = exchange_admin_token(&env.app, &child, &admin_sso).await;
    let (client_id, _secret) = support::insert_m2m_client(&env.pool, &child, &["openid"]).await;

    let res = send(
        &env.app,
        post(
            &child_tok,
            &format!("/{child}/admin/clients/{client_id}/permissions"),
            json!({ "permission_code": "idp.smtp:write" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a system-wide code must not be grantable inside a tenant"
    );

    // 同じ経路でも、テナントの中で意味を持つコードは今までどおり配れる（縛りを広げていない）。
    let res = send(
        &env.app,
        post(
            &child_tok,
            &format!("/{child}/admin/clients/{client_id}/permissions"),
            json!({ "permission_code": "idp.users:read" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "fine-grained tenant codes still work"
    );
}
