//! ゲスト招待の相手の指し方（ADR-0061）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_invitations
//!
//! 招く相手は所属元が他テナントの利用者で、⚠ **参加先の管理者は相手のテナントの名簿を見られない**
//! （ADR-0009 §3）。そのため内部 ID だけを受け付けていた頃は、assay のどこにも出てこない値を
//! 入力させていた。ここで確かめるのは、その解決がテナントを跨いで正しく効くこと:
//!
//! 1. **メールアドレスで招ける**（テナントを跨いで 1 人に決まるとき）。
//! 2. **同じアドレスの利用者が 2 つのテナントに居ると、誰も招かない** —— どちらを招くかを
//!    索引の都合で決めさせない。⚠ 応答は「見つからない」で、曖昧だったことは言い分けない。
//! 3. **内部 ID（旧項目名 `user_id`）は従来どおり通る**（既に叩いている機械を壊さない）。
//! 4. どちらでもない入力は、存在の話をする前に 400 で断る。
//!
//! 解決そのものは SQL（`users` をテナント横断に引く）なので、フェイクを使う単体テスト
//! （`application::invitation`）では確かめられない。

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_json, create_sso_session, exchange_admin_token, post, send, setup as support_setup,
    unique, TestEnv,
};

async fn setup() -> Option<TestEnv> {
    support_setup("admin invitations").await
}

/// SSO セッションを、操作対象テナント向けの管理トークンへ交換する（ADR-0037）。
async fn tok(env: &TestEnv, sso: &str, tenant_id: &str) -> String {
    exchange_admin_token(&env.app, tenant_id, sso).await
}

/// root が新しいテナントを作る（作成者 root はそのテナントの ACTIVE GUEST 管理者になる。§4）。
async fn create_tenant(env: &TestEnv, root_sso: &str, name: &str) -> String {
    let res = send(
        &env.app,
        post(
            &tok(env, root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": name }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create tenant {name}");
    body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string()
}

/// 指定テナントへメールアドレスを決めて利用者を作り、その内部 ID を返す。
async fn create_user(env: &TestEnv, root_sso: &str, tenant_id: &str, email: &str) -> String {
    let res = send(
        &env.app,
        post(
            &tok(env, root_sso, tenant_id).await,
            &format!("/{tenant_id}/admin/users"),
            json!({ "email": email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create user {email}");
    body_json(res).await["user_id"]
        .as_str()
        .expect("user id")
        .to_string()
}

/// root テナントをゲストの参加先として招待を作る。
async fn invite(
    env: &TestEnv,
    root_sso: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    send(
        &env.app,
        post(
            &tok(env, root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/invitations", env.root_tenant_id),
            body,
        ),
    )
    .await
}

#[tokio::test]
async fn a_guest_can_be_invited_by_email_address() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let home = create_tenant(&env, &root_sso, &format!("InviteByEmail{}", unique())).await;
    let email = format!("invitee-{}@example.com", unique());
    create_user(&env, &root_sso, &home, &email).await;

    let res = invite(&env, &root_sso, json!({ "invitee": email })).await;

    assert_eq!(res.status(), StatusCode::CREATED, "invited by email");
    let created = body_json(res).await;
    assert_eq!(
        created["invitee_email"].as_str(),
        Some(email.as_str()),
        "the invitation names the person that address belongs to"
    );
    assert!(
        created["token"].as_str().is_some_and(|t| t.len() >= 32),
        "the one-time token still comes back"
    );
}

/// ⚠ 同じメールアドレスの利用者が 2 つのテナントに居るときは**誰も招かない**。
///
/// `users.email` の一意性はテナントの中にしか無い。片方を選ぶと、招待先が索引の都合で決まる。
#[tokio::test]
async fn an_email_shared_by_two_tenants_invites_nobody() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let one = create_tenant(&env, &root_sso, &format!("SharedOne{}", unique())).await;
    let other = create_tenant(&env, &root_sso, &format!("SharedTwo{}", unique())).await;
    let email = format!("shared-{}@example.com", unique());
    create_user(&env, &root_sso, &one, &email).await;
    create_user(&env, &root_sso, &other, &email).await;

    let res = invite(&env, &root_sso, json!({ "invitee": email })).await;

    // ⚠ 「曖昧です」と言い分けない（言い分けると他テナントの利用者の存在だけが漏れる）。
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "nobody is invited");
}

/// 内部 ID での招待と、旧項目名 `user_id` は従来どおり通る。
#[tokio::test]
async fn the_old_user_id_field_still_names_the_guest() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let home = create_tenant(&env, &root_sso, &format!("InviteById{}", unique())).await;
    let email = format!("by-id-{}@example.com", unique());
    let user_id = create_user(&env, &root_sso, &home, &email).await;

    let res = invite(&env, &root_sso, json!({ "user_id": user_id })).await;

    assert_eq!(res.status(), StatusCode::CREATED, "invited by internal id");
    assert_eq!(
        body_json(res).await["invitee_email"].as_str(),
        Some(email.as_str())
    );
}

#[tokio::test]
async fn an_invitee_that_is_neither_an_email_nor_an_id_is_refused() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;

    let res = invite(&env, &root_sso, json!({ "invitee": "guest" })).await;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "not an identifier");
}
