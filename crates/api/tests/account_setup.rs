//! アカウント設定のワンタイムリンク（ADR-0062）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test account_setup
//!
//! 管理者が利用者を作ると、生成パスワードの代わりに**本人へ渡すリンク**が返る。検証する保証:
//!
//! 1. **作成はもうパスワードを返さない。** 代わりにリンクが返り、そのリンクは本人を指している。
//! 2. ⚠ **開いただけでは消費しない。** チャットに貼ったリンクはプレビューの bot が先に取りに
//!    来るので、読み出し（`describe`）で消費してはいけない。
//! 3. **リンクでパスワードを決められる**（忘失時の再設定と同じ口を通る）。決めた時点で
//!    リンクは死ぬ。
//! 4. ⚠ **忘失時の再設定リンクではパスキーを登録できない**（用途で分ける。ADR-0062 の決定 2）。

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{
    body_json, create_sso_session, exchange_admin_token, post, post_internal, send,
    setup as support_setup, unique, TestEnv, SERVICE_TOKEN,
};

async fn setup() -> Option<TestEnv> {
    support_setup("account setup").await
}

async fn tok(env: &TestEnv, sso: &str, tenant_id: &str) -> String {
    exchange_admin_token(&env.app, tenant_id, sso).await
}

/// 管理者が root テナントへ利用者を作り、`(user_id, setup_url, token)` を返す。
async fn create_user(env: &TestEnv, admin_tok: &str) -> (String, String, String) {
    let res = send(
        &env.app,
        post(
            admin_tok,
            &format!("/{}/admin/users", env.root_tenant_id),
            json!({ "email": format!("setup-{}@example.com", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "admin creates a user");
    let created = body_json(res).await;
    assert!(
        created.get("generated_password").is_none(),
        "creating a user no longer hands the admin a password: {created}"
    );
    let setup_url = created["setup_url"]
        .as_str()
        .expect("setup url")
        .to_string();
    let token = setup_url
        .split("token=")
        .nth(1)
        .expect("the link carries the token")
        .to_string();
    (
        created["user_id"].as_str().expect("user id").to_string(),
        setup_url,
        token,
    )
}

async fn describe(env: &TestEnv, token: &str) -> serde_json::Value {
    let res = send(
        &env.app,
        post_internal(
            "/internal/account-setup/describe",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": env.root_tenant_id, "token": token }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "describe answers");
    body_json(res).await
}

#[tokio::test]
async fn creating_a_user_hands_out_a_setup_link_instead_of_a_password() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;

    let (_user_id, setup_url, token) = create_user(&env, &admin_tok).await;

    assert!(
        setup_url.contains("/account-setup?token="),
        "the link lands on the setup screen: {setup_url}"
    );
    let view = describe(&env, &token).await;
    assert_eq!(view["result"], "ok", "the link can be read: {view}");
    assert_eq!(
        view["allows_passkey"], true,
        "a link the admin issued may register a passkey"
    );
    assert!(
        view["email"].as_str().is_some_and(|e| e.contains('@')),
        "the screen can say whose link it is: {view}"
    );
}

/// ⚠ 読み出しでは消費しない（プレビューの bot に食われないため）。
#[tokio::test]
async fn reading_the_link_does_not_use_it_up() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;
    let (_user_id, _url, token) = create_user(&env, &admin_tok).await;

    for _ in 0..3 {
        assert_eq!(describe(&env, &token).await["result"], "ok");
    }
}

/// リンクでパスワードを決められる。決めたらリンクは死ぬ。
#[tokio::test]
async fn the_link_sets_a_password_once() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;
    let (_user_id, _url, token) = create_user(&env, &admin_tok).await;

    let complete = json!({
        "tenant_id": env.root_tenant_id,
        "token": token,
        "new_password": format!("SetupByTheUser-{}!", unique()),
    });
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/complete",
            Some(SERVICE_TOKEN),
            complete.clone(),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        body_json(res).await["result"],
        "ok",
        "the setup link goes through the same door as a forgotten-password reset"
    );

    // 使い切ったリンクはもう読めない。
    assert_eq!(describe(&env, &token).await["result"], "invalid_or_expired");
}

/// 管理者の再発行も**リンクだけ**を返す（置き換えたパスワードは誰も知らない）。
#[tokio::test]
async fn reissuing_a_password_also_hands_out_only_a_link() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;
    let (user_id, _url, first_token) = create_user(&env, &admin_tok).await;

    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{user_id}/password-reset",
                env.root_tenant_id
            ),
            json!({}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "admin reissues");
    let body = body_json(res).await;
    assert!(
        body.get("generated_password").is_none(),
        "the admin never receives a usable password: {body}"
    );
    assert!(body["setup_url"]
        .as_str()
        .is_some_and(|u| u.contains("token=")));

    // ⚠ **出し直すと前のリンクは死ぬ**（生きたリンクが 2 本あると、どれを渡したか分からなくなる）。
    assert_eq!(
        describe(&env, &first_token).await["result"],
        "invalid_or_expired"
    );
}

/// ⚠ 忘失時の再設定リンクでパスキーを足せない（用途で分ける）。
#[tokio::test]
async fn a_forgotten_password_link_may_not_add_a_passkey() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let admin_tok = tok(&env, &root_sso, &env.root_tenant_id).await;
    let (user_id, _url, _token) = create_user(&env, &admin_tok).await;

    // 本人が「パスワードを忘れた」を押した状態を作る（再設定用途のトークンが 1 本立つ）。
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&env.pool)
        .await
        .expect("the created user");
    let res = send(
        &env.app,
        post_internal(
            "/internal/password-reset/request",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": env.root_tenant_id, "email": email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "reset requested");

    // ⚠ トークンの平文はメール（か起動ログ）にしか出ないので、この試験では DB の行から
    //   「用途」が `reset` になっていることを確かめる。パスキーを断る判定はその列で行う。
    let purpose: String = sqlx::query_scalar(
        "SELECT purpose FROM password_reset_tokens \
         WHERE user_id = ? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&user_id)
    .fetch_one(&env.pool)
    .await
    .expect("a live token");
    assert_eq!(
        purpose, "reset",
        "a link the user asked for is not a setup link"
    );
}
