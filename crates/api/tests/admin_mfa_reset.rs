//! 管理者による MFA 解除 API（`POST /{tenant_id}/admin/users/{user_id}/mfa-reset`。MT21）の
//! 統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_mfa_reset
//!
//! 端末を失って本人では解除できない状態からの復旧手段。検証するのは:
//!
//! 1. 認可（未認証 401 / 権限なし 403 / テナント越し・不存在 404 / 自分自身 403）。
//! 2. TOTP と Passkey を**両方**外すこと。片方でも残ると本人はログインできないままで、
//!    復旧手段として成立しない。他人のクレデンシャルは巻き込まない。
//! 3. 紛失端末が握っている SSO セッションが失効すること。
//! 4. MFA 未設定でも成功し、「何も外さなかった」ことが応答で分かること。
//! 5. 監査へ解除の粒度が残り、シークレットが漏れないこと。

mod support;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{body_json, create_plain_user, create_sso_session, post, send};

/// 対象ユーザーの TOTP シークレットを直接投入する（セットアップ API を通さずに「設定済み」を作る。
/// 本テストの関心は解除であって登録フローではない）。
async fn insert_totp(pool: &MySqlPool, user_id: &str) {
    sqlx::query(
        "INSERT INTO user_totp_secrets (user_id, secret_encrypted, confirmed_at) \
         VALUES (?, 'test-ciphertext', UTC_TIMESTAMP(6))",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert totp secret");
}

async fn insert_passkey(pool: &MySqlPool, user_id: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO user_webauthn_credentials \
         (id, user_id, credential_id, passkey_json, name, created_at) \
         VALUES (?, ?, ?, '{}', 'test device', UTC_TIMESTAMP(6))",
    )
    .bind(&id)
    .bind(user_id)
    .bind(format!("cred-{id}"))
    .execute(pool)
    .await
    .expect("insert passkey");
    id
}

async fn count_totp(pool: &MySqlPool, user_id: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM user_totp_secrets WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count totp")
        .get::<i64, _>("c")
}

async fn count_passkeys(pool: &MySqlPool, user_id: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM user_webauthn_credentials WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count passkeys")
        .get::<i64, _>("c")
}

async fn count_sso_sessions(pool: &MySqlPool, user_id: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM sso_sessions WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count sso sessions")
        .get::<i64, _>("c")
}

/// この実行で作った対象に限定した監査行（共有テスト DB に過去実行の行が残るため）。
async fn audit_reasons(pool: &MySqlPool, actor_id: &str, target_id: &str) -> Vec<String> {
    sqlx::query(
        "SELECT reason FROM audit_log \
         WHERE event_type = 'user.mfa_reset' AND user_id = ? AND result = 'success' \
           AND reason LIKE ?",
    )
    .bind(actor_id)
    .bind(format!("%user={target_id}%"))
    .fetch_all(pool)
    .await
    .expect("audit rows")
    .iter()
    .map(|row| row.get::<String, _>("reason"))
    .collect()
}

#[tokio::test]
async fn admin_resets_both_mfa_factors_and_revokes_sessions() {
    let Some(env) = support::setup("admin mfa reset").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let bystander = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/mfa-reset", env.root_tenant_id);

    // ── 認可: Cookie 無しは 401、権限の無い利用者は 403。
    let res = send(
        &env.app,
        support::anonymous(axum::http::Method::POST, &uri, None),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    let plain_cookie = create_sso_session(&env.pool, &bystander).await;
    let res = send(&env.app, post(&plain_cookie, &uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no admin perm -> 403");

    // ── 対象に TOTP と Passkey 2 件、無関係な利用者にも Passkey を 1 件用意する。
    insert_totp(&env.pool, &target).await;
    insert_passkey(&env.pool, &target).await;
    insert_passkey(&env.pool, &target).await;
    insert_passkey(&env.pool, &bystander).await;
    // 紛失端末が握っている想定の SSO セッション。
    create_sso_session(&env.pool, &target).await;
    assert!(count_sso_sessions(&env.pool, &target).await > 0);

    let res = send(&env.app, post(&admin_cookie, &uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::OK, "admin can reset mfa");
    let body = body_json(res).await;
    assert_eq!(body["user_id"], target);
    assert_eq!(body["totp_removed"], true);
    assert_eq!(body["passkeys_removed"], 2);

    // TOTP・Passkey が両方消え、無関係な利用者のものは残る。
    assert_eq!(count_totp(&env.pool, &target).await, 0);
    assert_eq!(count_passkeys(&env.pool, &target).await, 0);
    assert_eq!(
        count_passkeys(&env.pool, &bystander).await,
        1,
        "other users' passkeys must survive"
    );
    // 紛失端末のセッションも失効している。
    assert_eq!(count_sso_sessions(&env.pool, &target).await, 0);

    // 監査に粒度が残り、シークレットは漏れない。
    let reasons = audit_reasons(&env.pool, &env.root_admin_id, &target).await;
    assert_eq!(reasons.len(), 1, "one audit row: {reasons:?}");
    assert!(reasons[0].contains("totp=removed"), "{}", reasons[0]);
    assert!(reasons[0].contains("passkeys=2"), "{}", reasons[0]);
    assert!(
        !reasons[0].contains("test-ciphertext"),
        "secrets must not leak into the audit log: {}",
        reasons[0]
    );

    // ── 2 回目は「何も外さなかった」で成功する（管理者は設定の有無を知らずに操作する）。
    let res = send(&env.app, post(&admin_cookie, &uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["totp_removed"], false);
    assert_eq!(body["passkeys_removed"], 0);
}

#[tokio::test]
async fn mfa_reset_rejects_self_and_unknown_users() {
    let Some(env) = support::setup("admin mfa reset guards").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;

    // 自分自身は解除できない（セルフサービスを使う。誤操作によるロックアウト防止）。
    let self_uri = format!(
        "/{}/admin/users/{}/mfa-reset",
        env.root_tenant_id, env.root_admin_id
    );
    let res = send(&env.app, post(&admin_cookie, &self_uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "self -> 403");

    // 不存在・UUID 不正はいずれも 404（存在推測を防ぐ）。
    for target in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_string()] {
        let uri = format!("/{}/admin/users/{target}/mfa-reset", env.root_tenant_id);
        let res = send(&env.app, post(&admin_cookie, &uri, json!({}))).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "target={target}");
    }
}
