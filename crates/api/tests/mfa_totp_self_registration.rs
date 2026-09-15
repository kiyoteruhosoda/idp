//! 認証器の自己管理（AP9）を実 DB で通す統合テスト。
//!
//! 画面（web）は step-up のゲートを抜けてから api を呼ぶ。ここを通していなかったため、
//! **TOTP の登録が本番で一度も成功していなかった**ことに画面からしか気付けなかった
//! （api が `internal` を返し、web がログを残さずに 500 を出す）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test mfa_totp_self_registration

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{body_json, post_internal, send, SERVICE_TOKEN};

/// step-up のゲート（画面が最初に通す）。
async fn step_up_check(app: &axum::Router, tenant: &str, sso: &str) -> serde_json::Value {
    let response = send(
        app,
        post_internal(
            "/internal/step-up/check",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "sso_session_id": sso,
                "operation": "manage_authenticators",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "step-up check status");
    body_json(response).await
}

/// ログイン直後の利用者は TOTP の登録を始められる。
///
/// **QR の中身まで見る。** `otpauth://` URI は `{issuer}:{account}` を `:` で区切るため、
/// issuer に OIDC の issuer URL（`https://…`）が混ざると URI が組めず、登録が丸ごと失敗する。
/// 「200 が返った」だけでは、この失敗は捕まえられない。
#[tokio::test]
async fn a_signed_in_user_can_start_a_totp_registration() {
    let Some(env) = support::setup("totp self registration").await else {
        return;
    };
    let (app, pool, tenant) = (env.app, env.pool, env.root_tenant_id);

    let user_id = support::create_plain_user(&pool, &tenant).await;
    let sso = support::create_sso_session(&pool, &user_id).await;

    let check = step_up_check(&app, &tenant, &sso).await;
    assert_eq!(check["result"], "satisfied", "ログイン直後は満たされている");

    let response = send(
        &app,
        post_internal(
            "/internal/mfa/totp/setup",
            Some(SERVICE_TOKEN),
            json!({ "sso_session_id": sso }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "totp setup status");
    let setup = body_json(response).await;
    assert_eq!(
        setup["result"], "ok",
        "TOTP の仮登録が始められること: {setup}"
    );

    let uri = setup["totp_uri"].as_str().expect("totp_uri");
    assert!(uri.starts_with("otpauth://totp/"), "{uri}");
    // 見出しは URL ではなくホスト名。スキームの `:` が残っていたら totp-rs が弾いている。
    assert!(
        !uri.contains("https%3A") && !uri.contains("http%3A"),
        "{uri}"
    );
    // 宛名は api が利用者から引く（空だと認証アプリの一覧で見分けられない）。
    let account: String = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .expect("read user email");
    let encoded_account = account.replace('@', "%40");
    assert!(
        uri.contains(&encoded_account) || uri.contains(&account),
        "QR に宛名が載ること: uri={uri} account={account}"
    );

    let secret = setup["secret_base32"].as_str().expect("secret_base32");
    assert!(!secret.is_empty(), "QR が使えない利用者向けの生コード");
}

/// リカバリーコードの発行（AP9）。TOTP と同じ「認証器の自己管理」の並びにあり、同じく試験が無かった。
#[tokio::test]
async fn a_signed_in_user_can_issue_recovery_codes() {
    let Some(env) = support::setup("recovery codes").await else {
        return;
    };
    let (app, pool, tenant) = (env.app, env.pool, env.root_tenant_id);

    let user_id = support::create_plain_user(&pool, &tenant).await;
    let sso = support::create_sso_session(&pool, &user_id).await;

    let response = send(
        &app,
        post_internal(
            "/internal/account/recovery-codes",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": tenant, "sso_session_id": sso }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "recovery codes status");
    let issued = body_json(response).await;
    assert_eq!(issued["result"], "ok", "発行できること: {issued}");
    let codes = issued["codes"].as_array().expect("codes");
    assert!(!codes.is_empty(), "束が空でないこと: {issued}");

    // 画面が出す「残り n 本」に反映されること。
    let response = send(
        &app,
        post_internal(
            "/internal/account/authenticators",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": tenant, "sso_session_id": sso }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "authenticators status");
    let list = body_json(response).await;
    assert_eq!(list["result"], "ok", "認証器一覧が引けること: {list}");
    assert_eq!(
        list["recovery_codes_remaining"],
        codes.len() as u64,
        "残数が発行した本数と一致すること: {list}"
    );
}
