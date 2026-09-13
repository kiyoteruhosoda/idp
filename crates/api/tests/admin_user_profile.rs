//! 管理者による利用者プロフィール編集 API（`PATCH /{tenant_id}/admin/users/{user_id}/profile`。
//! MT25）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_user_profile
//!
//! 検証するのは:
//!
//! 1. 認可（未認証 401 / 権限なし 403 / テナント越し・不存在 404）と、状態変更と違って
//!    **自分自身も編集できる**こと（プロフィール変更はロックアウトを招かない）。
//! 2. 部分更新（省略したフィールドは変更しない）と、`name` の空文字による解除。
//! 3. テナント内の重複（email / preferred_username）が 409、書式・長さ違反が 400。
//! 4. 監査には変更した項目名だけが残り、値（PII）が漏れないこと。

mod support;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{admin_token, body_json, create_plain_user, patch, send};

/// この実行で作った対象に限定した監査行（共有テスト DB に過去実行の行が残るため）。
async fn audit_reasons(pool: &MySqlPool, actor_id: &str, target_id: &str) -> Vec<String> {
    sqlx::query(
        "SELECT reason FROM audit_log \
         WHERE event_type = 'user.profile_updated' AND user_id = ? AND result = 'success' \
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

async fn stored_profile(
    pool: &MySqlPool,
    user_id: &str,
) -> (String, Option<String>, Option<String>) {
    // ユーザー名の置き場所は登録簿（AP15b）。`users` には残っていない。
    let row = sqlx::query("SELECT email, name FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("load user");
    (
        row.get("email"),
        support::primary_username(pool, user_id).await,
        row.get("name"),
    )
}

#[tokio::test]
async fn admin_edits_email_username_and_display_name() {
    let Some(env) = support::setup("admin user profile").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let bystander = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/profile", env.root_tenant_id);
    let unique = uuid::Uuid::now_v7().simple().to_string();

    // ── 認可: トークン無しは 401、権限の無い利用者は 403。
    let res = send(
        &env.app,
        support::anonymous(axum::http::Method::PATCH, &uri, Some(json!({}))),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &bystander).await;
    let res = send(&env.app, patch(&plain_token, &uri, json!({}))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no admin perm -> 403");

    // ── 3 項目まとめて更新。
    let email = format!("renamed-{unique}@example.com");
    let username = format!("renamed-{unique}");
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &uri,
            json!({ "email": email, "preferred_username": username, "name": "Renamed User" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "admin can edit the profile");
    let body = body_json(res).await;
    assert_eq!(body["email"], email);
    assert_eq!(body["preferred_username"], username);
    assert_eq!(body["name"], "Renamed User");
    assert_eq!(
        stored_profile(&env.pool, &target).await,
        (
            email.clone(),
            Some(username.clone()),
            Some("Renamed User".to_string())
        )
    );

    // ── 部分更新: name のみ空文字 = 解除。email / preferred_username は現状維持。
    let res = send(&env.app, patch(&admin_tok, &uri, json!({ "name": "" }))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        stored_profile(&env.pool, &target).await,
        (email.clone(), Some(username.clone()), None)
    );

    // ── 監査は「変更した項目名」だけを残し、値（PII）は出さない。
    let reasons = audit_reasons(&env.pool, &env.root_admin_id, &target).await;
    assert_eq!(reasons.len(), 2, "one row per change: {reasons:?}");
    assert!(
        reasons[0].contains("fields=email,preferred_username,name"),
        "{}",
        reasons[0]
    );
    assert!(reasons[1].contains("fields=name"), "{}", reasons[1]);
    assert!(
        reasons.iter().all(|r| !r.contains(&email)),
        "email must not leak into the audit log: {reasons:?}"
    );
    assert!(
        reasons.iter().all(|r| !r.contains("Renamed User")),
        "display name must not leak into the audit log: {reasons:?}"
    );
}

/// メールアドレスを変えると主メール行が追随する（ADR-0050 決定 1）。
///
/// 追随しないと `users.email` と登録簿が割れ、変更前のアドレスが登録簿に居座る
/// （その値は誰も取れないのに誰のものでもない）。
///
/// **同じ値をユーザー名として持たせたときに行が消えることまで確かめる**（決定 6）。
/// 同じ正規化値の行は 1 本しか作れないので、そこでは主メール行を作らないと決めてある。
/// 消し損ねると、メールを戻したときに古い行が残って `users.email` と食い違う。
#[tokio::test]
async fn changing_the_email_moves_the_primary_email_row() {
    let Some(env) = support::setup("primary email follows the profile").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/profile", env.root_tenant_id);
    let unique = uuid::Uuid::now_v7().simple().to_string();
    let first = format!("pe1-{unique}@example.com");
    let second = format!("pe2-{unique}@example.com");
    // ⚠ ユーザー名を**メールの書式**にしておく。利用者をユーザー名の指定なしで作ると
    //   ユーザー名にはメールアドレスがそのまま入る（ADR-0009 §8）ので、この形は実在する。
    let username = format!("pe-{unique}@example.com");

    // ── 行が無いところから作られる（SQL で直接作った利用者は登録簿に行を持たない）。
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &uri,
            json!({ "email": first, "preferred_username": username }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await,
        Some(first)
    );

    // ── 変更で追随する（更新の分岐）。
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({ "email": second })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await,
        Some(second)
    );

    // ── メールを**自分のユーザー名と同じ値**にすると、主メール行は消える（決定 6）。
    //    同じ正規化値の行は 1 本しか作れないので、ユーザー名の行が既にその値を握っている
    //    ときは主メール行を作らない。消し損ねると `users.email` と登録簿が食い違う。
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({ "email": username })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await,
        None,
        "同じ値の行は 1 本だけ。ユーザー名の行が持っているので主メール行は作らない"
    );
    assert_eq!(
        support::primary_username(&env.pool, &target).await,
        Some(username),
        "ユーザー名の行は残る"
    );

    // ── メールを別の値へ戻すと、主メール行がまた作られる。
    let third = format!("pe3-{unique}@example.com");
    let res = send(&env.app, patch(&admin_tok, &uri, json!({ "email": third }))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await,
        Some(third)
    );
}

/// **他人がログイン識別子として持っている値へは、メールアドレスを変更できない**
/// （ADR-0050 決定 1。要件「メールアドレスは一意にしたい」の核心）。
///
/// ⚠ この向きが今まで素通りだった。`update_profile` が見ていたのは `users` 側の一意制約
/// （`(tenant_id, email)`）だけで、登録簿を見ていなかったため、**B がユーザー名や別名の
/// メールとして持っている値を A のメールにできた**。メールでのログインを許すと、
/// そのとき 1 つの入力が 2 人に当たる。
#[tokio::test]
async fn an_email_held_by_another_user_as_an_identifier_is_rejected() {
    let Some(env) = support::setup("primary email uniqueness").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let unique = uuid::Uuid::now_v7().simple().to_string();
    let alice = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let bob = create_plain_user(&env.pool, &env.root_tenant_id).await;

    // bob に別名のメールアドレスを足す（bob の `users.email` とは別の値）。
    let alias = format!("alias-{unique}@example.com");
    let res = send(
        &env.app,
        support::post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{bob}/login-identifiers",
                env.root_tenant_id
            ),
            json!({"identifier_type": "email", "value": alias}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);

    // alice のメールをその値へ変えようとすると 409。
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("/{}/admin/users/{alice}/profile", env.root_tenant_id),
            json!({ "email": alias }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "他人の識別子と同じ値はメールにできない"
    );

    // 断ったあとに `users` 側だけが書き換わっていないこと（同じトランザクションで失敗する）。
    let (stored_email, _, _) = stored_profile(&env.pool, &alice).await;
    assert_ne!(
        stored_email, alias,
        "断ったのに users 側だけ変わってはいけない"
    );
}

#[tokio::test]
async fn profile_edit_rejects_duplicates_and_invalid_input() {
    let Some(env) = support::setup("admin user profile guards").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let other = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/profile", env.root_tenant_id);
    let (other_email, ..) = stored_profile(&env.pool, &other).await;

    // 既に使われている email は 409。
    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({ "email": other_email })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT, "duplicate email -> 409");

    // 書式違反・ログイン識別子の解除は 400。
    for body in [
        json!({ "email": "not-an-email" }),
        json!({ "preferred_username": "" }),
        json!({ "name": "x".repeat(256) }),
    ] {
        let res = send(&env.app, patch(&admin_tok, &uri, body.clone())).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "body={body}");
    }

    // 不存在・UUID 不正はいずれも 404（存在推測を防ぐ）。
    for unknown in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_string()] {
        let uri = format!("/{}/admin/users/{unknown}/profile", env.root_tenant_id);
        let res = send(&env.app, patch(&admin_tok, &uri, json!({}))).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "target={unknown}");
    }
}

/// 状態変更・削除・パスワード再発行・MFA 解除は自己操作を禁止するが、プロフィール編集は許す
/// （ロックアウトを招かない。管理者が自分のメールを直せないと運用が詰まる）。
#[tokio::test]
async fn admin_can_edit_their_own_profile() {
    let Some(env) = support::setup("admin self profile").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!(
        "/{}/admin/users/{}/profile",
        env.root_tenant_id, env.root_admin_id
    );

    let res = send(
        &env.app,
        patch(&admin_tok, &uri, json!({ "name": "Root Operator" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "self edit is allowed");
    let (_, _, name) = stored_profile(&env.pool, &env.root_admin_id).await;
    assert_eq!(name.as_deref(), Some("Root Operator"));

    // 対照: 状態変更は自分自身に対して 403（既存の防御線が緩んでいないこと）。
    let status_uri = format!("/{}/admin/users/{}", env.root_tenant_id, env.root_admin_id);
    let res = send(
        &env.app,
        patch(&admin_tok, &status_uri, json!({ "status": "DISABLED" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "self disable -> 403");
}
