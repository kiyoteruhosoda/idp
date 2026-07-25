//! ゲストメンバーシップの一時停止・再開（`PATCH /{tenant_id}/admin/members/{user_id}`。MT24）の
//! 統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_member_suspension
//!
//! 解除（`DELETE`）はメンバーシップ行も当該テナント scope の権限行も消すため、戻すには招待から
//! やり直しになる。一時停止は**元に戻せる**ことが要件で、検証するのは:
//!
//! 1. 認可（未認証 401 / 権限なし 403）と入力検証（不正な status は 400）。
//! 2. 停止で `SUSPENDED` になり、**メンバーシップ行と権限行が残る**こと（＝再開で元に戻る）。
//! 3. 停止で当該テナント分の refresh token が失効し、**他テナント分は残る**こと。
//!    ゲストの停止は 1 テナントへの措置であり、所属元での利用を巻き込んではいけない。
//! 4. 遷移の制約（HOME は停止不可・二重停止不可・未停止の再開不可はいずれも 403）。
//! 5. 監査に停止・再開が残ること。

mod support;

use axum::http::{Method, StatusCode};
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{create_plain_user, create_sso_session, patch, send};

/// 当該テナントの GUEST メンバーシップ（`ACTIVE`）を直接作る（招待フローは別テストの関心事）。
async fn insert_active_guest(pool: &MySqlPool, tenant_id: &str, user_id: &str) {
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(tenant_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert guest membership");
}

async fn insert_refresh_token(pool: &MySqlPool, tenant_id: &str, user_id: &str) -> String {
    let hash = format!("{:064x}", uuid::Uuid::now_v7().as_u128());
    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, tenant_id, user_id, client_id, scope, expires_at) \
         VALUES (?, ?, ?, 'test-client', '[\"openid\"]', DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))",
    )
    .bind(&hash)
    .bind(tenant_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("insert refresh token");
    hash
}

async fn is_revoked(pool: &MySqlPool, token_hash: &str) -> bool {
    sqlx::query("SELECT revoked_at IS NOT NULL AS revoked FROM refresh_tokens WHERE token_hash = ?")
        .bind(token_hash)
        .fetch_one(pool)
        .await
        .expect("read refresh token")
        .get::<i64, _>("revoked")
        == 1
}

async fn membership_status(pool: &MySqlPool, tenant_id: &str, user_id: &str) -> Option<String> {
    sqlx::query("SELECT status FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?")
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .expect("read membership")
        .map(|row| row.get::<String, _>("status"))
}

async fn grant_permission(pool: &MySqlPool, tenant_id: &str, user_id: &str, code: &str) {
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, ?, ?)",
    )
    .bind(user_id)
    .bind(code)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("grant permission");
}

async fn count_permissions(pool: &MySqlPool, tenant_id: &str, user_id: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM user_permissions WHERE tenant_id = ? AND user_id = ?")
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count permissions")
        .get::<i64, _>("c")
}

async fn count_audit(pool: &MySqlPool, event_type: &str, target_id: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log \
         WHERE event_type = ? AND result = 'success' AND reason LIKE ?",
    )
    .bind(event_type)
    .bind(format!("%member={target_id}%"))
    .fetch_one(pool)
    .await
    .expect("count audit")
    .get::<i64, _>("c")
}

#[tokio::test]
async fn admin_suspends_and_resumes_a_guest_without_losing_membership_or_permissions() {
    let Some(env) = support::setup("admin member suspension").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    // ゲストは**別テナント所属**（所属元 = home_tenant）で root に GUEST 参加している、という
    // 実運用の形にする。`create_plain_user` は指定テナントに HOME メンバーシップを作るため、
    // 所属元を別テナントにしないと root の GUEST 行と主キー衝突する。
    let home_tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, ?, ?)")
        .bind(&home_tenant)
        .bind(&env.root_tenant_id)
        .bind(format!("guest-home-{}", &home_tenant[..8]))
        .execute(&env.pool)
        .await
        .expect("create home tenant for the guest");
    let guest = create_plain_user(&env.pool, &home_tenant).await;

    let uri = format!("/{}/admin/members/{guest}", env.root_tenant_id);

    // ── 認可: Cookie 無しは 401、権限の無い利用者は 403。
    let res = send(
        &env.app,
        support::anonymous(Method::PATCH, &uri, Some(json!({"status": "SUSPENDED"}))),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_cookie = create_sso_session(&env.pool, &plain).await;
    let res = send(
        &env.app,
        patch(&plain_cookie, &uri, json!({"status": "SUSPENDED"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no admin perm -> 403");

    // ── 準備: ACTIVE な GUEST、当該テナント scope の権限、両テナントの refresh token。
    insert_active_guest(&env.pool, &env.root_tenant_id, &guest).await;
    grant_permission(&env.pool, &env.root_tenant_id, &guest, "idp.tenant.admin").await;
    let host_token = insert_refresh_token(&env.pool, &env.root_tenant_id, &guest).await;
    // 所属元テナントで発行済みのトークン。停止は host テナントへの措置なので巻き込んではいけない。
    let home_token = insert_refresh_token(&env.pool, &home_tenant, &guest).await;

    // ── 不正な status は 400（INVITED は招待フローが管理する状態のため直接は設定させない）。
    for bad in ["INVITED", "nonsense", ""] {
        let res = send(&env.app, patch(&admin_cookie, &uri, json!({"status": bad}))).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "status={bad}");
    }

    // ── 停止。
    let res = send(
        &env.app,
        patch(&admin_cookie, &uri, json!({"status": "SUSPENDED"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "suspend");
    assert_eq!(
        membership_status(&env.pool, &env.root_tenant_id, &guest).await,
        Some("SUSPENDED".to_string())
    );
    // 解除と違い、メンバーシップも権限も残る（再開で元に戻せる）。
    assert_eq!(
        count_permissions(&env.pool, &env.root_tenant_id, &guest).await,
        1
    );
    // 当該テナント分の refresh token だけ失効する。
    assert!(
        is_revoked(&env.pool, &host_token).await,
        "host token revoked"
    );
    assert!(
        !is_revoked(&env.pool, &home_token).await,
        "the guest's home-tenant token must survive"
    );
    assert_eq!(
        count_audit(&env.pool, "tenant_membership.suspended", &guest).await,
        1
    );

    // ── 二重停止は 403（遷移できない状態）。
    let res = send(
        &env.app,
        patch(&admin_cookie, &uri, json!({"status": "SUSPENDED"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "double suspend");

    // ── 再開。権限はそのままなので停止前の状態へ戻る。
    let res = send(
        &env.app,
        patch(&admin_cookie, &uri, json!({"status": "ACTIVE"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "resume");
    assert_eq!(
        membership_status(&env.pool, &env.root_tenant_id, &guest).await,
        Some("ACTIVE".to_string())
    );
    assert_eq!(
        count_permissions(&env.pool, &env.root_tenant_id, &guest).await,
        1
    );
    assert_eq!(
        count_audit(&env.pool, "tenant_membership.resumed", &guest).await,
        1
    );

    // ── 未停止の再開は 403。
    let res = send(
        &env.app,
        patch(&admin_cookie, &uri, json!({"status": "ACTIVE"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "resume when active");
}

#[tokio::test]
async fn home_membership_cannot_be_suspended() {
    let Some(env) = support::setup("admin member suspension home").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    // create_plain_user は HOME メンバーシップ付きで作られる。
    let home_user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/members/{home_user}", env.root_tenant_id);

    // HOME は所属元そのもので、停止するとログインする先が無くなる（アカウント無効化を使う）。
    let res = send(
        &env.app,
        patch(&admin_cookie, &uri, json!({"status": "SUSPENDED"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "home -> 403");
    assert_eq!(
        membership_status(&env.pool, &env.root_tenant_id, &home_user).await,
        Some("ACTIVE".to_string()),
        "home membership must stay active"
    );

    // メンバーシップが無ければ 404（存在推測を防ぐ）。
    let unknown = uuid::Uuid::now_v7();
    let res = send(
        &env.app,
        patch(
            &admin_cookie,
            &format!("/{}/admin/members/{unknown}", env.root_tenant_id),
            json!({"status": "SUSPENDED"}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
