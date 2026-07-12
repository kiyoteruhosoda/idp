//! 利用者権限の付与・剥奪 API の E2E 統合テスト（Progress A2、ADR-0006、設計仕様 §7）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_permissions
//!
//! 認可は `RequirePerms<IdpAdmin>`（`idp.tenant.admin`。`idp.system.admin` は代替として許可）。
//! 初期管理者（seed で root テナントへ `idp.system.admin` 付与済み）の SSO セッションを
//! 直接作成し、その Cookie で管理 API を叩く。権限の無い利用者は 403 になること、
//! 付与・剥奪が `audit_log` に記録されることを検証する。

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{body_json, create_plain_user, create_sso_session, delete, get, post, send};

const ADMIN_PERM: &str = "idp.tenant.admin";

/// actor（user_id）と対象（reason 内の target UUID）で絞った監査行数。
/// 共有テスト DB では過去実行の行が残るため、この実行で作った target に限定して数える。
async fn count_audit(pool: &MySqlPool, event_type: &str, actor_id: &str, target_id: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log \
         WHERE event_type = ? AND user_id = ? AND result = 'success' AND reason LIKE ?",
    )
    .bind(event_type)
    .bind(actor_id)
    .bind(format!("%target={target_id}%"))
    .fetch_one(pool)
    .await
    .expect("count audit")
    .get::<i64, _>("c")
}

#[tokio::test]
async fn admin_can_grant_and_revoke_permissions() {
    let Some(env) = support::setup("admin permissions").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let target = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let perms_uri = format!("/{}/admin/users/{target}/permissions", env.root_tenant_id);

    // 未認証（Cookie 無し）→ 401。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(&perms_uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // 権限の無い利用者 → 403。
    let plain_cookie = create_sso_session(&env.pool, &target).await;
    let res = send(&env.app, get(&plain_cookie, &perms_uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // user_id が UUID でない → 400。
    let res = send(
        &env.app,
        get(
            &admin_cookie,
            &format!("/{}/admin/users/not-a-uuid/permissions", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "bad user_id -> 400");

    // 不存在の利用者への付与 → 404。
    let ghost = uuid::Uuid::new_v4();
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &format!("/{}/admin/users/{ghost}/permissions", env.root_tenant_id),
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "unknown user -> 404");

    // 未知の権限コード → 400。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &perms_uri,
            json!({ "permission_code": "idp.does-not-exist" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown code -> 400");

    // 初期状態: 権限なし。
    let res = send(&env.app, get(&admin_cookie, &perms_uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed = body_json(res).await;
    assert!(listed["permission_codes"].as_array().unwrap().is_empty());

    // 付与 → 200・一覧に反映・監査 granted 記録。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &perms_uri,
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant -> 200");
    let granted = body_json(res).await;
    assert_eq!(
        granted["permission_codes"].as_array().unwrap(),
        &vec![json!(ADMIN_PERM)]
    );
    assert_eq!(
        count_audit(
            &env.pool,
            "user_permission.granted",
            &env.root_admin_id,
            &target
        )
        .await,
        1,
        "granted audit recorded (actor = admin)"
    );

    // 冪等: 再付与しても重複しない。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &perms_uri,
            json!({ "permission_code": ADMIN_PERM }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let granted = body_json(res).await;
    assert_eq!(granted["permission_codes"].as_array().unwrap().len(), 1);

    // 付与された利用者は管理 API へアクセスできる（自分の権限一覧を取得）。
    let res = send(&env.app, get(&plain_cookie, &perms_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "granted user can now access admin"
    );

    // 剥奪 → 200・一覧空・監査 revoked 記録。
    let res = send(
        &env.app,
        delete(&admin_cookie, &format!("{perms_uri}/{ADMIN_PERM}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke -> 200");
    let revoked = body_json(res).await;
    assert!(revoked["permission_codes"].as_array().unwrap().is_empty());
    assert_eq!(
        count_audit(
            &env.pool,
            "user_permission.revoked",
            &env.root_admin_id,
            &target
        )
        .await,
        1,
        "revoked audit recorded"
    );

    // 剥奪は冪等（未保有でも 200）。
    let res = send(
        &env.app,
        delete(&admin_cookie, &format!("{perms_uri}/{ADMIN_PERM}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "revoke again -> 200");
}
