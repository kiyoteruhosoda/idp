//! 認証ポリシー管理 API と、ログインフローでのポリシー適用の統合テスト
//! （ユーザー認証・認証ポリシー仕様書 §7〜§9・§24）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_authentication_policies
//!
//! 検証すること:
//! - CRUD が `idp.tenant.admin` で保護されること（401 / 403）
//! - 作成・更新・削除が動き、`policy_code` 重複が 409 になること
//! - `deny` ポリシーが一致するとパスワードログインが拒否され、監査に記録されること
//! - `require_mfa` ポリシーが一致し TOTP 未設定だとログインが完了しないこと（仕様 §24.4）
//! - 無効化されたポリシーは適用されないこと

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{
    authorize_uri_openid_only, begin_login, body_json, create_plain_user, create_sso_session,
    delete, get, post, put, send, SERVICE_TOKEN, SERVICE_TOKEN_HEADER,
};

fn login_csrf(auth_session: &str, csrf_secret: &[u8; 32]) -> String {
    idp_api::application::login::csrf_token(auth_session, csrf_secret)
}

/// api の内部認証（`POST /internal/authenticate`）で資格情報検証を駆動する。
async fn internal_authenticate(
    app: &axum::Router,
    tenant: &str,
    auth_session: &str,
    username: &str,
    password: &str,
    csrf: &str,
) -> Value {
    let body = json!({
        "tenant_id": tenant,
        "auth_session_id": auth_session,
        "username": username,
        "password": password,
        "csrf_token": csrf,
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri("/internal/authenticate")
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "internal authenticate");
    body_json(response).await
}

/// 自己登録でユーザーを作成し、メール検証まで済ませる（ログイン可能な状態にする）。
async fn register_verified_user(
    app: &axum::Router,
    pool: &MySqlPool,
    tenant: &str,
    username: &str,
    password: &str,
) {
    let payload = json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": password,
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
    support::mark_email_verified(pool, tenant, username).await;
}

async fn audit_count(pool: &MySqlPool, event_type: &str, reason_like: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM audit_log WHERE event_type = ? AND reason LIKE ?")
        .bind(event_type)
        .bind(format!("%{reason_like}%"))
        .fetch_one(pool)
        .await
        .expect("count audit")
        .get::<i64, _>("c")
}

#[tokio::test]
async fn admin_can_manage_authentication_policies() {
    let Some(env) = support::setup("authentication policies CRUD").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let uri = format!("/{}/admin/authentication-policies", env.root_tenant_id);
    let code = format!("it-deny-{}", support::unique());

    // 未認証（Cookie 無し）→ 401。
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // 権限の無い利用者 → 403。
    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_cookie = create_sso_session(&env.pool, &plain).await;
    let res = send(&env.app, get(&plain_cookie, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // effect 不正 → 400。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "bad effect",
                "priority": 1,
                "effect": "block",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "bad effect -> 400");

    // 作成 → 200・監査記録。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "Deny legacy client",
                "priority": 10,
                "effect": "deny",
                "client_ids": ["legacy-app"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create -> 200");
    let created = body_json(res).await;
    assert_eq!(created["effect"], "deny");
    assert_eq!(created["enabled"], true, "enabled defaults to true");
    let policy_id = created["id"].as_str().expect("policy id").to_string();
    assert_eq!(
        audit_count(
            &env.pool,
            "authentication_policy.created",
            &format!("policy={code}")
        )
        .await,
        1
    );

    // policy_code 重複 → 409。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "duplicate",
                "priority": 20,
                "effect": "allow",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT, "duplicate code -> 409");

    // 一覧に載る。
    let res = send(&env.app, get(&admin_cookie, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed = body_json(res).await;
    assert!(
        listed["policies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == json!(policy_id)),
        "created policy is listed: {listed}"
    );

    // 更新（全項目置換）→ 200・監査記録。
    let res = send(
        &env.app,
        put(
            &admin_cookie,
            &format!("{uri}/{policy_id}"),
            json!({
                "policy_code": code,
                "policy_name": "Require MFA instead",
                "priority": 5,
                "enabled": false,
                "effect": "require_mfa",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "update -> 200");
    let updated = body_json(res).await;
    assert_eq!(updated["effect"], "require_mfa");
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["client_ids"], json!([]), "conditions replaced");
    assert_eq!(
        audit_count(
            &env.pool,
            "authentication_policy.updated",
            &format!("policy={code}")
        )
        .await,
        1
    );

    // 不存在 ID の更新・削除 → 404。
    let ghost = uuid::Uuid::new_v4();
    let res = send(
        &env.app,
        put(
            &admin_cookie,
            &format!("{uri}/{ghost}"),
            json!({
                "policy_code": "ghost",
                "policy_name": "ghost",
                "priority": 1,
                "effect": "allow",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "unknown id -> 404");

    // 削除 → 204・一覧から消える・監査記録。
    let res = send(
        &env.app,
        delete(&admin_cookie, &format!("{uri}/{policy_id}")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "delete -> 204");
    let res = send(&env.app, get(&admin_cookie, &uri)).await;
    let listed = body_json(res).await;
    assert!(
        !listed["policies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == json!(policy_id)),
        "deleted policy is gone"
    );
    assert_eq!(
        audit_count(
            &env.pool,
            "authentication_policy.deleted",
            &format!("policy={code}")
        )
        .await,
        1
    );
}

#[tokio::test]
async fn deny_policy_blocks_password_login_until_disabled() {
    let Some(env) = support::setup("deny policy blocks login").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let username = format!("policy-user-{}", support::unique());
    let password = "CorrectHorse9!";
    register_verified_user(
        &env.app,
        &env.pool,
        &env.root_tenant_id,
        &username,
        password,
    )
    .await;

    // 対象クライアント限定の deny ポリシーを作成する。
    let uri = format!("/{}/admin/authentication-policies", env.root_tenant_id);
    let code = format!("it-deny-login-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "Deny this client",
                "priority": 1,
                "effect": "deny",
                "client_ids": [client_id],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create deny policy");
    let policy_id = body_json(res).await["id"]
        .as_str()
        .expect("policy id")
        .to_string();

    // 正しい資格情報でも policy_denied で拒否され、監査に記録される。
    let authorize_uri = authorize_uri_openid_only(&env.root_tenant_id, &client_id);
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(body["result"], "policy_denied", "deny policy wins: {body}");
    assert_eq!(
        audit_count(&env.pool, "login.policy_denied", &format!("policy={code}")).await,
        1
    );

    // ポリシーを無効化するとログインできる（一致するポリシー無し → 既定 allow）。
    let res = send(
        &env.app,
        put(
            &admin_cookie,
            &format!("{uri}/{policy_id}"),
            json!({
                "policy_code": code,
                "policy_name": "Deny this client",
                "priority": 1,
                "enabled": false,
                "effect": "deny",
                "client_ids": [client_id],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "disable policy");

    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "success",
        "disabled policy is ignored: {body}"
    );
}

#[tokio::test]
async fn require_mfa_policy_blocks_single_factor_login_without_enrollment() {
    let Some(env) = support::setup("require_mfa policy").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let username = format!("mfa-user-{}", support::unique());
    let password = "CorrectHorse9!";
    register_verified_user(
        &env.app,
        &env.pool,
        &env.root_tenant_id,
        &username,
        password,
    )
    .await;

    // このユーザー限定の require_mfa ポリシーを作成する。
    let user_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("find user");
    let uri = format!("/{}/admin/authentication-policies", env.root_tenant_id);
    let code = format!("it-mfa-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "MFA required for this user",
                "priority": 1,
                "effect": "require_mfa",
                "user_ids": [user_id],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create require_mfa policy");

    // TOTP 未設定のため、単一要素（パスワードのみ）ではログインを完了できない（仕様 §24.4）。
    let authorize_uri = authorize_uri_openid_only(&env.root_tenant_id, &client_id);
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "mfa_enrollment_required",
        "single factor must not complete: {body}"
    );

    // 対象外のユーザーには適用されない（条件は AND・user_ids 限定）。
    let other = format!("other-user-{}", support::unique());
    register_verified_user(&env.app, &env.pool, &env.root_tenant_id, &other, password).await;
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &other,
        password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "success",
        "policy is scoped to user: {body}"
    );
}

/// レビュー修正の回帰テスト: `must_change_password`（管理者作成・パスワード再発行）ユーザーに
/// `require_mfa` ポリシーが一致する場合、強制パスワード変更フローの完了で SSO・code を発行しない
/// （TOTP 未設定なら単一要素での成立を拒否する。仕様 §24.4）。
#[tokio::test]
async fn require_mfa_policy_is_enforced_after_forced_password_change() {
    let Some(env) = support::setup("require_mfa after forced change").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    // 管理者が利用者を作成する（自動生成パスワード・must_change_password 付き）。
    let username = format!("forced-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &format!("/{}/admin/users", env.root_tenant_id),
            json!({
                "email": format!("{username}@example.com"),
                "preferred_username": username,
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "admin creates user");
    let created = body_json(res).await;
    let user_id = created["user_id"].as_str().expect("user id").to_string();
    let generated_password = created["generated_password"]
        .as_str()
        .expect("generated password")
        .to_string();

    // このユーザー限定の require_mfa ポリシーを作成する。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &format!("/{}/admin/authentication-policies", env.root_tenant_id),
            json!({
                "policy_code": format!("it-forced-mfa-{}", support::unique()),
                "policy_name": "MFA after forced change",
                "priority": 1,
                "effect": "require_mfa",
                "user_ids": [user_id],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create policy");

    // ログイン → password_change_required。
    let authorize_uri = authorize_uri_openid_only(&env.root_tenant_id, &client_id);
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        &generated_password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "password_change_required",
        "generated password forces change: {body}"
    );
    // パスワード検証を通った時点で `auth_session_id` は再生成される（SEC7）。以降は応答が返した
    // 新しい値を使う（web も Cookie を差し替える）。CSRF トークンも新しい id から導出し直す。
    let auth_session = body["auth_session_id"]
        .as_str()
        .expect("rotated auth_session_id")
        .to_string();
    let csrf = login_csrf(&auth_session, &env.csrf_secret);

    // 強制パスワード変更を完了しても、SSO・code は発行されず MFA 設定を要求される。
    let change_body = json!({
        "tenant_id": env.root_tenant_id,
        "auth_session_id": auth_session,
        "current_password": generated_password,
        "new_password": "NewSecurePass9!",
        "csrf_token": csrf,
    });
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/internal/change-password")
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(change_body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "change password call");
    let body = body_json(res).await;
    assert_eq!(
        body["result"], "mfa_enrollment_required",
        "forced-change flow must not bypass require_mfa: {body}"
    );
}
