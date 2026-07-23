//! テナント間分離・権限境界の E2E 統合テスト（MT16、ADR-0009 §1・§3・§4・§6・§8）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test tenant_isolation
//!
//! MariaDB に RLS はなく、アプリ層が唯一の分離防御線であるため、negative test を必須ケースとして
//! 検証する（ADR-0009 §8）。検証する保証:
//!
//! 1. **root は作成できるが内部を操作できない**（§1・§4・§9）: `idp.system.admin`（scope = root）は
//!    テナントを作成できるが、作成したテナントの管理 API には一律 403。内部を操作できるのは当該
//!    テナント scope の `idp.tenant.admin` のみ。
//! 2. **権限境界の完全一致**（§4）: `idp.tenant.admin` の scope は当該テナントのみに及び、他テナント
//!    （root を含む）の管理 API・システム設定・テナント作成には一律 403。`idp.system.admin` の
//!    scope = root は DB CHECK 制約でも強制される。
//! 3. **テナント間データ分離**（§8）: 利用者・クライアントは他テナントの管理 API から見えない
//!    （一覧に現れない・検索/取得は 404）。
//! 4. **ゲスト保護**（§3）: 招待トークンは本人 + 当該テナントでのみ承諾でき、監査ログに漏れない。
//!    参加先管理者はゲストの `users` レコードを操作できず、メンバーシップ解除と scope 権限の
//!    後始末のみ行える。HOME メンバーシップは解除できない。
//! 5. **OIDC フローのメンバーシップ判定と issuer 分離**（§6・§8）: メンバーシップのない SSO
//!    セッションは当該テナントのフローで未認証扱い。テナント A 発行のアクセストークンは
//!    テナント B の `/userinfo` で拒否される（`iss` 完全一致）。ゲストはメンバーシップ承諾後に
//!    参加先テナントのフローへ SSO で参加できる。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{Request, StatusCode};
use serde_json::json;
use sqlx::Row;
use support::{
    authorize_uri_openid_only as authorize_uri, body_json, create_sso_session, delete,
    exchange_code, get, location, post, query_param, send, setup as support_setup, unique, TestEnv,
    REDIRECT_URI,
};

async fn setup() -> Option<TestEnv> {
    support_setup("tenant isolation").await
}

/// API 経由で作成したテナントと、その正式な HOME 管理者。
struct CreatedTenant {
    id: String,
    admin_id: String,
    admin_cookie: String,
}

/// テナント作成のブートストラップフローを実行し、正式な HOME 管理者を用意する（ADR-0009 §4）。手順:
///   1. root がテナントを作成 → root が新テナントの ACTIVE GUEST 管理者になる。
///   2. root（ブートストラップ管理者）が正式な HOME 管理者を作成する。
///   3. その HOME 管理者へ `idp.tenant.admin` を付与する。
///
/// 返す `admin_id`/`admin_cookie` はこの HOME 管理者のもの。作成者（root）はこの時点でも当該テナントの
/// ゲスト管理者のまま残る（各テストは HOME 管理者の Cookie で内部を操作する。root の離脱は
/// [`root_leaves_tenant`] を明示的に呼ぶテストでのみ行い、共有 root 行に対する DELETE 競合を避ける）。
async fn create_tenant(env: &TestEnv, root_cookie: &str, name: &str) -> CreatedTenant {
    // 1. root がテナントを作成（root が ACTIVE GUEST + idp.tenant.admin を得る）。
    let res = send(
        &env.app,
        post(
            root_cookie,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": name }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create tenant {name}");
    let id = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();

    // 2. root（ブートストラップ管理者）が正式な HOME 管理者を作成する。
    let admin_email = format!("owner-{}@{}.example.com", unique(), name.to_lowercase());
    let res = send(
        &env.app,
        post(
            root_cookie,
            &format!("/{id}/admin/users"),
            json!({ "email": admin_email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create home admin");
    let admin_id = body_json(res).await["user_id"]
        .as_str()
        .expect("admin id")
        .to_string();

    // 3. HOME 管理者へ idp.tenant.admin を付与する。
    let res = send(
        &env.app,
        post(
            root_cookie,
            &format!("/{id}/admin/users/{admin_id}/permissions"),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.tenant.admin");

    let admin_cookie = create_sso_session(&env.pool, &admin_id).await;
    CreatedTenant {
        id,
        admin_id,
        admin_cookie,
    }
}

/// 作成者（root）が自身のゲストメンバーシップを解除して当該テナントから離脱する（解除時に当該テナント
/// scope の権限行も後始末される。ADR-0009 §3・§4）。離脱後は root は当該テナント内部を操作できない。
async fn root_leaves_tenant(env: &TestEnv, root_cookie: &str, tenant_id: &str) {
    let res = send(
        &env.app,
        delete(
            root_cookie,
            &format!("/{tenant_id}/admin/members/{}", env.root_admin_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "root leaves the tenant"
    );
}

/// テナント管理者として利用者を作成し `(user_id, email)` を返す。
async fn create_user(env: &TestEnv, admin_cookie: &str, tenant_id: &str) -> (String, String) {
    let email = format!("user-{}@example.com", unique());
    let res = send(
        &env.app,
        post(
            admin_cookie,
            &format!("/{tenant_id}/admin/users"),
            json!({ "email": email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create user");
    let created = body_json(res).await;
    (
        created["user_id"].as_str().expect("user id").to_string(),
        email,
    )
}

/// `openid` のみの scope の public client を登録する（同意ステップ不要）。
async fn insert_public_client(pool: &sqlx::MySqlPool, tenant_id: &str) -> String {
    support::insert_public_client(pool, tenant_id, &["openid"]).await
}

/// 保証 1: root（idp.system.admin）はテナントを作成でき、ブートストラップ中は内部を操作できるが、
/// 自身のゲストメンバーシップを解除して離脱したあとは、作成したテナントの内部（管理 API 全般）に
/// 一律 403 で触れない。内部を操作できるのは当該テナント scope の idp.tenant.admin のみ。
#[tokio::test]
async fn root_can_create_but_cannot_operate_inside_created_tenant() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let tenant = create_tenant(&env, &root_cookie, "Inner").await;
    // ブートストラップ完了後、作成者（root）は自身のゲストメンバーシップを解除して離脱する。
    root_leaves_tenant(&env, &root_cookie, &tenant.id).await;

    // 離脱後の root の system 管理者は、作成した子テナントの管理 API へ一切アクセスできない（§4・§9）。
    let forbidden_requests = vec![
        get(&root_cookie, &format!("/{}/admin/whoami", tenant.id)),
        get(&root_cookie, &format!("/{}/admin/members", tenant.id)),
        get(&root_cookie, &format!("/{}/admin/clients", tenant.id)),
        get(&root_cookie, &format!("/{}/admin/audit-logs", tenant.id)),
        get(
            &root_cookie,
            &format!("/{}/admin/settings/tenant", tenant.id),
        ),
        get(&root_cookie, &format!("/{}/admin/signing-keys", tenant.id)),
        post(
            &root_cookie,
            &format!("/{}/admin/users", tenant.id),
            json!({ "email": "intruder@example.com" }),
        ),
        post(
            &root_cookie,
            &format!("/{}/admin/clients", tenant.id),
            json!({
                "app_name": "X",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
        post(
            &root_cookie,
            &format!("/{}/admin/invitations", tenant.id),
            json!({ "user_id": env.root_admin_id }),
        ),
        delete(
            &root_cookie,
            &format!("/{}/admin/members/{}", tenant.id, tenant.admin_id),
        ),
        // 子テナント側でのテナント作成も root にはできない（system.admin の scope は root のみ）。
        post(
            &root_cookie,
            &format!("/{}/admin/tenants", tenant.id),
            json!({ "name": "Grand" }),
        ),
    ];
    for req in forbidden_requests {
        let (method, uri) = (req.method().clone(), req.uri().to_string());
        let res = send(&env.app, req).await;
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "root system admin must get 403 for {method} {uri}"
        );
    }

    // 当該テナントの管理者（idp.tenant.admin）は内部を操作できる。
    let res = send(
        &env.app,
        get(
            &tenant.admin_cookie,
            &format!("/{}/admin/whoami", tenant.id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "tenant admin whoami");
    assert_eq!(
        body_json(res).await["user_id"].as_str(),
        Some(tenant.admin_id.as_str())
    );

    // システム設定は idp.system.admin（scope = root）のみ: root では 200、テナント管理者は自
    // テナントでも 403（§9）。
    let res = send(
        &env.app,
        get(
            &root_cookie,
            &format!("/{}/admin/system-settings", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "root reads system settings");
    let res = send(
        &env.app,
        get(
            &tenant.admin_cookie,
            &format!("/{}/admin/system-settings", tenant.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "tenant admin cannot read system settings even in own tenant"
    );
}

/// 保証 2・3: idp.tenant.admin の権限境界は scope テナントとの完全一致で判定され、
/// 他テナント（root を含む）へは一律 403。データ（利用者・クライアント）も他テナントから見えない。
#[tokio::test]
async fn tenant_admin_boundary_is_exact_match_and_data_is_isolated() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let a = create_tenant(&env, &root_cookie, "AlphaCo").await;
    let b = create_tenant(&env, &root_cookie, "BravoCo").await;

    // A の管理者は B・root の管理 API に一切アクセスできない（完全一致。祖先・兄弟は無関係。§4）。
    let cross_tenant_requests = vec![
        get(&a.admin_cookie, &format!("/{}/admin/whoami", b.id)),
        get(&a.admin_cookie, &format!("/{}/admin/members", b.id)),
        get(&a.admin_cookie, &format!("/{}/admin/clients", b.id)),
        get(
            &a.admin_cookie,
            &format!("/{}/admin/whoami", env.root_tenant_id),
        ),
        get(
            &a.admin_cookie,
            &format!("/{}/admin/tenants", env.root_tenant_id),
        ),
        post(
            &a.admin_cookie,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": "Rogue" }),
        ),
        delete(
            &a.admin_cookie,
            &format!("/{}/admin/tenants/{}", env.root_tenant_id, b.id),
        ),
        get(
            &a.admin_cookie,
            &format!("/{}/admin/system-settings", env.root_tenant_id),
        ),
    ];
    for req in cross_tenant_requests {
        let (method, uri) = (req.method().clone(), req.uri().to_string());
        let res = send(&env.app, req).await;
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "tenant A admin must get 403 for {method} {uri}"
        );
    }

    // データ分離: A のクライアントは B の一覧に現れない（§8）。
    let res = send(
        &env.app,
        post(
            &a.admin_cookie,
            &format!("/{}/admin/clients", a.id),
            json!({
                "app_name": "Alpha App",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "A creates own client");
    let a_client_id = body_json(res).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let res = send(
        &env.app,
        get(&b.admin_cookie, &format!("/{}/admin/clients", b.id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let b_clients = body_json(res).await;
    assert!(
        b_clients
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["client_id"].as_str() != Some(a_client_id.as_str())),
        "tenant A's client must not appear in tenant B's list"
    );
    // B から A のクライアントを直接取得しても 404（存在を漏らさない）。
    let res = send(
        &env.app,
        get(
            &b.admin_cookie,
            &format!("/{}/admin/clients/{a_client_id}", b.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant client -> 404"
    );

    // データ分離: A の利用者は B から検索・取得できない（不存在と同じ 404。§8）。
    let (a_user_id, a_user_email) = create_user(&env, &a.admin_cookie, &a.id).await;
    let res = send(
        &env.app,
        get(
            &b.admin_cookie,
            &format!("/{}/admin/users?q={a_user_email}", b.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant search -> 404"
    );
    let res = send(
        &env.app,
        get(
            &b.admin_cookie,
            &format!("/{}/admin/users/{a_user_id}", b.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant get -> 404"
    );
    // 権限の付与・参照もテナント越しには不可（対象は所属元テナント限定）。
    let res = send(
        &env.app,
        post(
            &b.admin_cookie,
            &format!("/{}/admin/users/{a_user_id}/permissions", b.id),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "cross-tenant permission grant -> 404"
    );

    // idp.system.admin の付与は保有者のみ（テナント管理者は自テナントでも 403。§4）。
    let res = send(
        &env.app,
        post(
            &a.admin_cookie,
            &format!("/{}/admin/users/{a_user_id}/permissions", a.id),
            json!({ "permission_code": "idp.system.admin" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "tenant admin cannot grant idp.system.admin"
    );

    // DB レベルの二重防御: idp.system.admin は root 以外の scope で存在できない（CHECK 制約。§4）。
    let direct_insert = sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, 'idp.system.admin', ?)",
    )
    .bind(&a_user_id)
    .bind(&a.id)
    .execute(&env.pool)
    .await;
    assert!(
        direct_insert.is_err(),
        "DB CHECK must reject idp.system.admin scoped to a non-root tenant"
    );

    // 利用者・クライアントが残るテナントは root でも削除できない（ON DELETE RESTRICT → 409。§1）。
    let res = send(
        &env.app,
        delete(
            &root_cookie,
            &format!("/{}/admin/tenants/{}", env.root_tenant_id, a.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "tenant with users/clients cannot be deleted"
    );
}

/// 保証 4: 招待はトークン所持 + 被招待者本人のログイン済みセッション + 当該テナントの承諾経路が
/// すべて揃って初めて成立する。参加先管理者はゲストの users レコードに触れず、解除時は scope 権限
/// だけが後始末される（ゲストの本体・他テナント scope は残る）。HOME は解除できない。
#[tokio::test]
async fn guest_invitation_protects_user_state_and_cleans_up_scoped_permissions() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_cookie, "HostCo").await;
    let home = create_tenant(&env, &root_cookie, "HomeCo").await;

    // ゲスト候補は所属元（home）テナントの利用者。
    let (guest_id, guest_email) = create_user(&env, &home.admin_cookie, &home.id).await;
    let guest_cookie = create_sso_session(&env.pool, &guest_id).await;

    // host の管理者が招待を作成 → トークンは応答で一度だけ返り、監査ログに漏れない（§3）。
    let res = send(
        &env.app,
        post(
            &host.admin_cookie,
            &format!("/{}/admin/invitations", host.id),
            json!({ "user_id": guest_id }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "invitation created");
    let invitation = body_json(res).await;
    let token = invitation["token"].as_str().expect("token").to_string();
    assert!(token.len() >= 32, "invitation token is high-entropy");
    let leaked: i64 = sqlx::query("SELECT COUNT(*) AS c FROM audit_log WHERE reason LIKE ?")
        .bind(format!("%{token}%"))
        .fetch_one(&env.pool)
        .await
        .expect("audit scan")
        .get::<i64, _>("c");
    assert_eq!(leaked, 0, "invitation token must not appear in audit log");

    // 承諾は被招待者本人のみ（他人のセッション → 403）。
    let accept_uri = format!("/{}/invitations/accept", host.id);
    let res = send(
        &env.app,
        post(&host.admin_cookie, &accept_uri, json!({ "token": token })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "non-invitee -> 403");

    // 承諾は当該テナントの経路のみ（別テナントの accept へ提示 → 400）。
    let res = send(
        &env.app,
        post(
            &guest_cookie,
            &format!("/{}/invitations/accept", home.id),
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "wrong tenant -> 400");

    // 本人 + 正しいテナント → 204。メンバーシップが ACTIVE / GUEST になる。
    let res = send(
        &env.app,
        post(&guest_cookie, &accept_uri, json!({ "token": token })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "accept -> 204");
    let (mtype, mstatus): (String, String) = sqlx::query_as(
        "SELECT membership_type, status FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?",
    )
    .bind(&host.id)
    .bind(&guest_id)
    .fetch_one(&env.pool)
    .await
    .expect("membership row");
    assert_eq!((mtype.as_str(), mstatus.as_str()), ("GUEST", "ACTIVE"));

    // トークンの再利用（リプレイ）は不可。
    let res = send(
        &env.app,
        post(&guest_cookie, &accept_uri, json!({ "token": token })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "token replay -> 400");

    // ゲストはメンバー一覧に GUEST として現れる。
    let res = send(
        &env.app,
        get(&host.admin_cookie, &format!("/{}/admin/members", host.id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let members = body_json(res).await;
    let guest_entry = members
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user_id"].as_str() == Some(guest_id.as_str()))
        .expect("guest appears in member list");
    assert_eq!(guest_entry["membership_type"], "GUEST");

    // 参加先管理者はゲストの users レコードへ到達できない（取得・検索とも 404。§3）。
    let res = send(
        &env.app,
        get(
            &host.admin_cookie,
            &format!("/{}/admin/users/{guest_id}", host.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "guest user record -> 404"
    );
    let res = send(
        &env.app,
        get(
            &host.admin_cookie,
            &format!("/{}/admin/users?q={guest_email}", host.id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "guest user search -> 404"
    );

    // メンバーシップだけでは管理 API に触れない（権限なし → 403）。
    let res = send(
        &env.app,
        get(&guest_cookie, &format!("/{}/admin/whoami", host.id)),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "guest without perms -> 403"
    );

    // HOME メンバーシップは解除できない（§3）。
    let res = send(
        &env.app,
        delete(
            &host.admin_cookie,
            &format!("/{}/admin/members/{}", host.id, host.admin_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "HOME revoke -> 403");

    // ゲスト解除時は host scope の権限行だけが後始末され、ゲスト本体・他 scope は残る（§3）。
    // （scope 権限は DB 直接投入で用意する。付与 API は所属元限定のため。）
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, 'idp.tenant.admin', ?), (?, 'idp.tenant.admin', ?)",
    )
    .bind(&guest_id)
    .bind(&host.id)
    .bind(&guest_id)
    .bind(&home.id)
    .execute(&env.pool)
    .await
    .expect("seed guest permissions");
    let res = send(
        &env.app,
        delete(
            &host.admin_cookie,
            &format!("/{}/admin/members/{guest_id}", host.id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "guest revoke -> 204");
    let membership_left: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?",
    )
    .bind(&host.id)
    .bind(&guest_id)
    .fetch_one(&env.pool)
    .await
    .unwrap()
    .get::<i64, _>("c");
    assert_eq!(membership_left, 0, "guest membership removed");
    let scoped: Vec<String> =
        sqlx::query_scalar("SELECT tenant_id FROM user_permissions WHERE user_id = ?")
            .bind(&guest_id)
            .fetch_all(&env.pool)
            .await
            .unwrap();
    assert_eq!(
        scoped,
        vec![home.id.clone()],
        "only host-scoped permission rows are cleaned up"
    );
    let (still_home, status): (String, String) =
        sqlx::query_as("SELECT tenant_id, status FROM users WHERE id = ?")
            .bind(&guest_id)
            .fetch_one(&env.pool)
            .await
            .expect("guest user still exists");
    assert_eq!(
        still_home, home.id,
        "guest user record remains in home tenant"
    );
    assert_eq!(status, "ACTIVE", "guest user state untouched by host admin");
}

/// 保証 5: OIDC フローはメンバーシップ判定と per-tenant issuer で分離される。
/// - メンバーシップのない SSO セッションは当該テナントで未認証扱い（ログインへ）。
/// - テナント A 発行のアクセストークンはテナント B の /userinfo で拒否される（iss 完全一致）。
/// - クライアントもテナント境界を越えて解決されない。
/// - ゲストは承諾後、参加先テナントのフローへ SSO で参加できる。
#[tokio::test]
async fn oidc_flow_enforces_membership_and_per_tenant_issuer() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let a = create_tenant(&env, &root_cookie, "OidcA").await;
    let b = create_tenant(&env, &root_cookie, "OidcB").await;
    let client_a = insert_public_client(&env.pool, &a.id).await;
    let client_b = insert_public_client(&env.pool, &b.id).await;

    // テナント A の利用者（HOME メンバーシップ付き）と、その SSO セッション。
    let (user_a, _) = create_user(&env, &a.admin_cookie, &a.id).await;
    let sso_cookie = create_sso_session(&env.pool, &user_a).await;

    // メンバーシップのないテナント B のフローでは未認証扱い（code は出ずログインへ。§8）。
    let res = send(
        &env.app,
        Request::builder()
            .uri(authorize_uri(&b.id, &client_b))
            .header(COOKIE, format!("sso_session_id={sso_cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert_eq!(
        location(&res),
        format!("/{}/login", b.id),
        "SSO session without membership must not resume in tenant B"
    );

    // 所属元テナント A では SSO で code が発行される。
    let res = send(
        &env.app,
        Request::builder()
            .uri(authorize_uri(&a.id, &client_a))
            .header(COOKIE, format!("sso_session_id={sso_cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let callback = location(&res);
    assert!(
        callback.starts_with(REDIRECT_URI),
        "expected code redirect, got {callback}"
    );
    let code = query_param(&callback, "code").expect("authorization code");

    // A の code を B の /token で使うと client がテナント境界で解決されず拒否される。
    let res = exchange_code(&env.app, &b.id, &client_a, &code).await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "tenant A client must not resolve in tenant B token endpoint"
    );

    // 正しいテナント A の /token では交換できる。
    let res = exchange_code(&env.app, &a.id, &client_a, &code).await;
    assert_eq!(res.status(), StatusCode::OK, "token exchange in tenant A");
    let tokens = body_json(res).await;
    let access_token = tokens["access_token"].as_str().unwrap().to_string();

    // A 発行のアクセストークンは B の /userinfo で拒否される（iss 完全一致。§6）。
    let res = send(
        &env.app,
        Request::builder()
            .uri(format!("/{}/userinfo", b.id))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "tenant A access token must be rejected by tenant B userinfo"
    );
    // A の /userinfo では受理される。
    let res = send(
        &env.app,
        Request::builder()
            .uri(format!("/{}/userinfo", a.id))
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "tenant A userinfo accepts");

    // ゲスト参加: B が user_a を招待し、本人が承諾すると B のフローに SSO で参加できる（§8）。
    let res = send(
        &env.app,
        post(
            &b.admin_cookie,
            &format!("/{}/admin/invitations", b.id),
            json!({ "user_id": user_a }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let token = body_json(res).await["token"].as_str().unwrap().to_string();
    let res = send(
        &env.app,
        post(
            &sso_cookie,
            &format!("/{}/invitations/accept", b.id),
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "guest accepts invitation"
    );

    let res = send(
        &env.app,
        Request::builder()
            .uri(authorize_uri(&b.id, &client_b))
            .header(COOKIE, format!("sso_session_id={sso_cookie}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let callback = location(&res);
    assert!(
        callback.starts_with(REDIRECT_URI),
        "guest with ACTIVE membership resumes SSO in tenant B, got {callback}"
    );
    let code_b = query_param(&callback, "code").expect("code for tenant B");

    // ゲストのトークンも B の issuer で発行され、B の /userinfo で使える。
    let res = exchange_code(&env.app, &b.id, &client_b, &code_b).await;
    assert_eq!(res.status(), StatusCode::OK, "guest token exchange in B");
    let guest_tokens = body_json(res).await;
    let guest_access = guest_tokens["access_token"].as_str().unwrap();
    let res = send(
        &env.app,
        Request::builder()
            .uri(format!("/{}/userinfo", b.id))
            .header(AUTHORIZATION, format!("Bearer {guest_access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "guest userinfo in tenant B");
}
