//! 参加先テナントのログイン画面からのゲストログイン（ADR-0009 §8）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test guest_login
//!
//! 認証してよいのは「当該テナントに ACTIVE なメンバーシップを持つ利用者」（HOME または GUEST）で
//! あり、所属元（HOME）に限らない。ゲストの識別子は所属元テナントの登録簿にあるため、参加先の
//! ログイン画面で解決するには専用の引き方が要る（`UserRepository::find_active_guest_by_login_identifier`）。
//! 検証する保証:
//!
//! 1. **ゲストは参加先テナントのログイン画面から入れる**（OIDC 認可フロー・ポータル・管理
//!    コンソールの 3 経路とも）。
//!    テナント作成者は作成先の ACTIVE GUEST 管理者になる（§4）ので、これが無いと自分が作った
//!    テナントのコンソールへ直接ログインできない。
//! 2. **メンバーでないテナントからは入れない**（テナント境界。資格情報が正しくても解決しない）。
//! 3. **停止中（SUSPENDED）のゲストは入れない**（MT24。停止はアクセスを止める手段として効く）。
//! 4. **所属元テナントが DISABLED のゲストは入れない** —— 所属元の無効化はその組織の利用者を
//!    止める操作であって、参加先テナント経由の裏口を残す意味ではない。無効化したテナント自身の
//!    利用者も、内部 API 経由で入れない。
//! 5. **参加先の同名 HOME 利用者を巻き添えにしない**（解決は所属元優先。同じユーザー名のゲストが
//!    参加してきても、そのテナントの HOME 利用者は従来どおり解決される）。

mod support;

use axum::http::StatusCode;
use idp_api::application::login::csrf_token;
use serde_json::json;
use support::{
    begin_login, body_json, create_sso_session, get, mark_email_verified, patch, post,
    post_internal, register_user, send, setup as support_setup, unique, TestEnv, CODE_CHALLENGE,
    REDIRECT_URI_ENC, SERVICE_TOKEN,
};

async fn setup() -> Option<TestEnv> {
    support_setup("guest login").await
}

/// 所属元を root とする、パスワードの分かっている利用者を 1 人作る（自己登録 → メール検証済み）。
/// 返すのは `(user_id, username, password)`。
async fn create_home_user(env: &TestEnv) -> (String, String, String) {
    let username = format!("guest{}", unique());
    let password = format!("guest-password-{}", unique());
    register_user(&env.app, &env.root_tenant_id, &username, &password).await;
    mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;
    let user_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("registered user");
    (user_id, username, password)
}

/// root がテナントを作成し、その ID を返す（作成者は当該テナントの ACTIVE GUEST 管理者になる）。
async fn create_tenant(env: &TestEnv, root_cookie: &str, name: &str) -> String {
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
    body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string()
}

/// `user_id` を `tenant_id` の ACTIVE な GUEST にする（招待の作成 → 本人による承諾）。
async fn invite_and_accept(env: &TestEnv, admin_cookie: &str, tenant_id: &str, user_id: &str) {
    let res = send(
        &env.app,
        post(
            admin_cookie,
            &format!("/{tenant_id}/admin/invitations"),
            json!({ "user_id": user_id }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "invitation created");
    let token = body_json(res).await["token"]
        .as_str()
        .expect("token")
        .to_string();

    let guest_cookie = create_sso_session(&env.pool, user_id).await;
    let res = send(
        &env.app,
        post(
            &guest_cookie,
            &format!("/{tenant_id}/invitations/accept"),
            json!({ "token": token }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "accept invitation");
}

/// ポータルログイン（`/{tenant}/login` の実体）を 1 回試し、`result` タグを返す。
///
/// `ip` はテスト関数ごとに変える。IP 単位のレートリミッタはプロセス内メモリで、同一バイナリ内で
/// 並行に走るテストがバケツを共有するため。
async fn portal_login_result(
    env: &TestEnv,
    tenant: &str,
    ip: &str,
    username: &str,
    password: &str,
) -> String {
    login_result(
        env,
        "/internal/authenticate/portal",
        tenant,
        ip,
        username,
        password,
    )
    .await
}

/// 管理コンソールのログイン（`/{tenant}/admin/login` の実体）を 1 回試し、`result` タグを返す。
async fn admin_login_result(
    env: &TestEnv,
    tenant: &str,
    ip: &str,
    username: &str,
    password: &str,
) -> String {
    login_result(
        env,
        "/internal/authenticate/admin",
        tenant,
        ip,
        username,
        password,
    )
    .await
}

async fn login_result(
    env: &TestEnv,
    uri: &str,
    tenant: &str,
    ip: &str,
    username: &str,
    password: &str,
) -> String {
    let response = send(
        &env.app,
        post_internal(
            uri,
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "username": username,
                "password": password,
                "ip_address": ip,
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    body_json(response).await["result"]
        .as_str()
        .expect("result tag")
        .to_string()
}

/// 保証 1・2: 参加先テナントのポータルログイン画面からゲストが入れる。メンバーでないテナントの
/// 同じ画面では、同じ資格情報でも解決しない（テナント境界）。
#[tokio::test]
async fn guest_signs_in_from_the_host_tenant_portal() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_cookie, "GuestPortalHost").await;
    let stranger = create_tenant(&env, &root_cookie, "GuestPortalStranger").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_cookie, &host, &user_id).await;

    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.11", &username, &password).await,
        "success",
        "an active guest must be able to sign in on the host tenant's login screen"
    );
    // 所属元テナントからは従来どおり入れる（ゲスト解決を足しても HOME 経路は変わらない）。
    assert_eq!(
        portal_login_result(
            &env,
            &env.root_tenant_id,
            "203.0.113.12",
            &username,
            &password
        )
        .await,
        "success",
        "the home tenant keeps working"
    );
    // メンバーシップの無いテナントでは解決しない。
    assert_eq!(
        portal_login_result(&env, &stranger, "203.0.113.13", &username, &password).await,
        "invalid_credentials",
        "a tenant the user is not a member of must not resolve the identifier"
    );
}

/// 保証 1: テナント作成者（ACTIVE GUEST 管理者）は、作成したテナントの管理コンソールへ直接
/// ログインできる。root で入ってテナントスイッチする以外に道が無い、という状態にしない。
#[tokio::test]
async fn guest_admin_signs_in_to_the_host_tenant_console() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_cookie, "GuestConsoleHost").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_cookie, &host, &user_id).await;

    // 権限が無いうちは「利用者は特定できたが管理者ではない」= forbidden（解決自体は成功している）。
    assert_eq!(
        admin_login_result(&env, &host, "203.0.113.21", &username, &password).await,
        "forbidden",
        "resolved but not an admin yet"
    );

    let res = send(
        &env.app,
        post(
            &root_cookie,
            &format!("/{host}/admin/users/{user_id}/permissions"),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.tenant.admin");

    assert_eq!(
        admin_login_result(&env, &host, "203.0.113.22", &username, &password).await,
        "success",
        "a guest tenant admin must be able to sign in to that tenant's console"
    );
}

/// 保証 3: 停止中（SUSPENDED）のゲストは参加先の画面から入れない。停止は「メンバーシップ行と
/// 権限行を残したままアクセスだけを止める」手段（MT24）なので、ここが効かないと止められない。
#[tokio::test]
async fn suspended_guest_cannot_sign_in_on_the_host_tenant() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_cookie, "GuestSuspendHost").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_cookie, &host, &user_id).await;

    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.31", &username, &password).await,
        "success",
        "active guest signs in"
    );

    let res = send(
        &env.app,
        patch(
            &root_cookie,
            &format!("/{host}/admin/members/{user_id}"),
            json!({ "status": "SUSPENDED" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "suspend membership");

    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.32", &username, &password).await,
        "invalid_credentials",
        "a suspended guest must not sign in on the host tenant"
    );
    // 所属元テナントへは引き続き入れる（停止したのは参加先へのアクセスだけ）。
    assert_eq!(
        portal_login_result(
            &env,
            &env.root_tenant_id,
            "203.0.113.33",
            &username,
            &password
        )
        .await,
        "success",
        "suspension is scoped to the host tenant"
    );
}

/// 保証 5: 参加先に同じユーザー名の HOME 利用者が居ても、その HOME 利用者は従来どおり解決される
/// （解決は所属元優先。1 回で引くと「曖昧」になって双方が締め出される）。
#[tokio::test]
async fn a_same_named_guest_does_not_lock_out_the_host_tenants_home_user() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_cookie, "GuestClashHost").await;

    // host 側の HOME 利用者（自己登録を一時的に許可して、パスワードの分かる利用者を作る）。
    sqlx::query("UPDATE tenants SET self_registration_enabled = 1 WHERE id = ?")
        .bind(&host)
        .execute(&env.pool)
        .await
        .expect("enable self-registration on the host tenant");
    let shared_username = format!("clash{}", unique());
    let home_password = format!("home-password-{}", unique());
    register_user(&env.app, &host, &shared_username, &home_password).await;
    mark_email_verified(&env.pool, &host, &shared_username).await;

    // 同じユーザー名を持つ root 所属の利用者を host のゲストにする。
    let guest_password = format!("guest-password-{}", unique());
    register_user(
        &env.app,
        &env.root_tenant_id,
        &shared_username,
        &guest_password,
    )
    .await;
    mark_email_verified(&env.pool, &env.root_tenant_id, &shared_username).await;
    let guest_id =
        support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &shared_username)
            .await
            .expect("registered guest");
    invite_and_accept(&env, &root_cookie, &host, &guest_id).await;

    // host の HOME 利用者は自分のパスワードで入れる。
    assert_eq!(
        portal_login_result(
            &env,
            &host,
            "203.0.113.41",
            &shared_username,
            &home_password
        )
        .await,
        "success",
        "the host tenant's own user must keep signing in"
    );
    // 同名のゲストは、host では自分のパスワードでは解決されない（所属元優先で HOME が勝つ）。
    // 所属元テナントからは従来どおり入れる。
    assert_eq!(
        portal_login_result(
            &env,
            &host,
            "203.0.113.42",
            &shared_username,
            &guest_password
        )
        .await,
        "invalid_credentials",
        "the home user wins the name on the host tenant"
    );
    assert_eq!(
        portal_login_result(
            &env,
            &env.root_tenant_id,
            "203.0.113.43",
            &shared_username,
            &guest_password
        )
        .await,
        "success",
        "the guest still signs in on their home tenant"
    );
}

/// 保証 1: RP から参加先テナントの `/authorize` に来たゲストが、そのままログイン画面で認証を
/// 済ませて認可コードを受け取れる（SSO セッションを所属元テナントで先に作っておく必要がない）。
///
/// ここが通らないと、参加先の RP を踏んだゲストは「自分の所属元テナント ID を URL に打ち込んで
/// 一度ログインしてから戻る」以外に進む道が無い。
#[tokio::test]
async fn guest_completes_the_authorization_flow_on_the_host_tenant() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_cookie, "GuestAuthorizeHost").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_cookie, &host, &user_id).await;

    // 参加先テナントの RP。`openid` のみなので同意ステップは挟まらない。
    let client_id = support::insert_public_client(&env.pool, &host, &["openid"]).await;
    let authorize_uri = format!(
        "/{host}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}\
         &scope=openid&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
    )
    .replace(char::is_whitespace, "");
    let auth_session = begin_login(&env.app, &host, &authorize_uri).await;

    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": host,
                "auth_session_id": auth_session,
                "username": username,
                "password": password,
                "csrf_token": csrf_token(&auth_session, &env.csrf_secret),
                "ip_address": "203.0.113.51",
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(
        body["result"], "success",
        "a guest must be able to authenticate in the host tenant's authorization flow: {body}"
    );
    let code = support::query_param(body["redirect_to"].as_str().expect("redirect_to"), "code")
        .expect("authorization code");

    let response = support::exchange_code(&env.app, &host, &client_id, &code).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the code issued to a guest exchanges for tokens in the host tenant"
    );
}

/// テナントの状態を管理 API で切り替える（root の system 管理者のみ。MT11）。
///
/// **SQL で直接書き換えない。** テナント解決は TTL キャッシュ越しで、無効化を反映させるには
/// 更新時の invalidate が要る。DB だけ書き換えると、キャッシュが生きている間は「無効化したのに
/// 解決できる」状態をテストが観測してしまい、本番の経路（管理 API → invalidate）を検証できない。
async fn set_tenant_status(env: &TestEnv, root_cookie: &str, tenant_id: &str, status: &str) {
    let res = send(
        &env.app,
        patch(
            root_cookie,
            &format!("/{}/admin/tenants/{tenant_id}", env.root_tenant_id),
            json!({ "status": status }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "set tenant {tenant_id} to {status}"
    );
}

/// 保証 4: 所属元テナントを無効化すると、参加先テナントのログイン画面からも入れなくなる。
///
/// 所属元テナント自身の URL は `TenantResolutionService` が 404 で止めるが、参加先の URL は生きて
/// いる。ここを見ないと「所属元は止めたのに参加先からは入れる」利用者ができる。復帰も確認する
/// （無効化は可逆な操作で、`ACTIVE` へ戻せば元どおり入れる）。
#[tokio::test]
async fn a_guest_whose_home_tenant_is_disabled_cannot_sign_in_anywhere() {
    let Some(env) = setup().await else { return };
    let root_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_cookie, "DisabledHomeHost").await;
    // 所属元を root にすると他テストの共有 root を止めてしまうため、専用の所属元テナントを作る。
    let home = create_tenant(&env, &root_cookie, "DisabledHomeHome").await;
    sqlx::query("UPDATE tenants SET self_registration_enabled = 1 WHERE id = ?")
        .bind(&home)
        .execute(&env.pool)
        .await
        .expect("enable self-registration on the home tenant");

    let username = format!("dis{}", unique());
    let password = format!("guest-password-{}", unique());
    register_user(&env.app, &home, &username, &password).await;
    mark_email_verified(&env.pool, &home, &username).await;
    let user_id = support::find_user_id_by_username(&env.pool, &home, &username)
        .await
        .expect("registered user");
    invite_and_accept(&env, &root_cookie, &host, &user_id).await;

    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.61", &username, &password).await,
        "success",
        "baseline: the guest signs in on the host tenant while their home tenant is active"
    );

    set_tenant_status(&env, &root_cookie, &home, "DISABLED").await;

    // パスワード経路（解決クエリの `home.status = 'ACTIVE'`）。
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.62", &username, &password).await,
        "invalid_credentials",
        "a guest whose home tenant is disabled must not sign in on the host tenant"
    );
    // 所属元テナント自身のログインも止まる（無効化したテナントの利用者はどこからも入れない）。
    // 内部 API はテナントプレフィクスを持たず `TenantResolver` を通らないため、`DISABLED` の拒否は
    // `require_internal_tenant` が担う。資格情報を見る前に 400 で落ちる。
    let res = send(
        &env.app,
        post_internal(
            "/internal/authenticate/portal",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": home,
                "username": username,
                "password": password,
                "ip_address": "203.0.113.63",
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a disabled tenant must be rejected by the internal auth API before credentials are checked"
    );

    // 既存の SSO セッション経由（`is_active_member`）も止まる。管理コンソールの入口で確認する。
    let sso = create_sso_session(&env.pool, &user_id).await;
    let res = send(&env.app, get(&sso, &format!("/{host}/admin/whoami"))).await;
    assert_ne!(
        res.status(),
        StatusCode::OK,
        "an existing SSO session must not grant access once the home tenant is disabled"
    );

    // 復帰: 所属元を ACTIVE へ戻せば元どおり入れる。
    set_tenant_status(&env, &root_cookie, &home, "ACTIVE").await;
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.64", &username, &password).await,
        "success",
        "re-enabling the home tenant restores access"
    );
}
