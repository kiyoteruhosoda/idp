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
//! 6. **所属元テナントを無効化すると、発行済みのリフレッシュトークンも次の更新で止まる**（MT27）。
//!    参加先の `/{tenant_id}/token` は生きているため、ここを塞がないと最長で寿命（既定 30 日）
//!    まで更新し続けられる。

mod support;

use assay_api::application::login::csrf_token;
use axum::http::StatusCode;
use serde_json::json;
use support::{
    begin_login, body_json, cookie_post, create_sso_session, exchange_admin_token, get,
    mark_email_verified, patch, post, post_internal, register_user, send, setup as support_setup,
    unique, TestEnv, CODE_CHALLENGE, REDIRECT_URI_ENC, SERVICE_TOKEN,
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
/// SSO セッションを、指定テナント向けの管理トークンへ交換する（ADR-0037）。
async fn tok(env: &TestEnv, sso: &str, tenant_id: &str) -> String {
    exchange_admin_token(&env.app, tenant_id, sso).await
}

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

/// `user_id` を `tenant_id` の ACTIVE な GUEST にする（招待の作成 → 本人による承諾）。
async fn invite_and_accept(env: &TestEnv, admin_sso: &str, tenant_id: &str, user_id: &str) {
    let res = send(
        &env.app,
        post(
            &tok(env, admin_sso, tenant_id).await,
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

    let guest_sso = create_sso_session(&env.pool, user_id).await;
    let res = send(
        &env.app,
        cookie_post(
            &guest_sso,
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
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "GuestPortalHost").await;
    let stranger = create_tenant(&env, &root_sso, "GuestPortalStranger").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_sso, &host, &user_id).await;

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
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "GuestConsoleHost").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_sso, &host, &user_id).await;

    // 権限が無いうちは「利用者は特定できたが管理者ではない」= forbidden（解決自体は成功している）。
    assert_eq!(
        admin_login_result(&env, &host, "203.0.113.21", &username, &password).await,
        "forbidden",
        "resolved but not an admin yet"
    );

    let res = send(
        &env.app,
        post(
            &tok(&env, &root_sso, &host).await,
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
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "GuestSuspendHost").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_sso, &host, &user_id).await;

    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.31", &username, &password).await,
        "success",
        "active guest signs in"
    );

    let res = send(
        &env.app,
        patch(
            &tok(&env, &root_sso, &host).await,
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
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "GuestClashHost").await;

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
    invite_and_accept(&env, &root_sso, &host, &guest_id).await;

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
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "GuestAuthorizeHost").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_sso, &host, &user_id).await;

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
async fn set_tenant_status(env: &TestEnv, root_sso: &str, tenant_id: &str, status: &str) {
    let res = send(
        &env.app,
        patch(
            &tok(env, root_sso, &env.root_tenant_id).await,
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
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "DisabledHomeHost").await;
    // 所属元を root にすると他テストの共有 root を止めてしまうため、専用の所属元テナントを作る。
    let home = create_tenant(&env, &root_sso, "DisabledHomeHome").await;
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
    invite_and_accept(&env, &root_sso, &host, &user_id).await;

    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.61", &username, &password).await,
        "success",
        "baseline: the guest signs in on the host tenant while their home tenant is active"
    );

    set_tenant_status(&env, &root_sso, &home, "DISABLED").await;

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
    // 管理トークンへの交換が拒まれるか、交換できても権限が 0 件で whoami が通らないかの
    // いずれか（どちらで止まるかは実装の詳細で、要件は「入れないこと」。ADR-0037）。
    let sso = create_sso_session(&env.pool, &user_id).await;
    let exchanged = send(
        &env.app,
        post_internal(
            "/internal/admin/token",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": host, "sso_session_id": sso }),
        ),
    )
    .await;
    let denied = if exchanged.status() == StatusCode::OK {
        let token = body_json(exchanged).await["access_token"]
            .as_str()
            .expect("access_token")
            .to_string();
        send(&env.app, get(&token, &format!("/{host}/admin/whoami")))
            .await
            .status()
            != StatusCode::OK
    } else {
        true
    };
    assert!(
        denied,
        "an existing SSO session must not grant access once the home tenant is disabled"
    );

    // 復帰: 所属元を ACTIVE へ戻せば元どおり入れる。
    set_tenant_status(&env, &root_sso, &home, "ACTIVE").await;
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.64", &username, &password).await,
        "success",
        "re-enabling the home tenant restores access"
    );
}

/// 保証 6: 所属元テナントを無効化すると、参加先テナントで発行済みのリフレッシュトークンも
/// 次の更新で止まる（MT27）。
///
/// **無効化したテナント自身の `/{tenant_id}/token` は `TenantResolver` が 404 で止めるが、その
/// 利用者がゲストとして参加している他テナントの `/{tenant_id}/token` は生きている。** ここを
/// 塞がないと、ログインは止まっているのに発行済みトークンだけが寿命（既定 30 日）まで生き残る。
#[tokio::test]
async fn disabling_the_home_tenant_stops_refresh_tokens_issued_by_the_host_tenant() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "RefreshHost").await;
    let home = create_tenant(&env, &root_sso, "RefreshHome").await;
    sqlx::query("UPDATE tenants SET self_registration_enabled = 1 WHERE id = ?")
        .bind(&home)
        .execute(&env.pool)
        .await
        .expect("enable self-registration on the home tenant");

    let username = format!("rt{}", unique());
    let password = format!("guest-password-{}", unique());
    register_user(&env.app, &home, &username, &password).await;
    mark_email_verified(&env.pool, &home, &username).await;
    let user_id = support::find_user_id_by_username(&env.pool, &home, &username)
        .await
        .expect("registered user");
    invite_and_accept(&env, &root_sso, &host, &user_id).await;

    // 参加先テナントの RP から、ゲストがリフレッシュトークンまで取得する。
    let client_id =
        support::insert_public_client(&env.pool, &host, &["openid", "offline_access"]).await;
    let authorize_uri = format!(
        "/{host}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}\
         &scope=openid%20offline_access&state=st&nonce=no&code_challenge={CODE_CHALLENGE}\
         &code_challenge_method=S256"
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
                "ip_address": "203.0.113.71",
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    // `offline_access` は暗黙同意の対象外なので、同意ステップを挟むことがある。
    let callback = if body["result"] == "consent_required" {
        let consent_session = body["auth_session_id"].as_str().expect("auth_session_id");
        let response = send(
            &env.app,
            post_internal(
                "/internal/consent/approve",
                Some(SERVICE_TOKEN),
                json!({ "tenant_id": host, "auth_session_id": consent_session }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "consent approve");
        body_json(response).await["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string()
    } else {
        assert_eq!(body["result"], "success", "guest login: {body}");
        body["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string()
    };
    let code = support::query_param(&callback, "code").expect("authorization code");

    let response = support::exchange_code(&env.app, &host, &client_id, &code).await;
    assert_eq!(response.status(), StatusCode::OK, "guest token exchange");
    let refresh_token = body_json(response).await["refresh_token"]
        .as_str()
        .expect("refresh_token (offline_access)")
        .to_string();

    // 無効化前は更新できる。
    let response = refresh(&env, &host, &client_id, &refresh_token).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "baseline: refresh works while the home tenant is active"
    );
    let rotated = body_json(response).await["refresh_token"]
        .as_str()
        .expect("rotated refresh_token")
        .to_string();

    set_tenant_status(&env, &root_sso, &home, "DISABLED").await;

    // 所属元を止めたら、参加先で発行済みのトークンも更新できない。
    let response = refresh(&env, &host, &client_id, &rotated).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a refresh token must stop once the user's home tenant is disabled"
    );
    let body = body_json(response).await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

/// `refresh_token` grant を 1 回叩く（public client・PKCE なのでクライアント認証は無い）。
async fn refresh(
    env: &TestEnv,
    tenant: &str,
    client_id: &str,
    refresh_token: &str,
) -> axum::response::Response {
    send(
        &env.app,
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/token"))
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(axum::body::Body::from(format!(
                "grant_type=refresh_token&refresh_token={refresh_token}&client_id={client_id}"
            )))
            .unwrap(),
    )
    .await
}

/// 保証 6（MT25）: 所属元テナントで**曖昧**になった入力は、そこで解決を打ち切る。ゲスト解決へ
/// 落として「同じ値を持つゲスト」を認証してはいけない。
///
/// # この状態への到達経路
///
/// 種別ごとに正規化が違うため、1 つの入力が**複数の正規化値**へ広がる。`090-123-4567` は
/// ユーザー名としては `090-123-4567`、電話番号としては区切りを落とした `0901234567` である。
/// この 2 つは別の文字列なので、値の一意制約（migration 0041。テナント内で 1 正規化値 1 人）を
/// すり抜けて別人が持てる。
///
/// 追加時の空き判定は「実際のログイン経路と同じ引き方」で他人に当たる値を拒むが、**無効な行には
/// 当たらない**（無効化した識別子は解決しない）。そこで次の順で、1 つの入力が 2 人に当たる状態を作れる:
///
/// 1. A に電話番号 `0901234567` を**無効な状態で**割り当てる（無効化した既存の識別子と同じ状態）。
/// 2. B がユーザー名 `090-123-4567` を取る。A の行は無効なので空き判定に当たらず、正規化値も
///    違うので一意制約にも当たらない。
/// 3. A の電話番号を有効に戻す。ここで `090-123-4567` は A（電話番号）と B（ユーザー名）の
///    両方に当たる。
///
/// この状態で host のログイン欄に `090-123-4567` を入れると、修正前は「所属元で曖昧」が
/// 「所属元に不在」へ潰れてゲスト解決まで落ち、同じ値をユーザー名に持つゲストが**自分の
/// パスワードで入れて**いた。なりすましではないが、「曖昧なら通さない」「所属元がテナント内の
/// 名前の取り合いに勝つ」という 2 つの決めごとが同時に破れていた。
#[tokio::test]
async fn an_ambiguous_home_identifier_does_not_let_a_guest_sign_in() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "AmbiguousIdentifierHost").await;

    // 同じ入力が 2 通りに正規化される値を選ぶ（電話番号は区切りを落とし、ユーザー名は落とさない）。
    let digits = format!("0{:09}", uuid::Uuid::new_v4().as_u128() % 1_000_000_000);
    let dashed = format!("{}-{}-{}", &digits[0..3], &digits[3..6], &digits[6..10]);

    // host に HOME 利用者を 2 人（自己登録を一時的に許可してパスワードの分かる利用者を作る）。
    sqlx::query("UPDATE tenants SET self_registration_enabled = 1 WHERE id = ?")
        .bind(&host)
        .execute(&env.pool)
        .await
        .expect("enable self-registration on the host tenant");
    let alice = format!("alice{}", unique());
    let alice_password = format!("alice-password-{}", unique());
    register_user(&env.app, &host, &alice, &alice_password).await;
    mark_email_verified(&env.pool, &host, &alice).await;
    let alice_id = support::find_user_id_by_username(&env.pool, &host, &alice)
        .await
        .expect("registered alice");
    let bob = format!("bob{}", unique());
    let bob_password = format!("bob-password-{}", unique());
    register_user(&env.app, &host, &bob, &bob_password).await;
    mark_email_verified(&env.pool, &host, &bob).await;
    let bob_id = support::find_user_id_by_username(&env.pool, &host, &bob)
        .await
        .expect("registered bob");

    // 1. A の電話番号（無効）。
    let res = send(
        &env.app,
        post(
            &tok(&env, &root_sso, &host).await,
            &format!("/{host}/admin/users/{alice_id}/login-identifiers"),
            json!({ "identifier_type": "phone_number", "value": digits, "is_active": false }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "alice の電話番号");
    let alice_identifier = body_json(res).await["id"]
        .as_str()
        .expect("identifier id")
        .to_string();

    // 2. B のユーザー名（区切り付き）。A の行は無効なので空き判定に当たらない。
    let res = send(
        &env.app,
        post(
            &tok(&env, &root_sso, &host).await,
            &format!("/{host}/admin/users/{bob_id}/login-identifiers"),
            json!({ "identifier_type": "username", "value": dashed }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "無効な行には空き判定が当たらない（この前提が崩れたら経路ごと再検討する）"
    );

    // 3. A の電話番号を有効へ戻す。ここから `dashed` は 2 人に当たる。
    let res = send(
        &env.app,
        patch(
            &tok(&env, &root_sso, &host).await,
            &format!("/{host}/admin/users/{alice_id}/login-identifiers/{alice_identifier}"),
            json!({ "is_active": true }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "alice の電話番号を有効化");

    // 同じ値をユーザー名に持つ root 所属の利用者を host のゲストにする。
    let guest_password = format!("guest-password-{}", unique());
    register_user(&env.app, &env.root_tenant_id, &dashed, &guest_password).await;
    mark_email_verified(&env.pool, &env.root_tenant_id, &dashed).await;
    let guest_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &dashed)
        .await
        .expect("registered guest");
    invite_and_accept(&env, &root_sso, &host, &guest_id).await;

    // ── 本体: 曖昧な入力ではゲストも解決されない。
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.61", &dashed, &guest_password).await,
        "invalid_credentials",
        "曖昧な入力がゲスト解決へ落ちてはいけない"
    );
    // 曖昧の当事者である HOME 利用者も、その値では入れない（「曖昧なら通さない」の一貫性）。
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.62", &dashed, &bob_password).await,
        "invalid_credentials",
        "曖昧な入力は誰にも解決しない"
    );
    // 拒否されるのは曖昧な入力だけで、当人たちの一意な識別子は影響を受けない。
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.63", &alice, &alice_password).await,
        "success",
        "自分の一意なユーザー名では従来どおり入れる"
    );
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.64", &bob, &bob_password).await,
        "success",
        "自分の一意なユーザー名では従来どおり入れる"
    );
    // ゲストは所属元テナントでは値が一意なので、そちらからは入れる。
    assert_eq!(
        portal_login_result(
            &env,
            &env.root_tenant_id,
            "203.0.113.65",
            &dashed,
            &guest_password
        )
        .await,
        "success",
        "所属元では一意なので解決する"
    );

    // ── 監査には「不在」ではなく「曖昧」として残る。管理者の是正が要る状態なので、
    //    正しい資格情報を出しても入れない理由が読めなければならない。
    let reasons: Vec<String> = sqlx::query_scalar(
        "SELECT reason FROM audit_log \
         WHERE event_type = 'login.failed' AND tenant_id = ? AND result = 'failure' \
         ORDER BY occurred_at DESC LIMIT 20",
    )
    .bind(&host)
    .fetch_all(&env.pool)
    .await
    .expect("audit rows");
    assert!(
        reasons.iter().any(|r| r == "ambiguous_identifier"),
        "曖昧は unknown_user と区別して監査に残る: {reasons:?}"
    );
}

/// テナントへドメインを割り当てる（ADR-0029。`idp.system.admin` が必要なので root の管理トークンで呼ぶ）。
async fn assign_domain(env: &TestEnv, root_sso: &str, tenant_id: &str, domain: &str) {
    let res = send(
        &env.app,
        post(
            &tok(env, root_sso, &env.root_tenant_id).await,
            &format!("/{}/admin/tenants/{tenant_id}/domains", env.root_tenant_id),
            json!({ "domain": domain }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "assign {domain}");
}

/// テナントを 1 つ作り、自己登録を有効にして、パスワードの分かる利用者を 1 人置く。
/// 返すのは `(tenant_id, user_id)`。
async fn tenant_with_user(
    env: &TestEnv,
    root_sso: &str,
    name: &str,
    username: &str,
    password: &str,
) -> (String, String) {
    let tenant = create_tenant(env, root_sso, name).await;
    sqlx::query("UPDATE tenants SET self_registration_enabled = 1 WHERE id = ?")
        .bind(&tenant)
        .execute(&env.pool)
        .await
        .expect("enable self-registration");
    register_user(&env.app, &tenant, username, password).await;
    mark_email_verified(&env.pool, &tenant, username).await;
    let user_id = support::find_user_id_by_username(&env.pool, &tenant, username)
        .await
        .expect("registered user");
    (tenant, user_id)
}

/// 保証 7（MT25 / ADR-0029）: 同じユーザー名のゲストが 2 人参加すると、その名前では双方が
/// 締め出される。**所属元テナントにドメインを割り当てると、ドメイン修飾した入力で入れる。**
///
/// 締め出しは、識別子の一意性が 1 テナントの中でしか担保されていないのに、参加先の画面が
/// 解決する範囲は所属元をまたぐことから来る。ドメインは 1 つのテナントへ排他的に割り当てられる
/// ので、`local@domain` の形の入力からは所属元テナントが 1 つに決まり、引くのはそのテナントの
/// 登録簿だけで済む（横断走査を通らない ＝ 曖昧さが原理的に起きない）。
///
/// **加算であって置き換えではない**ことも確かめる —— 裸のユーザー名は従来どおり走査へ落ち、
/// 曖昧なら拒まれる。ドメインを持たない利用者の使い勝手は変わらない。
#[tokio::test]
async fn a_tenant_domain_lets_a_guest_sign_in_where_the_bare_name_is_ambiguous() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "DomainHost").await;

    // 同じユーザー名を持つ利用者を、別々の所属元テナントに 1 人ずつ。
    let shared_username = format!("dup{}", unique());
    let password_a = format!("a-password-{}", unique());
    let password_b = format!("b-password-{}", unique());
    let (tenant_a, user_a) = tenant_with_user(
        &env,
        &root_sso,
        "DomainHomeA",
        &shared_username,
        &password_a,
    )
    .await;
    let (_tenant_b, user_b) = tenant_with_user(
        &env,
        &root_sso,
        "DomainHomeB",
        &shared_username,
        &password_b,
    )
    .await;
    invite_and_accept(&env, &root_sso, &host, &user_a).await;
    invite_and_accept(&env, &root_sso, &host, &user_b).await;

    // ── 裸のユーザー名では双方とも入れない（走査が 2 人に当たり、fail-closed で拒む）。
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.71", &shared_username, &password_a).await,
        "invalid_credentials",
        "同名のゲストが 2 人参加すると、その名前では解決できない"
    );
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.72", &shared_username, &password_b).await,
        "invalid_credentials",
        "締め出しは双方に効く"
    );
    // 所属元テナントの画面からは従来どおり入れる（締め出されるのは参加先の画面だけ）。
    assert_eq!(
        portal_login_result(
            &env,
            &tenant_a,
            "203.0.113.73",
            &shared_username,
            &password_a
        )
        .await,
        "success",
        "所属元では一意なので解決する"
    );

    // ── A にドメインを割り当てると、A の利用者はドメイン修飾で参加先へ入れる。
    let domain = format!("a{}.example", unique());
    assign_domain(&env, &root_sso, &tenant_a, &domain).await;
    let qualified = format!("{shared_username}@{domain}");
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.74", &qualified, &password_a).await,
        "success",
        "ドメインで所属元が決まれば、走査を通らずに解決される"
    );

    // ── ドメインは所属元を名指しするので、同名でも B の利用者はこの綴りでは解決されない。
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.75", &qualified, &password_b).await,
        "invalid_credentials",
        "ドメインは所属元テナントを 1 つに決める"
    );

    // ── 加算であって置き換えではない: 裸のユーザー名の扱いは変わらない。
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.76", &shared_username, &password_a).await,
        "invalid_credentials",
        "裸の入力は従来どおり走査へ落ち、曖昧なら拒まれる"
    );
    // 割り当てられていないドメインも同じく走査へ落ちる（B の利用者は入れないまま）。
    assert_eq!(
        portal_login_result(
            &env,
            &host,
            "203.0.113.77",
            &format!("{shared_username}@unassigned{}.example", unique()),
            &password_b
        )
        .await,
        "invalid_credentials",
        "未割り当てのドメインは経路に掛からない"
    );
}

/// 保証 8（ADR-0029）: ドメインの一意性は**グローバル**で、root の system 管理者だけが割り当てる。
#[tokio::test]
async fn a_domain_belongs_to_exactly_one_tenant() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let first = create_tenant(&env, &root_sso, "DomainOwner").await;
    let second = create_tenant(&env, &root_sso, "DomainRival").await;
    let domain = format!("owned{}.example", unique());
    let uri = |t: &str| format!("/{}/admin/tenants/{t}/domains", env.root_tenant_id);
    // ドメイン割り当ては root テナントのパスで行う（`idp.system.admin` は root scope のみ）。
    // 対象テナントはパスの後段に入るだけなので、管理トークンは root のもの 1 本で足りる。
    let root_tok = tok(&env, &root_sso, &env.root_tenant_id).await;

    assign_domain(&env, &root_sso, &first, &domain).await;

    // 別のテナントは同じドメインを取れない（一意キーにテナントを含めない）。
    let res = send(
        &env.app,
        post(&root_tok, &uri(&second), json!({ "domain": &domain })),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "ドメインは 1 テナントだけのもの"
    );
    // 同じテナントでの重複も同じく 409。
    let res = send(
        &env.app,
        post(&root_tok, &uri(&first), json!({ "domain": &domain })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // 大小・末尾ドットは正規化されるので、同じドメインの別綴りも取れない。
    let res = send(
        &env.app,
        post(
            &root_tok,
            &uri(&second),
            json!({ "domain": format!("{}.", domain.to_uppercase()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT, "正規化してから照合する");

    // ドメインとして読めない値は 400（登録できると、掛からない割り当てが静かに残る）。
    for bad in ["", "-bad.example", "日本語.example"] {
        let res = send(
            &env.app,
            post(&root_tok, &uri(&second), json!({ "domain": bad })),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{bad:?}");
    }

    // 権限のない利用者は割り当てられない（idp.system.admin は root にしか存在しない）。
    let outsider = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let outsider_sso = create_sso_session(&env.pool, &outsider).await;
    let res = send(
        &env.app,
        post(
            &tok(&env, &outsider_sso, &env.root_tenant_id).await,
            &uri(&first),
            json!({ "domain": "x.example" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 一覧 → 解除 → 解除後は別テナントが取れる。
    let res = send(&env.app, get(&root_tok, &uri(&first))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed = body_json(res).await;
    let rows = listed.as_array().expect("array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["domain"], domain);
    let domain_id = rows[0]["id"].as_str().expect("id").to_string();

    let res = send(
        &env.app,
        support::delete(&root_tok, &format!("{}/{domain_id}", uri(&first))),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    // 他テナントの id 指定では消せない（先に消えているので 404）。
    let res = send(
        &env.app,
        support::delete(&root_tok, &format!("{}/{domain_id}", uri(&second))),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    assign_domain(&env, &root_sso, &second, &domain).await;
}

/// 保証 9（ADR-0029）: ドメインを割り当てたテナントでは、`ローカル部@そのドメイン` は
/// 「ローカル部の利用者」を指す綴りでもある。**その綴りを他人の識別子として登録させない。**
///
/// 登録できてしまうと、参加先テナントの画面ではその綴りが唯一の入り口になり得る当人が、
/// 突然そこから入れなくなる（横取り）。空き判定はログインの解決と同じ範囲を見る必要がある。
#[tokio::test]
async fn a_upn_spelling_cannot_be_taken_from_its_owner() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let domain = format!("upn{}.example", unique());
    let owner_name = format!("owner{}", unique());
    let password = format!("upn-password-{}", unique());
    let (tenant, _owner_id) =
        tenant_with_user(&env, &root_sso, "UpnHome", &owner_name, &password).await;
    assign_domain(&env, &root_sso, &tenant, &domain).await;

    // 同じテナントの別人。
    let other_name = format!("other{}", unique());
    register_user(&env.app, &tenant, &other_name, &password).await;
    mark_email_verified(&env.pool, &tenant, &other_name).await;
    let other_id = support::find_user_id_by_username(&env.pool, &tenant, &other_name)
        .await
        .expect("registered other");

    // `owner@そのドメイン` を別人の識別子にしようとすると 409。
    let res = send(
        &env.app,
        post(
            &tok(&env, &root_sso, &tenant).await,
            &format!("/{tenant}/admin/users/{other_id}/login-identifiers"),
            json!({
                "identifier_type": "email",
                "value": format!("{owner_name}@{domain}")
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "UPN 綴りは所有者のもの。他人へ足させない"
    );

    // 割り当てていないドメインなら従来どおり登録できる（判定はこのテナントのドメインに限る）。
    let res = send(
        &env.app,
        post(
            &tok(&env, &root_sso, &tenant).await,
            &format!("/{tenant}/admin/users/{other_id}/login-identifiers"),
            json!({
                "identifier_type": "email",
                "value": format!("{owner_name}@elsewhere{}.example", unique())
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "他所のドメインは UPN 解釈の対象外"
    );

    // 所有者は自分の UPN 綴りで従来どおり入れる。
    assert_eq!(
        portal_login_result(
            &env,
            &tenant,
            "203.0.113.78",
            &format!("{owner_name}@{domain}"),
            &password
        )
        .await,
        "success",
        "所有者は UPN 綴りで入れる"
    );
}
