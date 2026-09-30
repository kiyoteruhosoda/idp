//! 発行済みトークンの再発行（ADR-0047）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test token_reissue
//!
//! **単体テストでは証明できない**。失効は `refresh_tokens` への 1 本の UPDATE で、それが
//! 効いたかどうかは「更新が断られるか」でしか分からない。発行 → 更新 → 再発行 → 更新が
//! 断られる、までを実 DB で通して初めて経路が繋がっている確証になる。
//!
//! 何を守っているか:
//!
//! この操作は**トークンだけ**を入れ替える。セッションまで切れると、押した本人がその場で
//! 締め出され「アプリの鍵を替えたいだけ」の利用者が使えなくなる。逆にトークンが生き残れば
//! 何も替わっていない。どちらでもないことを、同じテストの中で確かめる。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use support::{
    admin_token, body_json, handoff_handle, post, post_internal, query_param, resume_authorize,
    send, TestEnv, CODE_CHALLENGE, CODE_VERIFIER, REDIRECT_URI, REDIRECT_URI_ENC, SERVICE_TOKEN,
};

const PASSWORD: &str = "correct-horse-battery";

/// ログイン 1 回ぶんの成果物。
struct LoggedIn {
    refresh_token: String,
    sso_cookie: String,
}

fn basic_auth(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

fn unique_username() -> String {
    format!("tr{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

/// `offline_access` 付きで一通り通し、refresh token と SSO Cookie を得る。
async fn log_in_with_offline_access(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    username: &str,
) -> LoggedIn {
    support::register_user(&env.app, &env.root_tenant_id, username, PASSWORD).await;
    support::mark_email_verified(&env.pool, &env.root_tenant_id, username).await;

    let response = send(
        &env.app,
        Request::builder()
            .uri(format!(
                "/{}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}&scope={}&state=st&nonce=nc&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256",
                env.root_tenant_id,
                utf8_percent_encode("openid offline_access", NON_ALPHANUMERIC)
            ))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "handoff to /login");
    let handle = handoff_handle(&response);

    let body = resume_authorize(&env.app, &env.root_tenant_id, &handle, None).await;
    assert_eq!(body["result"], "login_required");
    let auth_session = body["auth_session_id"].as_str().unwrap().to_string();
    let csrf = assay_api::application::login::csrf_token(&auth_session, &env.csrf_secret);

    let response = send(
        &env.app,
        post_internal(
            "/internal/authenticate",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "auth_session_id": auth_session,
                "username": username,
                "password": PASSWORD,
                "csrf_token": csrf,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let sso_cookie = body["sso_session_id"].as_str().unwrap().to_string();

    // `offline_access` は同意を挟む。挟まれたら承諾する。
    let callback = match body["result"].as_str() {
        Some("consent_required") => {
            let consent_session = body["auth_session_id"].as_str().unwrap().to_string();
            let response = send(
                &env.app,
                post_internal(
                    "/internal/consent/approve",
                    Some(SERVICE_TOKEN),
                    json!({
                        "tenant_id": env.root_tenant_id,
                        "auth_session_id": consent_session,
                    }),
                ),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            body_json(response).await["redirect_to"]
                .as_str()
                .unwrap()
                .to_string()
        }
        _ => body["redirect_to"]
            .as_str()
            .expect("redirect_to")
            .to_string(),
    };
    assert!(callback.starts_with(REDIRECT_URI));
    let code = query_param(&callback, "code").expect("authorization code");

    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_URI_ENC}&code_verifier={CODE_VERIFIER}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "token endpoint");
    let tokens = body_json(response).await;
    LoggedIn {
        refresh_token: tokens["refresh_token"]
            .as_str()
            .expect("refresh_token（offline_access を要求している）")
            .to_string(),
        sso_cookie,
    }
}

/// refresh grant を 1 回叩く。成功したら回転後の refresh token を返す。
async fn refresh(
    env: &TestEnv,
    client_id: &str,
    secret: &str,
    refresh_token: &str,
) -> (StatusCode, Option<String>) {
    let response = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic_auth(client_id, secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token={}",
                utf8_percent_encode(refresh_token, NON_ALPHANUMERIC)
            )))
            .unwrap(),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    let rotated = body["refresh_token"].as_str().map(|s| s.to_string());
    (status, rotated)
}

/// セキュリティ画面が開けるか（＝ SSO セッションが生きているか）を返す。
async fn security_screen_result(env: &TestEnv, sso_cookie: &str) -> String {
    let response = send(
        &env.app,
        post_internal(
            "/internal/account/security",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": sso_cookie,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await["result"]
        .as_str()
        .expect("result")
        .to_string()
}

/// 本人による再発行を 1 回。落とした本数を返す。
async fn reissue_own_tokens(env: &TestEnv, sso_cookie: &str) -> u64 {
    let response = send(
        &env.app,
        post_internal(
            "/internal/account/security/reissue-tokens",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "sso_session_id": sso_cookie,
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "reissue tokens");
    let body = body_json(response).await;
    assert_eq!(body["result"], "ok");
    body["revoked"].as_u64().expect("revoked")
}

/// **本人が再発行すると、発行済みトークンは使えなくなる。ただしログイン状態は残る。**
#[tokio::test]
async fn reissuing_your_tokens_stops_the_refresh_grant_and_keeps_you_signed_in() {
    let Some(env) = support::setup("self-service token reissue").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let logged_in = log_in_with_offline_access(&env, &client_id, &secret, &unique_username()).await;

    // 再発行の前は更新が通る（この前提が崩れていると、以降の assert は何も証明しない）。
    let (status, rotated) = refresh(&env, &client_id, &secret, &logged_in.refresh_token).await;
    assert_eq!(status, StatusCode::OK, "再発行前の更新は通る");
    let rotated = rotated.expect("回転後の refresh token");

    assert_eq!(
        reissue_own_tokens(&env, &logged_in.sso_cookie).await,
        1,
        "生きていた 1 本を落とす"
    );

    // **回転後のトークン**で試す。rotation を引き継いだ子まで落ちていないと、
    // 「再発行の直前に一度更新したアプリ」だけが生き残る。
    let (status, _) = refresh(&env, &client_id, &secret, &rotated).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "再発行後の更新は断られる（通るなら鍵は替わっていない）"
    );

    // セッションは残る。ここが切れていると、押した本人がその場で締め出される。
    assert_eq!(
        security_screen_result(&env, &logged_in.sso_cookie).await,
        "ok",
        "再発行してもログイン状態は続く"
    );

    // 2 回目は落とすものが無い（冪等。0 件でも成功する）。
    assert_eq!(reissue_own_tokens(&env, &logged_in.sso_cookie).await, 0);
}

/// **管理者が対象を指定して再発行できる。** 「あのアプリに配った鍵が心配だ」に対して、
/// 無効化（業務が止まる）もパスワード再発行（本人に再設定を強いる）も持ち出さずに応える。
#[tokio::test]
async fn an_administrator_reissues_another_users_tokens() {
    let Some(env) = support::setup("admin token reissue").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();
    let logged_in = log_in_with_offline_access(&env, &client_id, &secret, &username).await;
    let target = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("target user");
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/users/{target}/token-reissue", env.root_tenant_id);

    let (status, rotated) = refresh(&env, &client_id, &secret, &logged_in.refresh_token).await;
    assert_eq!(status, StatusCode::OK, "再発行前の更新は通る");
    let rotated = rotated.expect("回転後の refresh token");

    let response = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK, "admin can reissue");
    let body = body_json(response).await;
    assert_eq!(body["user_id"], target);
    assert_eq!(body["revoked"], 1);

    let (status, _) = refresh(&env, &client_id, &secret, &rotated).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "再発行後の更新は断られる");

    // 対象のログイン状態は切らない（切りたいなら無効化を使う。この操作は鍵だけを替える）。
    assert_eq!(
        security_screen_result(&env, &logged_in.sso_cookie).await,
        "ok"
    );

    // 監査に対象と本数が残り、トークンの値は残らない。
    let reasons: Vec<String> = sqlx::query_scalar(
        "SELECT reason FROM audit_log WHERE event_type = 'refresh_token.revoked' \
           AND user_id = ? AND reason LIKE ?",
    )
    .bind(&env.root_admin_id)
    .bind(format!("%user={target}%"))
    .fetch_all(&env.pool)
    .await
    .expect("audit rows");
    assert_eq!(reasons.len(), 1, "one audit row: {reasons:?}");
    assert!(reasons[0].contains("refresh_tokens=1"), "{}", reasons[0]);
    assert!(
        !reasons[0].contains(&rotated),
        "token values must not leak into the audit log"
    );

    // 2 回目は 0 件で成功する（管理者は本数を知らずに操作する）。
    let response = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["revoked"], 0);
}

/// 認可: 未認証は 401、権限の無い利用者は 403、不存在は 404。
/// 自分自身には実行できる（締め出しにならないため。無効化・MFA 解除と違う点）。
#[tokio::test]
async fn token_reissue_checks_authorization_and_allows_yourself() {
    let Some(env) = support::setup("admin token reissue guards").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let bystander = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!(
        "/{}/admin/users/{bystander}/token-reissue",
        env.root_tenant_id
    );

    let response = send(
        &env.app,
        support::anonymous(axum::http::Method::POST, &uri, None),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "no token -> 401"
    );

    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &bystander).await;
    let response = send(&env.app, post(&plain_token, &uri, json!({}))).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "no admin perm -> 403"
    );

    // 不存在・UUID 不正はいずれも 404（存在推測を防ぐ）。
    for target in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_string()] {
        let uri = format!("/{}/admin/users/{target}/token-reissue", env.root_tenant_id);
        let response = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "target={target}");
    }

    // 自分自身は許す（この操作はログイン状態を切らないので、ロックアウトが起きない）。
    let self_uri = format!(
        "/{}/admin/users/{}/token-reissue",
        env.root_tenant_id, env.root_admin_id
    );
    let response = send(&env.app, post(&admin_tok, &self_uri, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK, "self -> 200");
}

// --- いま有効なトークンの本数（task #83） ------------------------------------------------------

/// `refresh_tokens` へ 1 行を直に入れる。`(tenant_id, client_id)` の複合外部キーがあるので
/// 発行元クライアントは実在させる。`expires_in_days` を負にすれば期限切れ、`revoked` で失効済み。
async fn insert_refresh_token_row(
    pool: &sqlx::MySqlPool,
    tenant_id: &str,
    user_id: &str,
    client_id: &str,
    expires_in_days: i64,
    revoked: bool,
) {
    sqlx::query(
        "INSERT INTO refresh_tokens \
         (token_hash, tenant_id, user_id, client_id, scope, expires_at, revoked_at) \
         VALUES (?, ?, ?, ?, '[\"openid\"]', DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? DAY), \
                 IF(?, UTC_TIMESTAMP(6), NULL))",
    )
    .bind(format!("{:064x}", uuid::Uuid::now_v7().as_u128()))
    .bind(tenant_id)
    .bind(user_id)
    .bind(client_id)
    .bind(expires_in_days)
    .bind(revoked)
    .execute(pool)
    .await
    .expect("insert refresh token");
}

/// 子テナントを 1 つ作って ID を返す。
async fn create_child_tenant(env: &TestEnv) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, ?, ?)")
        .bind(&id)
        .bind(&env.root_tenant_id)
        .bind(format!("t83-{}", &id[..8]))
        .execute(&env.pool)
        .await
        .expect("create child tenant");
    id
}

async fn active_refresh_tokens(env: &TestEnv, token: &str, target: &str) -> (StatusCode, Value) {
    let uri = format!("/{}/admin/users/{target}/active-tokens", env.root_tenant_id);
    let response = send(&env.app, support::get(token, &uri)).await;
    let status = response.status();
    (status, body_json(response).await)
}

/// **押す前に本数が分かる。** 数えるのは未失効かつ期限内の refresh token だけで、失効済み・
/// 期限切れは数えない。数える範囲は再発行が落とす範囲（テナントを問わない。ADR-0047）に揃え、
/// 再発行の後は 0 になる。
#[tokio::test]
async fn an_administrator_sees_how_many_refresh_tokens_are_alive_before_reissuing() {
    let Some(env) = support::setup("admin active token count").await else {
        return;
    };
    let (client_id, secret) = support::insert_confidential_client(
        &env.pool,
        &env.root_tenant_id,
        &["openid", "offline_access"],
    )
    .await;
    let username = unique_username();
    // 実際の往復で 1 本（DB の直挿しだけだと、発行経路が書く行を数えている保証にならない）。
    log_in_with_offline_access(&env, &client_id, &secret, &username).await;
    let target = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("target user");

    // 数えないもの: 失効済み・期限切れ。
    insert_refresh_token_row(
        &env.pool,
        &env.root_tenant_id,
        &target,
        &client_id,
        30,
        true,
    )
    .await;
    insert_refresh_token_row(
        &env.pool,
        &env.root_tenant_id,
        &target,
        &client_id,
        -1,
        false,
    )
    .await;
    // 数えるもの: 同じ人が別のテナントのアプリへ渡している鍵（再発行はこれも落とす）。
    let child = create_child_tenant(&env).await;
    let (child_client, _) =
        support::insert_confidential_client(&env.pool, &child, &["openid"]).await;
    insert_refresh_token_row(&env.pool, &child, &target, &child_client, 30, false).await;
    // 別の人の鍵は数えない。
    let bystander = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    insert_refresh_token_row(
        &env.pool,
        &env.root_tenant_id,
        &bystander,
        &client_id,
        30,
        false,
    )
    .await;

    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (status, body) = active_refresh_tokens(&env, &admin_tok, &target).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["user_id"], target);
    assert_eq!(
        body["active_refresh_tokens"], 2,
        "往復の 1 本 + 別テナントの 1 本（失効済み・期限切れ・他人の分は数えない）: {body}"
    );

    let reissue = format!("/{}/admin/users/{target}/token-reissue", env.root_tenant_id);
    let response = send(&env.app, post(&admin_tok, &reissue, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (_, body) = active_refresh_tokens(&env, &admin_tok, &target).await;
    assert_eq!(
        body["active_refresh_tokens"], 0,
        "再発行の後は 0 本: {body}"
    );

    // 読み取りは監査に残さない（再発行の 1 行だけ）。
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND reason LIKE ?")
            .bind(&env.root_admin_id)
            .bind(format!("%user={target}%"))
            .fetch_one(&env.pool)
            .await
            .expect("audit rows");
    assert_eq!(rows, 1);
}

/// **テナント境界: 他テナントの利用者は数えない。** 所属元が子テナントの利用者を、親（root）の
/// 管理者が指しても 404（不存在と同じ。存在も推測させない）。再発行と同じ判定。
#[tokio::test]
async fn the_active_token_count_does_not_reach_another_tenants_user() {
    let Some(env) = support::setup("admin active token count tenant boundary").await else {
        return;
    };
    let child = create_child_tenant(&env).await;
    let (child_client, _) =
        support::insert_confidential_client(&env.pool, &child, &["openid"]).await;
    let outsider = support::create_plain_user(&env.pool, &child).await;
    insert_refresh_token_row(&env.pool, &child, &outsider, &child_client, 30, false).await;

    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (status, body) = active_refresh_tokens(&env, &admin_tok, &outsider).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "他テナントの利用者の本数は返さない: {body}"
    );
    assert!(body.get("active_refresh_tokens").is_none(), "{body}");
}

/// 認可: 資格情報なしは 401、権限の無い利用者は 403、不存在・UUID 不正は 404。
/// 権限は利用者の**読み取り**（`idp.users:read`）で足りる（書き込みまでは要らない）。
#[tokio::test]
async fn the_active_token_count_needs_only_the_user_read_permission() {
    let Some(env) = support::setup("admin active token count guards").await else {
        return;
    };
    let target = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/users/{target}/active-tokens", env.root_tenant_id);

    let response = send(
        &env.app,
        support::anonymous(axum::http::Method::GET, &uri, None),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "no token -> 401"
    );

    let plain = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    let (status, _) = active_refresh_tokens(&env, &plain_token, &target).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no perm -> 403");

    // `idp.users:read` だけを持つシステム用クライアントで数えられる。
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (m2m, m2m_secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let response = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/clients/{m2m}/permissions", env.root_tenant_id),
            json!({ "permission_code": "idp.users:read" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "grant idp.users:read");
    let response = support::request_management_token(
        &env.app,
        &env.issuer,
        &env.root_tenant_id,
        &m2m,
        &m2m_secret,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let read_only = body_json(response).await["access_token"]
        .as_str()
        .expect("management token")
        .to_string();
    let (status, body) = active_refresh_tokens(&env, &read_only, &target).await;
    assert_eq!(status, StatusCode::OK, "idp.users:read で足りる: {body}");
    assert_eq!(body["active_refresh_tokens"], 0);

    for missing in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_string()] {
        let (status, _) = active_refresh_tokens(&env, &admin_tok, &missing).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "target={missing}");
    }
}

// --- 再発行が数える本数と、画面の本数を揃える（task #123） --------------------------------------

/// 管理者の再発行を 1 回。応答の `revoked`（落とした本数）を返す。
async fn admin_reissue(env: &TestEnv, token: &str, target: &str) -> Value {
    let uri = format!("/{}/admin/users/{target}/token-reissue", env.root_tenant_id);
    let response = send(&env.app, post(token, &uri, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK, "admin can reissue");
    body_json(response).await["revoked"].clone()
}

/// **期限切れの行は再発行の本数に入らない。** 押す前に見せた本数（有効な本数）と、押した結果の
/// 本数が同じ範囲を指す。以前は期限切れで失効印の無い行まで落として数えたので、画面で 0 本でも
/// 「無効にしました」と出た。
#[tokio::test]
async fn reissue_counts_only_the_tokens_the_console_showed_as_alive() {
    let Some(env) = support::setup("admin token reissue skips expired rows").await else {
        return;
    };
    let (client_id, _) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let target = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // 期限切れで失効印の無い行だけがある: 画面は 0 本、押しても 0 本。
    for days in [-1, -30] {
        insert_refresh_token_row(
            &env.pool,
            &env.root_tenant_id,
            &target,
            &client_id,
            days,
            false,
        )
        .await;
    }
    let (status, body) = active_refresh_tokens(&env, &admin_tok, &target).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active_refresh_tokens"], 0, "{body}");
    assert_eq!(
        admin_reissue(&env, &admin_tok, &target).await,
        0,
        "期限切れの行は落とした本数に入らない（画面の 0 本と揃う）"
    );

    // 生きている行が加わると、画面の本数と押した結果の本数が一致する。
    for _ in 0..2 {
        insert_refresh_token_row(
            &env.pool,
            &env.root_tenant_id,
            &target,
            &client_id,
            30,
            false,
        )
        .await;
    }
    let (_, body) = active_refresh_tokens(&env, &admin_tok, &target).await;
    let shown = body["active_refresh_tokens"].clone();
    assert_eq!(shown, 2, "{body}");
    assert_eq!(
        admin_reissue(&env, &admin_tok, &target).await,
        shown,
        "押した結果の本数 = 押す前に見せた本数"
    );

    // 期限切れの行には失効印を付けていない（触っていない）。
    let untouched: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM refresh_tokens \
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at <= UTC_TIMESTAMP(6)",
    )
    .bind(&target)
    .fetch_one(&env.pool)
    .await
    .expect("expired rows");
    assert_eq!(untouched, 2);
    let (_, body) = active_refresh_tokens(&env, &admin_tok, &target).await;
    assert_eq!(
        body["active_refresh_tokens"], 0,
        "再発行の後は 0 本: {body}"
    );
}
