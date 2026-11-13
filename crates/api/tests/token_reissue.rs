//! Integration test for reissuing issued tokens (ADR-0047) (with DB).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test token_reissue
//!
//! **This cannot be proven by unit tests.** Revocation is one UPDATE on `refresh_tokens`, and whether it
//! worked shows only in "is refresh refused". Only running issue -> refresh -> reissue -> refresh refused
//! against a real DB proves the path is wired up.
//!
//! What this protects:
//!
//! This operation swaps **only the tokens**. If the session were cut too, the person pressing it would be
//! locked out on the spot, and a user who "just wants to change the app's key" could no longer use it. Conversely, if
//! tokens survived, nothing changed. The same test checks it is neither.

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

/// Artifacts of one login.
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

/// Runs through once with `offline_access` and obtains a refresh token and the SSO cookie.
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

    // `offline_access` interposes consent. Accept it if interposed.
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
            .expect("refresh_token (offline_access was requested)")
            .to_string(),
        sso_cookie,
    }
}

/// Calls the refresh grant once. On success returns the rotated refresh token.
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

/// Returns whether the security screen opens (= whether the SSO session is alive).
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

/// One reissue by the user. Returns the number dropped.
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

/// **When the user reissues, issued tokens become unusable. The login state remains, though.**
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

    // Before reissuing, refresh succeeds (if this premise breaks, the following asserts prove nothing).
    let (status, rotated) = refresh(&env, &client_id, &secret, &logged_in.refresh_token).await;
    assert_eq!(status, StatusCode::OK, "refresh before reissue succeeds");
    let rotated = rotated.expect("rotated refresh token");

    assert_eq!(
        reissue_own_tokens(&env, &logged_in.sso_cookie).await,
        1,
        "drops the one live token"
    );

    // Try with **the rotated token**. Unless children inherited through rotation are dropped too,
    // only "apps that refreshed once right before the reissue" would survive.
    let (status, _) = refresh(&env, &client_id, &secret, &rotated).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "refresh after reissue is refused (if it passes, the key was not changed)"
    );

    // The session remains. If it were cut, the person pressing it would be locked out on the spot.
    assert_eq!(
        security_screen_result(&env, &logged_in.sso_cookie).await,
        "ok",
        "the login state continues after reissue"
    );

    // The second time there is nothing to drop (idempotent; succeeds with 0).
    assert_eq!(reissue_own_tokens(&env, &logged_in.sso_cookie).await, 0);
}

/// **An admin can reissue for a specified target.** Answers "I worry about the key handed to that app"
/// without resorting to disabling (stops work) or a password reissue (forces the user to reset).
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
    assert_eq!(status, StatusCode::OK, "refresh before reissue succeeds");
    let rotated = rotated.expect("rotated refresh token");

    let response = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK, "admin can reissue");
    let body = body_json(response).await;
    assert_eq!(body["user_id"], target);
    assert_eq!(body["revoked"], 1);

    let (status, _) = refresh(&env, &client_id, &secret, &rotated).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "refresh after reissue is refused"
    );

    // The target's login state is not cut (use disabling for that; this operation only swaps keys).
    assert_eq!(
        security_screen_result(&env, &logged_in.sso_cookie).await,
        "ok"
    );

    // The audit keeps the target and the count, not the token values.
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

    // The second time succeeds with 0 (admins operate without knowing the count).
    let response = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["revoked"], 0);
}

/// Authorization: unauthenticated is 401, a user without permission is 403, nonexistent is 404.
/// It can be run on oneself (it causes no lockout; unlike disabling and MFA reset).
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

    // Nonexistent and invalid UUID are both 404 (prevents inferring existence).
    for target in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_string()] {
        let uri = format!("/{}/admin/users/{target}/token-reissue", env.root_tenant_id);
        let response = send(&env.app, post(&admin_tok, &uri, json!({}))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "target={target}");
    }

    // Oneself is allowed (this operation does not cut the login state, so no lockout happens).
    let self_uri = format!(
        "/{}/admin/users/{}/token-reissue",
        env.root_tenant_id, env.root_admin_id
    );
    let response = send(&env.app, post(&admin_tok, &self_uri, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK, "self -> 200");
}

// --- Number of currently valid tokens (task #83) ------------------------------------------------------

/// Inserts one row directly into `refresh_tokens`. There is a composite FK on `(tenant_id, client_id)`, so
/// the issuing client must exist. A negative `expires_in_days` makes it expired; `revoked` makes it revoked.
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

/// Creates a child tenant and returns its ID.
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

/// **The count is known before pressing.** Only unrevoked, unexpired refresh tokens are counted; revoked and
/// expired ones are not. The counted scope matches what reissue drops (any tenant; ADR-0047), and
/// after reissue it is 0.
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
    // One from a real round trip (direct DB inserts alone would not guarantee counting the rows the issuance path writes).
    log_in_with_offline_access(&env, &client_id, &secret, &username).await;
    let target = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("target user");

    // Not counted: revoked and expired.
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
    // Counted: keys the same person handed to an app in another tenant (reissue drops these too).
    let child = create_child_tenant(&env).await;
    let (child_client, _) =
        support::insert_confidential_client(&env.pool, &child, &["openid"]).await;
    insert_refresh_token_row(&env.pool, &child, &target, &child_client, 30, false).await;
    // Another person's keys are not counted.
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
        "one from the round trip + one in another tenant (revoked, expired and others' are not counted): {body}"
    );

    let reissue = format!("/{}/admin/users/{target}/token-reissue", env.root_tenant_id);
    let response = send(&env.app, post(&admin_tok, &reissue, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (_, body) = active_refresh_tokens(&env, &admin_tok, &target).await;
    assert_eq!(body["active_refresh_tokens"], 0, "0 after reissue: {body}");

    // Reads are not audited (only the one reissue row).
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND reason LIKE ?")
            .bind(&env.root_admin_id)
            .bind(format!("%user={target}%"))
            .fetch_one(&env.pool)
            .await
            .expect("audit rows");
    assert_eq!(rows, 1);
}

/// **Tenant boundary: users of other tenants are not counted.** Even if a parent (root) admin points at a user
/// whose home is a child tenant, it is 404 (same as nonexistent; existence is not revealed). Same decision as reissue.
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
        "no count is returned for another tenant's user: {body}"
    );
    assert!(body.get("active_refresh_tokens").is_none(), "{body}");
}

/// Authorization: no credentials is 401, a user without permission is 403, nonexistent or invalid UUID is 404.
/// Read permission on users (`idp.users:read`) is enough (write is not needed).
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

    // A system client holding only `idp.users:read` can count.
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
    assert_eq!(status, StatusCode::OK, "idp.users:read is enough: {body}");
    assert_eq!(body["active_refresh_tokens"], 0);

    for missing in [uuid::Uuid::now_v7().to_string(), "not-a-uuid".to_string()] {
        let (status, _) = active_refresh_tokens(&env, &admin_tok, &missing).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "target={missing}");
    }
}

// --- Align the count reissue reports with the count on screen (task #123) --------------------------------------

/// One admin reissue. Returns the response's `revoked` (number dropped).
async fn admin_reissue(env: &TestEnv, token: &str, target: &str) -> Value {
    let uri = format!("/{}/admin/users/{target}/token-reissue", env.root_tenant_id);
    let response = send(&env.app, post(token, &uri, json!({}))).await;
    assert_eq!(response.status(), StatusCode::OK, "admin can reissue");
    body_json(response).await["revoked"].clone()
}

/// **Expired rows are not included in the reissue count.** The count shown before pressing (valid count) and
/// the count resulting from pressing refer to the same scope. Previously expired rows without a revoked mark were
/// dropped and counted, so even with 0 on screen it said "Revoked".
#[tokio::test]
async fn reissue_counts_only_the_tokens_the_console_showed_as_alive() {
    let Some(env) = support::setup("admin token reissue skips expired rows").await else {
        return;
    };
    let (client_id, _) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let target = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // Only an expired row without a revoked mark exists: the screen shows 0, pressing gives 0.
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
        "expired rows are not included in the dropped count (matches the 0 on screen)"
    );

    // Once a live row is added, the count on screen and the count from pressing match.
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
        "count from pressing = count shown before pressing"
    );

    // The expired row has no revoked mark (it was not touched).
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
    assert_eq!(body["active_refresh_tokens"], 0, "0 after reissue: {body}");
}
