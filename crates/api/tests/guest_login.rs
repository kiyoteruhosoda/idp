//! Guest login from the login screen of the joined tenant (ADR-0009 §8).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test guest_login
//!
//! Those allowed to authenticate are "users with an ACTIVE membership in the tenant" (HOME or GUEST),
//! not only those homed there. A guest's identifier is in the home tenant's registry, so resolving it on the
//! joined tenant's login screen needs a dedicated lookup (`UserRepository::find_active_guest_by_login_identifier`).
//! Guarantees checked:
//!
//! 1. **Guests can sign in from the joined tenant's login screen** (all 3 paths: OIDC authorization flow, portal,
//!    admin console).
//!    A tenant creator becomes an ACTIVE GUEST admin of the created tenant (§4), so without this they could not
//!    sign in directly to the console of the tenant they created.
//! 2. **Cannot sign in from tenants one is not a member of** (tenant boundary; does not resolve even with correct credentials).
//! 3. **Suspended (SUSPENDED) guests cannot sign in** (MT24; suspension works as a way to stop access).
//! 4. **Guests whose home tenant is DISABLED cannot sign in** — disabling the home tenant stops that organization's
//!    users, not leaving a back door via joined tenants. Users of the disabled tenant itself
//!    cannot sign in via the internal API either.
//! 5. **HOME users of the joined tenant with the same name are not affected** (resolution prefers the home tenant;
//!    even if a guest with the same username joins, that tenant's HOME user resolves as before).
//! 6. **Disabling the home tenant also stops issued refresh tokens at the next refresh** (MT27).
//!    The joined tenant's `/{tenant_id}/token` is alive, so without blocking here they could keep refreshing
//!    up to the lifetime (30 days by default).

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

/// Creates one user homed in root with a known password (self-registration → email verified).
/// Returns `(user_id, username, password)`.
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

/// root creates a tenant and returns its ID (the creator becomes the tenant's ACTIVE GUEST admin).
/// Exchanges the SSO session for an admin token for the given tenant (ADR-0037).
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

/// Makes `user_id` an ACTIVE GUEST of `tenant_id` (create invitation → accepted by the user).
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

/// Tries the portal login (what `/{tenant}/login` does) once and returns the `result` tag.
///
/// `ip` differs per test function. The per-IP rate limiter lives in process memory, and tests running in parallel
/// in the same binary share buckets.
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

/// Tries the admin console login (what `/{tenant}/admin/login` does) once and returns the `result` tag.
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

/// Guarantees 1 and 2: guests can sign in from the joined tenant's portal login screen. On the same screen of a tenant
/// they are not a member of, the same credentials do not resolve (tenant boundary).
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
    // Signing in from the home tenant works as before (adding guest resolution does not change the HOME path).
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
    // Does not resolve in a tenant without a membership.
    assert_eq!(
        portal_login_result(&env, &stranger, "203.0.113.13", &username, &password).await,
        "invalid_credentials",
        "a tenant the user is not a member of must not resolve the identifier"
    );
}

/// Guarantee 1: a tenant creator (ACTIVE GUEST admin) can sign in directly to the admin console of the created
/// tenant. Avoids a state where entering via root and switching tenants is the only way.
#[tokio::test]
async fn guest_admin_signs_in_to_the_host_tenant_console() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "GuestConsoleHost").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_sso, &host, &user_id).await;

    // Without permission yet, "the user was identified but is not an admin" = forbidden (resolution itself succeeded).
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

/// Guarantee 3: suspended (SUSPENDED) guests cannot sign in from the joined tenant's screen. Suspension is the means
/// of "stopping only access while keeping membership and permission rows" (MT24), so without this they cannot be stopped.
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
    // Signing in to the home tenant still works (only access to the joined tenant was suspended).
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

/// Guarantee 5: even if the joined tenant has a HOME user with the same username, that HOME user resolves as before
/// (resolution prefers the home tenant; a single lookup would be "ambiguous" and lock both out).
/// Email login is decided by the switch of **the home tenant** (ADR-0050 decision 3).
///
/// Guests sign in from the joined tenant's screen, but their identifiers are in the home tenant's registry.
/// If the joined tenant's switch opened or closed the home tenant's entrance, **one's sign-in methods would change
/// because of a tenant one did not configure**. Only the tenant holding the identifier is consulted.
#[tokio::test]
async fn email_login_follows_the_home_tenant_switch_not_the_host() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "EmailSwitchHost").await;

    // Make a root-homed user a guest of host.
    let username = format!("es{}", unique());
    let password = format!("guest-password-{}", unique());
    register_user(&env.app, &env.root_tenant_id, &username, &password).await;
    mark_email_verified(&env.pool, &env.root_tenant_id, &username).await;
    let guest_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("registered guest");
    invite_and_accept(&env, &root_sso, &host, &guest_id).await;
    let email = format!("{username}@example.com");

    let set_switch = |tenant: String, on: bool| {
        let pool = env.pool.clone();
        async move {
            sqlx::query("UPDATE tenants SET email_login_enabled = ? WHERE id = ?")
                .bind(on)
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("toggle email login");
        }
    };

    // ⚠ Do not rely on defaults; turn both off explicitly (the tenant is shared with other tests and the DB spans runs).
    set_switch(env.root_tenant_id.clone(), false).await;
    set_switch(host.clone(), false).await;
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.61", &email, &password).await,
        "invalid_credentials",
        "with both off, email does not sign in"
    );

    // Turning on only the joined tenant (host) changes nothing.
    set_switch(host.clone(), true).await;
    let with_host_only = portal_login_result(&env, &host, "203.0.113.62", &email, &password).await;

    // Turning on the home tenant (root) lets one in.
    set_switch(env.root_tenant_id.clone(), true).await;
    let with_home = portal_login_result(&env, &host, "203.0.113.63", &email, &password).await;

    // The tenant is shared, so always restore.
    set_switch(env.root_tenant_id.clone(), false).await;
    set_switch(host, false).await;

    assert_eq!(
        with_host_only, "invalid_credentials",
        "the joined tenant's switch does not open the home tenant's entrance"
    );
    assert_eq!(with_home, "success", "the home tenant's switch opens it");
}

#[tokio::test]
async fn a_same_named_guest_does_not_lock_out_the_host_tenants_home_user() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "GuestClashHost").await;

    // A HOME user of host (temporarily allow self-registration to create a user with a known password).
    sqlx::query("UPDATE tenants SET self_registration_enabled = 1 WHERE id = ?")
        .bind(&host)
        .execute(&env.pool)
        .await
        .expect("enable self-registration on the host tenant");
    let shared_username = format!("clash{}", unique());
    let home_password = format!("home-password-{}", unique());
    register_user(&env.app, &host, &shared_username, &home_password).await;
    mark_email_verified(&env.pool, &host, &shared_username).await;

    // Make a root-homed user with the same username a guest of host.
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

    // The HOME user of host can sign in with their own password.
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
    // The same-named guest is not resolved at host with their own password (home preference: HOME wins).
    // Signing in from the home tenant works as before.
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

/// Guarantee 1: a guest arriving from an RP at the joined tenant's `/authorize` can authenticate right on the login
/// screen and receive an authorization code (no need to create an SSO session in the home tenant first).
///
/// Without this, a guest who opened the joined tenant's RP would have no way forward except "type one's home
/// tenant ID into the URL, sign in once and come back".
#[tokio::test]
async fn guest_completes_the_authorization_flow_on_the_host_tenant() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "GuestAuthorizeHost").await;
    let (user_id, username, password) = create_home_user(&env).await;
    invite_and_accept(&env, &root_sso, &host, &user_id).await;

    // The joined tenant's RP. Only `openid`, so no consent step.
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

/// Switches the tenant state via the admin API (root system admins only; MT11).
///
/// **Do not rewrite it with SQL directly.** Tenant resolution goes through a TTL cache, and reflecting the disable
/// needs invalidation on update. Rewriting only the DB would let the test observe "disabled but still resolvable"
/// while the cache lives, and the production path (admin API → invalidate) would not be tested.
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

/// Guarantee 4: disabling the home tenant also blocks signing in from the joined tenant's login screen.
///
/// The home tenant's own URLs are stopped with 404 by `TenantResolutionService`, but the joined tenant's URLs are
/// alive. Without checking here, users could "be stopped at home but get in from the joined tenant". Recovery is checked
/// too (disabling is reversible; returning to `ACTIVE` lets them in again).
#[tokio::test]
async fn a_guest_whose_home_tenant_is_disabled_cannot_sign_in_anywhere() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "DisabledHomeHost").await;
    // Using root as home would stop the root shared by other tests, so create a dedicated home tenant.
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

    // Password path (`home.status = 'ACTIVE'` in the resolution query).
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.62", &username, &password).await,
        "invalid_credentials",
        "a guest whose home tenant is disabled must not sign in on the host tenant"
    );
    // Signing in to the home tenant itself also stops (users of a disabled tenant cannot sign in anywhere).
    // The internal API has no tenant prefix and does not go through `TenantResolver`, so rejecting `DISABLED` is
    // done by `require_internal_tenant`. It fails with 400 before credentials are looked at.
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

    // Via an existing SSO session (`is_active_member`) it stops too. Checked at the admin console entrance.
    // Either the exchange for an admin token is refused, or it succeeds with zero permissions and whoami fails
    // (which one is an implementation detail; the requirement is "cannot get in"; ADR-0037).
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

    // Recovery: returning the home tenant to ACTIVE lets them in again.
    set_tenant_status(&env, &root_sso, &home, "ACTIVE").await;
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.64", &username, &password).await,
        "success",
        "re-enabling the home tenant restores access"
    );
}

/// Guarantee 6: disabling the home tenant also stops refresh tokens issued in the joined tenant at the next
/// refresh (MT27).
///
/// **The disabled tenant's own `/{tenant_id}/token` is stopped with 404 by `TenantResolver`, but the
/// `/{tenant_id}/token` of other tenants that user joined as a guest is alive.** Without blocking here,
/// logins would be stopped while issued tokens alone survive until their lifetime (30 days by default).
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

    // From the joined tenant's RP, the guest goes as far as obtaining a refresh token.
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
    // `offline_access` is not covered by implicit consent, so a consent step may come in.
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

    // Before disabling, refresh works.
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

    // Once the home tenant is stopped, tokens issued in the joined tenant cannot be refreshed either.
    let response = refresh(&env, &host, &client_id, &rotated).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a refresh token must stop once the user's home tenant is disabled"
    );
    let body = body_json(response).await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

/// Calls the `refresh_token` grant once (public client with PKCE, so no client authentication).
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

/// Guarantee 6 (MT25): input that is **ambiguous** in the home tenant stops resolution there. It must not fall
/// through to guest resolution and authenticate "a guest holding the same value".
///
/// # How this state is reached
///
/// Normalization differs per kind, so one input spreads into **several normalized values**. `090-123-4567` is
/// `090-123-4567` as a username and `0901234567` with separators dropped as a phone number.
/// These are different strings, so different people can hold them, slipping past the value unique constraint
/// (migration 0041; one normalized value per person within a tenant).
///
/// The availability check on add rejects values that hit others "the same way the real login path looks them up",
/// but **does not hit inactive rows** (disabled identifiers do not resolve). So in this order one input can hit two people:
///
/// 1. Assign phone number `0901234567` to A **in an inactive state** (the same state as a disabled existing identifier).
/// 2. B takes username `090-123-4567`. A's row is inactive, so the availability check misses it, and the normalized
///    value differs, so the unique constraint misses it too.
/// 3. Re-enable A's phone number. Now `090-123-4567` hits both A (phone number) and B (username).
///
///
/// Entering `090-123-4567` in host's login field in this state used to collapse "ambiguous at home" into
/// "absent at home" and fall through to guest resolution, letting a guest who holds the same value as a username
/// **sign in with their own password**. Not impersonation, but two rules — "ambiguous does not pass" and "the home
/// tenant wins name contention within the tenant" — were broken at once.
#[tokio::test]
async fn an_ambiguous_home_identifier_does_not_let_a_guest_sign_in() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "AmbiguousIdentifierHost").await;

    // Pick a value the same input normalizes two ways (phone numbers drop separators, usernames do not).
    let digits = format!("0{:09}", uuid::Uuid::new_v4().as_u128() % 1_000_000_000);
    let dashed = format!("{}-{}-{}", &digits[0..3], &digits[3..6], &digits[6..10]);

    // Two HOME users in host (temporarily allow self-registration to create users with known passwords).
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

    // 1. A's phone number (inactive).
    let res = send(
        &env.app,
        post(
            &tok(&env, &root_sso, &host).await,
            &format!("/{host}/admin/users/{alice_id}/login-identifiers"),
            json!({ "identifier_type": "phone_number", "value": digits, "is_active": false }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "alice's phone number");
    let alice_identifier = body_json(res).await["id"]
        .as_str()
        .expect("identifier id")
        .to_string();

    // 2. B's username (with separators). A's row is inactive, so the availability check misses it.
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
        "the availability check does not hit inactive rows (if this premise breaks, revisit the whole path)"
    );

    // 3. Re-enable A's phone number. From here `dashed` hits two people.
    let res = send(
        &env.app,
        patch(
            &tok(&env, &root_sso, &host).await,
            &format!("/{host}/admin/users/{alice_id}/login-identifiers/{alice_identifier}"),
            json!({ "is_active": true }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "enable alice's phone number");

    // Make a root-homed user holding the same value as a username a guest of host.
    let guest_password = format!("guest-password-{}", unique());
    register_user(&env.app, &env.root_tenant_id, &dashed, &guest_password).await;
    mark_email_verified(&env.pool, &env.root_tenant_id, &dashed).await;
    let guest_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &dashed)
        .await
        .expect("registered guest");
    invite_and_accept(&env, &root_sso, &host, &guest_id).await;

    // ── Main check: ambiguous input does not resolve guests either.
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.61", &dashed, &guest_password).await,
        "invalid_credentials",
        "ambiguous input must not fall through to guest resolution"
    );
    // The HOME users party to the ambiguity cannot sign in with that value either (consistency of "ambiguous does not pass").
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.62", &dashed, &bob_password).await,
        "invalid_credentials",
        "ambiguous input resolves to nobody"
    );
    // Only the ambiguous input is refused; the people's own unique identifiers are unaffected.
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.63", &alice, &alice_password).await,
        "success",
        "signing in with one's own unique username works as before"
    );
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.64", &bob, &bob_password).await,
        "success",
        "signing in with one's own unique username works as before"
    );
    // The guest's value is unique in the home tenant, so signing in from there works.
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
        "unique in the home tenant, so it resolves"
    );

    // ── The audit log records it as "ambiguous", not "absent". It needs admin correction, so
    //    the reason one cannot get in with correct credentials must be readable.
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
        "ambiguous is recorded in the audit log distinctly from unknown_user: {reasons:?}"
    );
}

/// Assigns a domain to a tenant (ADR-0029; needs `idp.system.admin`, so called with root's admin token).
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

/// Creates a tenant, enables self-registration and puts one user with a known password in it.
/// Returns `(tenant_id, user_id)`.
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

/// Guarantee 7 (MT25 / ADR-0029): when two guests with the same username join, both are locked out under that
/// name. **Assigning a domain to the home tenant lets them in with domain-qualified input.**
///
/// The lockout comes from identifier uniqueness being guaranteed only within one tenant, while the joined tenant's
/// screen resolves across home tenants. A domain is assigned exclusively to one tenant, so input of the form
/// `local@domain` determines exactly one home tenant, and only that tenant's registry needs to be looked up
/// (no cross-tenant scan = ambiguity cannot arise in principle).
///
/// Also checks that it is **additive, not a replacement** — bare usernames still fall through to the scan and are
/// rejected if ambiguous. Usability for users without a domain is unchanged.
#[tokio::test]
async fn a_tenant_domain_lets_a_guest_sign_in_where_the_bare_name_is_ambiguous() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let host = create_tenant(&env, &root_sso, "DomainHost").await;

    // One user with the same username in each of two different home tenants.
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

    // ── Neither can sign in with the bare username (the scan hits two people and fail-closed rejects).
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.71", &shared_username, &password_a).await,
        "invalid_credentials",
        "when two same-named guests join, that name cannot be resolved"
    );
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.72", &shared_username, &password_b).await,
        "invalid_credentials",
        "the lockout applies to both"
    );
    // Signing in from the home tenant's screen works as before (only the joined tenant's screen locks them out).
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
        "unique in the home tenant, so it resolves"
    );

    // ── Assigning a domain to A lets A's user into the joined tenant with domain qualification.
    let domain = format!("a{}.example", unique());
    assign_domain(&env, &root_sso, &tenant_a, &domain).await;
    let qualified = format!("{shared_username}@{domain}");
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.74", &qualified, &password_a).await,
        "success",
        "once the domain determines the home tenant, it resolves without the scan"
    );

    // ── The domain names the home tenant, so B's same-named user does not resolve with this spelling.
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.75", &qualified, &password_b).await,
        "invalid_credentials",
        "the domain determines exactly one home tenant"
    );

    // ── Additive, not a replacement: bare usernames are treated the same as before.
    assert_eq!(
        portal_login_result(&env, &host, "203.0.113.76", &shared_username, &password_a).await,
        "invalid_credentials",
        "bare input falls through to the scan as before and is rejected if ambiguous"
    );
    // Unassigned domains also fall through to the scan (B's user still cannot get in).
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
        "unassigned domains do not take that path"
    );
}

/// Guarantee 8 (ADR-0029): domain uniqueness is **global**, and only root's system admins assign them.
#[tokio::test]
async fn a_domain_belongs_to_exactly_one_tenant() {
    let Some(env) = setup().await else { return };
    let root_sso = create_sso_session(&env.pool, &env.root_admin_id).await;
    let first = create_tenant(&env, &root_sso, "DomainOwner").await;
    let second = create_tenant(&env, &root_sso, "DomainRival").await;
    let domain = format!("owned{}.example", unique());
    let uri = |t: &str| format!("/{}/admin/tenants/{t}/domains", env.root_tenant_id);
    // Domain assignment is done on the root tenant's path (`idp.system.admin` exists only in root scope).
    // The target tenant just goes later in the path, so a single root admin token suffices.
    let root_tok = tok(&env, &root_sso, &env.root_tenant_id).await;

    assign_domain(&env, &root_sso, &first, &domain).await;

    // Another tenant cannot take the same domain (the unique key does not include the tenant).
    let res = send(
        &env.app,
        post(&root_tok, &uri(&second), json!({ "domain": &domain })),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a domain belongs to only one tenant"
    );
    // A duplicate within the same tenant is also 409.
    let res = send(
        &env.app,
        post(&root_tok, &uri(&first), json!({ "domain": &domain })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // Case and trailing dots are normalized, so other spellings of the same domain cannot be taken either.
    let res = send(
        &env.app,
        post(
            &root_tok,
            &uri(&second),
            json!({ "domain": format!("{}.", domain.to_uppercase()) }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "normalized before matching"
    );

    // Values that cannot be read as a domain are 400 (if registrable, an assignment that never applies would silently remain).
    for bad in ["", "-bad.example", "日本語.example"] {
        let res = send(
            &env.app,
            post(&root_tok, &uri(&second), json!({ "domain": bad })),
        )
        .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{bad:?}");
    }

    // Users without permission cannot assign (idp.system.admin exists only in root).
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

    // List → remove → after removal another tenant can take it.
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
    // Cannot delete by specifying another tenant's id (it is already gone, so 404).
    let res = send(
        &env.app,
        support::delete(&root_tok, &format!("{}/{domain_id}", uri(&second))),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    assign_domain(&env, &root_sso, &second, &domain).await;
}

/// Guarantee 9 (ADR-0029): in a tenant with an assigned domain, `localpart@thatdomain` is also a spelling
/// pointing at "the user named localpart". **That spelling must not be registered as someone else's identifier.**
///
/// If it could be, the owner, for whom that spelling may be the only entrance on joined tenants' screens,
/// would suddenly be unable to get in (hijacking). The availability check must look at the same scope as login resolution.
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

    // Another person in the same tenant.
    let other_name = format!("other{}", unique());
    register_user(&env.app, &tenant, &other_name, &password).await;
    mark_email_verified(&env.pool, &tenant, &other_name).await;
    let other_id = support::find_user_id_by_username(&env.pool, &tenant, &other_name)
        .await
        .expect("registered other");

    // Trying to make `owner@thatdomain` another person's identifier gives 409.
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
        "the UPN spelling belongs to its owner; do not add it to someone else"
    );

    // For an unassigned domain registration works as before (the check is limited to this tenant's domains).
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
        "other domains are not subject to UPN interpretation"
    );

    // The owner can sign in with their own UPN spelling as before.
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
        "the owner can sign in with the UPN spelling"
    );
}
