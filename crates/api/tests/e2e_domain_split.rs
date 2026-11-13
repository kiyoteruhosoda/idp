//! web→api E2E tests (ADR-0018; replaces the cross-domain cookie check of the former ADR-0012 §7).
//!
//! Starts api and web together as real servers bound to local ports, and follows browser-like navigation with
//! an HTTP client with a cookie jar (reqwest `cookie_store` + `resolve()` overriding test host names to
//! `127.0.0.1`). Since the cookie jar interprets the `Domain` attribute and host matching,
//! "api never reads or writes browser cookies and the flow works with host-only cookies alone" can be
//! checked against real behaviour.
//!
//! Cases (acceptance criteria of ADR-0018):
//! 1. Separate-domain setup (api is a subdomain of web; nested host names of decision 1): `/authorize`
//!    (api domain) → 302 (with a one-time handle) → `/login` (web domain; moves the handle into a host-only
//!    cookie) → POST → SSO established → a second `/authorize` issues a code without the login screen.
//!    **api issues no browser cookies at all**, and web's cookies have no `Domain` attribute.
//! 2. RP-initiated Logout (web's `GET /{tenant_id}/logout`) removes the SSO cookie, and
//!    later `/authorize` requires signing in again. Same for portal logout (POST).
//! 3. Cleaning up the old setup: with `COOKIE_DOMAIN` set, `Domain` cookies left in the browser are
//!    cleaned up by sending deletions alongside, and do not shadow the new host-only session (migration path of decision 4).
//! 4. Regression: single-origin setup (`COOKIE_DOMAIN` unset) keeps the old behaviour, host-only with no deletions sent.

mod support;

use assay_contracts::csrf::login_csrf_token;
use axum::http::StatusCode;
use reqwest::cookie::CookieStore as _;
use reqwest::header::SET_COOKIE;
use std::future::IntoFuture;
use std::sync::Arc;
use support::{authorize_uri_openid_only, REDIRECT_URI};

/// Lock serializing the sections that assemble api/web Config while touching env vars (shared by the process).
static ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A started api + web stack.
struct Stack {
    /// api's public origin (= ISSUER, e.g. `http://api.idp.example.test:PORT`).
    api_base: String,
    /// web's public origin (= PUBLIC_WEB_BASE_URL).
    web_base: String,
    pool: sqlx::MySqlPool,
    root_tenant_id: String,
    csrf_secret: [u8; 32],
}

/// Starts api and web as real servers. `None` when `TEST_DATABASE_URL` is unset and skipping is allowed.
async fn start_stack(api_host: &str, web_host: &str, cookie_domain: Option<&str>) -> Option<Stack> {
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind api listener");
    let web_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind web listener");
    let api_base = format!(
        "http://{api_host}:{}",
        api_listener.local_addr().unwrap().port()
    );
    let web_base = format!(
        "http://{web_host}:{}",
        web_listener.local_addr().unwrap().port()
    );

    // Config is built from env vars. env is shared by the process, so hold the lock until construction finishes
    // (prevents races with other cases in this test binary; other test binaries are separate processes).
    let (env, web_config) = {
        let _guard = ENV_MUTEX.lock().await;
        std::env::set_var("ISSUER", &api_base);
        std::env::set_var("PUBLIC_WEB_BASE_URL", &web_base);
        match cookie_domain {
            Some(d) => std::env::set_var("COOKIE_DOMAIN", d),
            None => std::env::remove_var("COOKIE_DOMAIN"),
        }
        // Server-to-server internal target from web to api (does not go through the public domain; ADR-0012 §2).
        std::env::set_var(
            "API_BASE_URL",
            format!(
                "http://127.0.0.1:{}",
                api_listener.local_addr().unwrap().port()
            ),
        );
        let env = support::setup("e2e_domain_split").await;
        let web_config = assay_web::config::Config::from_env().expect("load web config");
        std::env::remove_var("ISSUER");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");
        std::env::remove_var("API_BASE_URL");
        (env?, web_config)
    };

    let web_state = assay_web::state::WebState::build(Arc::new(web_config));
    let web_app = assay_web::router::build(web_state);
    tokio::spawn(axum::serve(api_listener, env.app.clone()).into_future());
    tokio::spawn(axum::serve(web_listener, web_app).into_future());

    Some(Stack {
        api_base,
        web_base,
        pool: env.pool,
        root_tenant_id: env.root_tenant_id,
        csrf_secret: env.csrf_secret,
    })
}

/// A browser-like client with a cookie jar and manual redirect following. Test host names are
/// overridden to `127.0.0.1` with `resolve()` (the port comes from the URL).
fn browser(hosts: &[&str]) -> (reqwest::Client, Arc<reqwest::cookie::Jar>) {
    let jar = Arc::new(reqwest::cookie::Jar::default());
    let mut builder = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .redirect(reqwest::redirect::Policy::none());
    for host in hosts {
        builder = builder.resolve(host, "127.0.0.1:0".parse().unwrap());
    }
    (builder.build().expect("build reqwest client"), jar)
}

/// Creates a user with a verified email and known password directly in the root tenant and returns the username.
async fn create_login_user(stack: &Stack, password: &str) -> String {
    use assay_api::domain::password::PasswordHasher as _;
    let username = format!("e2e{}", support::unique());
    let hash = assay_api::infrastructure::password::Argon2PasswordHasher::new()
        .hash(password)
        .expect("hash password");
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, ?, 'ACTIVE')",
    )
    .bind(&id)
    .bind(&stack.root_tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!("{username}@example.com"))
    .bind(&hash)
    .execute(&stack.pool)
    .await
    .expect("insert user");
    // The username is held as the registry's primary identifier row (AP15b). Without it, sign-in fails.
    sqlx::query(
        "INSERT INTO user_login_identifiers \
         (id, tenant_id, user_id, identifier_type, display_value, normalized_value, is_active, \
          primary_of_user) \
         VALUES (?, ?, ?, 'username', ?, ?, 1, ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&stack.root_tenant_id)
    .bind(&id)
    .bind(&username)
    .bind(username.to_lowercase())
    .bind(&id)
    .execute(&stack.pool)
    .await
    .expect("insert primary login identifier");
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'HOME', 'ACTIVE')",
    )
    .bind(&stack.root_tenant_id)
    .bind(&id)
    .execute(&stack.pool)
    .await
    .expect("insert home membership");
    username
}

/// Returns every `Set-Cookie` of the response starting with `name`.
fn set_cookies_for(response: &reqwest::Response, name: &str) -> Vec<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|v| v.starts_with(&format!("{name}=")))
        .map(str::to_string)
        .collect()
}

fn location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get("location")
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string()
}

/// api issued no browser cookies at all (the core of ADR-0018 decision 2).
fn assert_no_set_cookie(response: &reqwest::Response, context: &str) {
    let cookies: Vec<_> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        cookies.is_empty(),
        "{context}: the api must not set browser cookies (ADR-0018), got {cookies:?}"
    );
}

/// Follows the browser navigation `/authorize` → web handoff → login → second `/authorize`,
/// returning the responses along the way for checking.
struct LoginFlowResult {
    /// Response of the first `/authorize` (api domain; handoff 302).
    authorize: reqwest::Response,
    /// Response of the GET to the handoff URL (`/login?auth_session=...`) (web moves the handle into a cookie).
    handoff: reqwest::Response,
    /// Response of a successful `POST /login`.
    login: reqwest::Response,
    /// Final response of the second `/authorize` after SSO is established, followed up to the web handoff
    /// (a 302 to the RP callback if SSO restore succeeded).
    second_authorize: reqwest::Response,
}

/// Starts `/authorize` (api) and follows until web receives the handoff (`?auth_session=` → 303).
/// Returns `(authorize response, handoff response)`.
async fn follow_handoff(
    client: &reqwest::Client,
    stack: &Stack,
    client_id: &str,
) -> (reqwest::Response, reqwest::Response) {
    let tenant = &stack.root_tenant_id;
    let authorize = client
        .get(format!(
            "{}{}",
            stack.api_base,
            authorize_uri_openid_only(tenant, client_id)
        ))
        .send()
        .await
        .expect("GET /authorize");
    assert_eq!(authorize.status(), StatusCode::FOUND, "authorize redirects");
    assert_no_set_cookie(&authorize, "/authorize");
    let handoff_url = location(&authorize);
    assert!(
        handoff_url.starts_with(&format!("{}/{tenant}/login?auth_session=", stack.web_base)),
        "authorize must hand off to the web origin with a one-time handle (ADR-0018), got {handoff_url}"
    );

    let handoff = client
        .get(&handoff_url)
        .send()
        .await
        .expect("GET handoff URL");
    (authorize, handoff)
}

async fn run_login_flow(
    client: &reqwest::Client,
    stack: &Stack,
    client_id: &str,
    username: &str,
    password: &str,
) -> LoginFlowResult {
    let tenant = &stack.root_tenant_id;

    // 1. /authorize (api domain) → 302 to web with a one-time handle → web moves the handle into a host-only
    //    cookie and 303s to its own URL (without the query).
    let (authorize, handoff) = follow_handoff(client, stack, client_id).await;
    assert_eq!(
        handoff.status(),
        StatusCode::SEE_OTHER,
        "the web must strip the handle from the URL with a 303"
    );
    let login_url = format!("{}{}", stack.web_base, location(&handoff));
    assert_eq!(login_url, format!("{}/{tenant}/login", stack.web_base));
    let auth_session_id = set_cookies_for(&handoff, "auth_session_id")
        .iter()
        .find_map(|c| {
            let value = c.split(';').next()?.split_once('=')?.1.to_string();
            (!value.is_empty()).then_some(value)
        })
        .expect("auth_session_id cookie value");

    // 2. Login screen (web domain): if the host-only auth_session_id cookie arrived,
    //    the OIDC login form (with a CSRF token derived from auth_session) is rendered.
    let expected_csrf = login_csrf_token(&auth_session_id, &stack.csrf_secret);
    let page = client.get(&login_url).send().await.expect("GET /login");
    assert_eq!(page.status(), StatusCode::OK);
    let body = page.text().await.expect("login page body");
    assert!(
        body.contains(&expected_csrf),
        "login page must render the OIDC form from the host-only auth_session_id cookie"
    );

    // 3. POST /login (web domain): on success issues the SSO cookie and 302s to the callback with a code.
    let login = client
        .post(format!("{}/{tenant}/login", stack.web_base))
        .form(&[
            ("username", username),
            ("password", password),
            ("csrf_token", &expected_csrf),
        ])
        .send()
        .await
        .expect("POST /login");
    assert_eq!(login.status(), StatusCode::FOUND, "login succeeds");
    let callback = location(&login);
    assert!(
        callback.starts_with(REDIRECT_URI),
        "login redirects to RP callback, got {callback}"
    );

    // 4. /authorize again (api domain) → web handoff: web reads the host-only SSO cookie and resumes,
    //    so it 302s to the RP callback without the login screen (the heart of SSO restore).
    let (second_authorize_hop, second_handoff) = follow_handoff(client, stack, client_id).await;
    drop(second_authorize_hop);
    LoginFlowResult {
        authorize,
        handoff,
        login,
        second_authorize: second_handoff,
    }
}

/// Checks that `/authorize` after logout goes back to the login form as "not signed in".
/// If the SSO cookie were not gone, a code would be issued immediately, so this detects it.
async fn assert_login_required_again(client: &reqwest::Client, stack: &Stack, client_id: &str) {
    let (_, handoff) = follow_handoff(client, stack, client_id).await;
    assert_eq!(
        handoff.status(),
        StatusCode::SEE_OTHER,
        "after logout the flow must return to the login form"
    );
    assert_eq!(
        format!("{}{}", stack.web_base, location(&handoff)),
        format!("{}/{}/login", stack.web_base, stack.root_tenant_id)
    );
}

/// `name` is not among the cookies the cookie jar sends to `url`.
fn assert_jar_dropped(jar: &reqwest::cookie::Jar, url: &str, name: &str) {
    let url: reqwest::Url = url.parse().unwrap();
    let remaining = jar
        .cookies(&url)
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    assert!(
        !remaining.contains(&format!("{name}=")),
        "jar still sends {name} to {url}: {remaining}"
    );
}

/// A second `/authorize` with successful SSO restore 302s to the RP callback at the web handoff.
fn assert_immediate_code(second_authorize: &reqwest::Response) {
    assert_eq!(second_authorize.status(), StatusCode::FOUND);
    let callback = location(second_authorize);
    assert!(
        callback.starts_with(REDIRECT_URI) && callback.contains("code="),
        "the web must resume the SSO session and issue a code immediately, got {callback}"
    );
}

/// Case 1: in a separate-domain setup (nested host names; ADR-0018 decision 1), the flow works without
/// cookies crossing domains. `COOKIE_DOMAIN` is not set (the default of decision 4).
#[tokio::test(flavor = "multi_thread")]
async fn cross_domain_login_works_without_sharing_cookies() {
    let Some(stack) = start_stack("api.idp.example.test", "idp.example.test", None).await else {
        return;
    };
    let client_id =
        support::insert_public_client(&stack.pool, &stack.root_tenant_id, &["openid"]).await;
    let password = "correct-horse-battery";
    let username = create_login_user(&stack, password).await;
    let (client, jar) = browser(&["api.idp.example.test", "idp.example.test"]);

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;

    // api issues no browser cookies at /authorize (also checked inside run_login_flow).
    assert_no_set_cookie(&result.authorize, "/authorize");

    // web's cookies are host-only (no Domain attribute, no deletions sent).
    let auth_cookies = set_cookies_for(&result.handoff, "auth_session_id");
    assert_eq!(auth_cookies.len(), 1, "{auth_cookies:?}");
    assert!(!auth_cookies[0].contains("Domain="), "{auth_cookies:?}");
    let sso_cookies = set_cookies_for(&result.login, "sso_session_id");
    assert_eq!(sso_cookies.len(), 1, "{sso_cookies:?}");
    assert!(!sso_cookies[0].contains("Domain="), "{sso_cookies:?}");

    // Host-only, so the SSO cookie is not sent to the api origin (the flow works without it).
    assert_jar_dropped(&jar, &format!("{}/", stack.api_base), "sso_session_id");

    assert_immediate_code(&result.second_authorize);
}

/// Case 2a: RP-initiated Logout (web's `GET /{tenant_id}/logout`; per ADR-0018 decision 2
/// end_session_endpoint is served by web) removes the SSO cookie, and afterwards sign-in is required again.
#[tokio::test(flavor = "multi_thread")]
async fn rp_initiated_logout_on_the_web_clears_the_sso_cookie() {
    let Some(stack) = start_stack("api.idp.example.test", "idp.example.test", None).await else {
        return;
    };
    let client_id =
        support::insert_public_client(&stack.pool, &stack.root_tenant_id, &["openid"]).await;
    let password = "correct-horse-battery";
    let username = create_login_user(&stack, password).await;
    let (client, jar) = browser(&["api.idp.example.test", "idp.example.test"]);

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;
    assert_immediate_code(&result.second_authorize);

    // The request has no `id_token_hint`, so a confirmation screen appears first (task #588). That alone does not finish it.
    let confirmation = client
        .get(format!(
            "{}/{}/logout",
            stack.web_base, stack.root_tenant_id
        ))
        .send()
        .await
        .expect("GET /logout");
    assert_eq!(confirmation.status(), StatusCode::OK);
    assert!(
        set_cookies_for(&confirmation, "sso_session_id").is_empty(),
        "the confirmation page must not end the session"
    );
    let page = confirmation.text().await.expect("confirmation page");
    let token = page
        .split(r#"name="csrf_token" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the confirmation form carries a csrf token")
        .to_string();

    let logout = client
        .post(format!(
            "{}/{}/logout/confirm",
            stack.web_base, stack.root_tenant_id
        ))
        .form(&[("csrf_token", token.as_str())])
        .send()
        .await
        .expect("POST /logout/confirm");
    // The client has no front-channel notification or post_logout_redirect_uri, so the completion page (200).
    assert_eq!(logout.status(), StatusCode::OK);
    let deletions = set_cookies_for(&logout, "sso_session_id");
    assert!(
        deletions.iter().any(|c| c.contains("Max-Age=0")),
        "logout must expire the SSO cookie: {deletions:?}"
    );

    assert_jar_dropped(&jar, &format!("{}/", stack.web_base), "sso_session_id");
    assert_login_required_again(&client, &stack, &client_id).await;
}

/// Case 2b: web's portal logout (`POST /{tenant_id}/logout`; the account settings form) also
/// removes the SSO cookie. The form's CSRF token is required; without it there is no logout (task #143).
#[tokio::test(flavor = "multi_thread")]
async fn portal_logout_clears_the_sso_cookie() {
    let Some(stack) = start_stack("api.idp.example.test", "idp.example.test", None).await else {
        return;
    };
    let client_id =
        support::insert_public_client(&stack.pool, &stack.root_tenant_id, &["openid"]).await;
    let password = "correct-horse-battery";
    let username = create_login_user(&stack, password).await;
    let (client, jar) = browser(&["api.idp.example.test", "idp.example.test"]);

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;
    assert_immediate_code(&result.second_authorize);
    let logout_url = format!("{}/{}/logout", stack.web_base, stack.root_tenant_id);

    // A POST without a token (sent from an external page) does not log out.
    let rejected = client
        .post(&logout_url)
        .form(&[("csrf_token", "")])
        .send()
        .await
        .expect("POST /logout without a token");
    assert_eq!(rejected.status(), StatusCode::FOUND);
    assert_eq!(
        location(&rejected),
        format!("/{}/settings?error=csrf", stack.root_tenant_id)
    );
    let web_url: reqwest::Url = format!("{}/", stack.web_base).parse().unwrap();
    let still_sent = jar
        .cookies(&web_url)
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    assert!(
        still_sent.contains("sso_session_id="),
        "a rejected logout must keep the session: {still_sent}"
    );

    // Send with the token embedded in the settings screen's logout form (same as when the user presses it).
    let settings = client
        .get(format!(
            "{}/{}/settings",
            stack.web_base, stack.root_tenant_id
        ))
        .send()
        .await
        .expect("GET /settings")
        .text()
        .await
        .expect("settings body");
    let marker = r#"name="csrf_token" value=""#;
    let token: String = settings
        .split_once(marker)
        .map(|(_, rest)| rest.chars().take(64).collect())
        .unwrap_or_else(|| panic!("no csrf token on the settings page: {settings}"));
    let logout = client
        .post(&logout_url)
        .form(&[("csrf_token", token.as_str())])
        .send()
        .await
        .expect("POST /logout");
    assert_eq!(logout.status(), StatusCode::FOUND);
    assert_eq!(
        location(&logout),
        format!("/{}/login", stack.root_tenant_id)
    );

    assert_jar_dropped(&jar, &format!("{}/", stack.web_base), "sso_session_id");
    assert_login_required_again(&client, &stack, &client_id).await;
}

/// Case 3: migration from the former ADR-0012 setup (sibling hosts + `COOKIE_DOMAIN`=apex). `Domain` cookies left in
/// the browser are cleaned up by the deletions sent alongside when `COOKIE_DOMAIN` is set, and do not shadow
/// the new host-only session (migration path of ADR-0018 decision 4; reverted to unset once cleanup is done).
#[tokio::test(flavor = "multi_thread")]
async fn legacy_domain_cookie_is_cleaned_up_on_login() {
    // COOKIE_DOMAIN is the **old** Domain to clean up (the apex of the old sibling setup = example.test). A value
    // equal to the web host is rejected by startup validation (the deletion cookie would remove the host-only session).
    let Some(stack) = start_stack(
        "api.idp.example.test",
        "idp.example.test",
        Some("example.test"),
    )
    .await
    else {
        return;
    };
    let client_id =
        support::insert_public_client(&stack.pool, &stack.root_tenant_id, &["openid"]).await;
    let password = "correct-horse-battery";
    let username = create_login_user(&stack, password).await;
    let (client, jar) = browser(&["api.idp.example.test", "idp.example.test"]);

    // Reproduce the state where the old setup's (ADR-0012) Domain SSO cookie remains in the browser.
    let web_url: reqwest::Url = format!("{}/", stack.web_base).parse().unwrap();
    jar.add_cookie_str(
        "sso_session_id=stale-domain-session; Domain=example.test; Path=/",
        &web_url,
    );

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;

    // On successful login, a Domain deletion cookie is sent alongside the new host-only cookie.
    let sso_cookies = set_cookies_for(&result.login, "sso_session_id");
    assert_eq!(sso_cookies.len(), 2, "{sso_cookies:?}");
    assert!(
        !sso_cookies[0].contains("Domain="),
        "the new session cookie must be host-only: {sso_cookies:?}"
    );
    assert!(
        sso_cookies[1].contains("Domain=example.test") && sso_cookies[1].contains("Max-Age=0"),
        "the legacy domain cookie must be deleted: {sso_cookies:?}"
    );
    // The stale one is cleaned up in the jar and only the new host-only session remains (no double sending).
    let remaining = jar
        .cookies(&web_url)
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    assert!(
        !remaining.contains("stale-domain-session"),
        "stale domain cookie must be removed, jar still sends: {remaining}"
    );

    // A code is issued immediately with the new session (not shadowed by the stale one).
    assert_immediate_code(&result.second_authorize);

    // Silent SSO restore (a path without explicit login) also reissues the SSO cookie as host-only and sends
    // the old Domain deletion alongside. Existing sessions that do not sign in again are migrated here too, so the
    // bearer credential stops being sent under the old parent domain.
    let resumed = set_cookies_for(&result.second_authorize, "sso_session_id");
    assert_eq!(resumed.len(), 2, "{resumed:?}");
    assert!(
        !resumed[0].contains("Domain=") && !resumed[0].contains("Max-Age=0"),
        "silent resume must reissue the session host-only: {resumed:?}"
    );
    assert!(
        resumed[1].contains("Domain=example.test") && resumed[1].contains("Max-Age=0"),
        "silent resume must delete the legacy domain cookie: {resumed:?}"
    );
}

/// Case 4 (regression): in a single-origin setup (`COOKIE_DOMAIN` unset) the old behaviour (host-only,
/// no Domain attribute, no deletions sent) is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn single_origin_without_cookie_domain_keeps_host_only_behavior() {
    // Reproduce single-origin with the same host name on different ports (cookies do not distinguish ports).
    let Some(stack) = start_stack("app.example.test", "app.example.test", None).await else {
        return;
    };
    let client_id =
        support::insert_public_client(&stack.pool, &stack.root_tenant_id, &["openid"]).await;
    let password = "correct-horse-battery";
    let username = create_login_user(&stack, password).await;
    let (client, _jar) = browser(&["app.example.test"]);

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;

    // No Domain attribute, only one (no deletions sent) = the default host-only behaviour.
    let auth_cookies = set_cookies_for(&result.handoff, "auth_session_id");
    assert_eq!(auth_cookies.len(), 1, "{auth_cookies:?}");
    assert!(!auth_cookies[0].contains("Domain="), "{auth_cookies:?}");
    let sso_cookies = set_cookies_for(&result.login, "sso_session_id");
    assert_eq!(sso_cookies.len(), 1, "{sso_cookies:?}");
    assert!(!sso_cookies[0].contains("Domain="), "{sso_cookies:?}");

    assert_immediate_code(&result.second_authorize);
}
