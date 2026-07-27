//! web→api E2E テスト（ADR-0018。旧 ADR-0012 §7 の Cookie 越境検証を置き換える）。
//!
//! api と web をローカルポートに bind した実サーバとして同時起動し、Cookie jar 有効の HTTP
//! クライアント（reqwest `cookie_store` + `resolve()` でテスト用ホスト名を `127.0.0.1` へ上書き）で
//! ブラウザ相当の遷移を辿る。Cookie jar が `Domain` 属性・ホスト一致を解釈するため、
//! 「api がブラウザ Cookie を一切読み書きせず、host-only Cookie だけでフローが成立する」ことを
//! 実挙動で検証できる。
//!
//! ケース（ADR-0018 の受け入れ条件）:
//! 1. 別ドメイン構成（api は web の子サブドメイン。決定 1 の入れ子ホスト名）: `/authorize`
//!    （api ドメイン）→ 302（単回ハンドル付き）→ `/login`（web ドメイン。ハンドルを host-only
//!    Cookie へ移す）→ POST → SSO 確立 → 再 `/authorize` はログイン画面を経ずに code 発行。
//!    **api はブラウザ Cookie を一切発行せず**、web の Cookie に `Domain` 属性が付かない。
//! 2. RP-initiated Logout（web の `GET /{tenant_id}/logout`）で SSO Cookie が消え、
//!    以後の `/authorize` は再ログインになる。ポータルログアウト（POST）も同様。
//! 3. 旧構成の掃除: `COOKIE_DOMAIN` 設定時、ブラウザに残った `Domain` 付き Cookie が
//!    削除併送で掃除され、新しい host-only セッションを覆い隠さない（決定 4 の移行経路）。
//! 4. 回帰: 単一オリジン構成（`COOKIE_DOMAIN` 未設定）で host-only・削除併送なしの従来挙動。

mod support;

use axum::http::StatusCode;
use idp_contracts::csrf::login_csrf_token;
use reqwest::cookie::CookieStore as _;
use reqwest::header::SET_COOKIE;
use std::future::IntoFuture;
use std::sync::Arc;
use support::{authorize_uri_openid_only, REDIRECT_URI};

/// 環境変数（プロセス共有）を触りながら api/web の Config を組み立てる区間を直列化するロック。
static ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// 起動済みの api + web スタック。
struct Stack {
    /// api の公開オリジン（= ISSUER。例 `http://api.idp.example.test:PORT`）。
    api_base: String,
    /// web の公開オリジン（= PUBLIC_WEB_BASE_URL）。
    web_base: String,
    pool: sqlx::MySqlPool,
    root_tenant_id: String,
    csrf_secret: [u8; 32],
}

/// api と web を実サーバとして起動する。`TEST_DATABASE_URL` 未設定でスキップ許可時は `None`。
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

    // Config は環境変数から組み立てる。env はプロセス共有のため、構築が終わるまでロックする
    // （このテストバイナリ内の他ケースとの競合を防ぐ。他のテストバイナリは別プロセス）。
    let (env, web_config) = {
        let _guard = ENV_MUTEX.lock().await;
        std::env::set_var("ISSUER", &api_base);
        std::env::set_var("PUBLIC_WEB_BASE_URL", &web_base);
        match cookie_domain {
            Some(d) => std::env::set_var("COOKIE_DOMAIN", d),
            None => std::env::remove_var("COOKIE_DOMAIN"),
        }
        // web→api のサーバ間内部到達先（公開ドメインを経由しない。ADR-0012 §2）。
        std::env::set_var(
            "API_BASE_URL",
            format!(
                "http://127.0.0.1:{}",
                api_listener.local_addr().unwrap().port()
            ),
        );
        let env = support::setup("e2e_domain_split").await;
        let web_config = idp_web::config::Config::from_env().expect("load web config");
        std::env::remove_var("ISSUER");
        std::env::remove_var("PUBLIC_WEB_BASE_URL");
        std::env::remove_var("COOKIE_DOMAIN");
        std::env::remove_var("API_BASE_URL");
        (env?, web_config)
    };

    let web_state = idp_web::state::WebState::build(Arc::new(web_config));
    let web_app = idp_web::router::build(web_state);
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

/// Cookie jar 有効・リダイレクト手動追跡のブラウザ相当クライアント。テスト用ホスト名は
/// `resolve()` で `127.0.0.1` へ上書きする（ポートは URL 側の指定が使われる）。
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

/// 検証済みメール・既知パスワードの利用者を root テナントへ直接作成し、username を返す。
async fn create_login_user(stack: &Stack, password: &str) -> String {
    use idp_api::domain::password::PasswordHasher as _;
    let username = format!("e2e{}", support::unique());
    let hash = idp_api::infrastructure::password::Argon2PasswordHasher::new()
        .hash(password)
        .expect("hash password");
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, preferred_username, \
         password_hash, status) VALUES (?, ?, ?, ?, 1, ?, ?, 'ACTIVE')",
    )
    .bind(&id)
    .bind(&stack.root_tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!("{username}@example.com"))
    .bind(&username)
    .bind(&hash)
    .execute(&stack.pool)
    .await
    .expect("insert user");
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

/// レスポンスの `Set-Cookie` から `name` で始まるものを全件返す。
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

/// api がブラウザ Cookie を一切発行していないこと（ADR-0018 決定 2 の中核）。
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

/// `/authorize` → web ハンドオフ → ログイン → 再 `/authorize` のブラウザ遷移を辿り、
/// 途中のレスポンスを検証に返す。
struct LoginFlowResult {
    /// 初回 `/authorize`（api ドメイン。ハンドオフ 302）のレスポンス。
    authorize: reqwest::Response,
    /// ハンドオフ URL（`/login?auth_session=...`）への GET（web がハンドルを Cookie へ移す）のレスポンス。
    handoff: reqwest::Response,
    /// `POST /login` 成功のレスポンス。
    login: reqwest::Response,
    /// SSO 確立後の再 `/authorize` を web ハンドオフまで辿った最終レスポンス
    /// （SSO 復元に成功していれば RP callback への 302）。
    second_authorize: reqwest::Response,
}

/// `/authorize`（api）を開始し、web のハンドオフ受領（`?auth_session=` → 303）まで辿る。
/// 戻り値は `(authorize 応答, ハンドオフ応答)`。
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

    // 1. /authorize（api ドメイン）→ 単回ハンドル付きで web へ 302 → web がハンドルを host-only
    //    Cookie へ移して 303 で自 URL（クエリなし）へ付け替える。
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

    // 2. ログイン画面（web ドメイン）: host-only の auth_session_id Cookie が届いていれば
    //    OIDC ログインフォーム（auth_session 由来の CSRF トークン入り）が描画される。
    let expected_csrf = login_csrf_token(&auth_session_id, &stack.csrf_secret);
    let page = client.get(&login_url).send().await.expect("GET /login");
    assert_eq!(page.status(), StatusCode::OK);
    let body = page.text().await.expect("login page body");
    assert!(
        body.contains(&expected_csrf),
        "login page must render the OIDC form from the host-only auth_session_id cookie"
    );

    // 3. POST /login（web ドメイン）: 成功で SSO Cookie を発行し、code 付き callback へ 302。
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

    // 4. 再度の /authorize（api ドメイン）→ web ハンドオフ: web が host-only の SSO Cookie を
    //    読んで resume するため、ログイン画面を経ずに RP callback へ 302 される（SSO 復元の本丸）。
    let (second_authorize_hop, second_handoff) = follow_handoff(client, stack, client_id).await;
    drop(second_authorize_hop);
    LoginFlowResult {
        authorize,
        handoff,
        login,
        second_authorize: second_handoff,
    }
}

/// ログアウト後の `/authorize` が「未ログイン」としてログインフォームへ戻ることを確かめる。
/// SSO Cookie が消えていなければ即時 code 発行になるため、ここで検出できる。
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

/// Cookie jar が `url` へ送る Cookie に `name` が残っていないこと。
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

/// SSO 復元に成功した再 `/authorize` は、web ハンドオフの時点で RP callback へ 302 される。
fn assert_immediate_code(second_authorize: &reqwest::Response) {
    assert_eq!(second_authorize.status(), StatusCode::FOUND);
    let callback = location(second_authorize);
    assert!(
        callback.starts_with(REDIRECT_URI) && callback.contains("code="),
        "the web must resume the SSO session and issue a code immediately, got {callback}"
    );
}

/// ケース 1: 別ドメイン構成（入れ子ホスト名。ADR-0018 決定 1）で、Cookie を越境させずに
/// フローが成立する。`COOKIE_DOMAIN` は設定しない（決定 4 の既定）。
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

    // api は /authorize でブラウザ Cookie を発行しない（run_login_flow 内でも検証済み）。
    assert_no_set_cookie(&result.authorize, "/authorize");

    // web の Cookie は host-only（Domain 属性なし・削除併送なし）。
    let auth_cookies = set_cookies_for(&result.handoff, "auth_session_id");
    assert_eq!(auth_cookies.len(), 1, "{auth_cookies:?}");
    assert!(!auth_cookies[0].contains("Domain="), "{auth_cookies:?}");
    let sso_cookies = set_cookies_for(&result.login, "sso_session_id");
    assert_eq!(sso_cookies.len(), 1, "{sso_cookies:?}");
    assert!(!sso_cookies[0].contains("Domain="), "{sso_cookies:?}");

    // host-only のため api オリジンへは SSO Cookie が送信されない（送信されなくてもフローは成立する）。
    assert_jar_dropped(&jar, &format!("{}/", stack.api_base), "sso_session_id");

    assert_immediate_code(&result.second_authorize);
}

/// ケース 2a: RP-initiated Logout（web の `GET /{tenant_id}/logout`。ADR-0018 決定 2 で
/// end_session_endpoint は web が受ける）で SSO Cookie が消え、以後は再ログインになる。
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

    let logout = client
        .get(format!(
            "{}/{}/logout",
            stack.web_base, stack.root_tenant_id
        ))
        .send()
        .await
        .expect("GET /logout");
    // front-channel 通知・post_logout_redirect_uri のないクライアントなので完了ページ（200）。
    assert_eq!(logout.status(), StatusCode::OK);
    let deletions = set_cookies_for(&logout, "sso_session_id");
    assert!(
        deletions.iter().any(|c| c.contains("Max-Age=0")),
        "logout must expire the SSO cookie: {deletions:?}"
    );

    assert_jar_dropped(&jar, &format!("{}/", stack.web_base), "sso_session_id");
    assert_login_required_again(&client, &stack, &client_id).await;
}

/// ケース 2b: web のポータル・ログアウト（`POST /{tenant_id}/logout`）でも SSO Cookie が消える。
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

    let logout = client
        .post(format!(
            "{}/{}/logout",
            stack.web_base, stack.root_tenant_id
        ))
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

/// ケース 3: 旧 ADR-0012 構成（兄弟ホスト + `COOKIE_DOMAIN`=apex）からの移行。ブラウザに残った
/// `Domain` 付き Cookie が、`COOKIE_DOMAIN` 設定時の削除併送で掃除され、新しい host-only
/// セッションを覆い隠さない（ADR-0018 決定 4 の移行経路。掃除完了後は未設定へ戻す）。
#[tokio::test(flavor = "multi_thread")]
async fn legacy_domain_cookie_is_cleaned_up_on_login() {
    // COOKIE_DOMAIN は掃除対象の**旧** Domain（旧兄弟構成の apex = example.test）。web ホストと
    // 同一値は起動時検証で拒否される（削除 Cookie が host-only セッションを消してしまうため）。
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

    // 旧構成（ADR-0012）の Domain 付き SSO Cookie がブラウザに残っている状態を再現する。
    let web_url: reqwest::Url = format!("{}/", stack.web_base).parse().unwrap();
    jar.add_cookie_str(
        "sso_session_id=stale-domain-session; Domain=example.test; Path=/",
        &web_url,
    );

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;

    // ログイン成功時、host-only の新 Cookie に加えて Domain 付きの削除 Cookie が併送される。
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
    // jar 上で stale が掃除され、host-only の新セッションのみが残る（二重送信の解消）。
    let remaining = jar
        .cookies(&web_url)
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    assert!(
        !remaining.contains("stale-domain-session"),
        "stale domain cookie must be removed, jar still sends: {remaining}"
    );

    // 新しいセッションで即時 code 発行が成立する（stale に覆い隠されない）。
    assert_immediate_code(&result.second_authorize);
}

/// ケース 4（回帰）: 単一オリジン構成（`COOKIE_DOMAIN` 未設定）で従来挙動（host-only・
/// Domain 属性なし・削除併送なし）が変わらない。
#[tokio::test(flavor = "multi_thread")]
async fn single_origin_without_cookie_domain_keeps_host_only_behavior() {
    // 単一オリジン構成をポート違いの同一ホスト名で再現する（Cookie はポートを区別しない）。
    let Some(stack) = start_stack("app.example.test", "app.example.test", None).await else {
        return;
    };
    let client_id =
        support::insert_public_client(&stack.pool, &stack.root_tenant_id, &["openid"]).await;
    let password = "correct-horse-battery";
    let username = create_login_user(&stack, password).await;
    let (client, _jar) = browser(&["app.example.test"]);

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;

    // Domain 属性なし・1 本のみ（削除併送なし）= host-only の既定挙動。
    let auth_cookies = set_cookies_for(&result.handoff, "auth_session_id");
    assert_eq!(auth_cookies.len(), 1, "{auth_cookies:?}");
    assert!(!auth_cookies[0].contains("Domain="), "{auth_cookies:?}");
    let sso_cookies = set_cookies_for(&result.login, "sso_session_id");
    assert_eq!(sso_cookies.len(), 1, "{sso_cookies:?}");
    assert!(!sso_cookies[0].contains("Domain="), "{sso_cookies:?}");

    assert_immediate_code(&result.second_authorize);
}
