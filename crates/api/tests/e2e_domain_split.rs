//! web→api E2E テスト（ADR-0012 §7）。
//!
//! api と web をローカルポートに bind した実サーバとして同時起動し、Cookie jar 有効の HTTP
//! クライアント（reqwest `cookie_store` + `resolve()` でテスト用ホスト名を `127.0.0.1` へ上書き）で
//! ブラウザ相当の遷移を辿る。Cookie jar が `Domain` 属性・ホスト一致を解釈するため、
//! サービス横断 Cookie（`sso_session_id`・`auth_session_id`）の越境可否を実挙動で検証できる
//! （`tests/oidc_flow.rs` のようなヘッダ文字列の手組みではブラウザの Cookie 規則を検証できない）。
//!
//! ケース（ADR-0012 §7 の受け入れ条件）:
//! 1. 別ドメイン構成: `/authorize`（api ドメイン）→ 302 → `/login`（web ドメイン）→ POST →
//!    SSO Cookie が `Domain=COOKIE_DOMAIN` で保存され、再度の `/authorize` に SSO Cookie が
//!    送信されて即時 code 発行される。`auth_session_id` の逆方向（api → web）も同フローで検証する。
//! 2. host-only 残留の掃除: 事前に host-only の同名 Cookie を仕込んだ状態でログインし、
//!    削除併送により二重 Cookie が解消される。
//! 3. 回帰: `COOKIE_DOMAIN` 未設定（単一オリジン構成）で従来挙動（host-only・Domain 属性なし）が
//!    変わらない。

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
    /// api の公開オリジン（= ISSUER。例 `http://api.example.test:PORT`）。
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

/// `/authorize` → ログイン → 再 `/authorize` のブラウザ遷移を辿り、途中のレスポンスを検証に返す。
struct LoginFlowResult {
    /// 初回 `/authorize`（未ログイン）のレスポンス。
    authorize: reqwest::Response,
    /// `POST /login` 成功のレスポンス。
    login: reqwest::Response,
    /// SSO 確立後の再 `/authorize` のレスポンス。
    second_authorize: reqwest::Response,
}

async fn run_login_flow(
    client: &reqwest::Client,
    stack: &Stack,
    client_id: &str,
    username: &str,
    password: &str,
) -> LoginFlowResult {
    let tenant = &stack.root_tenant_id;

    // 1. /authorize（api ドメイン）: 未ログインなので web のログイン画面へ 302。
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
    let login_url = location(&authorize);
    assert_eq!(
        login_url,
        format!("{}/{tenant}/login", stack.web_base),
        "authorize must redirect to the web origin as an absolute URL (ADR-0012 §4)"
    );
    let auth_session_id = set_cookies_for(&authorize, "auth_session_id")
        .iter()
        .find_map(|c| {
            let value = c.split(';').next()?.split_once('=')?.1.to_string();
            (!value.is_empty()).then_some(value)
        })
        .expect("auth_session_id cookie value");

    // 2. ログイン画面（web ドメイン）: auth_session_id Cookie が api → web へ届いていれば
    //    OIDC ログインフォーム（auth_session 由来の CSRF トークン入り）が描画される。
    //    届いていなければポータルログイン（別 CSRF）になり、ここで検出できる。
    let expected_csrf = login_csrf_token(&auth_session_id, &stack.csrf_secret);
    let page = client.get(&login_url).send().await.expect("GET /login");
    assert_eq!(page.status(), StatusCode::OK);
    let body = page.text().await.expect("login page body");
    assert!(
        body.contains(&expected_csrf),
        "login page must render the OIDC form; auth_session_id cookie did not cross to the web origin"
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

    // 4. 再度の /authorize（api ドメイン）: web が Set-Cookie した SSO Cookie が api に送信されれば
    //    ログイン画面を経ずに即時 code 発行される（ログイン→API 連携の本丸）。
    let second_authorize = client
        .get(format!(
            "{}{}",
            stack.api_base,
            authorize_uri_openid_only(tenant, client_id)
        ))
        .send()
        .await
        .expect("second GET /authorize");
    LoginFlowResult {
        authorize,
        login,
        second_authorize,
    }
}

fn assert_immediate_code(second_authorize: &reqwest::Response) {
    assert_eq!(second_authorize.status(), StatusCode::FOUND);
    let callback = location(second_authorize);
    assert!(
        callback.starts_with(REDIRECT_URI) && callback.contains("code="),
        "SSO cookie must cross to the api origin and issue a code immediately, got {callback}"
    );
}

/// ケース 1+2: 別ドメイン構成で SSO / auth_session Cookie が双方向に越境する。
#[tokio::test(flavor = "multi_thread")]
async fn cross_domain_login_shares_cookies_between_api_and_web() {
    let Some(stack) =
        start_stack("api.example.test", "id.example.test", Some("example.test")).await
    else {
        return;
    };
    let client_id =
        support::insert_public_client(&stack.pool, &stack.root_tenant_id, &["openid"]).await;
    let password = "correct-horse-battery";
    let username = create_login_user(&stack, password).await;
    let (client, _jar) = browser(&["api.example.test", "id.example.test"]);

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;

    // auth_session_id は Domain 付き発行 + host-only 削除の併送（ADR-0012 §3）。
    let auth_cookies = set_cookies_for(&result.authorize, "auth_session_id");
    assert_eq!(auth_cookies.len(), 2, "domain cookie + host-only cleanup");
    assert!(
        auth_cookies[0].contains("Domain=example.test"),
        "{auth_cookies:?}"
    );
    assert!(
        !auth_cookies[1].contains("Domain=") && auth_cookies[1].contains("Max-Age=0"),
        "{auth_cookies:?}"
    );

    // SSO Cookie も Domain 付き + host-only 削除の併送。
    let sso_cookies = set_cookies_for(&result.login, "sso_session_id");
    assert_eq!(sso_cookies.len(), 2, "domain cookie + host-only cleanup");
    assert!(
        sso_cookies[0].contains("Domain=example.test"),
        "{sso_cookies:?}"
    );
    assert!(
        !sso_cookies[1].contains("Domain=") && sso_cookies[1].contains("Max-Age=0"),
        "{sso_cookies:?}"
    );

    assert_immediate_code(&result.second_authorize);
}

/// ケース 3: 単一オリジン構成から移行したブラウザに残る host-only Cookie が削除併送で掃除され、
/// 古いセッションが新しいセッションを覆い隠さない。
#[tokio::test(flavor = "multi_thread")]
async fn host_only_residue_is_cleaned_up_on_login() {
    let Some(stack) =
        start_stack("api.example.test", "id.example.test", Some("example.test")).await
    else {
        return;
    };
    let client_id =
        support::insert_public_client(&stack.pool, &stack.root_tenant_id, &["openid"]).await;
    let password = "correct-horse-battery";
    let username = create_login_user(&stack, password).await;
    let (client, jar) = browser(&["api.example.test", "id.example.test"]);

    // 移行前（単一オリジン時代）の host-only SSO Cookie が web ホストに残っている状態を再現する。
    let web_url: reqwest::Url = format!("{}/", stack.web_base).parse().unwrap();
    jar.add_cookie_str("sso_session_id=stale-host-only-session; Path=/", &web_url);

    let result = run_login_flow(&client, &stack, &client_id, &username, password).await;

    // ログイン成功時の削除併送（host-only の Max-Age=0）で残留 Cookie が消えること。
    let sso_cookies = set_cookies_for(&result.login, "sso_session_id");
    assert!(
        sso_cookies
            .iter()
            .any(|c| !c.contains("Domain=") && c.contains("Max-Age=0")),
        "host-only cleanup cookie must be sent: {sso_cookies:?}"
    );
    // jar 上で stale が掃除され、Domain 付きの新セッションのみが残る（二重送信の解消）。
    let remaining = jar
        .cookies(&web_url)
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    assert!(
        !remaining.contains("stale-host-only-session"),
        "stale host-only cookie must be removed, jar still sends: {remaining}"
    );

    // 新しいセッションで即時 code 発行が成立する（stale に覆い隠されない）。
    assert_immediate_code(&result.second_authorize);
}

/// ケース 4（回帰）: `COOKIE_DOMAIN` 未設定の単一オリジン構成では従来挙動（host-only・
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

    // Domain 属性なし・1 本のみ（削除併送なし）= 従来挙動。
    let auth_cookies = set_cookies_for(&result.authorize, "auth_session_id");
    assert_eq!(auth_cookies.len(), 1, "{auth_cookies:?}");
    assert!(!auth_cookies[0].contains("Domain="), "{auth_cookies:?}");
    let sso_cookies = set_cookies_for(&result.login, "sso_session_id");
    assert_eq!(sso_cookies.len(), 1, "{sso_cookies:?}");
    assert!(!sso_cookies[0].contains("Domain="), "{sso_cookies:?}");

    assert_immediate_code(&result.second_authorize);
}
