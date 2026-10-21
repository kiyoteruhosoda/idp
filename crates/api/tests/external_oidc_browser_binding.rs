//! 外部 OIDC IdP の戻り口（callback）は、開始したブラウザからでないと進まない（task #581）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test external_oidc_browser_binding
//!
//! 攻撃者は自分のアカウントで外部 IdP のログインを途中まで進め、`code` と `state` の付いた戻り URL を
//! 手に入れられる。それを他人に踏ませると、その人のブラウザに攻撃者のアカウントでログインした状態が
//! 入っていた（ログイン CSRF）。戻り口は、開始時にブラウザへ渡した値（Cookie）が無いと進まない。
//!
//! 本物の外部 IdP は立てない。照合は**コードの交換より前**に行うので、照合に通れば交換へ進んで
//! 失敗し（`external_failure`）、通らなければ進行状態が無いのと同じ扱い（`state_expired`）になる。

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_json, post_internal, send, unique, TestEnv, SERVICE_TOKEN};

/// 届かない外部 IdP（`.invalid` は名前が引けない。RFC 6761）を DB へ直接登録し、`provider_code` を返す。
async fn register_unreachable_oidc_provider(env: &TestEnv) -> String {
    let provider_code = format!("oidc-{}", unique());
    sqlx::query(
        "INSERT INTO external_identity_providers \
         (id, tenant_id, provider_code, display_name, protocol, issuer, authorization_endpoint, \
          token_endpoint, jwks_uri, client_id, scopes, enabled, allow_auto_link) \
         VALUES (?, ?, ?, 'Unreachable', 'oidc', ?, ?, ?, ?, 'assay-test', ?, 1, 0)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&env.root_tenant_id)
    .bind(&provider_code)
    .bind(format!("https://oidc.invalid/{provider_code}"))
    .bind("https://oidc.invalid/authorize")
    .bind("https://oidc.invalid/token")
    .bind("https://oidc.invalid/jwks")
    .bind(json!(["openid", "email"]).to_string())
    .execute(&env.pool)
    .await
    .expect("insert oidc provider");
    provider_code
}

/// 外部ログインを始め、`(state, browser_binding)` を返す。
async fn start(env: &TestEnv, provider_code: &str) -> (String, String) {
    let res = send(
        &env.app,
        post_internal(
            "/internal/external/start",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": env.root_tenant_id, "provider_code": provider_code }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "start");
    let body = body_json(res).await;
    assert_eq!(body["result"], "redirect", "{body}");
    let location = url::Url::parse(body["location"].as_str().expect("location")).expect("url");
    let state = location
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state");
    let binding = body["browser_binding"]
        .as_str()
        .expect("browser_binding")
        .to_string();
    (state, binding)
}

async fn callback(env: &TestEnv, state: &str, browser_binding: Option<&str>) -> Value {
    let res = send(
        &env.app,
        post_internal(
            "/internal/external/callback",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": env.root_tenant_id,
                "state": state,
                "code": "attacker-code",
                "browser_binding": browser_binding
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "callback");
    body_json(res).await
}

#[tokio::test]
async fn the_callback_proceeds_only_in_the_browser_that_started_the_login() {
    let Some(env) = support::setup("external oidc browser binding").await else {
        return;
    };
    let provider_code = register_unreachable_oidc_provider(&env).await;

    // 開始時の値を持たないブラウザ（攻撃者の戻り URL を踏まされた人）。
    let (state, _) = start(&env, &provider_code).await;
    let body = callback(&env, &state, None).await;
    assert_eq!(body["result"], "state_expired", "{body}");

    // 別の外部ログインの値を持つブラウザ。
    let (attacker_state, _) = start(&env, &provider_code).await;
    let (_, victim_binding) = start(&env, &provider_code).await;
    let body = callback(&env, &attacker_state, Some(&victim_binding)).await;
    assert_eq!(body["result"], "state_expired", "{body}");

    // 開始したブラウザなら照合を通り、コードの交換へ進む（相手に届かないので失敗する）。
    let (state, binding) = start(&env, &provider_code).await;
    let body = callback(&env, &state, Some(&binding)).await;
    assert_eq!(body["result"], "external_failure", "{body}");
}
