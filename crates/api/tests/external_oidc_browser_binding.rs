//! The external OIDC IdP return endpoint (callback) proceeds only from the browser that started it (task #581).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test external_oidc_browser_binding
//!
//! An attacker can go partway through an external IdP login with their own account and obtain the return URL
//! with `code` and `state`. Making someone else open it used to sign that person's browser in as the attacker's
//! account (login CSRF). The return endpoint does not proceed without the value (cookie) given to the browser at start.
//!
//! No real external IdP is started. The check happens **before the code exchange**, so passing it proceeds to the
//! exchange and fails (`external_failure`), while failing it is treated as if there were no progress state (`state_expired`).

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_json, post_internal, send, unique, TestEnv, SERVICE_TOKEN};

/// Registers an unreachable external IdP (`.invalid` names do not resolve; RFC 6761) directly in the DB and returns `provider_code`.
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

/// Starts an external login and returns `(state, browser_binding)`.
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

    // A browser without the start value (someone made to open the attacker's return URL).
    let (state, _) = start(&env, &provider_code).await;
    let body = callback(&env, &state, None).await;
    assert_eq!(body["result"], "state_expired", "{body}");

    // A browser holding the value of another external login.
    let (attacker_state, _) = start(&env, &provider_code).await;
    let (_, victim_binding) = start(&env, &provider_code).await;
    let body = callback(&env, &attacker_state, Some(&victim_binding)).await;
    assert_eq!(body["result"], "state_expired", "{body}");

    // The browser that started it passes the check and proceeds to the code exchange (fails since the counterpart is unreachable).
    let (state, binding) = start(&env, &provider_code).await;
    let body = callback(&env, &state, Some(&binding)).await;
    assert_eq!(body["result"], "external_failure", "{body}");
}
