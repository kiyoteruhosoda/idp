//! ログイン画面の文脈 API（`/internal/authorize/login-context`。G12）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test authorize_login_context
//!
//! `/authorize` が受け取った `login_hint` / `ui_locales` は auth_session に保存されるが、web は
//! resume の 303 でこれらを手元に残せない。web が `auth_session_id` から引き直せることと、
//! 他テナント・未知のセッションでは何も返らない（fail-closed）ことを検証する。

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_json, post_internal, send, CODE_CHALLENGE, REDIRECT_URI_ENC, SERVICE_TOKEN};

/// `login_hint` / `ui_locales` 付きの認可リクエスト URI。
fn authorize_uri(tenant: &str, client_id: &str, login_hint: &str, ui_locales: &str) -> String {
    format!(
        "/{tenant}/authorize?response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI_ENC}\
         &scope=openid&state=st&nonce=no&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256\
         &login_hint={login_hint}&ui_locales={ui_locales}"
    )
}

async fn login_context(app: &axum::Router, tenant: &str, auth_session_id: &str) -> Value {
    let response = send(
        app,
        post_internal(
            "/internal/authorize/login-context",
            Some(SERVICE_TOKEN),
            json!({ "tenant_id": tenant, "auth_session_id": auth_session_id }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "login-context");
    body_json(response).await
}

#[tokio::test]
async fn returns_the_hints_the_rp_sent_to_authorize() {
    let Some(env) = support::setup("authorize login context").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        // `%20` 区切りの複数タグ・地域コード付きも RP は送ってくる。
        &authorize_uri(
            &root_tenant_id,
            &client_id,
            "alice%40example.com",
            "fr%20en-GB",
        ),
    )
    .await;

    let body = login_context(&app, &root_tenant_id, &auth_session).await;
    assert_eq!(body["result"], "ok", "{body}");
    assert_eq!(body["login_hint"], "alice@example.com");
    assert_eq!(body["ui_locales"], "fr en-GB");
}

/// サービストークン無しは 401（他の `/internal/*` と同じ多層防御）。
#[tokio::test]
async fn requires_the_service_token() {
    let Some(env) = support::setup("authorize login context auth").await else {
        return;
    };
    let response = send(
        &env.app,
        post_internal(
            "/internal/authorize/login-context",
            None,
            json!({ "tenant_id": env.root_tenant_id, "auth_session_id": "whatever" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 未知の `auth_session_id`・他テナントからの問い合わせは `session_expired`（存在も漏らさない）。
#[tokio::test]
async fn unknown_session_and_other_tenants_get_nothing() {
    let Some(env) = support::setup("authorize login context isolation").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let body = login_context(&app, &root_tenant_id, "0000000000000000").await;
    assert_eq!(body["result"], "session_expired", "{body}");

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        &authorize_uri(&root_tenant_id, &client_id, "bob", "en"),
    )
    .await;

    // 実在する別テナントからは、セッションはあっても何も読めない（auth_session の引きが
    // テナント scope のため）。**実在する ACTIVE なテナントを使う** —— 架空の UUID では
    // `require_internal_tenant` が先に 400 で弾き、テナント scope の検証にならない。
    let other_tenant = insert_active_tenant(&pool, &root_tenant_id).await;
    let body = login_context(&app, &other_tenant, &auth_session).await;
    assert_eq!(body["result"], "session_expired", "{body}");

    // 実在しない（あるいは無効化された）テナントは、資格情報やセッションを見る前に 400 で落ちる
    // （内部 API はテナントプレフィクスを持たず `TenantResolver` を通らないため、
    // `require_internal_tenant` がこの防御線を担う。ADR-0009 §7・§8）。
    let response = send(
        &app,
        post_internal(
            "/internal/authorize/login-context",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": uuid::Uuid::now_v7().to_string(),
                "auth_session_id": auth_session,
            }),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "an unknown tenant must be rejected before the session is looked up"
    );
    // 拒否の理由は**機械的に区別できる**必要がある。web はこのコードだけを 404 の画面へ倒し、
    // 他の非 2xx は 502 に倒す（MT28）。説明文で判別すると、文言を直した瞬間に静かに壊れる。
    assert_eq!(
        body_json(response).await["error"],
        idp_contracts::auth::UNKNOWN_TENANT_ERROR_CODE,
        "the web side distinguishes this rejection by its error code"
    );
}

/// ACTIVE な子テナントを 1 つ直接作る（このテストが要るのは「実在する別テナント」だけで、
/// 管理者・メンバーシップは要らない）。
async fn insert_active_tenant(pool: &sqlx::MySqlPool, parent_id: &str) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO tenants (id, parent_tenant_id, name, status) VALUES (?, ?, ?, 'ACTIVE')",
    )
    .bind(&id)
    .bind(parent_id)
    .bind(format!("Other {}", &id[..8]))
    .execute(pool)
    .await
    .expect("insert active tenant");
    id
}

/// `login_hint` / `ui_locales` を送らない RP では、両方とも `null` の `ok` が返る。
#[tokio::test]
async fn omitted_hints_are_null() {
    let Some(env) = support::setup("authorize login context empty").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (env.app, env.pool, env.root_tenant_id);
    let client_id = support::insert_public_client(&pool, &root_tenant_id, &["openid"]).await;

    let auth_session = support::begin_login(
        &app,
        &root_tenant_id,
        &support::authorize_uri_openid_only(&root_tenant_id, &client_id),
    )
    .await;

    let body = login_context(&app, &root_tenant_id, &auth_session).await;
    assert_eq!(body["result"], "ok", "{body}");
    assert!(body["login_hint"].is_null(), "{body}");
    assert!(body["ui_locales"].is_null(), "{body}");
}
