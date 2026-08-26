//! エラー・警告ログ（`log` テーブル）の取り込み・参照 API の E2E 統合テスト（CLAUDE.md「ログ」）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_application_logs
//!
//! web からの取り込み（`POST /internal/logs`）でレコードを作り、`GET /admin/logs` の絞り込みで
//! 取得できること・権限制御（`idp.system.admin` 必須）を検証する。

mod support;

use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{admin_token, body_json, create_plain_user, get, post_internal, send, SERVICE_TOKEN};

/// 取り込み用のレコード 1 件。`correlation_id` で後から特定できるようにする。
fn record(level: &str, service: &str, target: &str, correlation_id: &str) -> Value {
    json!({
        "occurred_at": "2026-07-27T12:00:00Z",
        "level": level,
        "service": service,
        "target": target,
        "message": "something went wrong",
        "correlation_id": correlation_id,
    })
}

async fn ingest(app: &axum::Router, records: Value) -> axum::response::Response {
    send(
        app,
        post_internal(
            "/internal/logs",
            Some(SERVICE_TOKEN),
            json!({ "records": records }),
        ),
    )
    .await
}

#[tokio::test]
async fn ingested_logs_are_queryable_with_filters() {
    let Some(env) = support::setup("application logs").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (&env.app, &env.pool, &env.root_tenant_id);
    let admin_tok = admin_token(&env.app, pool, &env.root_tenant_id, &env.root_admin_id).await;
    let correlation_id = format!("it-applog-{}", uuid::Uuid::now_v7().simple());

    let res = ingest(
        app,
        json!([
            record("ERROR", "web", "idp_web::handlers::login", &correlation_id),
            record(
                "WARN",
                "api",
                "idp_api::presentation::token",
                &correlation_id
            ),
            // 解釈できない行（INFO は記録対象外・未知サービス）は捨てられ、残りだけ書かれる。
            record("INFO", "api", "idp_api::presentation", &correlation_id),
            record("ERROR", "worker", "idp_worker::jobs", &correlation_id),
        ]),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["accepted"], 2);

    // correlation_id で絞り込む → 取り込めた 2 件だけが新しい順で返る。
    let res = send(
        app,
        get(
            &admin_tok,
            &format!("/{root_tenant_id}/admin/logs?correlation_id={correlation_id}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let entries = body_json(res).await;
    let entries = entries.as_array().expect("array");
    assert_eq!(entries.len(), 2);
    let levels: Vec<&str> = entries
        .iter()
        .map(|e| e["level"].as_str().expect("level"))
        .collect();
    assert!(levels.contains(&"ERROR") && levels.contains(&"WARN"));

    // level で絞り込む。
    let res = send(
        app,
        get(
            &admin_tok,
            &format!("/{root_tenant_id}/admin/logs?correlation_id={correlation_id}&level=ERROR"),
        ),
    )
    .await;
    let entries = body_json(res).await;
    let entries = entries.as_array().expect("array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["service"], "web");
    assert_eq!(entries[0]["target"], "idp_web::handlers::login");

    // target は前方一致で絞り込む。
    let res = send(
        app,
        get(
            &admin_tok,
            &format!("/{root_tenant_id}/admin/logs?correlation_id={correlation_id}&target=idp_api"),
        ),
    )
    .await;
    let entries = body_json(res).await;
    assert_eq!(entries.as_array().expect("array").len(), 1);

    // service で絞り込む。
    let res = send(
        app,
        get(
            &admin_tok,
            &format!("/{root_tenant_id}/admin/logs?correlation_id={correlation_id}&service=web"),
        ),
    )
    .await;
    let entries = body_json(res).await;
    assert_eq!(entries.as_array().expect("array").len(), 1);
}

#[tokio::test]
async fn invalid_datetime_filter_is_rejected() {
    let Some(env) = support::setup("application logs datetime").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/logs?from=not-a-date", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn non_system_admin_cannot_read_application_logs() {
    let Some(env) = support::setup("application logs authz").await else {
        return;
    };
    // 権限を持たない利用者は 403（`idp.system.admin` 必須。テナント横断の運用情報のため）。
    let user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let cookie = admin_token(&env.app, &env.pool, &env.root_tenant_id, &user_id).await;
    let res = send(
        &env.app,
        get(&cookie, &format!("/{}/admin/logs", env.root_tenant_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // 未認証は 401。
    let res = send(
        &env.app,
        get("", &format!("/{}/admin/logs", env.root_tenant_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ingest_requires_the_service_token() {
    let Some(env) = support::setup("application logs ingest authz").await else {
        return;
    };
    let res = send(
        &env.app,
        post_internal(
            "/internal/logs",
            None,
            json!({ "records": [record("ERROR", "web", "idp_web::x", "no-token")] }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
