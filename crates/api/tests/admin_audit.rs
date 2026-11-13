//! E2E integration tests for the audit log API (Progress A3, design spec §7).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_audit
//!
//! Creates the initial admin's SSO session directly, causes an audit event (client.registered) by registering
//! a client, then checks it can be fetched with `/admin/audit-logs` filters, plus access control.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use support::{admin_token, body_json, create_plain_user, get, post, send};

const REDIRECT_URI: &str = "https://app.example.com/callback";

#[tokio::test]
async fn admin_can_query_audit_logs_with_filters() {
    let Some(env) = support::setup("admin audit").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (&env.app, &env.pool, &env.root_tenant_id);
    let admin_tok = admin_token(&env.app, pool, &env.root_tenant_id, &env.root_admin_id).await;

    // Cause an audit event: client registration (client.registered / result=success).
    let res = send(
        app,
        post(
            &admin_tok,
            &format!("/{root_tenant_id}/admin/clients"),
            json!({
                "app_name": "Audit Probe",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created_client_id = body_json(res).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Filter by event_type → at least one row, including the registered client_id.
    let res = send(
        app,
        get(
            &admin_tok,
            &format!("/{root_tenant_id}/admin/audit-logs?event_type=client.registered"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let logs = body_json(res).await;
    let arr = logs.as_array().expect("array");
    assert!(
        !arr.is_empty(),
        "expected at least one client.registered log"
    );
    assert!(arr.iter().all(|e| e["event_type"] == "client.registered"));
    assert!(
        arr.iter()
            .any(|e| e["client_id"] == created_client_id.as_str()),
        "logs should include the newly registered client_id"
    );
    // The audit row records the processing tenant (root) (ADR-0009 §8).
    let recorded_tenant: Option<String> = sqlx::query_scalar(
        "SELECT tenant_id FROM audit_log WHERE client_id = ? AND event_type = 'client.registered' \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(&created_client_id)
    .fetch_one(pool)
    .await
    .expect("query audit tenant_id");
    assert_eq!(recorded_tenant.as_deref(), Some(root_tenant_id.as_str()));
    // Returned in descending occurred_at (newest first).
    let times: Vec<&str> = arr
        .iter()
        .map(|e| e["occurred_at"].as_str().unwrap())
        .collect();
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(times, sorted, "results must be newest-first");

    // Filtering by result=failure does not include client.registered.
    let res = send(
        app,
        get(
            &admin_tok,
            &format!(
                "/{root_tenant_id}/admin/audit-logs?event_type=client.registered&result=failure"
            ),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_json(res).await.as_array().unwrap().is_empty());

    // Malformed from → 400.
    let res = send(
        app,
        get(
            &admin_tok,
            &format!("/{root_tenant_id}/admin/audit-logs?from=not-a-date"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Unauthenticated → 401.
    let res = send(
        app,
        Request::builder()
            .method("GET")
            .uri(format!("/{root_tenant_id}/admin/audit-logs"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // User without permission → 403.
    let plain_user_id = create_plain_user(pool, root_tenant_id).await;
    let plain_token = admin_token(&env.app, pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(
        app,
        get(&plain_token, &format!("/{root_tenant_id}/admin/audit-logs")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
