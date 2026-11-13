//! G6: integration tests for Prometheus metrics (`GET /internal/metrics`).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test metrics
//!
//! Three things are checked:
//!
//! 1. **It is on the internal surface** (service token required). Metrics aggregate "who failed when and how often",
//!    which is not something to expose on the public surface.
//! 2. Audit events show up in counters (the basis for login success rate and token issuance rate).
//! 3. **Label cardinality is bounded**. If tenant IDs, user IDs or real URLs got into label values,
//!    time series on the monitoring side would grow in proportion to users. Breakage here would first show in production, so it is pinned.

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use support::{admin_token, body_text, get, send, SERVICE_TOKEN, SERVICE_TOKEN_HEADER};

const METRICS_PATH: &str = "/internal/metrics";

fn scrape(token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(METRICS_PATH);
    if let Some(t) = token {
        builder = builder.header(SERVICE_TOKEN_HEADER, t);
    }
    builder.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn metrics_are_served_only_on_the_internal_surface() {
    let Some(env) = support::setup("metrics service token").await else {
        return;
    };

    let res = send(&env.app, scrape(None)).await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "cannot be read without the service token"
    );

    let res = send(&env.app, scrape(Some("wrong-token"))).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = send(&env.app, scrape(Some(SERVICE_TOKEN))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let content_type = res
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/plain"),
        "returned in Prometheus text format: {content_type}"
    );
}

/// Audit events (here client registration via the admin API) appear in counters, and
/// the HTTP duration histogram is recorded with route templates.
#[tokio::test]
async fn audit_events_and_request_durations_are_recorded() {
    let Some(env) = support::setup("metrics recording").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // Cause an audit event (client.registered / result=success).
    let res = send(
        &env.app,
        support::post(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
            serde_json::json!({
                "app_name": "Metrics Probe",
                "client_type": "public",
                "redirect_uris": ["https://app.example.com/callback"],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);

    // Also call the list once to make sure a histogram with a route template appears.
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_text(send(&env.app, scrape(Some(SERVICE_TOKEN))).await).await;

    assert!(
        body.contains("idp_audit_events_total"),
        "the audit event counter is missing:\n{body}"
    );
    assert!(
        body.contains(r#"event_type="client.registered""#),
        "the event_type label is missing:\n{body}"
    );
    assert!(
        body.contains("idp_http_request_duration_seconds"),
        "the duration histogram is missing:\n{body}"
    );
    assert!(
        body.contains(r#"route="/{tenant_id}/admin/clients""#),
        "the route label is not a route template:\n{body}"
    );
}

/// Keeps label cardinality bounded (an operational essential of G6).
///
/// Checks that real URLs, tenant IDs, user IDs and correlation IDs do not appear in label values. If this slips,
/// monitoring time series grow with the number of users and tenants, first noticed when Prometheus falls over.
#[tokio::test]
async fn labels_never_carry_unbounded_values() {
    let Some(env) = support::setup("metrics cardinality").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // Send a request containing a tenant ID in the path (to check it is folded into the template).
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_text(send(&env.app, scrape(Some(SERVICE_TOKEN))).await).await;
    assert!(
        !body.contains(&env.root_tenant_id),
        "a tenant ID leaked into a label value (time series grow with the number of tenants):\n{body}"
    );
    assert!(
        !body.contains(&env.root_admin_id),
        "a user ID leaked into a label value:\n{body}"
    );
}
