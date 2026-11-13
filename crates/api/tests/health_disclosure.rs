//! Exposure scope of health endpoints (ADR-0031).
//!
//! Pins that the line "the public surface (`/healthz`) shows up to the service name, details (`/internal/health`)
//! are behind the internal token" holds in actual responses. If this loosens, **fingerprinting information readable
//! without auth** quietly grows (same reasoning as hiding Swagger UI by default; SEC12).

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use support::{body_json, body_text, send, SERVICE_TOKEN, SERVICE_TOKEN_HEADER};

/// Public liveness returns up to "which service answered".
#[tokio::test]
async fn liveness_names_the_service_and_nothing_more() {
    let Some(env) = support::setup("health_disclosure").await else {
        return;
    };
    let response = send(
        &env.app,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "api");
    // This is as far as the public surface may go (ADR-0031 decision 1).
    assert!(json.get("version").is_none(), "no version without auth");
    assert!(json.get("uptime_seconds").is_none());
    assert!(json.get("checks").is_none());
}

/// Detailed health cannot be read without the service token.
#[tokio::test]
async fn the_detailed_health_requires_the_service_token() {
    let Some(env) = support::setup("health_disclosure").await else {
        return;
    };
    for token in [None, Some("wrong-token")] {
        let mut builder = Request::builder().uri("/internal/health");
        if let Some(t) = token {
            builder = builder.header(SERVICE_TOKEN_HEADER, t);
        }
        let response = send(&env.app, builder.body(Body::empty()).expect("request")).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "detailed health must not be readable with token={token:?}"
        );
        assert!(
            !body_text(response).await.contains("git_version"),
            "no build info in the rejection response"
        );
    }
}

/// With the token, version, uptime, server time and dependency check results are returned.
#[tokio::test]
async fn the_detailed_health_reports_version_uptime_and_dependencies() {
    let Some(env) = support::setup("health_disclosure").await else {
        return;
    };
    let response = send(
        &env.app,
        Request::builder()
            .uri("/internal/health")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let json = body_json(response).await;
    assert_eq!(json["service"], "api");
    assert!(json["version"]["git_version"].is_string());
    assert!(json["started_at"].is_string());
    assert!(json["server_time"].is_string());
    assert!(json["uptime_seconds"].is_number());

    // Tests connect to a real migrated DB, so both checks should pass.
    let checks = json["checks"].as_array().expect("checks");
    let names: Vec<&str> = checks.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"database"), "checks={names:?}");
    assert!(names.contains(&"schema"), "checks={names:?}");
    assert_eq!(json["status"], "pass", "body={json}");

    // `detail` is a state summary, not the raw internal error (ADR-0031 decision 4). In a healthy environment the
    // failure path cannot be reached, so here we check the pass path's `detail` has the defined shape.
    // (Wording containing a table name like `_sqlx_migrations is unreadable` is legitimate, so a simple substring match
    //   cannot decide it. Not including the raw text is guaranteed by the handler sending it to `tracing::error!`.)
    let schema = checks
        .iter()
        .find(|c| c["name"] == "schema")
        .expect("schema check");
    let detail = schema["detail"].as_str().expect("schema detail");
    assert!(
        detail.starts_with("applied=") && detail.contains(" expected="),
        "detail={detail}"
    );
}
