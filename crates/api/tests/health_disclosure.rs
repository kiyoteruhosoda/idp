//! ヘルスの公開範囲（ADR-0031）。
//!
//! 公開面（`/healthz`）はサービス名まで、詳細（`/internal/health`）は内部トークンの内側という
//! 線引きが、実際の応答で守られていることを固定する。ここが緩むと、**無認証で読める指紋情報**が
//! 静かに増える（Swagger UI を既定で伏せている判断と同じ理由。SEC12）。

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use support::{body_json, body_text, send, SERVICE_TOKEN, SERVICE_TOKEN_HEADER};

/// 公開の liveness は「どのサービスが答えたか」までを返す。
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
    // 公開面へ足してよいのはここまで（ADR-0031 決定 1）。
    assert!(json.get("version").is_none(), "版数を無認証で出さない");
    assert!(json.get("uptime_seconds").is_none());
    assert!(json.get("checks").is_none());
}

/// 詳細ヘルスはサービストークン無しでは読めない。
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
            "token={token:?} で詳細ヘルスが読めてはならない"
        );
        assert!(
            !body_text(response).await.contains("git_version"),
            "拒否応答にビルド情報を載せない"
        );
    }
}

/// トークンを付ければ、版数・稼働時間・サーバー時刻・依存先の検査結果が返る。
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

    // テストは実 DB へ繋いでマイグレーション済みなので、両検査とも通るはず。
    let checks = json["checks"].as_array().expect("checks");
    let names: Vec<&str> = checks.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"database"), "checks={names:?}");
    assert!(names.contains(&"schema"), "checks={names:?}");
    assert_eq!(json["status"], "pass", "body={json}");

    // 内部エラーの原文を応答へ載せない（詳細はログが持つ。ADR-0031 決定 4）。
    for check in checks {
        if let Some(detail) = check["detail"].as_str() {
            assert!(
                !detail.contains("sqlx") && !detail.contains("Error"),
                "detail に内部エラーの原文を載せない: {detail}"
            );
        }
    }
}
