//! G6: Prometheus メトリクス（`GET /internal/metrics`）の統合テスト。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test metrics
//!
//! 検証するのは 3 点:
//!
//! 1. **内部面にある**（サービストークン必須）。メトリクスは「誰がいつ何回失敗したか」を
//!    集約した情報で、公開面に出す値ではない。
//! 2. 監査イベントがカウンタに出る（ログイン成功率・トークン発行レートの土台）。
//! 3. **ラベルの基数が有限**である。テナント ID・利用者 ID・実 URL がラベル値に混ざると、
//!    監視側の時系列が利用者数に比例して増える。ここが崩れると本番で初めて分かるため固定する。

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use support::{body_text, create_sso_session, get, send, SERVICE_TOKEN, SERVICE_TOKEN_HEADER};

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
        "サービストークン無しでは読めない"
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
        "Prometheus のテキスト形式で返す: {content_type}"
    );
}

/// 監査イベント（ここでは管理 API 越しのクライアント登録）がカウンタに現れ、
/// HTTP の所要時間ヒストグラムがルート雛形で記録される。
#[tokio::test]
async fn audit_events_and_request_durations_are_recorded() {
    let Some(env) = support::setup("metrics recording").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;

    // 監査イベントを発生させる（client.registered / result=success）。
    let res = send(
        &env.app,
        support::post(
            &admin_cookie,
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

    // 一覧も 1 回叩いて、ルート雛形付きのヒストグラムを確実に出す。
    let res = send(
        &env.app,
        get(
            &admin_cookie,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_text(send(&env.app, scrape(Some(SERVICE_TOKEN))).await).await;

    assert!(
        body.contains("idp_audit_events_total"),
        "監査イベントのカウンタが出ていない:\n{body}"
    );
    assert!(
        body.contains(r#"event_type="client.registered""#),
        "event_type ラベルが付いていない:\n{body}"
    );
    assert!(
        body.contains("idp_http_request_duration_seconds"),
        "所要時間ヒストグラムが出ていない:\n{body}"
    );
    assert!(
        body.contains(r#"route="/{tenant_id}/admin/clients""#),
        "route ラベルがルート雛形になっていない:\n{body}"
    );
}

/// ラベルの基数を有限に保つ（G6 の運用上の要）。
///
/// 実 URL・テナント ID・利用者 ID・相関 ID がラベル値に現れないことを確かめる。ここを外すと、
/// 監視側の時系列が利用者数・テナント数に比例して増え、Prometheus が落ちる形で初めて気づく。
#[tokio::test]
async fn labels_never_carry_unbounded_values() {
    let Some(env) = support::setup("metrics cardinality").await else {
        return;
    };
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;

    // テナント ID をパスに含む要求を出す（雛形へ畳まれることの確認）。
    let res = send(
        &env.app,
        get(
            &admin_cookie,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let body = body_text(send(&env.app, scrape(Some(SERVICE_TOKEN))).await).await;
    assert!(
        !body.contains(&env.root_tenant_id),
        "テナント ID がラベル値に漏れている（時系列がテナント数に比例して増える）:\n{body}"
    );
    assert!(
        !body.contains(&env.root_admin_id),
        "利用者 ID がラベル値に漏れている:\n{body}"
    );
}
