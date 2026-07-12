//! 監査ログ参照 API の E2E 統合テスト（Progress A3、設計仕様 §7）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_audit
//!
//! 初期管理者の SSO セッションを直接作成し、クライアント登録で監査イベント（client.registered）を
//! 発生させてから、`/admin/audit-logs` の絞り込みで取得できること・権限制御を検証する。

mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use support::{body_json, create_plain_user, create_sso_session, get, post, send};

const REDIRECT_URI: &str = "https://app.example.com/callback";

#[tokio::test]
async fn admin_can_query_audit_logs_with_filters() {
    let Some(env) = support::setup("admin audit").await else {
        return;
    };
    let (app, pool, root_tenant_id) = (&env.app, &env.pool, &env.root_tenant_id);
    let admin_cookie = create_sso_session(pool, &env.root_admin_id).await;

    // 監査イベントを発生させる: クライアント登録（client.registered / result=success）。
    let res = send(
        app,
        post(
            &admin_cookie,
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

    // event_type で絞り込み → 少なくとも 1 件、登録した client_id を含む。
    let res = send(
        app,
        get(
            &admin_cookie,
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
    // 監査行には処理テナント（root）が記録される（ADR-0009 §8）。
    let recorded_tenant: Option<String> = sqlx::query_scalar(
        "SELECT tenant_id FROM audit_log WHERE client_id = ? AND event_type = 'client.registered' \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(&created_client_id)
    .fetch_one(pool)
    .await
    .expect("query audit tenant_id");
    assert_eq!(recorded_tenant.as_deref(), Some(root_tenant_id.as_str()));
    // occurred_at 降順（新しい順）で返る。
    let times: Vec<&str> = arr
        .iter()
        .map(|e| e["occurred_at"].as_str().unwrap())
        .collect();
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(times, sorted, "results must be newest-first");

    // result=failure の絞り込みは client.registered を含まない。
    let res = send(
        app,
        get(
            &admin_cookie,
            &format!(
                "/{root_tenant_id}/admin/audit-logs?event_type=client.registered&result=failure"
            ),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_json(res).await.as_array().unwrap().is_empty());

    // from の形式不正 → 400。
    let res = send(
        app,
        get(
            &admin_cookie,
            &format!("/{root_tenant_id}/admin/audit-logs?from=not-a-date"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 未認証 → 401。
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

    // 権限の無い利用者 → 403。
    let plain_user_id = create_plain_user(pool, root_tenant_id).await;
    let plain_cookie = create_sso_session(pool, &plain_user_id).await;
    let res = send(
        app,
        get(
            &plain_cookie,
            &format!("/{root_tenant_id}/admin/audit-logs"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
