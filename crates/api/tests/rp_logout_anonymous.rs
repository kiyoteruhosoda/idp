//! ログイン状態の無い人には、サインアウトで RP の一覧を返さない（task #588）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test rp_logout_anonymous
//!
//! 以前は、終えるセッションが無くてもテナントの全クライアントの front-channel URI を返していたので、
//! Cookie を持たない誰にでも RP の一覧が見えた。

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{body_json, post_internal, send, SERVICE_TOKEN};

#[tokio::test]
async fn an_anonymous_logout_does_not_list_the_relying_parties() {
    let Some(env) = support::setup("rp logout anonymous").await else {
        return;
    };
    let (client_id, _) =
        support::insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    sqlx::query("UPDATE clients SET frontchannel_logout_uri = ? WHERE client_id = ?")
        .bind("https://app.example.com/frontchannel-logout")
        .bind(&client_id)
        .execute(&env.pool)
        .await
        .expect("set frontchannel_logout_uri");

    for sso_session_id in [None, Some("no-such-session")] {
        let res = send(
            &env.app,
            post_internal(
                "/internal/logout/rp",
                Some(SERVICE_TOKEN),
                json!({ "tenant_id": env.root_tenant_id, "sso_session_id": sso_session_id }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = body_json(res).await;
        assert_eq!(body["result"], "ok", "{body}");
        assert_eq!(body["frontchannel_uris"], json!([]), "{body}");
    }
}
