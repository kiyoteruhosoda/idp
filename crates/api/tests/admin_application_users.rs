//! アプリの名簿（`GET /{tenant_id}/admin/applications/oidc/{client_id}/users`。ADR-0057）。
//!
//! ここで固定するもの:
//!
//! - 認可（未提示は 401、権限不足は 403）
//! - ⚠ **binding が無い client は 404**。空の名簿を返すと、RP は全員を止める
//! - 「個別」の候補＝割り当てのある人。⚠ 止まっているアカウントは消えずに `blocked` で出る
//! - 「全員」の候補＝テナントのメンバー
//! - ⚠ **止めたアプリは「空」ではなく「全員 `blocked`」**（「引けなかった」と取り違えさせない）
//! - ⚠ **`subs` を渡したときだけ `unknown`（消えた）が返る**。聞いた `sub` は必ず 1 行で返る
//! - ⚠ `sub` が 1 つでも読めなければ 400（読めたものだけで答えると、綴り違いが「消えた」に化ける）
//! - ページングは**実際に適用した値**を返す
//! - ⚠ **機械（`client_credentials`）から叩ける**こと ——定期照合は人が回すものではない
//!
//! ⚠ 一覧はテナント全体を見るので、他のテストが足した行が混ざる。件数ではなく
//! 「自分が作った `sub` がどう出るか」で確かめる。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use serde_json::Value;
use sqlx::MySqlPool;
use support::{
    admin_token, anonymous, body_json, create_plain_user, get, insert_confidential_client,
    insert_m2m_client, open_client_as_application, send, unique,
};

/// 割り当てのモードを倒す（`open_client_as_application` は `EVERYONE` で開く）。
async fn set_mode(pool: &MySqlPool, application_id: &str, mode: &str) {
    sqlx::query("UPDATE applications SET assignment_mode = ? WHERE id = ?")
        .bind(mode)
        .bind(application_id)
        .execute(pool)
        .await
        .expect("set assignment mode");
}

async fn set_application_status(pool: &MySqlPool, application_id: &str, status: &str) {
    sqlx::query("UPDATE applications SET status = ? WHERE id = ?")
        .bind(status)
        .bind(application_id)
        .execute(pool)
        .await
        .expect("set application status");
}

async fn assign(pool: &MySqlPool, application_id: &str, user_id: &str) {
    sqlx::query("INSERT INTO application_assignments (application_id, user_id) VALUES (?, ?)")
        .bind(application_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("assign user");
}

async fn disable_user(pool: &MySqlPool, user_id: &str) {
    sqlx::query("UPDATE users SET status = 'DISABLED' WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("disable user");
}

async fn sub_of(pool: &MySqlPool, user_id: &str) -> String {
    sqlx::query_scalar("SELECT sub FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("the user must exist")
}

/// 応答から `sub` の状態を引く。載っていなければ `None`。
fn state_of(body: &Value, sub: &str) -> Option<String> {
    body["users"]
        .as_array()
        .expect("users array")
        .iter()
        .find(|user| user["sub"] == sub)
        .map(|user| user["state"].as_str().expect("state").to_string())
}

fn roster_uri(tenant_id: &str, client_id: &str) -> String {
    format!("/{tenant_id}/admin/applications/oidc/{client_id}/users")
}

#[tokio::test]
async fn the_roster_is_refused_without_a_token_and_without_the_permission() {
    let Some(env) = support::setup("application users authz").await else {
        return;
    };
    let (client_id, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    open_client_as_application(&env.pool, &env.root_tenant_id, &client_id).await;
    let uri = roster_uri(&env.root_tenant_id, &client_id);

    let res = send(&env.app, anonymous(Method::GET, &uri, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no token -> 401");

    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    let res = send(&env.app, get(&plain_token, &uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.applications:read を持たない主体は 403"
    );
}

/// ⚠ **空の名簿を返さない。** 「誰も使えない」と答えると、RP は全員を止める。
#[tokio::test]
async fn a_client_without_an_application_is_not_an_empty_roster() {
    let Some(env) = support::setup("application users unbound").await else {
        return;
    };
    let (client_id, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    // わざとアプリとして開かない（移行漏れ・binding が外れている状態）。
    let token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let res = send(
        &env.app,
        get(&token, &roster_uri(&env.root_tenant_id, &client_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    let res = send(
        &env.app,
        get(
            &token,
            &roster_uri(&env.root_tenant_id, &format!("no-such-client-{}", unique())),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "知らない client も同じ"
    );
}

/// 「個別」の候補は割り当てのある人。⚠ 止まっているアカウントは**消えずに `blocked`** で出る
/// （RP は「止まった＝戻る可能性がある」と「消えた」を分けて扱う）。
#[tokio::test]
async fn individual_mode_lists_the_assigned_and_marks_stopped_accounts() {
    let Some(env) = support::setup("application users individual").await else {
        return;
    };
    let (client_id, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let application_id =
        open_client_as_application(&env.pool, &env.root_tenant_id, &client_id).await;
    set_mode(&env.pool, &application_id, "INDIVIDUAL").await;

    let assigned = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let stopped = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let outsider = create_plain_user(&env.pool, &env.root_tenant_id).await;
    assign(&env.pool, &application_id, &assigned).await;
    assign(&env.pool, &application_id, &stopped).await;
    disable_user(&env.pool, &stopped).await;

    let assigned_sub = sub_of(&env.pool, &assigned).await;
    let stopped_sub = sub_of(&env.pool, &stopped).await;
    let outsider_sub = sub_of(&env.pool, &outsider).await;

    let token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = roster_uri(&env.root_tenant_id, &client_id);
    let res = send(&env.app, get(&token, &format!("{uri}?limit=200"))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;

    assert_eq!(state_of(&body, &assigned_sub).as_deref(), Some("allowed"));
    assert_eq!(
        state_of(&body, &stopped_sub).as_deref(),
        Some("blocked"),
        "止まっている人は名簿から消えず blocked で出る"
    );
    assert_eq!(
        state_of(&body, &outsider_sub),
        None,
        "割り当ての無い人は候補に入らない"
    );
    assert_eq!(body["total"], 2, "候補は割り当ての件数");

    // 聞けば、候補に居ない人の消息まで分かる。
    let gone = uuid::Uuid::now_v7().to_string();
    let res = send(
        &env.app,
        get(
            &token,
            &format!("{uri}?subs={assigned_sub},{stopped_sub},{outsider_sub},{gone}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["total"], 4, "聞いた sub は必ず 1 行で返る");
    assert_eq!(state_of(&body, &assigned_sub).as_deref(), Some("allowed"));
    assert_eq!(state_of(&body, &stopped_sub).as_deref(), Some("blocked"));
    assert_eq!(
        state_of(&body, &outsider_sub).as_deref(),
        Some("blocked"),
        "居るが使えない（⚠ 結び付きは残す側）"
    );
    assert_eq!(
        state_of(&body, &gone).as_deref(),
        Some("unknown"),
        "assay に居ない＝消えた（結び付きごと落としてよい）"
    );
}

/// 「全員」の候補はテナントのメンバー。⚠ **返る形は「個別」と同じ**（RP はモードを知らない）。
#[tokio::test]
async fn everyone_mode_lists_the_tenant_members() {
    let Some(env) = support::setup("application users everyone").await else {
        return;
    };
    let (client_id, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    // `open_client_as_application` は `EVERYONE` で開く。
    open_client_as_application(&env.pool, &env.root_tenant_id, &client_id).await;
    let member = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let member_sub = sub_of(&env.pool, &member).await;

    let token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(
        &env.app,
        get(
            &token,
            &format!(
                "{}?subs={member_sub}",
                roster_uri(&env.root_tenant_id, &client_id)
            ),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(
        state_of(&body, &member_sub).as_deref(),
        Some("allowed"),
        "割り当てが無くても、テナントのメンバーなら使ってよい"
    );
}

/// ⚠ 止めたアプリは**空にならない**。全員が `blocked` で返る
/// ——空を返すと、RP は「引けなかった」と区別できない。
#[tokio::test]
async fn a_disabled_application_blocks_everyone_without_emptying_the_roster() {
    let Some(env) = support::setup("application users disabled app").await else {
        return;
    };
    let (client_id, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let application_id =
        open_client_as_application(&env.pool, &env.root_tenant_id, &client_id).await;
    set_mode(&env.pool, &application_id, "INDIVIDUAL").await;
    let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    assign(&env.pool, &application_id, &user).await;
    set_application_status(&env.pool, &application_id, "DISABLED").await;
    let sub = sub_of(&env.pool, &user).await;

    let token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(
        &env.app,
        get(&token, &roster_uri(&env.root_tenant_id, &client_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["total"], 1, "候補は消えない");
    assert_eq!(state_of(&body, &sub).as_deref(), Some("blocked"));
}

/// ⚠ 読めたものだけで答えない。綴りを 1 文字間違えた `sub` が黙って「消えた」に化けると、
/// RP はその人の結び付きを落とす。
#[tokio::test]
async fn an_unreadable_sub_is_refused() {
    let Some(env) = support::setup("application users bad sub").await else {
        return;
    };
    let (client_id, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    open_client_as_application(&env.pool, &env.root_tenant_id, &client_id).await;
    let token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = roster_uri(&env.root_tenant_id, &client_id);

    let res = send(
        &env.app,
        get(
            &token,
            &format!("{uri}?subs={},not-a-uuid", uuid::Uuid::now_v7()),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let subs: Vec<String> = (0..101).map(|_| uuid::Uuid::now_v7().to_string()).collect();
    let res = send(
        &env.app,
        get(&token, &format!("{uri}?subs={}", subs.join(","))),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "一度に聞ける sub には上限がある"
    );
}

/// ページングは**要求値ではなく適用値**を返す（他の一覧と同じ）。
#[tokio::test]
async fn paging_reports_the_values_it_actually_applied() {
    let Some(env) = support::setup("application users paging").await else {
        return;
    };
    let (client_id, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let application_id =
        open_client_as_application(&env.pool, &env.root_tenant_id, &client_id).await;
    set_mode(&env.pool, &application_id, "INDIVIDUAL").await;
    for _ in 0..3 {
        let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
        assign(&env.pool, &application_id, &user).await;
    }
    let token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = roster_uri(&env.root_tenant_id, &client_id);

    let body = body_json(send(&env.app, get(&token, &format!("{uri}?limit=2"))).await).await;
    assert_eq!(body["users"].as_array().unwrap().len(), 2);
    assert_eq!(body["total"], 3, "総件数はページに左右されない");
    assert_eq!(body["limit"], 2);

    let body = body_json(send(&env.app, get(&token, &format!("{uri}?limit=100000"))).await).await;
    assert_eq!(body["limit"], 200, "上限で丸めた値を返す");

    // ページを跨いで重複・欠落が無い（並びは `sub` 昇順で安定）。
    let first =
        body_json(send(&env.app, get(&token, &format!("{uri}?limit=2&offset=0"))).await).await;
    let second =
        body_json(send(&env.app, get(&token, &format!("{uri}?limit=2&offset=2"))).await).await;
    let mut subs: Vec<String> = first["users"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["users"].as_array().unwrap().iter())
        .map(|user| user["sub"].as_str().unwrap().to_string())
        .collect();
    let before = subs.len();
    subs.sort();
    subs.dedup();
    assert_eq!(before, 3);
    assert_eq!(subs.len(), 3, "ページ間で重複しない");
}

/// ⚠ **定期照合は人が回すものではない。** 機械（`client_credentials`）から叩けることを固定する。
#[tokio::test]
async fn a_machine_can_read_the_roster_with_its_own_token() {
    let Some(env) = support::setup("application users machine").await else {
        return;
    };
    let (client_id, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let application_id =
        open_client_as_application(&env.pool, &env.root_tenant_id, &client_id).await;
    set_mode(&env.pool, &application_id, "INDIVIDUAL").await;
    let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    assign(&env.pool, &application_id, &user).await;
    let sub = sub_of(&env.pool, &user).await;

    // 照合を回す機械。⚠ 連携先の client とは別物である（`authorization_code` と
    // `client_credentials` は 1 つのクライアントに同居しない。ADR-0032 Revised）。
    let (machine_id, machine_secret) =
        insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let machine_row_id: String =
        sqlx::query_scalar("SELECT id FROM clients WHERE tenant_id = ? AND client_id = ?")
            .bind(&env.root_tenant_id)
            .bind(&machine_id)
            .fetch_one(&env.pool)
            .await
            .expect("the machine client must exist");
    sqlx::query("INSERT INTO client_permissions (client_id, permission_code) VALUES (?, ?)")
        .bind(&machine_row_id)
        .bind("idp.applications:read")
        .execute(&env.pool)
        .await
        .expect("grant idp.applications:read");

    let resource = format!("{}/{}/admin", env.issuer, env.root_tenant_id);
    let token_res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("{machine_id}:{machine_secret}"))
                ),
            )
            .body(Body::from(format!(
                "grant_type=client_credentials&resource={}",
                percent_encoding::utf8_percent_encode(
                    &resource,
                    percent_encoding::NON_ALPHANUMERIC
                )
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(token_res.status(), StatusCode::OK);
    let token = body_json(token_res).await["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let res = send(
        &env.app,
        get(&token, &roster_uri(&env.root_tenant_id, &client_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(state_of(&body, &sub).as_deref(), Some("allowed"));
}
