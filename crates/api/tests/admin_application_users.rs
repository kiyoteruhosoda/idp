//! 自分のアプリの名簿（`GET /{tenant_id}/admin/applications/self/users`。ADR-0057 / ADR-0059）。
//!
//! ここで固定するもの:
//!
//! - ⚠ **宛先は呼んできたサービスアカウントの名乗りで決まる**。RP は経路に何も書かない
//! - ⚠ **権限コードでは通らない**。`idp.applications:read` を持っていても、名乗りが無ければ 403
//! - ⚠ **結び付いていない主体（利用者・名乗りの無いサービスアカウント）は 403**。空の名簿を返すと、
//!   RP は全員を止める
//! - ⚠ **ログイン用の名乗り（`oidc`）では通らない**（同じ `client_id` 列でも種類が違う）
//! - 名乗りだけを持つサービスアカウント（権限コード 0 件）に**管理トークンが出る**
//! - 他のアプリの名簿は読めない
//! - 旧口 `/admin/applications/oidc/{client_id}/users` は無い
//! - 「個別」の候補＝割り当てのある人。⚠ 止まっているアカウントは消えずに `blocked` で出る
//! - ⚠ **サービスアカウントの割り当ては名簿に載らない**
//! - 「全員」の候補＝テナントのメンバー
//! - ⚠ **止めたアプリは「空」ではなく「全員 `blocked`」**（「引けなかった」と取り違えさせない）
//! - ⚠ **`subs` を渡したときだけ `unknown`（消えた）が返る**。聞いた `sub` は必ず 1 行で返る
//! - ⚠ `sub` が 1 つでも読めなければ 400（読めたものだけで答えると、綴り違いが「消えた」に化ける）
//! - ページングは**実際に適用した値**を返す
//!
//! ⚠ 一覧はテナント全体を見るので、他のテストが足した行が混ざる。件数ではなく
//! 「自分が作った `sub` がどう出るか」で確かめる。

mod support;

use axum::http::{Method, StatusCode};
use serde_json::Value;
use sqlx::MySqlPool;
use support::{
    admin_token, anonymous, body_json, create_plain_user, get, insert_confidential_client,
    insert_service_account, open_client_as_application, request_management_token, send, unique,
    TestEnv,
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
    sqlx::query(
        "INSERT INTO application_assignments (id, application_id, kind, user_id) \
         VALUES (?, ?, 'USER', ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
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

fn roster_uri(tenant_id: &str) -> String {
    format!("/{tenant_id}/admin/applications/self/users")
}

async fn client_row_id(pool: &MySqlPool, tenant_id: &str, client_id: &str) -> String {
    sqlx::query_scalar("SELECT id FROM clients WHERE tenant_id = ? AND client_id = ?")
        .bind(tenant_id)
        .bind(client_id)
        .fetch_one(pool)
        .await
        .expect("the client must exist")
}

/// 名乗りを直接足す（`kind` を試験で自由に選ぶため、管理 API を通さない）。
async fn bind(pool: &MySqlPool, application_id: &str, kind: &str, client_row_id: &str) {
    sqlx::query(
        "INSERT INTO application_bindings (id, application_id, kind, client_id) VALUES (?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(application_id)
    .bind(kind)
    .bind(client_row_id)
    .execute(pool)
    .await
    .expect("insert binding");
}

async fn grant(pool: &MySqlPool, client_row_id: &str, code: &str) {
    sqlx::query("INSERT INTO client_permissions (client_id, permission_code) VALUES (?, ?)")
        .bind(client_row_id)
        .bind(code)
        .execute(pool)
        .await
        .expect("grant permission");
}

/// 管理トークンを取る（取れることを前提にする）。
async fn management_token(env: &TestEnv, client_id: &str, secret: &str) -> String {
    let res = request_management_token(
        &env.app,
        &env.issuer,
        &env.root_tenant_id,
        client_id,
        secret,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "management token must be issued"
    );
    body_json(res).await["access_token"]
        .as_str()
        .expect("access token")
        .to_string()
}

/// アプリを 1 件開き、そのサービスアカウントの名乗りを付けて `(application_id, 管理トークン)` を返す。
async fn application_with_service_account(env: &TestEnv) -> (String, String) {
    let (login_client, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let application_id =
        open_client_as_application(&env.pool, &env.root_tenant_id, &login_client).await;
    let (service_account, secret) = insert_service_account(&env.pool, &env.root_tenant_id).await;
    let row_id = client_row_id(&env.pool, &env.root_tenant_id, &service_account).await;
    bind(&env.pool, &application_id, "service_account", &row_id).await;
    let token = management_token(env, &service_account, &secret).await;
    (application_id, token)
}

/// 名乗りだけを持つサービスアカウント（権限コード 0 件）に管理トークンが出て、自分のアプリの名簿が
/// 読める。⚠ **定期照合は人が回すものではない**。
#[tokio::test]
async fn a_bound_service_account_reads_its_own_roster_without_any_permission() {
    let Some(env) = support::setup("application users self").await else {
        return;
    };
    let (application_id, token) = application_with_service_account(&env).await;
    set_mode(&env.pool, &application_id, "INDIVIDUAL").await;
    let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    assign(&env.pool, &application_id, &user).await;
    let sub = sub_of(&env.pool, &user).await;

    let res = send(&env.app, get(&token, &roster_uri(&env.root_tenant_id))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(state_of(&body, &sub).as_deref(), Some("allowed"));

    // 権限コードは増えていない ——他の管理 API は 403 のまま。
    let res = send(
        &env.app,
        get(
            &token,
            &format!("/{}/admin/applications", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "the binding grants the roster only, not tenant-wide permissions"
    );
}

/// ⚠ 他のアプリの名簿は読めない（宛先を選ぶ手段がそもそも無い）。
#[tokio::test]
async fn a_service_account_does_not_see_another_applications_roster() {
    let Some(env) = support::setup("application users other app").await else {
        return;
    };
    let (mine, token) = application_with_service_account(&env).await;
    set_mode(&env.pool, &mine, "INDIVIDUAL").await;
    let (theirs, _) = application_with_service_account(&env).await;
    set_mode(&env.pool, &theirs, "INDIVIDUAL").await;
    let stranger = create_plain_user(&env.pool, &env.root_tenant_id).await;
    assign(&env.pool, &theirs, &stranger).await;
    let stranger_sub = sub_of(&env.pool, &stranger).await;

    let body = body_json(
        send(
            &env.app,
            get(
                &token,
                &format!("{}?limit=200", roster_uri(&env.root_tenant_id)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(state_of(&body, &stranger_sub), None);
    assert_eq!(body["total"], 0, "my application has nobody assigned");
}

/// ⚠ **結び付いていない主体は 403**（空の名簿を返さない）。テナント全体の
/// `idp.applications:read` を持っていても通らない。
#[tokio::test]
async fn callers_without_an_own_application_are_refused() {
    let Some(env) = support::setup("application users refused").await else {
        return;
    };
    let uri = roster_uri(&env.root_tenant_id);

    let res = send(&env.app, anonymous(Method::GET, &uri, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no token -> 401");

    // 利用者（テナント管理者であっても）には自分のアプリが無い。
    let admin = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(&env.app, get(&admin, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "a user -> 403");

    // 名乗りの無いサービスアカウント。権限コードがあってもトークンが取れるだけで、名簿は読めない。
    let (unbound, secret) = insert_service_account(&env.pool, &env.root_tenant_id).await;
    let row_id = client_row_id(&env.pool, &env.root_tenant_id, &unbound).await;
    grant(&env.pool, &row_id, "idp.applications:read").await;
    let token = management_token(&env, &unbound, &secret).await;
    let res = send(&env.app, get(&token, &uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "tenant-wide idp.applications:read does not stand in for the binding"
    );
    let body = body_json(res).await;
    assert!(
        body.get("users").is_none(),
        "no roster in the refusal: {body}"
    );
}

/// ⚠ **ログイン用の名乗りでは通らない。** ログイン用とサービスアカウントは同じ `client_id` 列を
/// 使うので、種類を見ないと取り違える。
#[tokio::test]
async fn a_login_binding_does_not_count_as_a_service_account_binding() {
    let Some(env) = support::setup("application users kind").await else {
        return;
    };
    let (login_client, _) =
        insert_confidential_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let application_id =
        open_client_as_application(&env.pool, &env.root_tenant_id, &login_client).await;
    let (service_account, secret) = insert_service_account(&env.pool, &env.root_tenant_id).await;
    let row_id = client_row_id(&env.pool, &env.root_tenant_id, &service_account).await;
    // わざと種類を取り違えて結び付ける。
    bind(&env.pool, &application_id, "oidc", &row_id).await;

    let res = request_management_token(
        &env.app,
        &env.issuer,
        &env.root_tenant_id,
        &service_account,
        &secret,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "no permission and no service-account binding -> no management token"
    );

    grant(&env.pool, &row_id, "idp.users:read").await;
    let token = management_token(&env, &service_account, &secret).await;
    let res = send(&env.app, get(&token, &roster_uri(&env.root_tenant_id))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// 旧口（RP が `client_id` を経路に書く形）は無い。
#[tokio::test]
async fn the_old_client_id_route_is_gone() {
    let Some(env) = support::setup("application users old route").await else {
        return;
    };
    let admin = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(
        &env.app,
        get(
            &admin,
            &format!(
                "/{}/admin/applications/oidc/client-{}/users",
                env.root_tenant_id,
                unique()
            ),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// 「個別」の候補は割り当てのある人。⚠ 止まっているアカウントは**消えずに `blocked`** で出る
/// （RP は「止まった＝戻る可能性がある」と「消えた」を分けて扱う）。
#[tokio::test]
async fn individual_mode_lists_the_assigned_and_marks_stopped_accounts() {
    let Some(env) = support::setup("application users individual").await else {
        return;
    };
    let (application_id, token) = application_with_service_account(&env).await;
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

    let uri = roster_uri(&env.root_tenant_id);
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

/// ⚠ **名簿に載るのは人だけ**（ADR-0059 の決定 5）。サービスアカウントの割り当ては候補にも件数にも
/// 入らない ——RP はローカル口座と突き合わせるので、口座の無い相手が混ざると照合が崩れる。
#[tokio::test]
async fn service_account_assignments_are_not_part_of_the_roster() {
    let Some(env) = support::setup("application users no service accounts").await else {
        return;
    };
    let (application_id, token) = application_with_service_account(&env).await;
    set_mode(&env.pool, &application_id, "INDIVIDUAL").await;
    let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    assign(&env.pool, &application_id, &user).await;
    let (other_service_account, _) = insert_service_account(&env.pool, &env.root_tenant_id).await;
    let row_id = client_row_id(&env.pool, &env.root_tenant_id, &other_service_account).await;
    sqlx::query(
        "INSERT INTO application_assignments (id, application_id, kind, client_id) \
         VALUES (?, ?, 'SERVICE_ACCOUNT', ?)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&application_id)
    .bind(&row_id)
    .execute(&env.pool)
    .await
    .expect("assign service account");

    let body = body_json(
        send(
            &env.app,
            get(
                &token,
                &format!("{}?limit=200", roster_uri(&env.root_tenant_id)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(body["total"], 1, "only the person is a candidate: {body}");
    assert_eq!(body["users"].as_array().unwrap().len(), 1);
}

/// 「全員」の候補はテナントのメンバー。⚠ **返る形は「個別」と同じ**（RP はモードを知らない）。
#[tokio::test]
async fn everyone_mode_lists_the_tenant_members() {
    let Some(env) = support::setup("application users everyone").await else {
        return;
    };
    // `open_client_as_application` は `EVERYONE` で開く。
    let (_, token) = application_with_service_account(&env).await;
    let member = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let member_sub = sub_of(&env.pool, &member).await;

    let res = send(
        &env.app,
        get(
            &token,
            &format!("{}?subs={member_sub}", roster_uri(&env.root_tenant_id)),
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
    let (application_id, token) = application_with_service_account(&env).await;
    set_mode(&env.pool, &application_id, "INDIVIDUAL").await;
    let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
    assign(&env.pool, &application_id, &user).await;
    set_application_status(&env.pool, &application_id, "DISABLED").await;
    let sub = sub_of(&env.pool, &user).await;

    let res = send(&env.app, get(&token, &roster_uri(&env.root_tenant_id))).await;
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
    let (_, token) = application_with_service_account(&env).await;
    let uri = roster_uri(&env.root_tenant_id);

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
    let (application_id, token) = application_with_service_account(&env).await;
    set_mode(&env.pool, &application_id, "INDIVIDUAL").await;
    for _ in 0..3 {
        let user = create_plain_user(&env.pool, &env.root_tenant_id).await;
        assign(&env.pool, &application_id, &user).await;
    }
    let uri = roster_uri(&env.root_tenant_id);

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
