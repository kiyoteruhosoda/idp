//! リソース指標（RFC 8707）の統合テスト（ADR-0042）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test resource_indicators
//!
//! 検証の要:
//! - 登録され、**あるアプリの名乗り**であり、要求元のサービスアカウントが**そのアプリに割り当て
//!   られている**宛名だけが `aud` に載ること（ADR-0059 の決定 6）。
//! - ⚠ 「全員（`EVERYONE`）」のアプリでも、サービスアカウントは個別に割り当てない限り取れないこと。
//! - 未登録・停止中・未許可を**応答で区別しない**こと（区別すると登録の有無を総当たりで探れる）。
//! - 宛名のトークンに `perms` が載らないこと。何をしてよいかはリソースサーバが決める（ADR-0033）。
//! - 管理 API 向けのトークン（ADR-0037）が従来どおりであること。

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{json, Value};
use support::{admin_token, body_json, delete, post, put, send, unique};

/// `ACCESS_TOKEN_TTL_SECS` の既定。宛名のトークンは通常のアクセストークンと同じ寿命で出る。
const ACCESS_TOKEN_TTL_SECS: u64 = 900;
/// `MANAGEMENT_TOKEN_TTL_SECS` の既定（ADR-0037）。
const MANAGEMENT_TOKEN_TTL_SECS: u64 = 300;

fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

async fn request_token(
    app: &axum::Router,
    tenant_id: &str,
    client_id: &str,
    secret: &str,
    resource: Option<&str>,
) -> axum::response::Response {
    let mut body = "grant_type=client_credentials".to_string();
    if let Some(r) = resource {
        body.push_str(&format!(
            "&resource={}",
            percent_encoding::utf8_percent_encode(r, percent_encoding::NON_ALPHANUMERIC)
        ));
    }
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant_id}/token"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(client_id, secret))
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

/// アクセストークン（JWT）のクレームを読む。署名は他のテストが見ているので、ここでは載る値だけを見る。
fn claims(access_token: &str) -> Value {
    let payload = access_token.split('.').nth(1).expect("payload segment");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&decoded).expect("claims json")
}

/// アプリを「個別」で作り、その id を返す。
async fn create_application(app: &axum::Router, admin_tok: &str, tenant_id: &str) -> String {
    let res = send(
        app,
        post(
            admin_tok,
            &format!("/{tenant_id}/admin/applications"),
            json!({ "display_name": format!("wiki-{}", unique()), "assign_creator": false }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create application");
    body_json(res).await["id"].as_str().unwrap().to_string()
}

/// 宛名を登録して、その id を返す。
async fn register_resource(
    app: &axum::Router,
    admin_tok: &str,
    tenant_id: &str,
    audience: &str,
) -> String {
    let res = send(
        app,
        post(
            admin_tok,
            &format!("/{tenant_id}/admin/resources"),
            json!({ "resource_uri": audience, "display_name": "machine API" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register the audience");
    body_json(res).await["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn only_an_audience_of_an_application_the_service_account_is_assigned_to_reaches_the_token() {
    let Some(env) = support::setup("resource indicators").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) = support::insert_service_account(&env.pool, &env.root_tenant_id).await;
    let audience = format!("api://wiki-{}", unique());
    let token = |resource: String| {
        let app = env.app.clone();
        let tenant = env.root_tenant_id.clone();
        let client_id = client_id.clone();
        let secret = secret.clone();
        async move { request_token(&app, &tenant, &client_id, &secret, Some(&resource)).await }
    };

    // 登録前は断る。
    let res = token(audience.clone()).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_target");

    register_resource(&env.app, &admin_tok, &env.root_tenant_id, &audience).await;

    // 登録しただけでは出ない（どのアプリの宛名でもない）。
    let res = token(audience.clone()).await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a name that belongs to no application must not be issued"
    );
    assert_eq!(body_json(res).await["error"], "invalid_target");

    // アプリの名乗りにしても、割り当てが無ければ出ない。
    let application_id = create_application(&env.app, &admin_tok, &env.root_tenant_id).await;
    let detail_uri = format!(
        "/{}/admin/applications/{application_id}",
        env.root_tenant_id
    );
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{detail_uri}/bindings"),
            json!({ "kind": "resource", "resource_uri": audience }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "bind the name to the application"
    );
    let res = token(audience.clone()).await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "bound but not assigned must not be issued"
    );

    // ⚠ 「全員」に含まれるのは人だけ。サービスアカウントには効かない。
    let set_mode = |mode: &'static str| {
        let app = env.app.clone();
        let admin_tok = admin_tok.clone();
        let detail_uri = detail_uri.clone();
        async move {
            let detail = body_json(send(&app, support::get(&admin_tok, &detail_uri)).await).await;
            let res = send(
                &app,
                put(
                    &admin_tok,
                    &detail_uri,
                    json!({
                        "display_name": detail["display_name"],
                        "status": "ACTIVE",
                        "assignment_mode": mode,
                    }),
                ),
            )
            .await;
            assert_eq!(res.status(), StatusCode::OK, "set mode {mode}");
        }
    };
    set_mode("EVERYONE").await;
    let res = token(audience.clone()).await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "EVERYONE means people only; a service account still needs its own assignment"
    );
    set_mode("INDIVIDUAL").await;

    // 割り当てると、宛名が `aud` に載る。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{detail_uri}/assignments"),
            json!({ "kind": "service_account", "client_id": client_id }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "assign the service account");
    let assigned = body_json(res).await;
    assert_eq!(
        assigned["assigned_service_accounts"][0]["client_id"],
        json!(client_id),
        "{assigned}"
    );
    assert_eq!(
        assigned["assigned_count"], 0,
        "service accounts are not counted as people"
    );

    let res = token(audience.clone()).await;
    assert_eq!(res.status(), StatusCode::OK);
    let issued = body_json(res).await;
    assert_eq!(issued["expires_in"].as_u64(), Some(ACCESS_TOKEN_TTL_SECS));
    let claims = claims(issued["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["aud"], json!(audience), "aud is the registered name");
    assert_eq!(claims["client_id"], json!(client_id));
    assert_eq!(claims["sub_type"], json!("client"));
    // 何をしてよいかは載らない（ADR-0033）。ここに権限が載り始めると、アプリの権限モデルを
    // 直すたびに idp を触ることになる。
    assert!(
        claims.get("perms").is_none_or(Value::is_null),
        "a resource token must not carry perms: {claims}"
    );

    // ⚠ `aud` に載るのは**登録された綴り**であること。`resources.resource_uri` の照合順序は
    // 大小を区別しない（`utf8mb4_unicode_ci`）ので、綴りを変えた要求でも同じ行が引ける。
    // 要求された綴りをそのまま返すと、登録値と完全一致で比べるリソースサーバ側で外れる。
    let shouted = audience.to_uppercase();
    assert_ne!(
        shouted, audience,
        "the fixture must actually differ in case"
    );
    let res = token(shouted).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the row is found case-insensitively"
    );
    // `claims` は上で束縛済みなので、関数はパスで呼ぶ。
    let shouted_claims = crate::claims(
        body_json(res).await["access_token"]
            .as_str()
            .expect("access_token"),
    );
    assert_eq!(
        shouted_claims["aud"],
        json!(audience),
        "aud must be the registered spelling, not the requested one"
    );

    // 止めたアプリの宛名は出ない。
    let detail = body_json(send(&env.app, support::get(&admin_tok, &detail_uri)).await).await;
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &detail_uri,
            json!({
                "display_name": detail["display_name"],
                "status": "DISABLED",
                "assignment_mode": "INDIVIDUAL",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = token(audience.clone()).await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a disabled application's names must not be issued"
    );
    set_mode("INDIVIDUAL").await;
    assert_eq!(token(audience.clone()).await.status(), StatusCode::OK);

    // 割り当てを外すと、次のトークンからは出なくなる（発行済みは TTL まで有効）。
    let res = send(
        &env.app,
        delete(
            &admin_tok,
            &format!("{detail_uri}/assignments/service-accounts/{client_id}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "unassign");
    let res = token(audience).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_target");
}

/// ⚠ サービスアカウントとして割り当てられるのは `client_credentials` だけの client。
#[tokio::test]
async fn only_a_service_account_can_be_assigned_as_one() {
    let Some(env) = support::setup("resource indicators not a service account").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let application_id = create_application(&env.app, &admin_tok, &env.root_tenant_id).await;
    let assignments_uri = format!(
        "/{}/admin/applications/{application_id}/assignments",
        env.root_tenant_id
    );
    // `authorization_code` も持つ client（ログインに使える）。
    let (mixed, _) = support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &assignments_uri,
            json!({ "kind": "service_account", "client_id": mixed }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // 種類を指さない・種類に合わない欄だけの要求も 400。
    let (service_account, _) =
        support::insert_service_account(&env.pool, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &assignments_uri,
            json!({ "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "no kind");
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &assignments_uri,
            json!({ "kind": "user", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "wrong field for the kind"
    );
}

#[tokio::test]
async fn a_disabled_audience_stops_new_tokens_without_losing_the_assignment() {
    let Some(env) = support::setup("resource indicators disabled").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) = support::insert_service_account(&env.pool, &env.root_tenant_id).await;
    let audience = format!("api://blob-{}", unique());
    let resource_id = register_resource(&env.app, &admin_tok, &env.root_tenant_id, &audience).await;
    let application_id = create_application(&env.app, &admin_tok, &env.root_tenant_id).await;
    let detail_uri = format!(
        "/{}/admin/applications/{application_id}",
        env.root_tenant_id
    );
    for (uri, body) in [
        (
            format!("{detail_uri}/bindings"),
            json!({ "kind": "resource", "resource_uri": audience }),
        ),
        (
            format!("{detail_uri}/assignments"),
            json!({ "kind": "service_account", "client_id": client_id }),
        ),
    ] {
        let res = send(&env.app, post(&admin_tok, &uri, body)).await;
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
    }

    // 停止する。
    let res = send(
        &env.app,
        support::patch(
            &admin_tok,
            &format!("/{}/admin/resources/{resource_id}", env.root_tenant_id),
            json!({ "status": "DISABLED" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["status"], "DISABLED");

    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a disabled audience must not be issued"
    );

    // 名乗りと割り当ては消えていない——再開すればそのまま出る（停止は削除の代わりに使える）。
    let res = send(
        &env.app,
        support::patch(
            &admin_tok,
            &format!("/{}/admin/resources/{resource_id}", env.root_tenant_id),
            json!({ "status": "ACTIVE" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "re-enabling restores issuing");
}

#[tokio::test]
async fn the_management_audience_stays_separate_from_registered_ones() {
    let Some(env) = support::setup("resource indicators management").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let management_aud = format!("{}/{}/admin", env.issuer, env.root_tenant_id);

    // 管理 API の `aud` は登録できない。登録できると、`perms` の付かない管理宛のトークンを
    // 誰にでも出せてしまう（`aud` だけを見る相手はそれを通す）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/resources", env.root_tenant_id),
            json!({ "resource_uri": management_aud, "display_name": "management" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "the management audience must be reserved"
    );

    // 完全一致だけを拒むと `…/admin/` のような紛らわしい名前が登録できてしまう。issuer 配下は
    // 丸ごと予約する（いま実害があるからではなく、貸してよい理由が無いため）。
    for near_miss in [
        format!("{management_aud}/"),
        format!("{}/{}/userinfo", env.issuer, env.root_tenant_id),
        format!("{}/anything", env.issuer),
    ] {
        let res = send(
            &env.app,
            post(
                &admin_tok,
                &format!("/{}/admin/resources", env.root_tenant_id),
                json!({ "resource_uri": near_miss, "display_name": "near miss" }),
            ),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "names inside our own issuer must be reserved: {near_miss}"
        );
    }

    // 従来どおり、権限を付けたクライアントには短命の管理トークンが出る。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/clients/{client_id}/permissions",
                env.root_tenant_id
            ),
            json!({ "permission_code": "idp.users:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&management_aud),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let issued = body_json(res).await;
    assert_eq!(
        issued["expires_in"].as_u64(),
        Some(MANAGEMENT_TOKEN_TTL_SECS)
    );
    let claims = claims(issued["access_token"].as_str().expect("access_token"));
    assert_eq!(claims["aud"], json!(management_aud));
    assert_eq!(claims["perms"], json!("idp.users:read"));
}

/// アプリの状態を倒す（表示名・割り当てのモードは今の値のまま）。
async fn set_application_status(
    app: &axum::Router,
    admin_tok: &str,
    detail_uri: &str,
    status: &str,
) {
    let detail = body_json(send(app, support::get(admin_tok, detail_uri)).await).await;
    let res = send(
        app,
        put(
            admin_tok,
            detail_uri,
            json!({
                "display_name": detail["display_name"],
                "status": status,
                "assignment_mode": detail["assignment_mode"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "set status {status}");
}

/// ⚠ **アプリを止めると、その名乗りのサービスアカウントも止まる**（ADR-0060）。
///
/// - 既定のトークンも、**他のアプリの宛名**のトークンも出ない（`unauthorized_client`）
/// - ⚠ **管理トークンは出るが、権限コードは載らない。** 通るのは自分の名簿（self）だけで、
///   名簿は「全員 `blocked`」と答える ——ここを塞ぐと RP は止まったことを定期照合で知れない
/// - 名乗り・割り当て・権限コードは消えない。再開すればそのまま戻る
#[tokio::test]
async fn disabling_an_application_stops_the_service_account_it_is_named_by() {
    let Some(env) = support::setup("resource indicators own application disabled").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) = support::insert_service_account(&env.pool, &env.root_tenant_id).await;
    let row_id: String =
        sqlx::query_scalar("SELECT id FROM clients WHERE tenant_id = ? AND client_id = ?")
            .bind(&env.root_tenant_id)
            .bind(&client_id)
            .fetch_one(&env.pool)
            .await
            .expect("the service account must exist");
    sqlx::query("INSERT INTO client_permissions (client_id, permission_code) VALUES (?, ?)")
        .bind(&row_id)
        .bind("idp.applications:read")
        .execute(&env.pool)
        .await
        .expect("grant permission");

    // 名乗りのアプリ（mp3play にあたる）。
    let own_id = create_application(&env.app, &admin_tok, &env.root_tenant_id).await;
    let own_uri = format!("/{}/admin/applications/{own_id}", env.root_tenant_id);
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{own_uri}/bindings"),
            json!({ "kind": "service_account", "client_id": client_id }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "bind the service account");

    // 使う側のアプリ（blobshare にあたる）。サービスアカウントは使う主体として割り当ててある。
    let audience = format!("api://blob-{}", unique());
    register_resource(&env.app, &admin_tok, &env.root_tenant_id, &audience).await;
    let other_id = create_application(&env.app, &admin_tok, &env.root_tenant_id).await;
    let other_uri = format!("/{}/admin/applications/{other_id}", env.root_tenant_id);
    for (uri, body) in [
        (
            format!("{other_uri}/bindings"),
            json!({ "kind": "resource", "resource_uri": audience }),
        ),
        (
            format!("{other_uri}/assignments"),
            json!({ "kind": "service_account", "client_id": client_id }),
        ),
    ] {
        let res = send(&env.app, post(&admin_tok, &uri, body)).await;
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
    }

    let applications_uri = format!("/{}/admin/applications", env.root_tenant_id);
    let roster_uri = format!("/{}/admin/applications/self/users", env.root_tenant_id);
    let management_token = || async {
        let res = support::request_management_token(
            &env.app,
            &env.issuer,
            &env.root_tenant_id,
            &client_id,
            &secret,
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "management token");
        body_json(res).await["access_token"]
            .as_str()
            .expect("access_token")
            .to_string()
    };

    // 動いているあいだは、どれも出る。
    let res = request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await;
    assert_eq!(res.status(), StatusCode::OK, "default token while active");
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "resource token while active");
    let token = management_token().await;
    assert_eq!(claims(&token)["perms"], json!("idp.applications:read"));
    let res = send(&env.app, support::get(&token, &applications_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "permission works while active"
    );

    // 名乗りのアプリを止める。
    set_application_status(&env.app, &admin_tok, &own_uri, "DISABLED").await;

    let res = request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "default token");
    assert_eq!(body_json(res).await["error"], "unauthorized_client");
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "another application's audience must not be issued to a stopped application's account"
    );
    assert_eq!(body_json(res).await["error"], "unauthorized_client");

    let token = management_token().await;
    assert!(
        claims(&token)["perms"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "no permission codes for a stopped application's account: {}",
        claims(&token)
    );
    let res = send(&env.app, support::get(&token, &applications_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "tenant-wide permissions are suspended"
    );
    let res = send(&env.app, support::get(&token, &roster_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the roster stays readable so the RP learns that everyone is blocked"
    );

    // 再開すれば、名乗り・割り当て・権限コードはそのまま戻る。
    set_application_status(&env.app, &admin_tok, &own_uri, "ACTIVE").await;
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&audience),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "re-enabling restores issuing");
    let token = management_token().await;
    assert_eq!(claims(&token)["perms"], json!("idp.applications:read"));
}
