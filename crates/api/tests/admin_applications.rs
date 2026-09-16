//! アプリ管理 API の E2E 統合テスト（ADR-0054）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_applications
//!
//! 認可は権限コード（`idp.applications:read` / `:write`。`idp.tenant.admin`・`idp.system.admin` は
//! 含意により許可。ADR-0037）。

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{admin_token, body_json, create_plain_user, delete, get, post, put, send};

const REDIRECT_URI: &str = "https://app.example.com/callback";

#[tokio::test]
async fn admin_can_manage_applications_but_others_cannot() {
    let Some(env) = support::setup("admin applications").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/applications", env.root_tenant_id);

    // 権限の無い利用者 → 403。
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(&env.app, get(&plain_token, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // 登録。⚠ 既定は「個別」で、作った本人が名簿に入る（決定 3）。
    let name = format!("app-{}", support::unique());
    let res = send(
        &env.app,
        post(&admin_tok, &uri, json!({ "display_name": name })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create -> 201");
    let created = body_json(res).await;
    assert_eq!(created["assignment_mode"], "INDIVIDUAL", "default is 個別");
    assert_eq!(created["status"], "ACTIVE");
    assert_eq!(
        created["assigned_count"], 1,
        "the creator is assigned so they are not locked out: {created}"
    );
    let application_id = created["id"].as_str().expect("id").to_string();

    // 詳細に名簿が載る。
    let detail_uri = format!("{uri}/{application_id}");
    let detail = body_json(send(&env.app, get(&admin_tok, &detail_uri)).await).await;
    assert_eq!(detail["assigned"].as_array().unwrap().len(), 1);
    assert_eq!(detail["assigned"][0]["user_id"], json!(env.root_admin_id));

    // 一覧に載り、いまの判定の段階が添えられる。
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(
        listed["enforcement"], "record_only",
        "the gate starts out recording only: {listed}"
    );
    assert!(listed["applications"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["id"] == json!(application_id)));

    // OIDC の連携先を繋ぐ。
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{detail_uri}/bindings"),
            json!({ "kind": "oidc", "client_id": client_id }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "bind -> 200");
    let bound = body_json(res).await;
    assert_eq!(bound["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(bound["bindings"][0]["kind"], "oidc");
    assert_eq!(bound["bindings"][0]["identifier"], json!(client_id));

    // ⚠ 1 つの連携先は 1 つのアプリにしか属さない。2 つ目のアプリへ繋ごうとすると 409。
    let other = body_json(
        send(
            &env.app,
            post(
                &admin_tok,
                &uri,
                json!({ "display_name": format!("other-{}", support::unique()) }),
            ),
        )
        .await,
    )
    .await;
    let other_id = other["id"].as_str().expect("id").to_string();
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{uri}/{other_id}/bindings"),
            json!({ "kind": "oidc", "client_id": client_id }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a client belongs to one application"
    );
    let refusal = body_json(res).await;
    assert!(
        refusal["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&name),
        "the refusal names the application that owns it: {refusal}"
    );

    // ⚠ 種類を指さない要求は 400（既定の種類を置かない）。
    let res = send(
        &env.app,
        post(&admin_tok, &format!("{detail_uri}/bindings"), json!({})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "no target -> 400");

    // 割り当ての追加・解除。
    let member_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let assigned = body_json(
        send(
            &env.app,
            post(
                &admin_tok,
                &format!("{detail_uri}/assignments"),
                json!({ "kind": "user", "user_id": member_id }),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(assigned["assigned"].as_array().unwrap().len(), 2);
    let res = send(
        &env.app,
        delete(
            &admin_tok,
            &format!("{detail_uri}/assignments/users/{member_id}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "unassign -> 204");

    // 「全員」へ倒すと、いま入れている人（テナントのメンバー）が引ける。
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &detail_uri,
            json!({
                "display_name": name,
                "status": "ACTIVE",
                "assignment_mode": "EVERYONE",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "update -> 200");
    let current = body_json(
        send(
            &env.app,
            get(&admin_tok, &format!("{detail_uri}/current-users")),
        )
        .await,
    )
    .await;
    assert!(
        current["total"].as_i64().unwrap() >= 1,
        "everyone mode lists the tenant's members: {current}"
    );

    // 削除しても、繋がっていた連携先の登録は残る（アプリは括りであって繋ぎ方ではない）。
    let res = send(&env.app, delete(&admin_tok, &detail_uri)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "delete -> 204");
    let res = send(&env.app, get(&admin_tok, &detail_uri)).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "deleted -> 404");
    let clients = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{}/admin/clients", env.root_tenant_id),
            ),
        )
        .await,
    )
    .await;
    assert!(
        clients["clients"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["client_id"] == json!(client_id)),
        "the relying party survives its application: {clients}"
    );
}

/// ⚠ 登録した連携先は、その場でアプリとして開かれる（ADR-0054 の決定 7）。
/// 開かないと、登録しただけの RP が**全員に開いたまま**になり、それが画面のどこにも出ない。
#[tokio::test]
async fn registering_a_relying_party_opens_it_as_an_application() {
    let Some(env) = support::setup("register opens an application").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let app_name = format!("rp-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": app_name,
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register -> 201");
    let client_id = body_json(res).await["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();

    let listed = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{}/admin/applications", env.root_tenant_id),
            ),
        )
        .await,
    )
    .await;
    let opened = listed["applications"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| {
            a["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b["identifier"] == json!(client_id))
        })
        .unwrap_or_else(|| panic!("the registered client must have an application: {listed}"))
        .clone();
    assert_eq!(opened["display_name"], json!(app_name));
    // ⚠ 既定は「個別」。絞り忘れが全員に開いたままにならないようにする。
    assert_eq!(opened["assignment_mode"], "INDIVIDUAL");
    // ⚠ 登録した本人が名簿に入る（直後に誰も入れないアプリにしない）。
    assert_eq!(opened["assigned_count"], 1);
}

/// サービスアカウント（`client_credentials`。ADR-0038）にはアプリを作らない
/// ——入る利用者が居らず判定も走らないので、空の名簿を持つアプリが並ぶだけになる。
#[tokio::test]
async fn a_service_account_does_not_get_an_application() {
    let Some(env) = support::setup("service account without an application").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let app_name = format!("machine-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": app_name,
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["openid"],
                "allow_client_credentials": true,
                "token_endpoint_auth_method": "client_secret_basic",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register -> 201");

    let listed = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{}/admin/applications", env.root_tenant_id),
            ),
        )
        .await,
    )
    .await;
    assert!(
        !listed["applications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["display_name"] == json!(app_name)),
        "a service account has no users to admit: {listed}"
    );
}

/// 名乗りの種類と相手の性質を突き合わせる（ADR-0059）。
///
/// - サービスアカウントとして結び付けられるのは `client_credentials` だけの client
/// - ログイン用として結び付けられるのは `authorization_code` の client
/// - 宛名は URI で指す。どれも 1 つのアプリにだけ属する
#[tokio::test]
async fn binding_kinds_must_match_what_the_target_is() {
    let Some(env) = support::setup("application binding kinds").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/applications", env.root_tenant_id);
    let create = |name: String| {
        let admin_tok = admin_tok.clone();
        let uri = uri.clone();
        let app = env.app.clone();
        async move {
            body_json(
                send(
                    &app,
                    post(&admin_tok, &uri, json!({ "display_name": name })),
                )
                .await,
            )
            .await["id"]
                .as_str()
                .expect("id")
                .to_string()
        }
    };
    let application_id = create(format!("wiki-{}", support::unique())).await;
    let bindings_uri = format!("{uri}/{application_id}/bindings");

    let (service_account, _) =
        support::insert_service_account(&env.pool, &env.root_tenant_id).await;
    let login_client =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    // ⚠ ログイン用の client をサービスアカウントとして結び付けない（利用者のトークンで self が読める）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "service_account", "client_id": login_client }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "login client as a service account"
    );

    // ⚠ サービスアカウントをログイン用として結び付けない（ログインの判定から外れる）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "oidc", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "service account as a login"
    );

    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "service_account", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "service account -> 200");
    let bound = body_json(res).await;
    assert!(
        bound["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["kind"] == "service_account" && b["identifier"] == json!(service_account)),
        "{bound}"
    );

    // 同じアプリへもう一度は冪等。別のアプリへは 409。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "service_account", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "same application -> idempotent"
    );
    let other_id = create(format!("other-{}", support::unique())).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{uri}/{other_id}/bindings"),
            json!({ "kind": "service_account", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a service account belongs to one application"
    );

    // 宛名は URI で指す。
    let resource_uri = format!("https://api-{}.example.com", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/resources", env.root_tenant_id),
            json!({ "resource_uri": resource_uri, "display_name": "wiki API" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register resource");
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "resource", "resource_uri": resource_uri }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "resource -> 200");
    let bound = body_json(res).await;
    assert!(
        bound["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["kind"] == "resource" && b["identifier"] == json!(resource_uri)),
        "{bound}"
    );
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{uri}/{other_id}/bindings"),
            json!({ "kind": "resource", "resource_uri": resource_uri }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a resource belongs to one application"
    );

    // 知らない種類・種類に合わない欄だけの要求は 400。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "machine", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown kind");
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "resource", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "wrong field for the kind"
    );
}
