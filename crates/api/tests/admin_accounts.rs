//! アカウント（人とサービスアカウント）の統合テスト（ADR-0065）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_accounts
//!
//! 検証するのは:
//!
//! 1. 一覧（`GET /admin/accounts`）が人とサービスアカウントを 1 つに並べ、**呼んだ主体が読める種別
//!    だけ**を並べること。読めない種別を指定すると 403（空にしない）、未知の種別は 400。
//! 2. サービスアカウントのメモが人のメモと同じ規則で書け（上限・空で消す・監査に中身を残さない）、
//!    一覧・1 件の口に載り、メモの言葉で絞り込めること。連携先には書けないこと。
//! 3. 作成と同時にメモを書けること（連携先に送ると 400 で、何も作らない）。
//! 4. サービスアカウントが使えるアプリが**トークン発行と同じ規則**で答えられること（宛名の名乗りの
//!    無いアプリは載らない・「全員」でも含まれない・止めたアプリは使えない）。
//! 5. 名乗り（binding）のアプリが 1 件の口に出ること。

mod support;

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{admin_token, body_json, create_plain_user, get, post, put, send};

async fn grant(pool: &MySqlPool, user_id: &str, code: &str, tenant_id: &str) {
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, ?, ?)",
    )
    .bind(user_id)
    .bind(code)
    .bind(tenant_id)
    .execute(pool)
    .await
    .expect("grant permission");
}

async fn rename_service_account(pool: &MySqlPool, tenant_id: &str, client_id: &str, name: &str) {
    sqlx::query("UPDATE clients SET app_name = ? WHERE tenant_id = ? AND client_id = ?")
        .bind(name)
        .bind(tenant_id)
        .bind(client_id)
        .execute(pool)
        .await
        .expect("rename service account");
}

async fn note_audit_reasons(pool: &MySqlPool, client_id: &str) -> Vec<String> {
    sqlx::query(
        "SELECT reason FROM audit_log \
         WHERE event_type = 'account.note_updated' AND reason LIKE ? ORDER BY id",
    )
    .bind(format!("%service_account={client_id}%"))
    .fetch_all(pool)
    .await
    .expect("read audit")
    .iter()
    .map(|row| row.get::<Option<String>, _>("reason").unwrap_or_default())
    .collect()
}

fn kinds(body: &Value, key: &str) -> Vec<String> {
    body[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key}: {body}"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn one_list_holds_both_kinds_and_only_what_the_caller_may_read() {
    let Some(env) = support::setup("admin accounts list").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let admin_tok = admin_token(&env.app, &env.pool, tenant, &env.root_admin_id).await;
    let marker = format!("acct{}", support::unique());

    // 人 1 人（メモに目印）とサービスアカウント 1 つ（登録名に目印）。
    let member = create_plain_user(&env.pool, tenant).await;
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("/{tenant}/admin/members/{member}/note"),
            json!({ "note": format!("{marker} の家族") }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let (service_account, _) = support::insert_service_account(&env.pool, tenant).await;
    rename_service_account(
        &env.pool,
        tenant,
        &service_account,
        &format!("{marker} 同期"),
    )
    .await;

    // ── 管理者: 2 種類とも並ぶ。
    let listed = body_json(
        send(
            &env.app,
            get(&admin_tok, &format!("/{tenant}/admin/accounts?q={marker}")),
        )
        .await,
    )
    .await;
    assert_eq!(listed["total"], 2, "{listed}");
    assert_eq!(kinds(&listed, "kinds"), ["user", "service_account"]);
    assert_eq!(
        kinds(&listed, "readable_kinds"),
        ["user", "service_account"]
    );
    let rows = listed["accounts"].as_array().unwrap();
    let user_row = rows.iter().find(|r| r["kind"] == "user").expect("user row");
    assert_eq!(user_row["user"]["user_id"], json!(member), "{listed}");
    assert!(user_row.get("service_account").is_none(), "{user_row}");
    let sa_row = rows
        .iter()
        .find(|r| r["kind"] == "service_account")
        .expect("service account row");
    assert_eq!(
        sa_row["service_account"]["client_id"],
        json!(service_account),
        "{listed}"
    );
    assert_eq!(sa_row["service_account"]["status"], "ACTIVE");
    assert!(sa_row.get("user").is_none(), "{sa_row}");

    // ── 種別で絞る。
    let only_sa = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{tenant}/admin/accounts?kind=service_account&q={marker}"),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(only_sa["total"], 1, "{only_sa}");
    assert_eq!(kinds(&only_sa, "kinds"), ["service_account"]);
    assert_eq!(
        kinds(&only_sa, "readable_kinds"),
        ["user", "service_account"],
        "the other kinds stay selectable"
    );

    // ── 綴り違いは 400（「すべて」に倒さない）。
    let res = send(
        &env.app,
        get(&admin_tok, &format!("/{tenant}/admin/accounts?kind=users")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // ── 人だけ読める管理者: 人だけが並び、サービスアカウントを求めると 403。
    let members_reader = create_plain_user(&env.pool, tenant).await;
    grant(&env.pool, &members_reader, "idp.members:read", tenant).await;
    let tok = admin_token(&env.app, &env.pool, tenant, &members_reader).await;
    let listed = body_json(
        send(
            &env.app,
            get(&tok, &format!("/{tenant}/admin/accounts?q={marker}")),
        )
        .await,
    )
    .await;
    assert_eq!(listed["total"], 1, "{listed}");
    assert_eq!(kinds(&listed, "kinds"), ["user"]);
    assert_eq!(kinds(&listed, "readable_kinds"), ["user"]);
    let res = send(
        &env.app,
        get(
            &tok,
            &format!("/{tenant}/admin/accounts?kind=service_account"),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an unreadable kind is refused, not emptied"
    );

    // ── どちらも読めない主体は 403、トークンが無ければ 401。
    let nobody = create_plain_user(&env.pool, tenant).await;
    let tok = admin_token(&env.app, &env.pool, tenant, &nobody).await;
    let res = send(&env.app, get(&tok, &format!("/{tenant}/admin/accounts"))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = send(
        &env.app,
        support::anonymous(Method::GET, &format!("/{tenant}/admin/accounts"), None),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_service_account_note_follows_the_member_note_rules() {
    let Some(env) = support::setup("admin service account notes").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let admin_tok = admin_token(&env.app, &env.pool, tenant, &env.root_admin_id).await;
    let (service_account, _) = support::insert_service_account(&env.pool, tenant).await;
    let uri = format!("/{tenant}/admin/service-accounts/{service_account}/note");
    let marker = format!("経緯-{}", support::unique());
    let text = format!("{marker}\nwiki の夜間同期");

    // ── 認可（書くのは idp.clients:write）。
    let members_writer = create_plain_user(&env.pool, tenant).await;
    grant(&env.pool, &members_writer, "idp.members:write", tenant).await;
    let tok = admin_token(&env.app, &env.pool, tenant, &members_writer).await;
    let res = send(&env.app, put(&tok, &uri, json!({ "note": "x" }))).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "members:write is not enough"
    );

    // ── 書くと 1 件の口にも一覧にも載り、メモの言葉で探せる。
    let res = send(&env.app, put(&admin_tok, &uri, json!({ "note": text }))).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let detail = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{tenant}/admin/service-accounts/{service_account}"),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(detail["client_id"], json!(service_account), "{detail}");
    assert_eq!(detail["note"]["text"], json!(text), "{detail}");
    let found = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{tenant}/admin/accounts?q={}", urlencoding(&marker)),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(found["total"], 1, "{found}");
    assert_eq!(
        found["accounts"][0]["service_account"]["note"]["text"],
        json!(text)
    );

    // ── ⚠ 監査に中身を残さない。
    let reasons = note_audit_reasons(&env.pool, &service_account).await;
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(!reasons[0].contains(&marker), "{reasons:?}");

    // ── 長すぎれば 400。空で送ると消える。
    let res = send(
        &env.app,
        put(&admin_tok, &uri, json!({ "note": "あ".repeat(2001) })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = send(&env.app, put(&admin_tok, &uri, json!({ "note": " \n" }))).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let detail = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{tenant}/admin/service-accounts/{service_account}"),
            ),
        )
        .await,
    )
    .await;
    assert!(detail.get("note").is_none(), "{detail}");
    let reasons = note_audit_reasons(&env.pool, &service_account).await;
    assert!(reasons.last().unwrap().ends_with("cleared"), "{reasons:?}");

    // ── 連携先（ログイン用の client）はサービスアカウントではない: 1 件の口もメモも 404。
    let relying_party = support::insert_public_client(&env.pool, tenant, &["openid"]).await;
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{tenant}/admin/service-accounts/{relying_party}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("/{tenant}/admin/service-accounts/{relying_party}/note"),
            json!({ "note": "x" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_note_can_be_written_when_the_service_account_is_created() {
    let Some(env) = support::setup("admin service account created with a note").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let admin_tok = admin_token(&env.app, &env.pool, tenant, &env.root_admin_id).await;
    let marker = format!("created-{}", support::unique());

    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{tenant}/admin/clients"),
            json!({
                "app_name": marker,
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["openid"],
                "allow_client_credentials": true,
                "token_endpoint_auth_method": "client_secret_basic",
                "note": format!("{marker} のメモ"),
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    let client_id = created["client_id"].as_str().unwrap().to_string();
    let detail = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{tenant}/admin/service-accounts/{client_id}"),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(detail["note"]["text"], json!(format!("{marker} のメモ")));
    assert_eq!(note_audit_reasons(&env.pool, &client_id).await.len(), 1);

    // ── 連携先にメモを付けて作ろうとすると 400 で、何も作らない。
    let rp_name = format!("rp-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{tenant}/admin/clients"),
            json!({
                "app_name": rp_name,
                "client_type": "public",
                "redirect_uris": ["https://rp.example.com/callback"],
                "scopes": ["openid"],
                "note": "連携先のメモ",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let count: i64 = sqlx::query("SELECT COUNT(*) AS c FROM clients WHERE app_name = ?")
        .bind(&rp_name)
        .fetch_one(&env.pool)
        .await
        .expect("count")
        .get("c");
    assert_eq!(count, 0, "nothing is created");
}

#[tokio::test]
async fn service_account_applications_follow_the_same_rule_as_the_token_endpoint() {
    let Some(env) = support::setup("admin service account applications").await else {
        return;
    };
    let tenant = &env.root_tenant_id;
    let admin_tok = admin_token(&env.app, &env.pool, tenant, &env.root_admin_id).await;
    let (service_account, _) = support::insert_service_account(&env.pool, tenant).await;
    let uri = format!("/{tenant}/admin/service-accounts/{service_account}/applications");

    // 宛名を名乗るアプリを 2 つ（「個別」と「全員」）、名乗りの無いアプリを 1 つ。
    let create_app = |name: String, mode: &'static str| {
        let app = env.app.clone();
        let tok = admin_tok.clone();
        let tenant = tenant.clone();
        async move {
            let created = body_json(
                send(
                    &app,
                    post(
                        &tok,
                        &format!("/{tenant}/admin/applications"),
                        json!({ "display_name": name, "assignment_mode": mode }),
                    ),
                )
                .await,
            )
            .await;
            created["id"].as_str().expect("id").to_string()
        }
    };
    let bind_resource = |application: String| {
        let app = env.app.clone();
        let tok = admin_tok.clone();
        let tenant = tenant.clone();
        async move {
            let resource_uri = format!("https://api-{}.example.com", support::unique());
            let res = send(
                &app,
                post(
                    &tok,
                    &format!("/{tenant}/admin/resources"),
                    json!({ "resource_uri": resource_uri, "display_name": "API" }),
                ),
            )
            .await;
            assert_eq!(res.status(), StatusCode::CREATED, "register resource");
            let res = send(
                &app,
                post(
                    &tok,
                    &format!("/{tenant}/admin/applications/{application}/bindings"),
                    json!({ "kind": "resource", "resource_uri": resource_uri }),
                ),
            )
            .await;
            assert_eq!(res.status(), StatusCode::OK, "bind resource");
        }
    };
    let individual = create_app(format!("api-ind-{}", support::unique()), "INDIVIDUAL").await;
    bind_resource(individual.clone()).await;
    let everyone = create_app(format!("api-all-{}", support::unique()), "EVERYONE").await;
    bind_resource(everyone.clone()).await;
    let without_resource = create_app(format!("no-api-{}", support::unique()), "INDIVIDUAL").await;

    let find = |body: &Value, id: &str| {
        body["applications"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["application_id"] == json!(id))
            .cloned()
    };

    // ── 認可（idp.applications:read）。
    let plain = create_plain_user(&env.pool, tenant).await;
    let plain_tok = admin_token(&env.app, &env.pool, tenant, &plain).await;
    let res = send(&env.app, get(&plain_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(
        find(&listed, &individual).expect("individual listed")["access"],
        "not_assigned"
    );
    assert_eq!(
        find(&listed, &everyone).expect("everyone listed")["access"],
        "not_assigned",
        "EVERYONE does not include service accounts: {listed}"
    );
    assert!(
        find(&listed, &without_resource).is_none(),
        "an application without an API is not listed: {listed}"
    );

    // ── 割り当てると使える。止めたアプリは割り当てがあっても使えない。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{tenant}/admin/applications/{individual}/assignments"),
            json!({ "kind": "service_account", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "assign");
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let row = find(&listed, &individual).expect("individual listed");
    assert_eq!(row["access"], "allowed", "{row}");
    assert!(row["assigned_at"].is_string(), "{row}");
    sqlx::query("UPDATE applications SET status = 'DISABLED' WHERE id = ?")
        .bind(&individual)
        .execute(&env.pool)
        .await
        .expect("disable");
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(
        find(&listed, &individual).expect("individual listed")["access"],
        "application_disabled"
    );

    // ── 名乗りのアプリは 1 件の口に出る（使えるアプリとは別の関係）。
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{tenant}/admin/applications/{without_resource}/bindings"),
            json!({ "kind": "service_account", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "bind as identity");
    let detail = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{tenant}/admin/service-accounts/{service_account}"),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(
        detail["identity_of"]["application_id"],
        json!(without_resource),
        "{detail}"
    );

    // ── サービスアカウントでない相手へは 404。
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{tenant}/admin/service-accounts/no-such-client/applications"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// クエリ文字列用の最小限のエンコード（非 ASCII と記号を %XX にする）。
fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
