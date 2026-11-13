//! Integration tests for accounts (people and service accounts) (ADR-0065).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_accounts
//!
//! What is checked:
//!
//! 1. The list (`GET /admin/accounts`) lines up people and service accounts together, **only the kinds
//!    the caller can read**. Asking for an unreadable kind is 403 (not empty); an unknown kind is 400.
//! 2. Service account notes are written under the same rules as people's notes (limit, empty clears, content not in audit),
//!    appear in the list and single-item endpoint, and can be filtered by note words. Not writable on linked apps.
//! 3. A note can be written at creation (sending it for a linked app is 400 and creates nothing).
//! 4. The apps a service account can use are answered **with the same rules as token issuance** (apps without
//!    an audience identity are not listed, not included even under "Everyone", suspended apps are unusable).
//! 5. The app of the identity (binding) appears on the single-item endpoint.

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

    // One person (marker in the note) and one service account (marker in the registered name).
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

    // ── Admin: both kinds are listed.
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

    // ── Filter by kind.
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

    // ── A misspelling is 400 (not treated as "all").
    let res = send(
        &env.app,
        get(&admin_tok, &format!("/{tenant}/admin/accounts?kind=users")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // ── Admin who can read only people: only people are listed; asking for service accounts is 403.
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

    // ── A principal that can read neither gets 403; without a token 401.
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

    // ── Authorization (writing needs idp.clients:write).
    let members_writer = create_plain_user(&env.pool, tenant).await;
    grant(&env.pool, &members_writer, "idp.members:write", tenant).await;
    let tok = admin_token(&env.app, &env.pool, tenant, &members_writer).await;
    let res = send(&env.app, put(&tok, &uri, json!({ "note": "x" }))).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "members:write is not enough"
    );

    // ── Once written, it appears on the single-item endpoint and in the list, and is searchable by note words.
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

    // ── ⚠ The content is not left in the audit log.
    let reasons = note_audit_reasons(&env.pool, &service_account).await;
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(!reasons[0].contains(&marker), "{reasons:?}");

    // ── Too long is 400. Sending empty clears it.
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

    // ── A linked app (login client) is not a service account: both the single-item endpoint and the note are 404.
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

    // ── Trying to create a linked app with a note is 400 and creates nothing.
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

    // Two apps with an audience identity ("Individual" and "Everyone") and one app without an identity.
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

    // ── Authorization (idp.applications:read).
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

    // ── Assigning makes it usable. A suspended app is unusable even with an assignment.
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

    // ── The identity's app appears on the single-item endpoint (a different relation from usable apps).
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

    // ── 404 for a counterpart that is not a service account.
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

/// Minimal encoding for query strings (non-ASCII and symbols become %XX).
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
