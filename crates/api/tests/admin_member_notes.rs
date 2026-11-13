//! Integration tests (ADR-0063) for a member's admin note (`PUT /{tenant_id}/admin/members/{user_id}/note`) and
//! the apps one member can use (`GET /{tenant_id}/admin/members/{user_id}/applications`).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_member_notes
//!
//! What is checked:
//!
//! 1. Authorization (unauthenticated 401 / no permission 403), and 404 for users who are not members.
//! 2. A written note appears in the details and list, and **the list can be filtered by note words**. Sending empty clears it.
//! 3. ⚠ **The note content is not left in the audit log** (free-form background contains PII).
//! 4. Removing a guest also removes the note (the previous note does not silently come back on re-invitation).
//! 5. Usable apps are answered with the same rules as the decision, and apps without a login identity are not listed.

mod support;

use axum::http::{Method, StatusCode};
use serde_json::json;
use sqlx::{MySqlPool, Row};
use support::{admin_token, body_json, create_plain_user, delete, get, post, put, send};

async fn note_rows(pool: &MySqlPool, tenant_id: &str, user_id: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM account_notes WHERE tenant_id = ? AND user_id = ?")
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count notes")
        .get::<i64, _>("c")
}

async fn audit_reasons(pool: &MySqlPool, target_id: &str) -> Vec<String> {
    sqlx::query(
        "SELECT reason FROM audit_log \
         WHERE event_type = 'account.note_updated' AND reason LIKE ? ORDER BY id",
    )
    .bind(format!("%user={target_id}%"))
    .fetch_all(pool)
    .await
    .expect("read audit")
    .iter()
    .map(|row| row.get::<Option<String>, _>("reason").unwrap_or_default())
    .collect()
}

#[tokio::test]
async fn admin_writes_reads_searches_and_clears_a_member_note() {
    let Some(env) = support::setup("admin member notes").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let member = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!("/{}/admin/members/{member}/note", env.root_tenant_id);
    let marker = format!("経緯-{}", support::unique());
    let text = format!("{marker}\n2026-09 に家族として招待");

    // ── Authorization.
    let res = send(
        &env.app,
        support::anonymous(Method::PUT, &uri, Some(json!({ "note": "x" }))),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no token -> 401");
    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    let res = send(&env.app, put(&plain_tok, &uri, json!({ "note": "x" }))).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // ── Write. It appears in both the details and the list.
    let res = send(&env.app, put(&admin_tok, &uri, json!({ "note": text }))).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "write -> 204");
    let detail = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{}/admin/members/{member}", env.root_tenant_id),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(detail["note"]["text"], json!(text), "{detail}");
    assert!(detail["note"]["updated_at"].is_string(), "{detail}");

    // ── Filterable by note words.
    let found = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!(
                    "/{}/admin/members?q={}",
                    env.root_tenant_id,
                    urlencoding(&marker)
                ),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(found["total"], 1, "{found}");
    assert_eq!(found["members"][0]["user_id"], json!(member));
    assert_eq!(found["members"][0]["note"]["text"], json!(text));

    // ── ⚠ The content is not left in the audit log.
    let reasons = audit_reasons(&env.pool, &member).await;
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(!reasons[0].contains(&marker), "{reasons:?}");

    // ── Too long is 400 (counted in characters). The previous note stays.
    let res = send(
        &env.app,
        put(&admin_tok, &uri, json!({ "note": "あ".repeat(2001) })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "too long -> 400");
    let res = send(
        &env.app,
        put(&admin_tok, &uri, json!({ "note": "あ".repeat(2000) })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "2000 chars fit");

    // ── Sending empty clears it.
    let res = send(&env.app, put(&admin_tok, &uri, json!({ "note": "  \n " }))).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "clear -> 204");
    assert_eq!(note_rows(&env.pool, &env.root_tenant_id, &member).await, 0);
    let reasons = audit_reasons(&env.pool, &member).await;
    assert!(reasons.last().unwrap().ends_with("cleared"), "{reasons:?}");

    // ── 404 for a user who is not a member (someone from another tenant).
    let other_tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, ?, ?)")
        .bind(&other_tenant)
        .bind(&env.root_tenant_id)
        .bind(format!("notes-other-{}", &other_tenant[..8]))
        .execute(&env.pool)
        .await
        .expect("create another tenant");
    let outsider = create_plain_user(&env.pool, &other_tenant).await;
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("/{}/admin/members/{outsider}/note", env.root_tenant_id),
            json!({ "note": "x" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "not a member -> 404");
}

/// A note can be written when creating the user (creation is when the background is best remembered).
#[tokio::test]
async fn a_note_can_be_written_when_the_user_is_created() {
    let Some(env) = support::setup("admin member notes on create").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let users_uri = format!("/{}/admin/users", env.root_tenant_id);
    let email = format!("created-{}@example.com", support::unique());

    // Too long: the user is not created at all.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &users_uri,
            json!({ "email": email, "note": "あ".repeat(2001) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "too long -> 400");
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
        .bind(&email)
        .fetch_one(&env.pool)
        .await
        .expect("count users");
    assert_eq!(exists, 0, "a rejected note must not leave a user behind");

    let res = send(
        &env.app,
        post(
            &admin_tok,
            &users_uri,
            json!({ "email": email, "note": "取引先の担当者として作成" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create with a note");
    let created = body_json(res).await;
    let user_id = created["user_id"].as_str().expect("user_id").to_string();

    let detail = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{}/admin/members/{user_id}", env.root_tenant_id),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(
        detail["note"]["text"], "取引先の担当者として作成",
        "{detail}"
    );
    let reasons = audit_reasons(&env.pool, &user_id).await;
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(!reasons[0].contains("取引先"), "{reasons:?}");
}

#[tokio::test]
async fn revoking_a_guest_drops_the_note_with_the_membership() {
    let Some(env) = support::setup("admin member notes cascade").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let home_tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, ?, ?)")
        .bind(&home_tenant)
        .bind(&env.root_tenant_id)
        .bind(format!("notes-guest-home-{}", &home_tenant[..8]))
        .execute(&env.pool)
        .await
        .expect("create home tenant for the guest");
    let guest = create_plain_user(&env.pool, &home_tenant).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&env.root_tenant_id)
    .bind(&guest)
    .execute(&env.pool)
    .await
    .expect("insert guest membership");

    // Guests can have notes too (a memo of this tenant's admin).
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("/{}/admin/members/{guest}/note", env.root_tenant_id),
            json!({ "note": "取引先から招待" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(note_rows(&env.pool, &env.root_tenant_id, &guest).await, 1);

    let res = send(
        &env.app,
        delete(
            &admin_tok,
            &format!("/{}/admin/members/{guest}", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "revoke");
    assert_eq!(
        note_rows(&env.pool, &env.root_tenant_id, &guest).await,
        0,
        "the note goes with the membership"
    );
}

#[tokio::test]
async fn member_applications_follow_the_same_rule_as_the_gate() {
    let Some(env) = support::setup("admin member applications").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let member = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let uri = format!(
        "/{}/admin/members/{member}/applications",
        env.root_tenant_id
    );

    // An "Everyone" app (with a login identity).
    let everyone_client =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let everyone =
        support::open_client_as_application(&env.pool, &env.root_tenant_id, &everyone_client).await;
    // An "Individual" app (with a login identity).
    let individual_client =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let individual =
        support::open_client_as_application(&env.pool, &env.root_tenant_id, &individual_client)
            .await;
    sqlx::query("UPDATE applications SET assignment_mode = 'INDIVIDUAL' WHERE id = ?")
        .bind(&individual)
        .execute(&env.pool)
        .await
        .expect("make it individual");
    // An app without an identity is not a place people enter, so it is not listed.
    let created = body_json(
        send(
            &env.app,
            post(
                &admin_tok,
                &format!("/{}/admin/applications", env.root_tenant_id),
                json!({ "display_name": format!("no-login-{}", support::unique()) }),
            ),
        )
        .await,
    )
    .await;
    let without_login = created["id"].as_str().expect("id").to_string();

    // ── Authorization.
    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    let res = send(&env.app, get(&plain_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    let find = |body: &serde_json::Value, id: &str| {
        body["applications"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["application_id"] == json!(id))
            .cloned()
    };

    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(listed["enforcement"], "record_only", "{listed}");
    let row = find(&listed, &everyone).expect("everyone app listed");
    assert_eq!(row["access"], "allowed");
    let row = find(&listed, &individual).expect("individual app listed");
    assert_eq!(row["access"], "not_assigned");
    assert!(row.get("assigned_at").is_none(), "{row}");
    assert!(
        find(&listed, &without_login).is_none(),
        "an application nobody signs in to is not listed: {listed}"
    );

    // ── Assigning makes it usable.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/applications/{individual}/assignments",
                env.root_tenant_id
            ),
            json!({ "kind": "user", "user_id": member }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "assign");
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let row = find(&listed, &individual).expect("individual app listed");
    assert_eq!(row["access"], "allowed", "{row}");
    assert!(row["assigned_at"].is_string(), "{row}");

    // ── Suspending the app makes it unusable even with an assignment.
    sqlx::query("UPDATE applications SET status = 'DISABLED' WHERE id = ?")
        .bind(&individual)
        .execute(&env.pool)
        .await
        .expect("disable");
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let row = find(&listed, &individual).expect("individual app listed");
    assert_eq!(row["access"], "application_disabled", "{row}");

    // ── 404 for a user who is not a member.
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!(
                "/{}/admin/members/{}/applications",
                env.root_tenant_id,
                uuid::Uuid::now_v7()
            ),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "not a member -> 404");
}

/// A provisional person shows the setup link expiry, and `setup_link_expired` is set once it lapses.
#[tokio::test]
async fn a_pending_member_carries_the_setup_link_deadline() {
    let Some(env) = support::setup("admin member setup link deadline").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let email = format!("pending-{}@example.com", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/users", env.root_tenant_id),
            json!({ "email": email }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    let user_id = created["user_id"].as_str().unwrap().to_string();
    let uri = format!("/{}/admin/members/{user_id}", env.root_tenant_id);

    let member = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(member["pending_setup"], true, "{member}");
    assert!(member["setup_link_expires_at"].is_string(), "{member}");
    assert_eq!(member["setup_link_expired"], false, "{member}");

    // Moving the expiry into the past makes it judged expired at read time.
    sqlx::query("UPDATE password_reset_tokens SET expires_at = ? WHERE user_id = ?")
        .bind(chrono::Utc::now().naive_utc() - chrono::Duration::hours(1))
        .bind(&user_id)
        .execute(&env.pool)
        .await
        .expect("expire the link");
    let member = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(member["setup_link_expired"], true, "{member}");

    // Reissuing restores the expiry.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{user_id}/password-reset",
                env.root_tenant_id
            ),
            json!({}),
        ),
    )
    .await;
    assert!(res.status().is_success(), "reissue: {}", res.status());
    let member = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(member["setup_link_expired"], false, "{member}");
    assert_eq!(member["pending_setup"], true, "{member}");
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
