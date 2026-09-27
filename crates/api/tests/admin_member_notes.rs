//! メンバーの管理者メモ（`PUT /{tenant_id}/admin/members/{user_id}/note`）と、メンバー 1 人が
//! 使えるアプリ（`GET /{tenant_id}/admin/members/{user_id}/applications`）の統合テスト（ADR-0063）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_member_notes
//!
//! 検証するのは:
//!
//! 1. 認可（未認証 401 / 権限なし 403）と、メンバーでない利用者へは 404。
//! 2. 書いたメモが詳細・一覧に載り、**メモの言葉で絞り込める**こと。空で送ると消えること。
//! 3. ⚠ **監査にメモの中身が残らない**こと（経緯の自由記述は PII を含む）。
//! 4. ゲストを解除するとメモも消えること（招き直したときに前回のメモが黙って復活しない）。
//! 5. 使えるアプリが判定と同じ規則で答えられ、ログインの名乗りの無いアプリは載らないこと。

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

    // ── 認可。
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

    // ── 書く。詳細にも一覧にも載る。
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

    // ── メモの言葉で絞り込める。
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

    // ── ⚠ 監査に中身を残さない。
    let reasons = audit_reasons(&env.pool, &member).await;
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(!reasons[0].contains(&marker), "{reasons:?}");

    // ── 長すぎれば 400（文字で数える）。前のメモはそのまま。
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

    // ── 空で送ると消える。
    let res = send(&env.app, put(&admin_tok, &uri, json!({ "note": "  \n " }))).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "clear -> 204");
    assert_eq!(note_rows(&env.pool, &env.root_tenant_id, &member).await, 0);
    let reasons = audit_reasons(&env.pool, &member).await;
    assert!(reasons.last().unwrap().ends_with("cleared"), "{reasons:?}");

    // ── メンバーでない利用者（別テナントの人）へは 404。
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

/// 利用者の作成と同時にメモを書ける（作ったときがいちばん経緯を覚えている）。
#[tokio::test]
async fn a_note_can_be_written_when_the_user_is_created() {
    let Some(env) = support::setup("admin member notes on create").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let users_uri = format!("/{}/admin/users", env.root_tenant_id);
    let email = format!("created-{}@example.com", support::unique());

    // 長すぎれば利用者ごと作らない。
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

    // ゲストにも書ける（このテナントの管理者の覚え書き）。
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

    // 「全員」のアプリ（ログインの名乗りあり）。
    let everyone_client =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let everyone =
        support::open_client_as_application(&env.pool, &env.root_tenant_id, &everyone_client).await;
    // 「個別」のアプリ（ログインの名乗りあり）。
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
    // 名乗りの無いアプリは人が入る先ではないので載らない。
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

    // ── 認可。
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

    // ── 割り当てると使えるようになる。
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

    // ── アプリを止めると、割り当てがあっても使えない。
    sqlx::query("UPDATE applications SET status = 'DISABLED' WHERE id = ?")
        .bind(&individual)
        .execute(&env.pool)
        .await
        .expect("disable");
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let row = find(&listed, &individual).expect("individual app listed");
    assert_eq!(row["access"], "application_disabled", "{row}");

    // ── メンバーでない利用者へは 404。
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

/// 仮登録の人には設定リンクの期限が出て、切れたら `setup_link_expired` が立つ。
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

    // 期限を過去にすると、読んだ時点で期限切れと判定される。
    sqlx::query("UPDATE password_reset_tokens SET expires_at = ? WHERE user_id = ?")
        .bind(chrono::Utc::now().naive_utc() - chrono::Duration::hours(1))
        .bind(&user_id)
        .execute(&env.pool)
        .await
        .expect("expire the link");
    let member = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(member["setup_link_expired"], true, "{member}");

    // 出し直すと期限が戻る。
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
