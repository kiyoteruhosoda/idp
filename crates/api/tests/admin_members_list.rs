//! Integration tests (with DB) for paging and filtering the member list (`GET /{tenant_id}/admin/members`; MT22).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_members_list
//!
//! The list returns the whole tenant, so to target only test rows it is filtered by **email addresses
//! containing a unique marker** (so count checks do not break even if other tests sharing the same DB add rows
//! to the root tenant). What is checked:
//!
//! 1. Authorization (unauthenticated 401 / no permission 403).
//! 2. `limit` / `offset` cut out a page, and `total` returns the total after filtering.
//! 3. No rows are duplicated or missing across pages (the order is stable).
//! 4. `limit` is clamped to the cap, and the clamped value appears in the response's `limit`.
//! 5. `LIKE` wildcards are escaped (`%` does not become "match everything").
//! 6. The list targets **memberships** (guests homed in other tenants appear / non-members do not).

mod support;

use axum::http::{Method, StatusCode};
use serde_json::Value;
use sqlx::MySqlPool;
use support::{admin_token, body_json, create_plain_user, get, send};

/// Creates a user in the tenant whose email address contains the unique marker (with a HOME membership).
/// `index` is zero-padded so the order (ascending email address) is predictable.
async fn insert_marked_user(pool: &MySqlPool, tenant_id: &str, marker: &str, index: u32) -> String {
    let id = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, name, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, ?, 'x', 'ACTIVE')",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!("{marker}-{index:02}@example.com"))
    .bind(format!("Member {index:02}"))
    .execute(pool)
    .await
    .expect("insert marked user");
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'HOME', 'ACTIVE')",
    )
    .bind(tenant_id)
    .bind(&id)
    .execute(pool)
    .await
    .expect("insert home membership");
    id
}

fn emails(body: &Value) -> Vec<String> {
    body["members"]
        .as_array()
        .expect("members array")
        .iter()
        .map(|m| m["email"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test]
async fn member_list_pages_and_filters_on_the_server() {
    let Some(env) = support::setup("admin members list").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let marker = format!("mt22-{}", uuid::Uuid::now_v7().simple());
    for index in 1..=5 {
        insert_marked_user(&env.pool, &env.root_tenant_id, &marker, index).await;
    }
    let base = format!("/{}/admin/members", env.root_tenant_id);

    // ── Authorization: no token is 401, a user without permission is 403.
    let res = send(&env.app, support::anonymous(Method::GET, &base, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    let res = send(&env.app, get(&plain_token, &base)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no admin perm -> 403");

    // ── First page. `total` is the total number of matches ignoring limit.
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&limit=2&offset=0")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let first = body_json(res).await;
    assert_eq!(first["total"], 5, "total after filtering");
    assert_eq!(first["limit"], 2);
    assert_eq!(first["offset"], 0);
    let page1 = emails(&first);
    assert_eq!(
        page1,
        vec![
            format!("{marker}-01@example.com"),
            format!("{marker}-02@example.com"),
        ],
        "one page is returned in ascending email order"
    );

    // ── Second page. No rows duplicated or missing across pages (the order is stable).
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&limit=2&offset=2")),
    )
    .await;
    let second = body_json(res).await;
    assert_eq!(second["total"], 5);
    let page2 = emails(&second);
    assert_eq!(
        page2,
        vec![
            format!("{marker}-03@example.com"),
            format!("{marker}-04@example.com"),
        ]
    );

    // ── The last page is the remainder (1 left).
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&limit=2&offset=4")),
    )
    .await;
    let third = body_json(res).await;
    assert_eq!(emails(&third), vec![format!("{marker}-05@example.com")]);

    // ── An out-of-range offset gives an empty page (not an error). total does not change.
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&offset=999")),
    )
    .await;
    let beyond = body_json(res).await;
    assert_eq!(beyond["total"], 5);
    assert!(emails(&beyond).is_empty());

    // ── limit is clamped to the cap (200) and the clamped value is in the response (so callers can page with it).
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{base}?q={marker}&limit=100000")),
    )
    .await;
    let clamped = body_json(res).await;
    assert_eq!(clamped["limit"], 200, "clamped to the cap");
    assert_eq!(clamped["members"].as_array().unwrap().len(), 5);

    // ── The name also matches partially (LIKE on `name`).
    let res = send(&env.app, get(&admin_tok, &format!("{base}?q=Member%2003"))).await;
    let by_name = body_json(res).await;
    assert!(
        emails(&by_name).contains(&format!("{marker}-03@example.com")),
        "found by partial name match: {by_name}"
    );
}

/// `%` / `_` are `LIKE` wildcards, so without escaping a search term matches unintentionally broadly
/// (`%` alone matches everything).
/// The list carries the username (primary login identifier) and can be filtered by it too.
///
/// ⚠ **The username is not in `users`** (removed in migration 0039). It is looked up from the registry's primary
/// identifier row with a correlated subquery.
///
/// ⚠ **Do not make it a JOIN.** Users without a username (accounts created from the admin screen without one)
/// would **vanish from the list entirely**. Then that person can no longer be operated from the admin screen
/// — invisible, so there is no way to find them. This test also guards that one point.
#[tokio::test]
async fn the_list_carries_the_login_identifier_and_can_filter_on_it() {
    let Some(env) = support::setup("member list login identifier").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let base = format!("/{}/admin/members", env.root_tenant_id);
    let unique = uuid::Uuid::now_v7().simple().to_string();
    let marker = format!("mlid{}", &unique[..8]);

    // A user with a username (profile edit creates the primary identifier row).
    let named = insert_marked_user(&env.pool, &env.root_tenant_id, &marker, 1).await;
    let username = format!("{marker}-login");
    let res = send(
        &env.app,
        support::patch(
            &admin_tok,
            &format!("/{}/admin/users/{named}/profile", env.root_tenant_id),
            serde_json::json!({ "preferred_username": username }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    // A user without a username (created directly with SQL, so no registry row).
    let nameless = insert_marked_user(&env.pool, &env.root_tenant_id, &marker, 2).await;

    // ── Filtering by email shows both. The one without a username has `preferred_username` omitted.
    let body =
        body_json(send(&env.app, get(&admin_tok, &format!("{base}?q={marker}"))).await).await;
    assert_eq!(body["total"], 2, "{body}");
    let members = body["members"].as_array().expect("members");
    let named_row = members
        .iter()
        .find(|m| m["user_id"] == Value::String(named.clone()))
        .expect("named member is listed");
    assert_eq!(named_row["preferred_username"], username);
    let nameless_row = members
        .iter()
        .find(|m| m["user_id"] == Value::String(nameless.clone()))
        .expect("users without a username are listed too (a JOIN would drop them)");
    assert!(
        nameless_row["preferred_username"].is_null(),
        "{nameless_row}"
    );

    // ── Filtering by username works too (if values shown in the list cannot be searched, "visible but not findable").
    let body =
        body_json(send(&env.app, get(&admin_tok, &format!("{base}?q={username}"))).await).await;
    assert_eq!(body["total"], 1, "{body}");
    assert_eq!(body["members"][0]["user_id"], Value::String(named));
}

#[tokio::test]
async fn like_wildcards_in_the_search_term_are_escaped() {
    let Some(env) = support::setup("admin members list wildcards").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let marker = format!("mt22esc-{}", uuid::Uuid::now_v7().simple());
    insert_marked_user(&env.pool, &env.root_tenant_id, &marker, 1).await;
    let base = format!("/{}/admin/members", env.root_tenant_id);

    // `%` matches not everything but only rows containing a literal `%` (= none).
    let res = send(&env.app, get(&admin_tok, &format!("{base}?q=%25"))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let escaped = body_json(res).await;
    assert_eq!(escaped["total"], 0, "`%` must not match everything");

    // `_` likewise (a literal, not any single character). The marker's `-` does not match `_`.
    let res = send(&env.app, get(&admin_tok, &format!("{base}?q=mt22esc_"))).await;
    let underscore = body_json(res).await;
    assert_eq!(
        underscore["total"], 0,
        "`_` must not be any single character"
    );

    // Normal searches still work with escaping.
    let res = send(&env.app, get(&admin_tok, &format!("{base}?q={marker}"))).await;
    assert_eq!(body_json(res).await["total"], 1);
}

/// The list targets **the tenant's memberships**, not "users homed in the tenant".
/// Guests homed in other tenants appear, and users without a membership do not (tenant isolation).
#[tokio::test]
async fn list_covers_memberships_not_home_users() {
    let Some(env) = support::setup("admin members list scope").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let marker = format!("mt22scope-{}", uuid::Uuid::now_v7().simple());

    // Two people in another tenant (a child of root). Only one joins root as a guest.
    let other_tenant = uuid::Uuid::now_v7().to_string();
    sqlx::query("INSERT INTO tenants (id, parent_tenant_id, name) VALUES (?, ?, ?)")
        .bind(&other_tenant)
        .bind(&env.root_tenant_id)
        .bind(format!("other-{}", &other_tenant[..8]))
        .execute(&env.pool)
        .await
        .expect("create other tenant");
    let guest = insert_marked_user(&env.pool, &other_tenant, &marker, 1).await;
    insert_marked_user(&env.pool, &other_tenant, &marker, 2).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(&env.root_tenant_id)
    .bind(&guest)
    .execute(&env.pool)
    .await
    .expect("invite guest into root");

    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/members?q={marker}", env.root_tenant_id),
        ),
    )
    .await;
    let body = body_json(res).await;
    assert_eq!(
        body["total"], 1,
        "only the one guest is a member of root: {body}"
    );
    assert_eq!(emails(&body), vec![format!("{marker}-01@example.com")]);
    assert_eq!(body["members"][0]["membership_type"], "GUEST");

    // Pending invitations (not accepted) are membership rows too, so they are listed (distinguishable by state).
    let invited = insert_marked_user(&env.pool, &other_tenant, &marker, 3).await;
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'INVITED')",
    )
    .bind(&env.root_tenant_id)
    .bind(&invited)
    .execute(&env.pool)
    .await
    .expect("invite guest into root");
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/members?q={marker}", env.root_tenant_id),
        ),
    )
    .await;
    let body = body_json(res).await;
    assert_eq!(body["total"], 2);
    assert_eq!(body["members"][1]["status"], "INVITED");
}

/// Fetches one member by name (`GET /{tenant_id}/admin/members/{user_id}`).
///
/// ⚠ **An endpoint so callers need not search the list.** The list is paged, so the caller cannot know which page
/// the person is on. If not in the requested tenant, 404 (no guessing the existence of other tenants'
/// members).
#[tokio::test]
async fn one_member_can_be_fetched_by_id() {
    let Some(env) = support::setup("member detail").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let marker = format!("detail-{}", uuid::Uuid::now_v7().simple());
    let user_id = insert_marked_user(&env.pool, &env.root_tenant_id, &marker, 1).await;
    let path = format!("/{}/admin/members/{}", env.root_tenant_id, user_id);

    // Authorization (same gate as the list).
    let res = send(&env.app, support::anonymous(Method::GET, &path, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no token -> 401");

    let res = send(&env.app, get(&admin_tok, &path)).await;
    assert_eq!(res.status(), StatusCode::OK, "member detail -> 200");
    let body: Value = body_json(res).await;
    assert_eq!(body["user_id"], user_id);
    assert_eq!(body["email"], format!("{marker}-01@example.com"));
    assert_eq!(body["membership_type"], "HOME");
    assert_eq!(body["status"], "ACTIVE");

    // A user who is not a member is 404 (does not leak existence).
    // ⚠ `create_plain_user` also creates a HOME membership, so it cannot be used. Insert **only the row**.
    let stranger = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, sub, email, email_verified, password_hash, status) \
         VALUES (?, ?, ?, ?, 1, 'x', 'ACTIVE')",
    )
    .bind(&stranger)
    .bind(&env.root_tenant_id)
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(format!("{marker}-stranger@example.com"))
    .execute(&env.pool)
    .await
    .expect("insert non-member user");
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/members/{}", env.root_tenant_id, stranger),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "not a member -> 404");
}
