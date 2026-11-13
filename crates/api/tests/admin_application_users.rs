//! The roster of one's own app (`GET /{tenant_id}/admin/applications/self/users`; ADR-0057 / ADR-0059).
//!
//! What this pins down:
//!
//! - ⚠ **The target is determined by the calling service account's identity**. The RP writes nothing in the path
//! - ⚠ **Permission codes do not get through**. Even with `idp.applications:read`, no identity means 403
//! - ⚠ **Unbound principals (users, service accounts without an identity) get 403**. Returning an empty roster
//!   would make the RP block everyone
//! - ⚠ **A login identity (`oidc`) does not get through** (same `client_id` column, different kind)
//! - A service account with only an identity (zero permission codes) **gets an admin token**
//! - Other apps' rosters cannot be read
//! - The old endpoint `/admin/applications/oidc/{client_id}/users` does not exist
//! - "Individual" candidates = people with an assignment. ⚠ Suspended accounts do not disappear; they show as `blocked`
//! - ⚠ **Service account assignments are not in the roster**
//! - "Everyone" candidates = the tenant's members
//! - ⚠ **A suspended app is not "empty" but "everyone `blocked`"** (so it is not mistaken for "could not fetch")
//! - ⚠ **`unknown` (gone) is returned only when `subs` is passed**. Every asked `sub` comes back as exactly one row
//! - ⚠ If even one `sub` cannot be parsed, 400 (answering with only the parsed ones turns typos into "gone")
//! - Paging returns **the values actually applied**
//!
//! ⚠ The list looks at the whole tenant, so rows added by other tests get mixed in. Check
//! "how the `sub`s we created appear" rather than counts.

mod support;

use axum::http::{Method, StatusCode};
use serde_json::Value;
use sqlx::MySqlPool;
use support::{
    admin_token, anonymous, body_json, create_plain_user, get, insert_confidential_client,
    insert_service_account, open_client_as_application, request_management_token, send, unique,
    TestEnv,
};

/// Flips the assignment mode (`open_client_as_application` opens with `EVERYONE`).
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

/// Looks up the state of a `sub` in the response. `None` if absent.
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

/// Adds an identity directly (bypasses the admin API so the test can pick `kind` freely).
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

/// Gets an admin token (assumes it can be obtained).
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

/// Opens one app, binds the identity of its service account and returns `(application_id, admin token)`.
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

/// A service account with only an identity (zero permission codes) gets an admin token and can read its
/// own app's roster. ⚠ **Periodic reconciliation is not something a person runs**.
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

    // Permission codes have not increased — other admin APIs stay 403.
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

/// ⚠ Other apps' rosters cannot be read (there is no way to choose the target at all).
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

/// ⚠ **Unbound principals get 403** (no empty roster). Tenant-wide `idp.applications:read`
/// does not get through either.
#[tokio::test]
async fn callers_without_an_own_application_are_refused() {
    let Some(env) = support::setup("application users refused").await else {
        return;
    };
    let uri = roster_uri(&env.root_tenant_id);

    let res = send(&env.app, anonymous(Method::GET, &uri, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no token -> 401");

    // A user (even a tenant admin) has no app of their own.
    let admin = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(&env.app, get(&admin, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "a user -> 403");

    // A service account without an identity. Permission codes only get it a token; the roster stays unreadable.
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

/// ⚠ **A login identity does not get through.** Login clients and service accounts use the same `client_id`
/// column, so without checking the kind they get mixed up.
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
    // Deliberately bind with the wrong kind.
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

/// The old endpoint (where the RP writes `client_id` in the path) does not exist.
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

/// "Individual" candidates are people with an assignment. ⚠ Suspended accounts **do not disappear; they show as `blocked`**
/// (the RP treats "suspended = may come back" differently from "gone").
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
        "a suspended person stays in the roster as blocked"
    );
    assert_eq!(
        state_of(&body, &outsider_sub),
        None,
        "a person without an assignment is not a candidate"
    );
    assert_eq!(body["total"], 2, "candidates = number of assignments");

    // Asking also reveals the fate of people who are not candidates.
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
    assert_eq!(
        body["total"], 4,
        "every asked sub comes back as exactly one row"
    );
    assert_eq!(state_of(&body, &assigned_sub).as_deref(), Some("allowed"));
    assert_eq!(state_of(&body, &stopped_sub).as_deref(), Some("blocked"));
    assert_eq!(
        state_of(&body, &outsider_sub).as_deref(),
        Some("blocked"),
        "present but not allowed (⚠ the side that keeps the link)"
    );
    assert_eq!(
        state_of(&body, &gone).as_deref(),
        Some("unknown"),
        "not in assay = gone (the link may be dropped)"
    );
}

/// ⚠ **Only people are in the roster** (ADR-0059 decision 5). Service account assignments count neither as
/// candidates nor in totals — the RP matches against local accounts, so counterparts without one break matching.
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

/// "Everyone" candidates are the tenant's members. ⚠ **The shape is the same as "Individual"** (the RP does not know the mode).
#[tokio::test]
async fn everyone_mode_lists_the_tenant_members() {
    let Some(env) = support::setup("application users everyone").await else {
        return;
    };
    // `open_client_as_application` opens with `EVERYONE`.
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
        "a tenant member may use it even without an assignment"
    );
}

/// ⚠ A suspended app **does not become empty**. Everyone comes back as `blocked`
/// — returning empty would leave the RP unable to tell it from "could not fetch".
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
    assert_eq!(body["total"], 1, "candidates do not disappear");
    assert_eq!(state_of(&body, &sub).as_deref(), Some("blocked"));
}

/// ⚠ Do not answer with only what parsed. If a `sub` with a one-character typo silently became "gone",
/// the RP would drop that person's link.
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
        "there is a cap on how many subs can be asked at once"
    );
}

/// Paging returns **the applied values, not the requested ones** (same as other lists).
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
    assert_eq!(body["total"], 3, "the total does not depend on the page");
    assert_eq!(body["limit"], 2);

    let body = body_json(send(&env.app, get(&token, &format!("{uri}?limit=100000"))).await).await;
    assert_eq!(body["limit"], 200, "returns the value clamped to the cap");

    // No duplicates or gaps across pages (order is stable by ascending `sub`).
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
    assert_eq!(subs.len(), 3, "no duplicates across pages");
}
