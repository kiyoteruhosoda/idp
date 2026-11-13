//! Integration tests (with DB) for the login identifier admin API
//! (`/{tenant_id}/admin/users/{user_id}/login-identifiers`; AP8).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_login_identifiers
//!
//! What is checked:
//!
//! 1. Authorization (unauthenticated 401 / no permission 403).
//! 2. An added identifier **can actually be used to sign in** (adding to the registry changes resolution; ADR-0025).
//! 3. Disabling it stops matching, but the row stays so nobody else can take the same value.
//! 4. Values already usable for login are rejected (others' identifiers, others' emails, one's own primary identifier).
//! 5. The primary login identifier appears in the list as a synthetic row but is not stored, so it cannot be operated on.
//! 6. Only the kind remains in the audit log; the value (PII) does not leak.

mod support;

/// Rate limit bucket per test function (see the comment on `admin_login_result` below).
const IP_ASSIGN: &str = "203.0.113.81";
const IP_CONFLICT: &str = "203.0.113.82";

use axum::http::{Method, StatusCode};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{
    admin_token, body_json, delete, get, patch, post, post_empty, post_internal, send,
    SERVICE_TOKEN,
};

/// Checks resolution through the admin console login path (`/internal/authenticate/admin`).
///
/// All 4 paths resolve login identifiers through the same `find_by_login_identifier`, so one representative suffices.
/// Admin login is chosen because it shows just "input → result" without preparing an `auth_session`.
/// For a user without admin permission, correct credentials give `forbidden` (= the user was identified),
/// and an unidentified one gives `invalid_credentials`. The difference reveals whether resolution succeeded.
///
/// `ip` differs per test function. The per-IP rate limiter lives in process memory (single
/// instance assumed), and tests running in parallel in the same binary share buckets.
async fn admin_login_result(
    app: &axum::Router,
    tenant: &str,
    ip: &str,
    username: &str,
    password: &str,
) -> String {
    let response = send(
        app,
        post_internal(
            "/internal/authenticate/admin",
            Some(SERVICE_TOKEN),
            json!({
                "tenant_id": tenant,
                "username": username,
                "password": password,
                "ip_address": ip,
                "user_agent": "integration-test",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await["result"]
        .as_str()
        .expect("result tag")
        .to_string()
}

async fn audit_reasons(pool: &MySqlPool, tenant_id: &str, event_type: &str) -> Vec<String> {
    sqlx::query(
        "SELECT reason FROM audit_log WHERE event_type = ? AND tenant_id = ? AND result = 'success' \
         ORDER BY occurred_at DESC LIMIT 20",
    )
    .bind(event_type)
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .expect("audit rows")
    .iter()
    .map(|row| row.get::<Option<String>, _>("reason").unwrap_or_default())
    .collect()
}

/// Creates one user by self-registration and returns its internal ID.
async fn register(env: &support::TestEnv, username: &str, password: &str) -> String {
    support::register_user(&env.app, &env.root_tenant_id, username, password).await;
    support::find_user_id_by_username(&env.pool, &env.root_tenant_id, username)
        .await
        .expect("registered user")
}

#[tokio::test]
async fn admin_assigns_a_phone_identifier_that_can_then_be_used_to_sign_in() {
    let Some(env) = support::setup("admin login identifiers").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let unique = uuid::Uuid::now_v7().simple().to_string();
    let username = format!("li{}", &unique[..10]);
    let password = "correct-horse-battery";
    let target = register(&env, &username, password).await;
    let uri = format!(
        "/{}/admin/users/{target}/login-identifiers",
        env.root_tenant_id
    );

    // ── Authorization.
    let res = send(&env.app, support::anonymous(Method::GET, &uri, None)).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let outsider = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let outsider_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &outsider).await;
    let res = send(&env.app, get(&outsider_token, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // ── The list starts with the primary identifier, then the primary email (ADR-0050). Since AP15 the registry also
    //    has real rows, so they have an `id` (synthetic rows come back only for users created before the migration;
    //    see the `primary_login_identifier` test).
    let res = send(&env.app, get(&admin_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed = body_json(res).await;
    let rows = listed.as_array().expect("array");
    assert_eq!(rows.len(), 2, "{listed}");
    assert_eq!(rows[0]["is_primary"], Value::Bool(true));
    assert!(rows[0]["id"].is_string(), "{listed}");
    assert_eq!(rows[0]["normalized_value"], username.to_lowercase());
    assert_eq!(rows[1]["is_primary_email"], Value::Bool(true));
    assert_eq!(rows[1]["identifier_type"], "email");
    let stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_login_identifiers \
         WHERE user_id = ? AND primary_of_user IS NOT NULL",
    )
    .bind(&target)
    .fetch_one(&env.pool)
    .await
    .expect("count");
    assert_eq!(
        stored, 1,
        "the primary identifier is in the registry too (in both during the migration)"
    );

    // ── Add a phone number. Displayed as registered, matched on the normalized value.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "phone_number", "value": "090-1234-5678"}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let added = body_json(res).await;
    assert_eq!(added["display_value"], "090-1234-5678");
    assert_eq!(added["normalized_value"], "09012345678");
    assert_eq!(added["is_primary"], Value::Bool(false));
    let identifier_id = added["id"].as_str().expect("id").to_string();

    // ── Different separator styles resolve to the same number (normalization at work).
    //    The international form (`+81…`) is **a different key** (guessing the mapping between country code and
    //    domestic prefix could hit someone else's number; see the domain::login_identifier tests).
    assert_eq!(
        admin_login_result(
            &env.app,
            &env.root_tenant_id,
            IP_ASSIGN,
            "(090) 1234.5678",
            password
        )
        .await,
        "forbidden",
        "the phone number identifies the user, but this user has no admin permission"
    );
    // Different credentials give invalid_credentials. Identifier resolution and password verification are separate.
    assert_eq!(
        admin_login_result(
            &env.app,
            &env.root_tenant_id,
            IP_ASSIGN,
            "09012345678",
            "wrong-password"
        )
        .await,
        "invalid_credentials"
    );

    // ── Once disabled it is not resolved (= treated like an unknown user).
    let item_uri = format!("{uri}/{identifier_id}");
    let res = send(
        &env.app,
        patch(&admin_tok, &item_uri, json!({"is_active": false})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["is_active"], Value::Bool(false));
    assert_eq!(
        admin_login_result(
            &env.app,
            &env.root_tenant_id,
            IP_ASSIGN,
            "090-1234-5678",
            password
        )
        .await,
        "invalid_credentials"
    );

    // ── Disabling keeps the row, so other users cannot take the same value.
    let other = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{other}/login-identifiers",
                env.root_tenant_id
            ),
            json!({"identifier_type": "phone_number", "value": "09012345678"}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // ── Only the kind remains in the audit log, not the number.
    let reasons = audit_reasons(
        &env.pool,
        &env.root_tenant_id,
        "user.login_identifier_added",
    )
    .await;
    assert!(reasons.iter().any(|r| r.contains("type=phone_number")));
    assert!(
        !reasons.iter().any(|r| r.contains("1234")),
        "the phone number remains in the audit log: {reasons:?}"
    );

    // ── It can be deleted (disabled rows too).
    let res = send(&env.app, delete(&admin_tok, &item_uri)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = send(&env.app, delete(&admin_tok, &item_uri)).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "second time is 404");
}

#[tokio::test]
async fn rejects_values_that_are_already_usable_for_signing_in() {
    let Some(env) = support::setup("login identifier conflicts").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let unique = uuid::Uuid::now_v7().simple().to_string();
    let alice = format!("la{}", &unique[..10]);
    let bob = format!("lb{}", &unique[..10]);
    let password = "correct-horse-battery";
    let alice_id = register(&env, &alice, password).await;
    register(&env, &bob, password).await;
    let uri = format!(
        "/{}/admin/users/{alice_id}/login-identifiers",
        env.root_tenant_id
    );

    // Another person's username (different case) is rejected. Allowing it would return someone else at login.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "username", "value": bob.to_uppercase()}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // Another person's email address is rejected too (email is not currently a login entry, but it allows impersonation).
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "email", "value": format!("{bob}@example.com")}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // A value equal to one's own primary identifier is also rejected. If it could be registered, even after disabling that row
    // authentication would pass via the fallback to `users.preferred_username` ("stopped but still usable").
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "username", "value": alice.to_uppercase()}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // ── Even with a different kind, nobody else can take the same value (migration 0041). **Not even for an inactive row.**
    //
    //    Inactive rows hit neither resolution nor availability checks, so only the unique constraint stops this.
    //    Without it, someone else could take the same value with another kind while it is disabled, and the moment it
    //    is re-enabled "one input matches two people" — those people can no longer get in even with correct
    //    passwords, and nobody else can see why.
    let reserved = format!("7{:09}", uuid::Uuid::new_v4().as_u128() % 1_000_000_000);
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "employee_number", "value": reserved, "is_active": false}),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "alice's employee number (inactive)"
    );

    let bob_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &bob)
        .await
        .expect("registered bob");
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!(
                "/{}/admin/users/{bob_id}/login-identifiers",
                env.root_tenant_id
            ),
            json!({"identifier_type": "username", "value": reserved}),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a value held by an inactive row cannot be taken by someone else even with another kind"
    );

    // Malformed input is 400 (if it could be registered it would be "an identifier that never matches", with no visible reason).
    for bad in [
        json!({"identifier_type": "phone_number", "value": "090-1234-abcd"}),
        json!({"identifier_type": "employee_number", "value": "A 1234"}),
        json!({"identifier_type": "not-a-type", "value": "x"}),
    ] {
        let res = send(&env.app, post(&admin_tok, &uri, bad.clone())).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{bad}");
    }

    // One's own email address is rejected too. Since ADR-0050 `users.email` **is in the registry as the primary email
    // row**, so adding the same value as another row is a duplicate (this used to be 201).
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "email", "value": format!("{alice}@example.com")}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // ── Email login is decided by the tenant switch (ADR-0050 decision 3).
    //
    //    The rows exist since migration / creation, but do not match in the login field until the switch is on.
    //    This confirms that "uniqueness always applies / the tenant opens the entrance" are kept separate.
    //
    //    ⚠ **Do not rely on the default; set both states explicitly.** The tenant is shared with other tests and the DB is
    //    reused across runs. Without turning it off first, the "off" check passes trivially with the switch a previous
    //    run left on (the second run actually failed because of that).
    let set_email_login = |on: bool| {
        let pool = env.pool.clone();
        let tenant = env.root_tenant_id.clone();
        async move {
            sqlx::query("UPDATE tenants SET email_login_enabled = ? WHERE id = ?")
                .bind(on)
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("toggle email login");
        }
    };

    set_email_login(false).await;
    assert_eq!(
        admin_login_result(
            &env.app,
            &env.root_tenant_id,
            IP_CONFLICT,
            &format!("{alice}@example.com"),
            password
        )
        .await,
        "invalid_credentials",
        "email cannot identify the user until the switch is on"
    );

    set_email_login(true).await;
    let with_switch_on = admin_login_result(
        &env.app,
        &env.root_tenant_id,
        IP_CONFLICT,
        &format!("{alice}@example.com"),
        password,
    )
    .await;
    // The tenant is shared, so always restore after checking (do not carry it over to the next test or run).
    set_email_login(false).await;
    assert_eq!(
        with_switch_on, "forbidden",
        "with the switch on, email identifies the user (this user has no admin permission)"
    );
}

#[tokio::test]
async fn the_primary_rows_cannot_be_targeted_even_by_their_real_id() {
    let Some(env) = support::setup("login identifier primary").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let unique = uuid::Uuid::now_v7().simple().to_string();
    let username = format!("lp{}", &unique[..10]);
    let target = register(&env, &username, "correct-horse-battery").await;
    let uri = format!(
        "/{}/admin/users/{target}/login-identifiers",
        env.root_tenant_id
    );

    // A nonexistent id is 404.
    let stray = uuid::Uuid::now_v7();
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("{uri}/{stray}"),
            json!({"is_active": false}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = send(&env.app, delete(&admin_tok, &format!("{uri}/{stray}"))).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // ── ⚠ **Shoot at real ids.** Since AP15b the primary identifier is also a registry row with an `id`, so
    //    "synthetic rows have no id, so no target can be built" no longer holds. What protects them is only
    //    the repository condition (`primary_of_user IS NULL` / `primary_email_of_user IS NULL`), and
    //    unless that is hit, this test **passes for the wrong reason**.
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let rows = listed.as_array().expect("array");
    for key in ["is_primary", "is_primary_email"] {
        let row = rows
            .iter()
            .find(|r| r[key] == Value::Bool(true))
            .unwrap_or_else(|| panic!("no row with {key}: {listed}"));
        let id = row["id"].as_str().expect("real id");
        let res = send(
            &env.app,
            patch(
                &admin_tok,
                &format!("{uri}/{id}"),
                json!({"is_active": false}),
            ),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "{key} cannot be disabled"
        );
        let res = send(&env.app, delete(&admin_tok, &format!("{uri}/{id}"))).await;
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "{key} cannot be deleted"
        );
    }

    // Changing the login identifier via profile edit makes the list follow (during the AP15 migration both `users` and
    // the registry are written, so no old value remains on one side).
    let renamed = format!("lq{}", &unique[..10]);
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("/{}/admin/users/{target}/profile", env.root_tenant_id),
            json!({"preferred_username": renamed}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let rows = listed.as_array().expect("array");
    assert_eq!(rows.len(), 2, "{listed}");
    assert_eq!(rows[0]["is_primary"], Value::Bool(true));
    assert_eq!(rows[0]["normalized_value"], renamed.to_lowercase());
    // Renaming moves only the username row. The primary email row is a copy of the email address, and
    // since the profile edit did not change the email it stays as is (ADR-0050).
    assert_eq!(rows[1]["is_primary_email"], Value::Bool(true));
    assert_eq!(rows[1]["identifier_type"], "email");
}

/// Promotes an alias email to the primary email (ADR-0052).
///
/// What matters is less "that they swap" than **that the swap happens as one transaction**
/// — whether `users.email` (= notification address) and the registry's primary email row point to the same value at once.
#[tokio::test]
async fn promoting_an_alias_email_swaps_the_primary_email() {
    let Some(env) = support::setup("login identifier promote email").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let unique = uuid::Uuid::now_v7().simple().to_string();
    let username = format!("lm{}", &unique[..10]);
    let target = register(&env, &username, "correct-horse-battery").await;
    let uri = format!(
        "/{}/admin/users/{target}/login-identifiers",
        env.root_tenant_id
    );
    let original = format!("{username}@example.com");
    let alias = format!("{username}-alt@example.com");
    assert_eq!(
        support::primary_email(&env.pool, &target).await.as_deref(),
        Some(original.as_str())
    );

    // ── Add the alias **while inactive**. It must be active after promotion — the primary email row
    //    cannot be enabled per identifier, so promoting it while inactive would make a row that can never
    //    be enabled the notification address.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "email", "value": alias, "is_active": false}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let added = body_json(res).await;
    let alias_id = added["id"].as_str().expect("id").to_string();
    assert_eq!(added["is_active"], Value::Bool(false));
    assert_eq!(added["is_primary_email"], Value::Bool(false));

    // ── Non-email values cannot be promoted (if a non-email string got into `users.email`,
    //    password resets would be sent there).
    //
    //    ⚠ **Use a different value every time.** The tenant is shared with other tests and the DB is reused
    //    across runs. A fixed value may already be held by another test, and the add fails with 409.
    let employee_number = format!("E{:09}", uuid::Uuid::new_v4().as_u128() % 1_000_000_000);
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({"identifier_type": "employee_number", "value": employee_number}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let employee_id = body_json(res).await["id"].as_str().expect("id").to_string();
    let res = send(
        &env.app,
        post_empty(&admin_tok, &format!("{uri}/{employee_id}/primary-email")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // A nonexistent row is 404 too (the demotion never runs first and loses the address).
    let stray = uuid::Uuid::now_v7();
    let res = send(
        &env.app,
        post_empty(&admin_tok, &format!("{uri}/{stray}/primary-email")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        support::primary_email(&env.pool, &target).await.as_deref(),
        Some(original.as_str()),
        "the failed promotion did not delete the primary email row"
    );

    // ── Promote.
    let res = send(
        &env.app,
        post_empty(&admin_tok, &format!("{uri}/{alias_id}/primary-email")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let promoted = body_json(res).await;
    assert_eq!(promoted["is_primary_email"], Value::Bool(true));
    assert_eq!(promoted["is_active"], Value::Bool(true), "{promoted}");
    assert_eq!(promoted["display_value"], alias);

    // The registry and `users.email` point to the same value. If only one moved, the entrance and the address would diverge.
    assert_eq!(
        support::primary_email(&env.pool, &target).await.as_deref(),
        Some(alias.as_str())
    );
    let stored_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(&target)
        .fetch_one(&env.pool)
        .await
        .expect("users.email");
    assert_eq!(stored_email, alias);

    // ── The former primary email **remains as an alias** (not deleted; deleting it would let others take the value).
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    let rows = listed.as_array().expect("array");
    let demoted = rows
        .iter()
        .find(|r| r["display_value"] == Value::String(original.clone()))
        .unwrap_or_else(|| panic!("the former primary email row disappeared: {listed}"));
    assert_eq!(demoted["is_primary_email"], Value::Bool(false), "{listed}");
    assert_eq!(demoted["identifier_type"], "email");
    let primary_rows = rows
        .iter()
        .filter(|r| r["is_primary_email"] == Value::Bool(true))
        .count();
    assert_eq!(primary_rows, 1, "exactly one primary email row: {listed}");

    // ── Pressing twice does not break anything (operating on a screen left open is common).
    let res = send(
        &env.app,
        post_empty(&admin_tok, &format!("{uri}/{alias_id}/primary-email")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        support::primary_email(&env.pool, &target).await.as_deref(),
        Some(alias.as_str())
    );

    // ── Only the fact of promotion remains in the audit log, not the address.
    let reasons = audit_reasons(&env.pool, &env.root_tenant_id, "user.primary_email_changed").await;
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("source=login_identifier")),
        "{reasons:?}"
    );
    assert!(
        !reasons.iter().any(|r| r.contains(&username)),
        "the address remains in the audit log: {reasons:?}"
    );
}
