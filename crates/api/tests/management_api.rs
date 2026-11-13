//! Integration tests for the admin API that operates the IdP itself from machines (ADR-0037).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test management_api
//!
//! Key points checked:
//! - A system client obtains an **admin token** via `client_credentials` + `resource` and can operate only
//!   within the fine-grained permissions granted.
//! - A token obtained without `resource` (`aud` is `/userinfo`) cannot call the admin API.
//!   If it could, tokens for user sign-in could be carried into the admin surface.
//! - Broad admin permissions (`idp.tenant.admin` / `idp.system.admin`) cannot be granted to clients.
//! - Admin tokens do not cross tenants.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::json;
use support::{admin_token, body_json, delete, get, post, send, unique};

/// Default of `MANAGEMENT_TOKEN_TTL_SECS` (paired with the definition in `domain::system_setting`).
const MANAGEMENT_TOKEN_TTL_SECS: u64 = 300;
/// Default of `ACCESS_TOKEN_TTL_SECS`.
const ACCESS_TOKEN_TTL_SECS: u64 = 900;

fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// Calls `/token` with `client_credentials` (`resource` is optional).
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

/// Resource indicator pointing at assay's admin API (`{issuer}/{tenant_id}/admin`).
fn management_resource(env: &support::TestEnv, tenant_id: &str) -> String {
    format!("{}/{}/admin", env.issuer, tenant_id)
}

#[tokio::test]
async fn a_system_client_operates_the_idp_within_the_permissions_it_was_granted() {
    let Some(env) = support::setup("management api").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let perms_uri = format!(
        "/{}/admin/clients/{client_id}/permissions",
        env.root_tenant_id
    );

    // While there are no permissions, requesting the admin API issues no admin token (do not create a token
    // that was obtained but lets nothing through).
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&management_resource(&env, &env.root_tenant_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["error"],
        "invalid_target",
        "no permissions -> invalid_target"
    );

    // Grant read only.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &perms_uri,
            json!({ "permission_code": "idp.users:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant idp.users:read");
    assert_eq!(
        body_json(res).await["permission_codes"],
        json!(["idp.users:read"])
    );

    // Obtain an admin token.
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&management_resource(&env, &env.root_tenant_id)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let issued = body_json(res).await;
    // Admin tokens are shorter-lived than normal access tokens (ADR-0037 decision 2). `perms` is read from the token,
    // so this lifetime is the upper bound of "from revoking a permission until it actually takes effect". If the default
    // ACCESS_TOKEN_TTL_SECS (900) were used, revocation would stay ineffective 3 times longer.
    assert_eq!(
        issued["expires_in"].as_u64(),
        Some(MANAGEMENT_TOKEN_TTL_SECS),
        "a management token must use MANAGEMENT_TOKEN_TTL_SECS, not ACCESS_TOKEN_TTL_SECS"
    );
    let machine_tok = issued["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // Reading passes.
    let user_uri = format!("/{}/admin/users/{}", env.root_tenant_id, env.root_admin_id);
    let res = send(&env.app, get(&machine_tok, &user_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "idp.users:read allows reading"
    );

    // Writing does not pass (`:read` does not imply `:write`).
    let res = send(
        &env.app,
        post(
            &machine_tok,
            &format!("/{}/admin/users", env.root_tenant_id),
            json!({ "email": format!("machine-{}@example.com", support::unique()) }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.users:read must not allow writing"
    );

    // It does not extend to other resources either.
    let res = send(
        &env.app,
        get(
            &machine_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.users:read must not reach clients"
    );

    // After revocation, the next token obtained does not carry it (issued tokens stay valid until TTL).
    let res = send(
        &env.app,
        delete(&admin_tok, &format!("{perms_uri}/idp.users:read")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["permission_codes"], json!([]));
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some(&management_resource(&env, &env.root_tenant_id)),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a revoked client can no longer get a management token"
    );
}

/// A token obtained without `resource` is for `/userinfo` and gets 401 at the admin API.
///
/// If it passed, tokens RPs receive from user sign-in would reach the admin surface with the same `aud`.
#[tokio::test]
async fn a_token_minted_for_userinfo_cannot_reach_the_management_api() {
    let Some(env) = support::setup("management api audience").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
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

    // No `resource` → `aud` is `/userinfo`. The lifetime stays that of a normal access token
    // (do not extend the short admin token lifetime to unrelated tokens).
    let res = request_token(&env.app, &env.root_tenant_id, &client_id, &secret, None).await;
    assert_eq!(res.status(), StatusCode::OK);
    let issued = body_json(res).await;
    assert_eq!(
        issued["expires_in"].as_u64(),
        Some(ACCESS_TOKEN_TTL_SECS),
        "a userinfo-audience token keeps the ordinary access token lifetime"
    );
    let userinfo_tok = issued["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let res = send(
        &env.app,
        get(
            &userinfo_tok,
            &format!("/{}/admin/users/{}", env.root_tenant_id, env.root_admin_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "audience mismatch -> 401"
    );

    // Grants that authenticated a user do not accept `resource` (silently ignoring it would leave a caller who
    // thought they asked for an admin token unable to find out why the admin API returns 401).
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, basic(&client_id, &secret))
            .body(Body::from(format!(
                "grant_type=refresh_token&refresh_token=whatever&resource={}",
                percent_encoding::utf8_percent_encode(
                    &management_resource(&env, &env.root_tenant_id),
                    percent_encoding::NON_ALPHANUMERIC
                )
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(res).await["error"],
        "invalid_target",
        "resource is only meaningful for client_credentials"
    );

    // Requests for unknown resources get `invalid_target` (RFC 8707 §2).
    let res = request_token(
        &env.app,
        &env.root_tenant_id,
        &client_id,
        &secret,
        Some("https://someone-elses.example.com/api"),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_target");
}

/// Broad admin permissions cannot be granted to clients (double defence: app layer and DB CHECK).
#[tokio::test]
async fn blanket_admin_permissions_cannot_be_granted_to_a_client() {
    let Some(env) = support::setup("management api blanket").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (client_id, _secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let perms_uri = format!(
        "/{}/admin/clients/{client_id}/permissions",
        env.root_tenant_id
    );

    for code in ["idp.tenant.admin", "idp.system.admin"] {
        let res = send(
            &env.app,
            post(&admin_tok, &perms_uri, json!({ "permission_code": code })),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "{code} must not be grantable to a client"
        );
    }

    // Unknown codes are rejected too (not in the master = FK violation).
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &perms_uri,
            json!({ "permission_code": "idp.made-up:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// **Users** holding only fine-grained codes follow the same boundary via the admin console (admin token).
/// Also checks that existing `idp.tenant.admin` holders still pass everything as before.
#[tokio::test]
async fn fine_grained_codes_bound_a_user_while_tenant_admin_still_implies_everything() {
    let Some(env) = support::setup("management api user scope").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // Existing holders of broad codes (the seeded root admin has idp.system.admin) pass everything.
    let res = send(
        &env.app,
        get(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    // Create a user holding only `idp.audit:read`.
    let target = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/users/{target}/permissions", env.root_tenant_id),
            json!({ "permission_code": "idp.audit:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let scoped_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &target).await;
    let res = send(
        &env.app,
        get(
            &scoped_tok,
            &format!("/{}/admin/audit-logs", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "idp.audit:read allows reading audit logs"
    );

    let res = send(
        &env.app,
        get(
            &scoped_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "idp.audit:read must not reach clients"
    );

    // The console entrance (whoami) still requires the broad code, so it does not pass (ADR-0037 leftover).
    let res = send(
        &env.app,
        get(
            &scoped_tok,
            &format!("/{}/admin/whoami", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// Narrowing the grant candidates is done by api (`?grantable_to=client`; ADR-0037).
///
/// web does not depend on core, so writing this decision on the web side too would leave **one side stale when the
/// master grows**. The admin console's choices are this response itself, so if broad codes were mixed in,
/// "permissions that cannot be granted" could be chosen on screen.
#[tokio::test]
async fn the_grantable_to_client_filter_removes_the_blanket_admin_codes() {
    let Some(env) = support::setup("management api grantable filter").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/permissions", env.root_tenant_id);

    // Without a filter, the whole master (including broad codes).
    let res = send(&env.app, get(&admin_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let all = body_json(res).await;
    let all: Vec<String> = serde_json::from_value(all["codes"].clone()).expect("codes");
    assert!(all.iter().any(|c| c == "idp.tenant.admin"));
    assert!(all.iter().any(|c| c == "idp.system.admin"));
    assert!(all.iter().any(|c| c == "idp.users:read"));

    // `grantable_to=client` drops only the broad codes and keeps fine-grained ones.
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{uri}?grantable_to=client")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let filtered = body_json(res).await;
    let filtered: Vec<String> = serde_json::from_value(filtered["codes"].clone()).expect("codes");
    assert!(
        !filtered.iter().any(|c| c == "idp.tenant.admin"),
        "blanket tenant admin must not be offered as a client grant"
    );
    assert!(
        !filtered.iter().any(|c| c == "idp.system.admin"),
        "blanket system admin must not be offered as a client grant"
    );
    assert!(filtered.iter().any(|c| c == "idp.users:read"));
    assert_eq!(filtered.len(), all.len() - 2);

    // Unknown values do not filter (it is a support API, so typos are not made 400).
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{uri}?grantable_to=nonsense")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let unfiltered = body_json(res).await;
    let unfiltered: Vec<String> =
        serde_json::from_value(unfiltered["codes"].clone()).expect("codes");
    assert_eq!(unfiltered.len(), all.len());
}

/// In non-root tenants `idp.system.admin` **cannot be granted**, so it is not offered as a candidate either.
///
/// This permission can exist only in root scope (`user_permissions_system_admin_scope_chk`; ADR-0009 §4),
/// and granting it in non-root fails no matter who does it. Leaving it as a candidate would put **a choice that is
/// selectable but always 403** on the admin console's grant form (ADR-0032 "do not show what cannot be chosen").
///
/// It is checked in two steps: it is gone from the candidates, and **calling api directly is still 403**.
/// With only the former, a change that just hid it on screen while loosening api would pass.
#[tokio::test]
async fn system_admin_is_neither_offered_nor_grantable_outside_the_root_tenant() {
    let Some(env) = support::setup("management api system admin scope").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    // root creates a child tenant. The creator root remains an ACTIVE GUEST admin of that child tenant
    // (bootstrap of ADR-0009 §4), so from here on it acts as a "guest admin".
    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("SystemAdminScope{}", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create child tenant");
    let child = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();
    let guest_tok = admin_token(&env.app, &env.pool, &child, &env.root_admin_id).await;

    // 1. idp.system.admin does not appear in the grant candidates (it does in the root tenant; covered by the test above).
    let res = send(
        &env.app,
        get(&guest_tok, &format!("/{child}/admin/permissions")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let codes = body_json(res).await;
    let codes: Vec<String> = serde_json::from_value(codes["codes"].clone()).expect("codes");
    assert!(
        !codes.iter().any(|c| c == "idp.system.admin"),
        "system admin must not be offered outside the root tenant"
    );
    assert!(
        codes.iter().any(|c| c == "idp.tenant.admin"),
        "tenant admin remains grantable in a child tenant"
    );

    // 2. It was not just hidden from the candidates while loosening api.
    let res = send(
        &env.app,
        post(
            &guest_tok,
            &format!("/{child}/admin/users"),
            json!({ "email": format!("scope-{}@example.com", unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create target user");
    let target = body_json(res).await["user_id"]
        .as_str()
        .expect("user id")
        .to_string();

    let res = send(
        &env.app,
        post(
            &guest_tok,
            &format!("/{child}/admin/users/{target}/permissions"),
            json!({ "permission_code": "idp.system.admin" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "granting system admin outside root must stay refused"
    );
}
