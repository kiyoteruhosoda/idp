//! Integration tests for resource indicators (RFC 8707) (ADR-0042).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test resource_indicators
//!
//! Key points checked:
//! - Only audiences that are registered, are **some app's identity**, and whose app **the requesting service account
//!   is assigned to** go into `aud` (ADR-0059 decision 6).
//! - ⚠ Even for an "Everyone" (`EVERYONE`) app, a service account cannot get it unless individually assigned.
//! - Unregistered, suspended and not permitted are **not distinguished in the response** (otherwise registration could be probed by brute force).
//! - Audience tokens carry no `perms`. What may be done is decided by the resource server (ADR-0033).
//! - Tokens for the admin API (ADR-0037) work as before.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::{json, Value};
use support::{admin_token, body_json, delete, post, put, send, unique};

/// Default of `ACCESS_TOKEN_TTL_SECS`. Audience tokens are issued with the same lifetime as normal access tokens.
const ACCESS_TOKEN_TTL_SECS: u64 = 900;
/// Default of `MANAGEMENT_TOKEN_TTL_SECS` (ADR-0037).
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

/// Reads the claims of an access token (JWT). Signatures are checked by other tests; here only the values are looked at.
fn claims(access_token: &str) -> Value {
    let payload = access_token.split('.').nth(1).expect("payload segment");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&decoded).expect("claims json")
}

/// Creates an app as "Individual" and returns its id.
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

/// Registers an audience and returns its id.
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

    // Refused before registration.
    let res = token(audience.clone()).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error"], "invalid_target");

    register_resource(&env.app, &admin_tok, &env.root_tenant_id, &audience).await;

    // Registering alone does not issue it (it is no app's audience).
    let res = token(audience.clone()).await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a name that belongs to no application must not be issued"
    );
    assert_eq!(body_json(res).await["error"], "invalid_target");

    // Even as an app identity, it is not issued without an assignment.
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

    // ⚠ "Everyone" includes only people. It does not apply to service accounts.
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

    // Once assigned, the audience goes into `aud`.
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
    // What may be done is not included (ADR-0033). If permissions started appearing here, idp would need changes
    // every time an app's permission model is fixed.
    assert!(
        claims.get("perms").is_none_or(Value::is_null),
        "a resource token must not carry perms: {claims}"
    );

    // ⚠ What goes into `aud` must be **the registered spelling**. The collation of `resources.resource_uri` is
    // case-insensitive (`utf8mb4_unicode_ci`), so requests with a different spelling find the same row.
    // Returning the requested spelling as is would fail at resource servers comparing exactly with the registered value.
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
    // `claims` is already bound above, so the function is called by path.
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

    // Audiences of suspended apps are not issued.
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

    // Removing the assignment stops it from the next token (issued ones stay valid until TTL).
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

/// ⚠ Only `client_credentials`-only clients can be assigned as service accounts.
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
    // A client that also has `authorization_code` (usable for login).
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

    // Requests without a kind or with only fields not fitting the kind are 400 too.
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

    // Suspend.
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

    // Identities and assignments are not gone — resuming issues it as is (suspension can be used instead of deletion).
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

    // The admin API `aud` cannot be registered. If it could, admin-addressed tokens without `perms` could be
    // issued to anyone (counterparts looking only at `aud` would let them through).
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

    // Rejecting only exact matches would allow confusing names like `…/admin/`. Everything under the issuer
    // is reserved (not because of present harm, but because there is no reason to lend it).
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

    // As before, clients with permissions get short-lived admin tokens.
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

/// Flips the app state (display name and assignment mode keep their current values).
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

/// ⚠ **Suspending an app also stops the service account of its identity** (ADR-0060).
///
/// - Neither default tokens nor tokens for **other apps' audiences** are issued (`unauthorized_client`)
/// - ⚠ **An admin token is issued, but without permission codes.** Only its own roster (self) passes, and
///   the roster answers "everyone `blocked`" — blocking this would keep RPs from learning of the suspension via periodic reconciliation
/// - Identities, assignments and permission codes are not removed. Resuming restores them as they were
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

    // The identity's app (corresponds to mp3play).
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

    // The using app (corresponds to blobshare). The service account is assigned as a using principal.
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

    // While running, all are issued.
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

    // Suspend the identity's app.
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

    // On resuming, identities, assignments and permission codes come back as they were.
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
