//! E2E integration tests for the client (RP) registration and management API (Progress A1, design spec §9.3).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_clients
//!
//! Authorization is by permission code (`idp.clients:read` / `:write`; `idp.tenant.admin` and `idp.system.admin`
//! are allowed by implication; ADR-0037).
//! Creates the SSO session of the initial admin (granted `idp.system.admin` on the root tenant by seed)
//! directly, exchanges it for an admin token and calls the admin API. Also checks users without permission get 403.

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use serde_json::json;
use support::{admin_token, body_json, create_plain_user, delete, get, patch, post, send};

const REDIRECT_URI: &str = "https://app.example.com/callback";

#[tokio::test]
async fn admin_can_manage_clients_but_others_cannot() {
    let Some(env) = support::setup("admin clients").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);

    // Unauthenticated (no token) → 401.
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(&clients_uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(json!({}).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // User without permission → 403.
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(
        &env.app,
        post(
            &plain_token,
            &clients_uri,
            json!({
                "app_name": "X",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // Validation: redirect_uri with a fragment → 400.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "Bad",
                "client_type": "public",
                "redirect_uris": ["https://app.example.com/cb#frag"],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "fragment uri -> 400");

    // Public client registration → 201, no secret.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "Public App",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid", "profile"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "public create -> 201");
    let created = body_json(res).await;
    let public_client_id = created["client_id"].as_str().unwrap().to_string();
    assert!(
        created.get("client_secret").is_none(),
        "public has no secret"
    );
    assert_eq!(created["token_endpoint_auth_method"], "none");

    // Secret reissue for a public client → 400.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{clients_uri}/{public_client_id}/secret"),
            json!({}),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "public secret -> 400"
    );

    // Confidential client registration → 201, plaintext secret included.
    // The default is `private_key_jwt` (ADR-0036), so the method must be explicit to receive a secret.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "Confidential App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "token_endpoint_auth_method": "client_secret_basic",
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "confidential create -> 201"
    );
    let created = body_json(res).await;
    let conf_client_id = created["client_id"].as_str().unwrap().to_string();
    let first_secret = created["client_secret"]
        .as_str()
        .expect("confidential returns secret")
        .to_string();
    assert!(!first_secret.is_empty());
    assert_eq!(created["token_endpoint_auth_method"], "client_secret_basic");

    // The list contains both clients.
    let res = send(&env.app, get(&admin_tok, &clients_uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    // The list returns a paged object (`{clients, total, limit, offset}`) (G7).
    let list = body_json(res).await;
    let ids: Vec<&str> = list["clients"]
        .as_array()
        .expect("clients array")
        .iter()
        .map(|c| c["client_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&public_client_id.as_str()));
    assert!(ids.contains(&conf_client_id.as_str()));

    // Update: status to DISABLED.
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("{clients_uri}/{public_client_id}"),
            json!({ "client_status": "DISABLED" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["client_status"], "DISABLED");

    // Confidential secret reissue → 200, new value (different from the old one).
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{clients_uri}/{conf_client_id}/secret"),
            json!({}),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let rotated = body_json(res).await["client_secret"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!rotated.is_empty());
    assert_ne!(rotated, first_secret, "rotation changes the secret");

    // Fetching a nonexistent one → 404.
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{clients_uri}/does-not-exist")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "missing client -> 404");
}

/// Client authentication methods (G3). Confidential clients can choose `client_secret_post` and switch later.
/// `none` (= no authentication) and setting it on public clients are rejected.
#[tokio::test]
async fn confidential_clients_can_choose_the_client_authentication_method() {
    let Some(env) = support::setup("admin clients auth method").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);

    // client_secret_post can be chosen at registration.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "Post Auth App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "token_endpoint_auth_method": "client_secret_post",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    assert_eq!(created["token_endpoint_auth_method"], "client_secret_post");
    let client_id = created["client_id"].as_str().unwrap().to_string();

    // It can be switched back to client_secret_basic later (secret unchanged; only where it is presented changes).
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("{clients_uri}/{client_id}"),
            json!({ "token_endpoint_auth_method": "client_secret_basic" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        body_json(res).await["token_endpoint_auth_method"],
        "client_secret_basic"
    );

    // `none` cannot be chosen for confidential clients (authentication would be removed while holding a secret).
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("{clients_uri}/{client_id}"),
            json!({ "token_endpoint_auth_method": "none" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Unknown values are rejected too.
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("{clients_uri}/{client_id}"),
            json!({ "token_endpoint_auth_method": "private_key_jwt" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Cannot be set on public clients.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "Public App",
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let public_client_id = body_json(res).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &format!("{clients_uri}/{public_client_id}"),
            json!({ "token_endpoint_auth_method": "client_secret_post" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// `?grant_type=` splits the list by lineage (ADR-0038).
///
/// **Filtering must happen at the same layer as paging.** If web thinned out a page after receiving it,
/// `total` and the pager would not match the real counts. Here we check that both the returned content and
/// `total` are post-filter values.
///
/// ⚠ **Counts inside a dedicated tenant.** Counting in the root tenant piles up clients created by other
/// tests in the same DB, and once they no longer fit on one page (50) `total` and the returned count
/// disagree and the test fails (actually hit; it keeps reproducing until the DB is recreated). With a
/// separate tenant only the 2 this test creates count, so `total` can be **checked against the real number**.
#[tokio::test]
async fn the_client_list_can_be_split_by_grant_type() {
    let Some(env) = support::setup("admin clients grant filter").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("grant-filter-{}", support::unique()) }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "create an isolated tenant"
    );
    let tenant_id = body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string();
    // The creator (root) becomes an ACTIVE GUEST admin of the new tenant (ADR-0009 §4). Admin tokens are
    // per tenant, so get a new one.
    let admin_tok = admin_token(&env.app, &env.pool, &tenant_id, &env.root_admin_id).await;
    let clients_uri = format!("/{tenant_id}/admin/clients");

    // One linked app (has redirect_uri) and one service account (has none).
    for body in [
        json!({
            "app_name": "Relying Party App",
            "client_type": "confidential",
            "redirect_uris": [REDIRECT_URI],
            "scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic",
        }),
        json!({
            "app_name": "Service Account App",
            "client_type": "confidential",
            "redirect_uris": [],
            "scopes": ["openid"],
            "allow_client_credentials": true,
            "token_endpoint_auth_method": "client_secret_basic",
        }),
    ] {
        let res = send(&env.app, post(&admin_tok, &clients_uri, body)).await;
        assert_eq!(res.status(), StatusCode::CREATED);
    }

    let names_for = |uri: String| {
        let app = env.app.clone();
        let tok = admin_tok.clone();
        async move {
            let res = send(&app, get(&tok, &uri)).await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = body_json(res).await;
            let names: Vec<String> = body["clients"]
                .as_array()
                .expect("clients")
                .iter()
                .map(|c| c["app_name"].as_str().unwrap_or_default().to_string())
                .collect();
            (names, body["total"].as_i64().expect("total"))
        }
    };

    let (all, all_total) = names_for(clients_uri.clone()).await;
    assert!(all.iter().any(|n| n == "Relying Party App"));
    assert!(all.iter().any(|n| n == "Service Account App"));

    let (rps, rp_total) = names_for(format!("{clients_uri}?grant_type=authorization_code")).await;
    assert!(rps.iter().any(|n| n == "Relying Party App"));
    assert!(
        !rps.iter().any(|n| n == "Service Account App"),
        "service accounts must not be mixed into the linked app list"
    );

    let (sas, sa_total) = names_for(format!("{clients_uri}?grant_type=client_credentials")).await;
    assert!(sas.iter().any(|n| n == "Service Account App"));
    assert!(!sas.iter().any(|n| n == "Relying Party App"));

    // total is also the post-filter value (the pager shows "Next" based on it). The tenant is separate,
    // so the expected value is exactly "the 2 this test created".
    assert_eq!(
        (all.len(), all_total),
        (2, 2),
        "only the 2 created are visible"
    );
    assert_eq!((rps.len(), rp_total), (1, 1));
    assert_eq!((sas.len(), sa_total), (1, 1));
    assert_eq!(
        rp_total + sa_total,
        all_total,
        "both at once cannot be created, so they split exclusively"
    );

    // Unknown values are 400, not silently ignored. Ignoring them would make a filter failure look like success on screen.
    let res = send(
        &env.app,
        get(&admin_tok, &format!("{clients_uri}?grant_type=nonsense")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// The "both" shape (`authorization_code` + `client_credentials` + redirect_uri) is rejected on both
/// registration and update (ADR-0032 decision 3, Revised).
///
/// ADR-0032 originally had a grace period for `update` — unconditionally rejecting existing rows saved in that
/// shape would make it impossible even to DISABLE a leaked client. The grace was removed on 2026-08-27 because
/// **`delete` does not go through this validation**. Even if such a row appears, e.g. by touching the DB directly,
/// logical deletion can always stop it (ADR-0035; DELETED has `is_active()` false, so authorization and token
/// paths reject it too). Having a way to stop it is the condition for removing the grace, so it is checked here too.
#[tokio::test]
async fn a_dual_usage_client_is_refused_on_update_but_can_still_be_stopped() {
    let Some(env) = support::setup("admin clients dual usage").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    // A shape the api cannot create, so insert it into the DB directly.
    let (client_id, _) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let client_uri = format!("/{}/admin/clients/{client_id}", env.root_tenant_id);

    // Update is rejected (the essence of removing the grace).
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &client_uri,
            json!({ "client_status": "DISABLED" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "an update keeping the dual-purpose shape is not allowed"
    );

    // It can still be stopped. If this stops passing, the grace needs to come back.
    let res = send(&env.app, delete(&admin_tok, &client_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "logical deletion skips the purpose validation, so it can always stop it"
    );

    // Registrations that would make it dual-purpose are rejected too.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": "Both Usages App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "allow_client_credentials": true,
                "token_endpoint_auth_method": "client_secret_basic",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// ADR-0035: deletion is logical. The row remains, but it disappears from the list and admin ops and authorization paths reject it.
#[tokio::test]
async fn a_deleted_client_disappears_from_the_console_but_stays_in_the_database() {
    let Some(env) = support::setup("admin clients delete").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let base = format!("/{}/admin/clients", env.root_tenant_id);

    let created = body_json(
        send(
            &env.app,
            post(
                &admin_tok,
                &base,
                json!({
                    "app_name": "Doomed App",
                    "client_type": "confidential",
                    "redirect_uris": [REDIRECT_URI],
                    "scopes": ["openid"],
                    "token_endpoint_auth_method": "client_secret_basic",
                }),
            ),
        )
        .await,
    )
    .await;
    let client_id = created["client_id"].as_str().expect("client_id");
    let client_uri = format!("{base}/{client_id}");

    // Deletion is done only by the dedicated path. If an update could set the state to DELETED, an irreversible
    // deletion without a `client.deleted` audit record would be possible (ADR-0035).
    let res = send(
        &env.app,
        patch(
            &admin_tok,
            &client_uri,
            json!({ "client_status": "DELETED" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "cannot delete through the update path"
    );

    let res = send(&env.app, delete(&admin_tok, &client_uri)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "admin delete -> 204");

    // Disappears from the list.
    let listed = body_json(send(&env.app, get(&admin_tok, &base)).await).await;
    let ids: Vec<&str> = listed["clients"]
        .as_array()
        .expect("clients")
        .iter()
        .filter_map(|c| c["client_id"].as_str())
        .collect();
    assert!(
        !ids.contains(&client_id),
        "deleted clients are not listed: {ids:?}"
    );

    // Fetch, update and re-delete are all 404 (`load` treats deleted ones as "missing").
    for res in [
        send(&env.app, get(&admin_tok, &client_uri)).await,
        send(
            &env.app,
            patch(&admin_tok, &client_uri, json!({ "app_name": "Revived" })),
        )
        .await,
        send(&env.app, delete(&admin_tok, &client_uri)).await,
    ] {
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    // **The row still exists** (so it can be traced when looking up the client_id in the audit log).
    let status: String =
        sqlx::query_scalar("SELECT client_status FROM clients WHERE client_id = ?")
            .bind(client_id)
            .fetch_one(&env.pool)
            .await
            .expect("row still exists");
    assert_eq!(status, "DELETED");
}

/// ADR-0036: registration without an auth method becomes `private_key_jwt`.
///
/// Deliberately departs from the OIDC Registration 1.0 default (`client_secret_basic`). A default is the
/// value used "when the chooser wrote nothing", so it leans toward public keys rather than a shared secret.
/// Only choosing the weaker one has to be explicit.
#[tokio::test]
async fn omitting_the_authentication_method_registers_a_private_key_jwt_client() {
    let Some(env) = support::setup("admin clients default auth method").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let clients_uri = format!("/{}/admin/clients", env.root_tenant_id);

    // Registration with neither method nor verification key is rejected. Since the default is `private_key_jwt`,
    // letting it through would create "a client that cannot authenticate with any credential".
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "No Method App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // The body even says what the default is. "A verification key is required" alone would not explain
    // the reason to a caller who does not remember writing `private_key_jwt`.
    let message = body_json(res).await["message"]
        .as_str()
        .expect("message")
        .to_string();
    assert!(
        message.contains("token_endpoint_auth_method") && message.contains("private_key_jwt"),
        "the default and the omitted field name are missing from the body: {message}"
    );

    // Sending only a verification key registers as `private_key_jwt` without writing the method.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &clients_uri,
            json!({
                "app_name": "Default Method App",
                "client_type": "confidential",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
                "jwks": support::sample_client_jwks(),
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    assert_eq!(created["token_endpoint_auth_method"], "private_key_jwt");
    // Clients with this method hold no shared secret (ADR-0030).
    assert!(
        created["client_secret"].is_null(),
        "private_key_jwt issued a secret: {created}"
    );
}
