//! E2E integration tests for the app admin API (ADR-0054).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_applications
//!
//! Authorization is by permission code (`idp.applications:read` / `:write`; `idp.tenant.admin` and `idp.system.admin`
//! are allowed by implication; ADR-0037).

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{admin_token, body_json, create_plain_user, delete, get, post, put, send};

const REDIRECT_URI: &str = "https://app.example.com/callback";

#[tokio::test]
async fn admin_can_manage_applications_but_others_cannot() {
    let Some(env) = support::setup("admin applications").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/applications", env.root_tenant_id);

    // User without permission → 403.
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(&env.app, get(&plain_token, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // Register. ⚠ The default is "Individual", and the creator is put in the roster (decision 3).
    let name = format!("app-{}", support::unique());
    let res = send(
        &env.app,
        post(&admin_tok, &uri, json!({ "display_name": name })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create -> 201");
    let created = body_json(res).await;
    assert_eq!(
        created["assignment_mode"], "INDIVIDUAL",
        "default is Individual"
    );
    assert_eq!(created["status"], "ACTIVE");
    assert_eq!(
        created["assigned_count"], 1,
        "the creator is assigned so they are not locked out: {created}"
    );
    let application_id = created["id"].as_str().expect("id").to_string();

    // The roster appears in the details.
    let detail_uri = format!("{uri}/{application_id}");
    let detail = body_json(send(&env.app, get(&admin_tok, &detail_uri)).await).await;
    assert_eq!(detail["assigned"].as_array().unwrap().len(), 1);
    assert_eq!(detail["assigned"][0]["user_id"], json!(env.root_admin_id));

    // It appears in the list, with the current decision stage attached.
    let listed = body_json(send(&env.app, get(&admin_tok, &uri)).await).await;
    assert_eq!(
        listed["enforcement"], "record_only",
        "the gate starts out recording only: {listed}"
    );
    assert!(listed["applications"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["id"] == json!(application_id)));

    // Connect an OIDC linked app.
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{detail_uri}/bindings"),
            json!({ "kind": "oidc", "client_id": client_id }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "bind -> 200");
    let bound = body_json(res).await;
    assert_eq!(bound["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(bound["bindings"][0]["kind"], "oidc");
    assert_eq!(bound["bindings"][0]["identifier"], json!(client_id));

    // ⚠ One linked app belongs to only one app. Connecting it to a second app is 409.
    let other = body_json(
        send(
            &env.app,
            post(
                &admin_tok,
                &uri,
                json!({ "display_name": format!("other-{}", support::unique()) }),
            ),
        )
        .await,
    )
    .await;
    let other_id = other["id"].as_str().expect("id").to_string();
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{uri}/{other_id}/bindings"),
            json!({ "kind": "oidc", "client_id": client_id }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a client belongs to one application"
    );
    let refusal = body_json(res).await;
    assert!(
        refusal["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&name),
        "the refusal names the application that owns it: {refusal}"
    );

    // ⚠ A request without a kind is 400 (no default kind).
    let res = send(
        &env.app,
        post(&admin_tok, &format!("{detail_uri}/bindings"), json!({})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "no target -> 400");

    // Adding and removing assignments.
    let member_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let assigned = body_json(
        send(
            &env.app,
            post(
                &admin_tok,
                &format!("{detail_uri}/assignments"),
                json!({ "kind": "user", "user_id": member_id }),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(assigned["assigned"].as_array().unwrap().len(), 2);
    let res = send(
        &env.app,
        delete(
            &admin_tok,
            &format!("{detail_uri}/assignments/users/{member_id}"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "unassign -> 204");

    // Switching to "Everyone" lets us fetch the people currently included (the tenant's members).
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &detail_uri,
            json!({
                "display_name": name,
                "status": "ACTIVE",
                "assignment_mode": "EVERYONE",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "update -> 200");
    let current = body_json(
        send(
            &env.app,
            get(&admin_tok, &format!("{detail_uri}/current-users")),
        )
        .await,
    )
    .await;
    assert!(
        current["total"].as_i64().unwrap() >= 1,
        "everyone mode lists the tenant's members: {current}"
    );

    // Deleting it keeps the registration of the connected linked app (an app is a grouping, not a connection method).
    let res = send(&env.app, delete(&admin_tok, &detail_uri)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "delete -> 204");
    let res = send(&env.app, get(&admin_tok, &detail_uri)).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "deleted -> 404");
    let clients = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{}/admin/clients", env.root_tenant_id),
            ),
        )
        .await,
    )
    .await;
    assert!(
        clients["clients"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["client_id"] == json!(client_id)),
        "the relying party survives its application: {clients}"
    );
}

/// ⚠ A registered linked app is opened as an app on the spot (ADR-0054 decision 7).
/// Otherwise a merely registered RP would stay **open to everyone**, and that would show nowhere on screen.
#[tokio::test]
async fn registering_a_relying_party_opens_it_as_an_application() {
    let Some(env) = support::setup("register opens an application").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let app_name = format!("rp-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": app_name,
                "client_type": "public",
                "redirect_uris": [REDIRECT_URI],
                "scopes": ["openid"],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register -> 201");
    let client_id = body_json(res).await["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();

    let listed = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{}/admin/applications", env.root_tenant_id),
            ),
        )
        .await,
    )
    .await;
    let opened = listed["applications"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| {
            a["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b["identifier"] == json!(client_id))
        })
        .unwrap_or_else(|| panic!("the registered client must have an application: {listed}"))
        .clone();
    assert_eq!(opened["display_name"], json!(app_name));
    // ⚠ The default is "Individual", so forgetting to narrow it down does not leave it open to everyone.
    assert_eq!(opened["assignment_mode"], "INDIVIDUAL");
    // ⚠ The registrant is put in the roster (so the app is not left with nobody able to enter right after).
    assert_eq!(opened["assigned_count"], 1);
}

/// No app is created for service accounts (`client_credentials`; ADR-0038)
/// — no users enter and no decision runs, so it would just list apps with empty rosters.
#[tokio::test]
async fn a_service_account_does_not_get_an_application() {
    let Some(env) = support::setup("service account without an application").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let app_name = format!("machine-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/clients", env.root_tenant_id),
            json!({
                "app_name": app_name,
                "client_type": "confidential",
                "redirect_uris": [],
                "scopes": ["openid"],
                "allow_client_credentials": true,
                "token_endpoint_auth_method": "client_secret_basic",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register -> 201");

    let listed = body_json(
        send(
            &env.app,
            get(
                &admin_tok,
                &format!("/{}/admin/applications", env.root_tenant_id),
            ),
        )
        .await,
    )
    .await;
    assert!(
        !listed["applications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["display_name"] == json!(app_name)),
        "a service account has no users to admit: {listed}"
    );
}

/// Matches the identity kind against the counterpart's nature (ADR-0059).
///
/// - Only `client_credentials`-only clients can be bound as service accounts
/// - Only `authorization_code` clients can be bound as login identities
/// - Audiences are addressed by URI. Each belongs to only one app
#[tokio::test]
async fn binding_kinds_must_match_what_the_target_is() {
    let Some(env) = support::setup("application binding kinds").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/applications", env.root_tenant_id);
    let create = |name: String| {
        let admin_tok = admin_tok.clone();
        let uri = uri.clone();
        let app = env.app.clone();
        async move {
            body_json(
                send(
                    &app,
                    post(&admin_tok, &uri, json!({ "display_name": name })),
                )
                .await,
            )
            .await["id"]
                .as_str()
                .expect("id")
                .to_string()
        }
    };
    let application_id = create(format!("wiki-{}", support::unique())).await;
    let bindings_uri = format!("{uri}/{application_id}/bindings");

    let (service_account, _) =
        support::insert_service_account(&env.pool, &env.root_tenant_id).await;
    let login_client =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    // ⚠ Do not bind a login client as a service account (a user's token could read self).
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "service_account", "client_id": login_client }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "login client as a service account"
    );

    // ⚠ Do not bind a service account as a login identity (it would fall outside the login decision).
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "oidc", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "service account as a login"
    );

    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "service_account", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "service account -> 200");
    let bound = body_json(res).await;
    assert!(
        bound["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["kind"] == "service_account" && b["identifier"] == json!(service_account)),
        "{bound}"
    );

    // Binding to the same app again is idempotent. To another app it is 409.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "service_account", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "same application -> idempotent"
    );
    let other_id = create(format!("other-{}", support::unique())).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{uri}/{other_id}/bindings"),
            json!({ "kind": "service_account", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a service account belongs to one application"
    );

    // Audiences are addressed by URI.
    let resource_uri = format!("https://api-{}.example.com", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/resources", env.root_tenant_id),
            json!({ "resource_uri": resource_uri, "display_name": "wiki API" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "register resource");
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "resource", "resource_uri": resource_uri }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "resource -> 200");
    let bound = body_json(res).await;
    assert!(
        bound["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["kind"] == "resource" && b["identifier"] == json!(resource_uri)),
        "{bound}"
    );
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{uri}/{other_id}/bindings"),
            json!({ "kind": "resource", "resource_uri": resource_uri }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "a resource belongs to one application"
    );

    // Requests with an unknown kind or only fields that do not fit the kind are 400.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "machine", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "unknown kind");
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "resource", "client_id": service_account }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "wrong field for the kind"
    );
}

/// Identity candidates and moving from another app (ADR-0067).
///
/// - Candidates are only those fitting the kind, with **which app they currently identify** attached
/// - Those already identities of this app do not appear as candidates
/// - Naming the source app does unbind + bind in one go. If the named one differs from the current owner it stays 409
/// - The audit is one `application_binding.moved` row with both the source and destination
#[tokio::test]
async fn candidates_name_their_current_application_and_a_binding_can_be_moved() {
    let Some(env) = support::setup("application binding candidates").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/applications", env.root_tenant_id);
    let create = |name: String| {
        let admin_tok = admin_tok.clone();
        let uri = uri.clone();
        let app = env.app.clone();
        async move {
            body_json(
                send(
                    &app,
                    post(&admin_tok, &uri, json!({ "display_name": name })),
                )
                .await,
            )
            .await["id"]
                .as_str()
                .expect("id")
                .to_string()
        }
    };
    let source_name = format!("auto-{}", support::unique());
    let source_id = create(source_name.clone()).await;
    let target_id = create(format!("wiki-{}", support::unique())).await;
    let decoy_id = create(format!("decoy-{}", support::unique())).await;

    let login_client =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let (service_account, _) =
        support::insert_service_account(&env.pool, &env.root_tenant_id).await;
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("{uri}/{source_id}/bindings"),
            json!({ "kind": "oidc", "client_id": login_client }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "bind to the source");

    // Users without permission are not shown candidates (same permission as app details).
    let candidates_uri = format!("{uri}/{target_id}/binding-candidates");
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(&env.app, get(&plain_token, &candidates_uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    let listed = body_json(send(&env.app, get(&admin_tok, &candidates_uri)).await).await;
    let candidates = listed["candidates"].as_array().expect("candidates");
    let login = candidates
        .iter()
        .find(|c| c["identifier"] == json!(login_client))
        .unwrap_or_else(|| panic!("the login client is a candidate: {listed}"));
    assert_eq!(login["kind"], "oidc");
    assert_eq!(login["reference"], json!(login_client));
    assert_eq!(
        login["application_id"],
        json!(source_id),
        "the candidate names the application that owns it: {listed}"
    );
    assert_eq!(login["application_name"], json!(source_name));
    let machine = candidates
        .iter()
        .find(|c| c["identifier"] == json!(service_account))
        .unwrap_or_else(|| panic!("the service account is a candidate: {listed}"));
    // ⚠ Service accounts are not offered as login identities (kind matching is the same as binding).
    assert_eq!(machine["kind"], "service_account");
    assert!(machine["application_id"].is_null(), "{listed}");

    // Without naming it stays 409 (no silent takeover).
    let bindings_uri = format!("{uri}/{target_id}/bindings");
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({ "kind": "oidc", "client_id": login_client }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT, "no move_from -> 409");

    // ⚠ If the named one differs from the current owner, 409 (no taking from an unverified app).
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({
                "kind": "oidc",
                "client_id": login_client,
                "move_from_application_id": decoy_id,
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT, "wrong owner -> 409");
    let refusal = body_json(res).await;
    assert!(
        refusal["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&source_name),
        "the refusal names the real owner: {refusal}"
    );

    // Naming the current owner moves it in one go.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &bindings_uri,
            json!({
                "kind": "oidc",
                "client_id": login_client,
                "move_from_application_id": source_id,
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "move -> 200");
    let moved = body_json(res).await;
    assert!(
        moved["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["kind"] == "oidc" && b["identifier"] == json!(login_client)),
        "the target now has the binding: {moved}"
    );
    let source =
        body_json(send(&env.app, get(&admin_tok, &format!("{uri}/{source_id}"))).await).await;
    assert!(
        source["bindings"].as_array().unwrap().is_empty(),
        "the source lost the binding: {source}"
    );

    // The login decision is also looked up on the destination app (counterpart → app resolution returns the new owner).
    let owner: String = sqlx::query_scalar(
        "SELECT b.application_id FROM application_bindings b JOIN clients c ON c.id = b.client_id \
         WHERE c.client_id = ? AND b.kind = 'oidc'",
    )
    .bind(&login_client)
    .fetch_one(&env.pool)
    .await
    .expect("binding row");
    assert_eq!(owner, target_id);

    // What became this app's identity disappears from this app's candidates.
    let listed = body_json(send(&env.app, get(&admin_tok, &candidates_uri)).await).await;
    assert!(
        !listed["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["identifier"] == json!(login_client)),
        "already bound here: {listed}"
    );

    // The audit is one row showing both the source and the destination.
    let reasons: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT reason FROM audit_log WHERE event_type = 'application_binding.moved' \
         AND reason LIKE ? ORDER BY id",
    )
    .bind(format!("%from_application={source_id}%"))
    .fetch_all(&env.pool)
    .await
    .expect("read audit");
    assert_eq!(reasons.len(), 1, "one audit row for one move: {reasons:?}");
    let reason = reasons[0].clone().unwrap_or_default();
    assert!(
        reason.contains(&format!("application={target_id}")),
        "{reason}"
    );
    assert!(
        reason.contains(&format!("target={login_client}")),
        "{reason}"
    );

    // The emptied source app can be deleted (the identity's counterpart is not deleted).
    let res = send(&env.app, delete(&admin_tok, &format!("{uri}/{source_id}"))).await;
    assert_eq!(
        res.status(),
        StatusCode::NO_CONTENT,
        "delete the emptied application"
    );
}
