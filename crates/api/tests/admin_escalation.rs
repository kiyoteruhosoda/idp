//! Integration tests that fine-grained codes cannot escalate to admin (task #579; high-1 of the 2026-10-20 vulnerability review).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_escalation
//!
//! Fine-grained codes are for "dividing work inside a tenant", and collecting them never reaches
//! `idp.tenant.admin` / `idp.system.admin` (ADR-0037). Previously these three reached it:
//!
//! - (a) `idp.users:write` alone could reissue admins' passwords, reset their MFA and change their profiles
//! - (b) `idp.permissions:write` alone could grant codes the caller did not hold (`idp.tenant.admin` etc.)
//! - (c) `idp.clients:write` alone could grant clients codes the caller did not hold
//!
//! In addition, checks that machines whose job is handling admin accounts (break-glass) can continue
//! as before with `idp.admins:write`.

mod support;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use serde_json::json;
use support::{admin_token, body_json, delete, get, patch, post, post_empty, send, TestEnv};

/// As the root admin (`idp.system.admin`), grants permissions to a user.
async fn grant_user(env: &TestEnv, root_tok: &str, user_id: &str, code: &str) {
    let res = send(
        &env.app,
        post(
            root_tok,
            &format!("/{}/admin/users/{user_id}/permissions", env.root_tenant_id),
            json!({ "permission_code": code }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant {code} to {user_id}");
}

/// Creates a user holding only the given permissions and returns its admin token.
async fn delegate(env: &TestEnv, root_tok: &str, codes: &[&str]) -> (String, String) {
    let user_id = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    for code in codes {
        grant_user(env, root_tok, &user_id, code).await;
    }
    let tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &user_id).await;
    (user_id, tok)
}

/// Creates a system client holding only the given permissions and returns its admin token.
async fn machine(env: &TestEnv, root_tok: &str, codes: &[&str]) -> (String, String) {
    let (client_id, secret) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    for code in codes {
        let res = send(
            &env.app,
            post(
                root_tok,
                &format!(
                    "/{}/admin/clients/{client_id}/permissions",
                    env.root_tenant_id
                ),
                json!({ "permission_code": code }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK, "grant {code} to the machine");
    }
    let resource = format!("{}/{}/admin", env.issuer, env.root_tenant_id);
    let body = format!(
        "grant_type=client_credentials&resource={}",
        percent_encoding::utf8_percent_encode(&resource, percent_encoding::NON_ALPHANUMERIC)
    );
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(format!("/{}/token", env.root_tenant_id))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, format!("Basic {basic}"))
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "machine management token");
    let tok = body_json(res).await["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    (client_id, tok)
}

fn users_uri(env: &TestEnv, user_id: &str, rest: &str) -> String {
    format!("/{}/admin/users/{user_id}{rest}", env.root_tenant_id)
}

/// (a) `idp.users:write` alone cannot handle admin accounts. Ordinary users can be handled as before.
#[tokio::test]
async fn users_writer_cannot_take_over_an_administrator() {
    let Some(env) = support::setup("admin escalation users").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_, writer) = delegate(&env, &root_tok, &["idp.users:write"]).await;
    let (admin_id, _) = delegate(&env, &root_tok, &["idp.tenant.admin"]).await;
    let plain = support::create_plain_user(&env.pool, &env.root_tenant_id).await;

    for target in [admin_id.as_str(), env.root_admin_id.as_str()] {
        for request in [
            post_empty(&writer, &users_uri(&env, target, "/password-reset")),
            post_empty(&writer, &users_uri(&env, target, "/mfa-reset")),
            patch(
                &writer,
                &users_uri(&env, target, "/profile"),
                json!({ "email": format!("taken-{}@example.com", support::unique()) }),
            ),
            patch(
                &writer,
                &users_uri(&env, target, ""),
                json!({ "status": "DISABLED" }),
            ),
            post(
                &writer,
                &users_uri(&env, target, "/login-identifiers"),
                json!({ "identifier_type": "username", "value": format!("x{}", support::unique()) }),
            ),
            delete(&writer, &users_uri(&env, target, "")),
        ] {
            let uri = request.uri().to_string();
            let res = send(&env.app, request).await;
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "{uri}");
        }
    }

    // Ordinary users can be handled as before (a setup link is returned).
    let res = send(
        &env.app,
        post_empty(&writer, &users_uri(&env, &plain, "/password-reset")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "reset a plain user");
    assert!(body_json(res).await["setup_url"].is_string());

    // Admins themselves (idp.tenant.admin) can handle other admins' accounts as before.
    let (_, tenant_admin) = delegate(&env, &root_tok, &["idp.tenant.admin"]).await;
    let res = send(
        &env.app,
        post_empty(&tenant_admin, &users_uri(&env, &admin_id, "/mfa-reset")),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "tenant admin resets an admin's MFA"
    );
    // ⚠ But it does not reach holders of idp.system.admin.
    let res = send(
        &env.app,
        post_empty(
            &tenant_admin,
            &users_uri(&env, &env.root_admin_id, "/password-reset"),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "system admin is out of reach"
    );
}

/// (b) `idp.permissions:write` alone can neither grant nor revoke codes the caller does not hold.
#[tokio::test]
async fn permissions_writer_cannot_grant_what_it_does_not_hold() {
    let Some(env) = support::setup("admin escalation permissions").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (writer_id, writer) = delegate(&env, &root_tok, &["idp.permissions:write"]).await;
    let (admin_id, _) = delegate(&env, &root_tok, &["idp.tenant.admin"]).await;

    for (target, code) in [
        (writer_id.as_str(), "idp.tenant.admin"),
        (writer_id.as_str(), "idp.smtp:write"),
        (writer_id.as_str(), "idp.users:write"),
        (writer_id.as_str(), "idp.admins:write"),
    ] {
        let res = send(
            &env.app,
            post(
                &writer,
                &users_uri(&env, target, "/permissions"),
                json!({ "permission_code": code }),
            ),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "grant {code}");
    }
    let res = send(
        &env.app,
        delete(
            &writer,
            &users_uri(&env, &admin_id, "/permissions/idp.tenant.admin"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "revoke tenant admin");

    // Within what the caller holds (:write includes :read), granting works as before.
    let res = send(
        &env.app,
        post(
            &writer,
            &users_uri(&env, &admin_id, "/permissions"),
            json!({ "permission_code": "idp.permissions:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant a code it implies");

    // Codes that cannot be granted do not appear among the grant form candidates either.
    let res = send(
        &env.app,
        get(
            &writer,
            &format!("/{}/admin/permissions", env.root_tenant_id),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let codes: Vec<String> =
        serde_json::from_value(body_json(res).await["codes"].clone()).expect("codes");
    assert!(
        codes.iter().any(|c| c == "idp.permissions:read"),
        "{codes:?}"
    );
    assert!(!codes.iter().any(|c| c == "idp.tenant.admin"), "{codes:?}");
    assert!(!codes.iter().any(|c| c == "idp.users:write"), "{codes:?}");
}

/// (c) `idp.clients:write` alone cannot grant clients codes the caller does not hold.
#[tokio::test]
async fn clients_writer_cannot_grant_a_client_what_it_does_not_hold() {
    let Some(env) = support::setup("admin escalation clients").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_, writer) = delegate(&env, &root_tok, &["idp.clients:write"]).await;
    let (client_id, _) =
        support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let uri = format!(
        "/{}/admin/clients/{client_id}/permissions",
        env.root_tenant_id
    );

    for code in [
        "idp.users:write",
        "idp.permissions:write",
        "idp.admins:write",
    ] {
        let res = send(
            &env.app,
            post(&writer, &uri, json!({ "permission_code": code })),
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "grant {code} to a client"
        );
    }
    let res = send(
        &env.app,
        post(
            &writer,
            &uri,
            json!({ "permission_code": "idp.clients:read" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant a code it implies");
}

/// `idp.clients:write` alone cannot take over clients holding permissions the caller lacks (task #756).
///
/// Regenerating the secret, replacing the public key or changing the auth method would let one exercise that client's permissions.
/// Deletion uses the same check (aligned with account deletion). ⚠ Clients without permissions are handled as before.
#[tokio::test]
async fn clients_writer_cannot_take_over_a_stronger_client() {
    let Some(env) = support::setup("admin escalation client takeover").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_, writer) = machine(&env, &root_tok, &["idp.clients:write"]).await;

    // A client holding permissions the caller lacks
    let (strong, _) = support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let granted = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{}/admin/clients/{strong}/permissions", env.root_tenant_id),
            json!({ "permission_code": "idp.users:write" }),
        ),
    )
    .await;
    assert_eq!(granted.status(), StatusCode::OK);
    let strong_uri = format!("/{}/admin/clients/{strong}", env.root_tenant_id);

    let rotate = send(
        &env.app,
        post_empty(&writer, &format!("{strong_uri}/secret")),
    )
    .await;
    assert_eq!(rotate.status(), StatusCode::FORBIDDEN, "rotate the secret");
    let swap_key = send(
        &env.app,
        patch(
            &writer,
            &strong_uri,
            json!({
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": "{\"keys\":[]}",
            }),
        ),
    )
    .await;
    assert_eq!(swap_key.status(), StatusCode::FORBIDDEN, "swap the key");
    let removed = send(&env.app, delete(&writer, &strong_uri)).await;
    assert_eq!(removed.status(), StatusCode::FORBIDDEN, "delete");

    // Clients without permissions: as before
    let (plain, _) = support::insert_m2m_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let plain_uri = format!("/{}/admin/clients/{plain}", env.root_tenant_id);
    let rotate = send(
        &env.app,
        post_empty(&writer, &format!("{plain_uri}/secret")),
    )
    .await;
    assert_eq!(rotate.status(), StatusCode::OK, "rotate a plain client");

    // Someone holding the same permissions (here the admin) can handle it
    let rotate = send(
        &env.app,
        post_empty(&root_tok, &format!("{strong_uri}/secret")),
    )
    .await;
    assert_eq!(
        rotate.status(),
        StatusCode::OK,
        "the administrator can still rotate"
    );

    // Other tenants' or nonexistent clients stay 404 (403 would reveal existence)
    let missing = send(
        &env.app,
        post_empty(
            &writer,
            &format!(
                "/{}/admin/clients/no-such-client/secret",
                env.root_tenant_id
            ),
        ),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND, "missing client");
}

/// A break-glass machine (`idp.users:write` + `idp.permissions:write` + `idp.admins:write`) can grant
/// `idp.tenant.admin` to an emergency account and reset its password. ⚠ It does not reach system admins.
#[tokio::test]
async fn admins_write_lets_the_break_glass_machine_keep_working() {
    let Some(env) = support::setup("admin escalation break-glass").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let (_, breakglass) = machine(
        &env,
        &root_tok,
        &[
            "idp.users:write",
            "idp.permissions:write",
            "idp.admins:write",
        ],
    )
    .await;
    let account = support::create_plain_user(&env.pool, &env.root_tenant_id).await;

    // create: grant idp.tenant.admin to the emergency account.
    let res = send(
        &env.app,
        post(
            &breakglass,
            &users_uri(&env, &account, "/permissions"),
            json!({ "permission_code": "idp.tenant.admin" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "grant tenant admin");
    // rotate: reset the password of the emergency account (now an admin) via a setup link.
    let res = send(
        &env.app,
        post_empty(&breakglass, &users_uri(&env, &account, "/password-reset")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "reset an admin account");

    // ⚠ It does not reach system admin accounts or their permissions.
    let res = send(
        &env.app,
        post_empty(
            &breakglass,
            &users_uri(&env, &env.root_admin_id, "/password-reset"),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "system admin account");
    let res = send(
        &env.app,
        post(
            &breakglass,
            &users_uri(&env, &account, "/permissions"),
            json!({ "permission_code": "idp.smtp:write" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "root-only code beyond tenant admin"
    );
}

/// Makes the user an ACTIVE guest of the given tenant with that tenant's permissions (builds the production account shape in the DB).
async fn make_guest_with(env: &TestEnv, user_id: &str, tenant_id: &str, code: &str) {
    sqlx::query(
        "INSERT INTO tenant_memberships (tenant_id, user_id, membership_type, status) \
         VALUES (?, ?, 'GUEST', 'ACTIVE')",
    )
    .bind(tenant_id)
    .bind(user_id)
    .execute(&env.pool)
    .await
    .expect("insert guest membership");
    sqlx::query(
        "INSERT INTO user_permissions (user_id, permission_code, tenant_id) VALUES (?, ?, ?)",
    )
    .bind(user_id)
    .bind(code)
    .bind(tenant_id)
    .execute(&env.pool)
    .await
    .expect("insert guest permission");
}

/// The root admin creates a tenant and returns its ID (the creator becomes that tenant's admin).
async fn create_child_tenant(env: &TestEnv, root_tok: &str) -> String {
    let res = send(
        &env.app,
        post(
            root_tok,
            &format!("/{}/admin/tenants", env.root_tenant_id),
            json!({ "name": format!("child-{}", support::unique()) }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "create child tenant");
    body_json(res).await["id"]
        .as_str()
        .expect("tenant id")
        .to_string()
}

/// A child tenant's admin cannot handle root's guest admin accounts (task #757, ADR-0070).
///
/// Recreating the account would reach root administration, so even the home tenant's admin is refused. ⚠ Guest admins of other
/// child tenants can be handled by their home tenant's admin as before (ADR-0009 §3). With root as the home tenant, root's machine
/// can handle it (the break-glass shape).
#[tokio::test]
async fn a_child_tenant_cannot_take_over_a_guest_administrator_of_the_root() {
    let Some(env) = support::setup("admin escalation root guest").await else {
        return;
    };
    let root_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let child = create_child_tenant(&env, &root_tok).await;
    let other_child = create_child_tenant(&env, &root_tok).await;
    let child_tok = admin_token(&env.app, &env.pool, &child, &env.root_admin_id).await;
    let child_uri = |user: &str, rest: &str| format!("/{child}/admin/users/{user}{rest}");

    let root_guest = support::create_plain_user(&env.pool, &child).await;
    make_guest_with(&env, &root_guest, &env.root_tenant_id, "idp.tenant.admin").await;
    for request in [
        post_empty(&child_tok, &child_uri(&root_guest, "/password-reset")),
        post_empty(&child_tok, &child_uri(&root_guest, "/mfa-reset")),
        patch(
            &child_tok,
            &child_uri(&root_guest, "/profile"),
            json!({ "email": format!("taken-{}@example.com", support::unique()) }),
        ),
        patch(
            &child_tok,
            &child_uri(&root_guest, ""),
            json!({ "status": "DISABLED" }),
        ),
        delete(&child_tok, &child_uri(&root_guest, "")),
    ] {
        let uri = request.uri().to_string();
        let res = send(&env.app, request).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{uri}");
    }

    // Guest admins of other child tenants can be handled by their home tenant's admin as before.
    let child_guest = support::create_plain_user(&env.pool, &child).await;
    make_guest_with(&env, &child_guest, &other_child, "idp.tenant.admin").await;
    let res = send(
        &env.app,
        post_empty(&child_tok, &child_uri(&child_guest, "/password-reset")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "guest of another child");

    // An emergency account homed in root can be handled by root's machine even if it is also a child tenant's guest admin.
    let (_, breakglass) = machine(
        &env,
        &root_tok,
        &[
            "idp.users:write",
            "idp.permissions:write",
            "idp.admins:write",
        ],
    )
    .await;
    let account = support::create_plain_user(&env.pool, &env.root_tenant_id).await;
    grant_user(&env, &root_tok, &account, "idp.tenant.admin").await;
    make_guest_with(&env, &account, &child, "idp.tenant.admin").await;
    let res = send(
        &env.app,
        post_empty(&breakglass, &users_uri(&env, &account, "/password-reset")),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "break-glass homed in root");
}

/// A service account assigned to an app cannot be handled with `idp.clients:write` alone (task #787).
///
/// Replacing its key would reach that app. With `idp.applications:write`, which can decide assignments, it can be handled.
#[tokio::test]
async fn clients_writer_cannot_take_over_a_machine_assigned_to_an_application() {
    let Some(env) = support::setup("admin escalation assigned machine").await else {
        return;
    };
    let tenant = env.root_tenant_id.clone();
    let root_tok = admin_token(&env.app, &env.pool, &tenant, &env.root_admin_id).await;
    let (_, clients_only) = machine(&env, &root_tok, &["idp.clients:write"]).await;
    let (_, with_applications) = machine(
        &env,
        &root_tok,
        &["idp.clients:write", "idp.applications:write"],
    )
    .await;

    let (assigned, _) = support::insert_service_account(&env.pool, &tenant).await;
    let created = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{tenant}/admin/applications"),
            json!({ "display_name": format!("app-{}", support::unique()) }),
        ),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let application = body_json(created).await["id"]
        .as_str()
        .expect("application id")
        .to_string();
    let res = send(
        &env.app,
        post(
            &root_tok,
            &format!("/{tenant}/admin/applications/{application}/assignments"),
            json!({ "kind": "service_account", "client_id": assigned }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "assign");

    let uri = format!("/{tenant}/admin/clients/{assigned}");
    for request in [
        post_empty(&clients_only, &format!("{uri}/secret")),
        patch(&clients_only, &uri, json!({ "app_name": "renamed" })),
        delete(&clients_only, &uri),
    ] {
        let target = request.uri().to_string();
        let res = send(&env.app, request).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{target}");
    }

    // Machines without assignments: as before.
    let (plain, _) = support::insert_service_account(&env.pool, &tenant).await;
    let res = send(
        &env.app,
        patch(
            &clients_only,
            &format!("/{tenant}/admin/clients/{plain}"),
            json!({ "app_name": "renamed" }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "a machine with no assignment");

    // Someone who can decide assignments can handle it.
    let res = send(
        &env.app,
        patch(&with_applications, &uri, json!({ "app_name": "renamed" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "with idp.applications:write");
}
