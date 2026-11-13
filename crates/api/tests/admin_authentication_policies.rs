//! Integration tests for the auth policy admin API and policy enforcement in the login flow
//! (user authentication / auth policy spec §7–§9, §24).
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test admin_authentication_policies
//!
//! What is checked:
//! - CRUD is protected by `idp.tenant.admin` (401 / 403)
//! - Create, update and delete work, and a duplicate `policy_code` is 409
//! - A matching `deny` policy rejects password login and is recorded in the audit log
//! - A matching `require_mfa` policy without TOTP set up does not complete login (spec §24.4)
//! - Disabled policies are not applied
//! - When an RP requests the reserved `urn:assay:ac:mfa`, MFA applies even with no policies (ADR-0043)

mod support;

use axum::body::Body;

/// Id of a nonexistent app. Used by tests that only look at the condition round trip (save → read → replace)
/// — existence is not checked, so it need not exist.
const LEGACY_APPLICATION_ID: &str = "01990000-0000-7000-8000-00000000beef";

use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use sqlx::{MySqlPool, Row};
use support::{
    admin_token, authorize_uri_openid_only, begin_login, body_json, create_plain_user, delete,
    force_password_change, get, post, put, send, SERVICE_TOKEN, SERVICE_TOKEN_HEADER,
};

/// `/authorize` URI with `acr_values` (mimics an RP sending the reserved value).
fn authorize_uri_with_acr(tenant: &str, client_id: &str, acr_values: &str) -> String {
    format!(
        "{}&acr_values={}",
        authorize_uri_openid_only(tenant, client_id),
        utf8_percent_encode(acr_values, NON_ALPHANUMERIC)
    )
}

fn login_csrf(auth_session: &str, csrf_secret: &[u8; 32]) -> String {
    assay_api::application::login::csrf_token(auth_session, csrf_secret)
}

/// Drives credential verification through api's internal authentication (`POST /internal/authenticate`).
async fn internal_authenticate(
    app: &axum::Router,
    tenant: &str,
    auth_session: &str,
    username: &str,
    password: &str,
    csrf: &str,
) -> Value {
    let body = json!({
        "tenant_id": tenant,
        "auth_session_id": auth_session,
        "username": username,
        "password": password,
        "csrf_token": csrf,
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri("/internal/authenticate")
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "internal authenticate");
    body_json(response).await
}

/// Creates a user by self-registration and completes email verification (so it can sign in).
async fn register_verified_user(
    app: &axum::Router,
    pool: &MySqlPool,
    tenant: &str,
    username: &str,
    password: &str,
) {
    let payload = json!({
        "email": format!("{username}@example.com"),
        "preferred_username": username,
        "password": password,
    });
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/{tenant}/auth/register"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "user registration");
    support::mark_email_verified(pool, tenant, username).await;
}

async fn audit_count(pool: &MySqlPool, event_type: &str, reason_like: &str) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM audit_log WHERE event_type = ? AND reason LIKE ?")
        .bind(event_type)
        .bind(format!("%{reason_like}%"))
        .fetch_one(pool)
        .await
        .expect("count audit")
        .get::<i64, _>("c")
}

#[tokio::test]
async fn admin_can_manage_authentication_policies() {
    let Some(env) = support::setup("authentication policies CRUD").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/authentication-policies", env.root_tenant_id);
    let code = format!("it-deny-{}", support::unique());

    // Unauthenticated (no token) → 401.
    let res = send(
        &env.app,
        Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // User without permission → 403.
    let plain = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain).await;
    let res = send(&env.app, get(&plain_token, &uri)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no permission -> 403");

    // Invalid effect → 400.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "bad effect",
                "priority": 1,
                "effect": "block",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "bad effect -> 400");

    // Create → 200, audited.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "Deny legacy client",
                "priority": 10,
                "effect": "deny",
                "application_ids": [LEGACY_APPLICATION_ID],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create -> 200");
    let created = body_json(res).await;
    assert_eq!(created["effect"], "deny");
    assert_eq!(created["enabled"], true, "enabled defaults to true");
    let policy_id = created["id"].as_str().expect("policy id").to_string();
    assert_eq!(
        audit_count(
            &env.pool,
            "authentication_policy.created",
            &format!("policy={code}")
        )
        .await,
        1
    );

    // Duplicate policy_code → 409.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "duplicate",
                "priority": 20,
                "effect": "allow",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CONFLICT, "duplicate code -> 409");

    // Appears in the list.
    let res = send(&env.app, get(&admin_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let listed = body_json(res).await;
    assert!(
        listed["policies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == json!(policy_id)),
        "created policy is listed: {listed}"
    );

    // Update (replace all fields) → 200, audited.
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("{uri}/{policy_id}"),
            json!({
                "policy_code": code,
                "policy_name": "Require MFA instead",
                "priority": 5,
                "enabled": false,
                "effect": "require_mfa",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "update -> 200");
    let updated = body_json(res).await;
    assert_eq!(updated["effect"], "require_mfa");
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["application_ids"], json!([]), "conditions replaced");
    assert_eq!(
        audit_count(
            &env.pool,
            "authentication_policy.updated",
            &format!("policy={code}")
        )
        .await,
        1
    );

    // Update / delete of a nonexistent ID → 404.
    let ghost = uuid::Uuid::new_v4();
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("{uri}/{ghost}"),
            json!({
                "policy_code": "ghost",
                "policy_name": "ghost",
                "priority": 1,
                "effect": "allow",
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "unknown id -> 404");

    // Delete → 204, disappears from the list, audited.
    let res = send(&env.app, delete(&admin_tok, &format!("{uri}/{policy_id}"))).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "delete -> 204");
    let res = send(&env.app, get(&admin_tok, &uri)).await;
    let listed = body_json(res).await;
    assert!(
        !listed["policies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == json!(policy_id)),
        "deleted policy is gone"
    );
    assert_eq!(
        audit_count(
            &env.pool,
            "authentication_policy.deleted",
            &format!("policy={code}")
        )
        .await,
        1
    );
}

#[tokio::test]
async fn deny_policy_blocks_password_login_until_disabled() {
    let Some(env) = support::setup("deny policy blocks login").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    // The policy target is an app (ADR-0054 decision 5). A client inserted directly has no app, so open it
    // in the migrated shape (one app + one OIDC binding) before using the id.
    let application_id =
        support::open_client_as_application(&env.pool, &env.root_tenant_id, &client_id).await;
    let username = format!("policy-user-{}", support::unique());
    let password = "CorrectHorse9!";
    register_verified_user(
        &env.app,
        &env.pool,
        &env.root_tenant_id,
        &username,
        password,
    )
    .await;

    // Create a deny policy limited to the target app.
    let uri = format!("/{}/admin/authentication-policies", env.root_tenant_id);
    let code = format!("it-deny-login-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "Deny this client",
                "priority": 1,
                "effect": "deny",
                "application_ids": [application_id],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create deny policy");
    let policy_id = body_json(res).await["id"]
        .as_str()
        .expect("policy id")
        .to_string();

    // Even correct credentials are rejected with policy_denied and audited.
    let authorize_uri = authorize_uri_openid_only(&env.root_tenant_id, &client_id);
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(body["result"], "policy_denied", "deny policy wins: {body}");
    assert_eq!(
        audit_count(&env.pool, "login.policy_denied", &format!("policy={code}")).await,
        1
    );

    // Disabling the policy allows login (no matching policy → default allow).
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &format!("{uri}/{policy_id}"),
            json!({
                "policy_code": code,
                "policy_name": "Deny this client",
                "priority": 1,
                "enabled": false,
                "effect": "deny",
                "application_ids": [application_id],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "disable policy");

    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "success",
        "disabled policy is ignored: {body}"
    );
}

#[tokio::test]
async fn require_mfa_policy_blocks_single_factor_login_without_enrollment() {
    let Some(env) = support::setup("require_mfa policy").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let username = format!("mfa-user-{}", support::unique());
    let password = "CorrectHorse9!";
    register_verified_user(
        &env.app,
        &env.pool,
        &env.root_tenant_id,
        &username,
        password,
    )
    .await;

    // Create a require_mfa policy limited to this user.
    let user_id = support::find_user_id_by_username(&env.pool, &env.root_tenant_id, &username)
        .await
        .expect("find user");
    let uri = format!("/{}/admin/authentication-policies", env.root_tenant_id);
    let code = format!("it-mfa-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({
                "policy_code": code,
                "policy_name": "MFA required for this user",
                "priority": 1,
                "effect": "require_mfa",
                "user_ids": [user_id],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create require_mfa policy");

    // TOTP is not set up, so login cannot complete with a single factor (password only) (spec §24.4).
    let authorize_uri = authorize_uri_openid_only(&env.root_tenant_id, &client_id);
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "mfa_enrollment_required",
        "single factor must not complete: {body}"
    );

    // Not applied to users outside the target (conditions are AND, limited by user_ids).
    let other = format!("other-user-{}", support::unique());
    register_verified_user(&env.app, &env.pool, &env.root_tenant_id, &other, password).await;
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &other,
        password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "success",
        "policy is scoped to user: {body}"
    );
}

/// Regression test for a review fix: when a `require_mfa` policy matches a `must_change_password` user
/// (admin-created, password reissued), finishing the forced password change flow issues no SSO or code
/// (without TOTP set up, single-factor completion is refused; spec §24.4).
#[tokio::test]
async fn require_mfa_policy_is_enforced_after_forced_password_change() {
    let Some(env) = support::setup("require_mfa after forced change").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;

    // The admin creates a user (auto-generated password, with must_change_password).
    let username = format!("forced-{}", support::unique());
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/users", env.root_tenant_id),
            json!({
                "email": format!("{username}@example.com"),
                "preferred_username": username,
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "admin creates user");
    let created = body_json(res).await;
    let user_id = created["user_id"].as_str().expect("user id").to_string();
    // ⚠ Neither creation nor reissue returns a password anymore (ADR-0062; the user sets it via the setup link).
    // This test needs "credentials that can sign in with `must_change_password` set", so
    // that state is created directly.
    let generated_password = format!("ForcedChange-{}!", support::unique());
    force_password_change(&env.pool, &user_id, &generated_password).await;

    // Create a require_mfa policy limited to this user.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &format!("/{}/admin/authentication-policies", env.root_tenant_id),
            json!({
                "policy_code": format!("it-forced-mfa-{}", support::unique()),
                "policy_name": "MFA after forced change",
                "priority": 1,
                "effect": "require_mfa",
                "user_ids": [user_id],
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "create policy");

    // Login → password_change_required.
    let authorize_uri = authorize_uri_openid_only(&env.root_tenant_id, &client_id);
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &authorize_uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        &generated_password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "password_change_required",
        "generated password forces change: {body}"
    );
    // `auth_session_id` is regenerated once password verification passes (SEC7). From here on use the new
    // value the response returned (web swaps the cookie too). The CSRF token is re-derived from the new id.
    let auth_session = body["auth_session_id"]
        .as_str()
        .expect("rotated auth_session_id")
        .to_string();
    let csrf = login_csrf(&auth_session, &env.csrf_secret);

    // Even after the forced password change completes, no SSO or code is issued and MFA setup is required.
    let change_body = json!({
        "tenant_id": env.root_tenant_id,
        "auth_session_id": auth_session,
        "current_password": generated_password,
        "new_password": "NewSecurePass9!",
        "csrf_token": csrf,
    });
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri("/internal/change-password")
            .header(CONTENT_TYPE, "application/json")
            .header(SERVICE_TOKEN_HEADER, SERVICE_TOKEN)
            .body(Body::from(change_body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "change password call");
    let body = body_json(res).await;
    assert_eq!(
        body["result"], "mfa_enrollment_required",
        "forced-change flow must not bypass require_mfa: {body}"
    );
}

/// **Unknown keys are not silently dropped.** If a request with a typo in a condition name or an unsupported
/// condition (`country` etc.) returned 200, a policy without that restriction would be saved while the sender
/// believes it narrowed things — for auth policies "configured but not in effect" is the most dangerous failure (ADR-0028).
#[tokio::test]
async fn an_unknown_condition_key_is_rejected_instead_of_being_dropped() {
    let Some(env) = support::setup("auth policy unknown key").await else {
        return;
    };
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    let uri = format!("/{}/admin/authentication-policies", env.root_tenant_id);

    for unknown in [
        // Unsupported condition (decided not to implement; ADR-0028).
        json!({"country": ["JP"]}),
        // Typo of an existing condition. If ignored it becomes "a deny matching every network".
        json!({"ip_cidr": ["10.0.0.0/8"]}),
    ] {
        let mut body = json!({
            "policy_code": format!("unknown-{}", support::unique()),
            "policy_name": "Unknown condition",
            "priority": 10,
            "effect": "deny",
        });
        for (key, value) in unknown.as_object().expect("object") {
            body[key] = value.clone();
        }
        // 422 (rejected by the `Json` extractor). It differs from the nearby "invalid effect → 400" because that one
        // parses and then fails business validation, whereas here **the body cannot be parsed**.
        let res = send(&env.app, post(&admin_tok, &uri, body.clone())).await;
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "an unknown key must not be silently dropped: {body}"
        );
    }

    // Nothing slipped through (the rejected requests created no rows).
    let res = send(&env.app, get(&admin_tok, &uri)).await;
    let listed = body_json(res).await;
    let policies = listed["policies"].as_array().expect("policies");
    assert!(
        !policies.iter().any(|p| p["policy_code"]
            .as_str()
            .is_some_and(|c| c.starts_with("unknown-"))),
        "rejected requests must not create policies: {listed}"
    );
}

/// ADR-0043 decision 1. MFA applies by the reserved value alone, **without creating any policy**.
///
/// Without this, "send this value to get MFA" cannot be published in discovery
/// — a behaviour that only works when the tenant writes a matching policy cannot be communicated to RPs.
#[tokio::test]
async fn the_reserved_acr_value_requires_mfa_without_a_policy() {
    let Some(env) = support::setup("acr_values requires mfa").await else {
        return;
    };
    let client_id =
        support::insert_public_client(&env.pool, &env.root_tenant_id, &["openid"]).await;
    let username = format!("acr-user-{}", support::unique());
    let password = "CorrectHorse9!";
    register_verified_user(
        &env.app,
        &env.pool,
        &env.root_tenant_id,
        &username,
        password,
    )
    .await;

    // Requesting the reserved value prevents users without TOTP from completing with a single factor (same as spec §24.4).
    let uri = authorize_uri_with_acr(&env.root_tenant_id, &client_id, "urn:assay:ac:mfa");
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_eq!(
        body["result"], "mfa_enrollment_required",
        "the reserved word must require MFA on its own: {body}"
    );

    // Unknown values enforce nothing, as before (do not break tenants using their own strings as conditions).
    let uri = authorize_uri_with_acr(&env.root_tenant_id, &client_id, "urn:example:loa2");
    let auth_session = begin_login(&env.app, &env.root_tenant_id, &uri).await;
    let csrf = login_csrf(&auth_session, &env.csrf_secret);
    let body = internal_authenticate(
        &env.app,
        &env.root_tenant_id,
        &auth_session,
        &username,
        password,
        &csrf,
    )
    .await;
    assert_ne!(
        body["result"], "mfa_enrollment_required",
        "an unknown acr value must not require anything: {body}"
    );
}
