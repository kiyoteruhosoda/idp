//! Router-level integration tests of the authentication policy admin screen (AP1; built on G11).
//!
//! The key point of this screen is that "api updates **replace all fields**". A condition left out when editing
//! disappears the moment it is saved, so here we stub the api and check with real HTTP bodies that *all conditions
//! appear on screen* and *the submission reaches the api as is*.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use assay_web::csrf::console_csrf_token;
use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_text, get_with_cookies, location, post_form, send, setup, WebEnv};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "admin-session";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    console_csrf_token(SSO, support::TEST_CSRF_SECRET)
}

async fn stub_admin(env: &WebEnv) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin",
            "preferred_username": "admin"
        })))
        .mount(&env.api)
        .await;
}

fn sample_policy() -> Value {
    json!({
        "id": "019f8ea8-f5dd-7fc7-ac15-a7d4337e4610",
        "policy_code": "office-hours",
        "policy_name": "Office hours",
        "priority": 10,
        "enabled": true,
        "effect": "require_specific_method",
        "effect_params": { "methods": ["webauthn"], "user_verification": true },
        "application_ids": ["01990000-0000-7000-8000-00000000000a", "01990000-0000-7000-8000-00000000000b"],
        "user_ids": [],
        "ip_cidrs": ["10.0.0.0/8"],
        "time_windows": [
            { "days": [1, 2, 3, 4, 5], "start_minute": 540, "end_minute": 1080, "utc_offset_minutes": 540 }
        ],
        "requested_acr": [],
        "created_at": "2026-08-10T00:00:00Z",
        "updated_at": "2026-08-10T00:00:00Z"
    })
}

/// Body of the policy **create call** (`None` if it did not arrive).
///
/// Do not simply pick "the first POST" among recorded requests. The admin console layout POSTs
/// `/internal/account/profile` for display, which would be caught instead.
async fn created_policy_body(env: &WebEnv) -> Option<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with("/admin/authentication-policies")
        })
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
}

/// Whether a call rewriting policies (create, update, delete) reached the api.
async fn wrote_a_policy(env: &WebEnv) -> bool {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .any(|r| {
            r.url.path().contains("/admin/authentication-policies")
                && r.method != wiremock::http::Method::GET
        })
}

async fn stub_list(env: &WebEnv, policies: Value) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "policies": policies, "default_effect": "allow" })),
        )
        .mount(&env.api)
        .await;
}

/// Returns only that tenant's list, with the given default effect.
async fn stub_list_for_tenant(env: &WebEnv, tenant: &str, default_effect: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/{tenant}/admin/authentication-policies")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "policies": [], "default_effect": default_effect })),
        )
        .mount(&env.api)
        .await;
}

async fn list_page(env: &WebEnv, tenant: &str) -> String {
    let response = send(
        &env.app,
        get_with_cookies(
            &format!("/{tenant}/admin/authentication-policies"),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    body_text(response).await
}

/// Without the default effect visible, the same "1 deny" cannot be interpreted.
///
/// ⚠ The default effect is **decided by the tenant** (ADR-0058 §4), so web renders not its own setting but the tenant's
/// value carried in the api response. Return different values for 2 tenants and check that each screen shows its own value
/// -- with only 1 tenant, it would pass even if web showed the global startup value (default `allow`).
#[tokio::test]
async fn the_list_shows_the_tenants_own_default_effect_because_a_policy_alone_does_not_decide_anything(
) {
    let env = setup().await;
    stub_admin(&env).await;
    let strict = env.tenant.clone();
    let lenient = uuid::Uuid::now_v7().to_string();
    stub_list_for_tenant(&env, &strict, "deny").await;
    stub_list_for_tenant(&env, &lenient, "allow").await;

    let html = list_page(&env, &strict).await;
    assert!(html.contains("<code>deny</code>"), "strict tenant: {html}");
    assert!(
        !html.contains("<code>allow</code>"),
        "strict tenant: {html}"
    );

    let html = list_page(&env, &lenient).await;
    assert!(
        html.contains("<code>allow</code>"),
        "lenient tenant: {html}"
    );
    assert!(
        !html.contains("<code>deny</code>"),
        "lenient tenant: {html}"
    );
}

/// When the list could not be fetched, the default effect is not shown (with a guessed value, a mismatch with the
/// tenant's actual value would go unnoticed).
#[tokio::test]
async fn the_default_effect_is_not_guessed_when_the_list_fails() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies$"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&env.api)
        .await;

    let html = list_page(&env, &env.tenant).await;
    assert!(!html.contains("<code>allow</code>"), "{html}");
    assert!(!html.contains("<code>deny</code>"), "{html}");
}

#[tokio::test]
async fn editing_prefills_every_condition_so_a_save_cannot_silently_drop_one() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_policy()])).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!(
                "{}/admin/authentication-policies?edit=019f8ea8-f5dd-7fc7-ac15-a7d4337e4610",
                env.prefix()
            ),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;

    assert!(html.contains(r#"value="office-hours""#), "code: {html}");
    assert!(html.contains(r#"value="10""#), "priority: {html}");
    assert!(
        html.contains("01990000-0000-7000-8000-00000000000a\n01990000-0000-7000-8000-00000000000b"),
        "application ids: {html}"
    );
    assert!(html.contains("10.0.0.0/8"), "cidrs: {html}");
    assert!(
        html.contains("mon,tue,wed,thu,fri 09:00-18:00 +09:00"),
        "time window must round-trip into the textarea: {html}"
    );
    // Updates go via a dedicated POST path (HTML forms cannot send PUT).
    assert!(
        html.contains("/admin/authentication-policies/019f8ea8-f5dd-7fc7-ac15-a7d4337e4610/update"),
        "edit form must post to the update path: {html}"
    );
}

#[tokio::test]
async fn creating_a_policy_sends_the_conditions_the_operator_typed() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_policy()))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/authentication-policies", env.prefix()),
            Some(&cookies()),
            &[
                ("policy_code", "office-hours"),
                ("policy_name", "Office hours"),
                ("priority", "10"),
                ("enabled", "1"),
                ("effect", "require_specific_method"),
                ("method_webauthn", "1"),
                ("user_verification", "1"),
                (
                    "application_ids",
                    "01990000-0000-7000-8000-00000000000a\n01990000-0000-7000-8000-00000000000b",
                ),
                ("user_ids", ""),
                ("ip_cidrs", "10.0.0.0/8"),
                ("time_windows", "mon,tue,wed,thu,fri 09:00-18:00 +09:00"),
                ("requested_acr", ""),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        location(&response).ends_with("?saved=1"),
        "{}",
        location(&response)
    );

    let body = created_policy_body(&env)
        .await
        .expect("the create call must reach the api");

    assert_eq!(body["policy_code"], "office-hours");
    assert_eq!(body["priority"], 10);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["effect"], "require_specific_method");
    assert_eq!(body["effect_params"]["methods"], json!(["webauthn"]));
    assert_eq!(body["effect_params"]["user_verification"], true);
    assert_eq!(
        body["application_ids"],
        json!([
            "01990000-0000-7000-8000-00000000000a",
            "01990000-0000-7000-8000-00000000000b"
        ])
    );
    assert_eq!(body["ip_cidrs"], json!(["10.0.0.0/8"]));
    assert_eq!(body["time_windows"][0]["days"], json!([1, 2, 3, 4, 5]));
    assert_eq!(body["time_windows"][0]["start_minute"], 540);
    assert_eq!(body["time_windows"][0]["utc_offset_minutes"], 540);
}

/// web drops the mix-up where a check merely remained after switching the effect
/// (the api rejects requirements sent with anything other than `require_specific_method`).
#[tokio::test]
async fn method_requirements_are_not_sent_for_other_effects() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_policy()))
        .mount(&env.api)
        .await;

    send(
        &env.app,
        post_form(
            &format!("{}/admin/authentication-policies", env.prefix()),
            Some(&cookies()),
            &[
                ("policy_code", "deny-legacy"),
                ("policy_name", "Deny legacy"),
                ("priority", "1"),
                ("effect", "deny"),
                ("method_webauthn", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;

    let body = created_policy_body(&env)
        .await
        .expect("the create call must reach the api");
    assert_eq!(body["effect_params"], Value::Null);
    // Unchecked checkboxes are not submitted = saved as disabled.
    assert_eq!(body["enabled"], false);
}

/// Unreadable time windows are **not saved**. Sending only the readable rows would show "Saved" while the
/// condition you wrote silently disappeared.
#[tokio::test]
async fn an_unreadable_time_window_stops_the_save_and_keeps_the_edit_context() {
    let env = setup().await;
    stub_admin(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!(
                "{}/admin/authentication-policies/019f8ea8-f5dd-7fc7-ac15-a7d4337e4610/update",
                env.prefix()
            ),
            Some(&cookies()),
            &[
                ("policy_code", "office-hours"),
                ("policy_name", "Office hours"),
                ("priority", "10"),
                ("effect", "deny"),
                (
                    "application_ids",
                    "01990000-0000-7000-8000-00000000000a\n01990000-0000-7000-8000-00000000000b",
                ),
                ("time_windows", "mon 09:00-18:00\nnonsense"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        !wrote_a_policy(&env).await,
        "nothing may be written when a condition could not be read"
    );

    // Input is not lost. Do not make users retype everything to fix one field.
    let html = body_text(response).await;
    assert!(
        html.contains(r#"value="office-hours""#),
        "code kept: {html}"
    );
    assert!(
        html.contains("01990000-0000-7000-8000-00000000000a\n01990000-0000-7000-8000-00000000000b"),
        "application ids kept: {html}"
    );
    assert!(
        html.contains("mon 09:00-18:00\nnonsense"),
        "the rejected time windows must stay so the operator can fix them: {html}"
    );
    // Do not lose the edit target (turning into a create form would add another policy).
    assert!(
        html.contains("/admin/authentication-policies/019f8ea8-f5dd-7fc7-ac15-a7d4337e4610/update"),
        "the form must still target the policy being edited: {html}"
    );
}

#[tokio::test]
async fn a_csrf_mismatch_never_reaches_the_api() {
    let env = setup().await;
    stub_admin(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/authentication-policies", env.prefix()),
            Some(&cookies()),
            &[
                ("policy_code", "x"),
                ("policy_name", "x"),
                ("priority", "1"),
                ("effect", "deny"),
                ("csrf_token", "wrong"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        created_policy_body(&env).await.is_none(),
        "a rejected form must not be forwarded"
    );
}

#[tokio::test]
async fn deleting_a_policy_forwards_to_the_api_and_reports_it() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/[^/]+/admin/authentication-policies/[^/]+$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!(
                "{}/admin/authentication-policies/019f8ea8-f5dd-7fc7-ac15-a7d4337e4610/delete",
                env.prefix()
            ),
            Some(&cookies()),
            &[("csrf_token", &csrf())],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).ends_with("?deleted=1"));
}
