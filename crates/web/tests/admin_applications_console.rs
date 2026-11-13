//! Runs moving identities and deleting on the app screen **through the router** (api replaced by wiremock; ADR-0067).
//!
//! Three key points:
//!
//! - ⚠ **When another app's identity is chosen, do not send immediately.** Show a "move from X" confirmation, and only
//!   when resent from the confirmation, ask the api naming the source (the api detaches + binds in one go)
//! - A counterpart belonging nowhere is bound directly without confirmation
//! - "Delete this app" goes to the api's DELETE and returns to the list

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use assay_web::csrf::console_csrf_token;
use axum::http::StatusCode;
use serde_json::{json, Value};
use support::{body_text, location, post_form, send, setup, WebEnv};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "admin-session";
const APP_ID: &str = "app-1";
const OWNER_ID: &str = "app-auto";

fn cookies() -> String {
    format!("{SSO_SESSION_COOKIE}={SSO}")
}

fn csrf() -> String {
    console_csrf_token(SSO, support::TEST_CSRF_SECRET)
}

fn application() -> Value {
    json!({
        "id": APP_ID,
        "display_name": "wiki",
        "status": "ACTIVE",
        "assignment_mode": "INDIVIDUAL",
        "bindings": [],
        "assigned_count": 0,
        "created_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z"
    })
}

async fn stub(env: &WebEnv) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })))
        .mount(&env.api)
        .await;
    let mut detail = application();
    detail["assigned"] = json!([]);
    detail["assigned_service_accounts"] = json!([]);
    detail["enforcement"] = json!("enforce");
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/applications/app-1$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/[^/]+/admin/applications/app-1/binding-candidates$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [
                {
                    "kind": "oidc",
                    "reference": "wiki-login",
                    "identifier": "wiki-login",
                    "display_name": "wiki",
                    "application_id": OWNER_ID,
                    "application_name": "wiki（自動）"
                },
                {
                    "kind": "resource",
                    "reference": "api://wiki",
                    "identifier": "api://wiki",
                    "display_name": "wiki API",
                    "application_id": null,
                    "application_name": null
                }
            ]
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/applications/app-1/bindings$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(application()))
        .mount(&env.api)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/[^/]+/admin/applications/app-1$"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&env.api)
        .await;
}

/// Body of the add-identity request that reached the api.
async fn bind_requests(env: &WebEnv) -> Vec<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.url.path().ends_with("/bindings") && r.method == wiremock::http::Method::POST)
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
        .collect()
}

#[tokio::test]
async fn a_target_owned_by_another_application_is_moved_only_after_confirmation() {
    let env = setup().await;
    stub(&env).await;
    let uri = format!("{}/admin/applications/{APP_ID}/bind", env.prefix());

    // 1st: choose a counterpart that has an owner -> confirmation screen. Nothing is sent to the api yet.
    let response = send(
        &env.app,
        post_form(
            &uri,
            Some(&cookies()),
            &[("csrf_token", &csrf()), ("candidate", "oidc:wiki-login")],
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a confirmation, not a redirect"
    );
    let html = body_text(response).await;
    assert!(html.contains("「wiki（自動）」から移しますか？"), "{html}");
    assert!(
        html.contains(&format!(r#"name="move_from" value="{OWNER_ID}""#)),
        "{html}"
    );
    assert!(
        bind_requests(&env).await.is_empty(),
        "nothing is moved before the confirmation"
    );

    // 2nd: resend from the confirmation -> to the api, naming the source.
    let response = send(
        &env.app,
        post_form(
            &uri,
            Some(&cookies()),
            &[
                ("csrf_token", &csrf()),
                ("candidate", "oidc:wiki-login"),
                ("move_from", OWNER_ID),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/admin/applications/{APP_ID}", env.prefix())
    );
    let sent = bind_requests(&env).await;
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        sent[0],
        json!({
            "kind": "oidc",
            "client_id": "wiki-login",
            "move_from_application_id": OWNER_ID,
        })
    );
}

#[tokio::test]
async fn a_free_target_is_bound_without_a_confirmation() {
    let env = setup().await;
    stub(&env).await;
    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/applications/{APP_ID}/bind", env.prefix()),
            Some(&cookies()),
            &[
                ("csrf_token", &csrf()),
                ("candidate", "resource:api://wiki"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let sent = bind_requests(&env).await;
    assert_eq!(
        sent,
        vec![json!({ "kind": "resource", "resource_uri": "api://wiki" })],
        "a URI containing ':' survives the choice value"
    );
}

#[tokio::test]
async fn deleting_an_application_goes_to_the_api_and_back_to_the_list() {
    let env = setup().await;
    stub(&env).await;

    // Before deleting, the detail screen shows "what gets detached" and the delete button.
    let response = send(
        &env.app,
        support::get_with_cookies(
            &format!("{}/admin/applications/{APP_ID}", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains("このアプリには名乗りも使う主体もありません。"),
        "{html}"
    );
    assert!(html.contains("/admin/applications/app-1/delete"), "{html}");

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/applications/{APP_ID}/delete", env.prefix()),
            Some(&cookies()),
            &[("csrf_token", &csrf())],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("{}/admin/applications", env.prefix())
    );
    let deletes = env
        .api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .filter(|r| r.method == wiremock::http::Method::DELETE)
        .count();
    assert_eq!(deletes, 1, "the api's DELETE is called once");
}
