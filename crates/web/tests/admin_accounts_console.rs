//! Runs the account list and single-item screens (people, service accounts) **through the router** (api replaced by wiremock).
//!
//! ⚠ **Rendering unit tests alone were not enough.** Tests rendering templates directly passed while
//! the real route returned 500 (caught by E2E). Unless the wiring between handlers and the api client is
//! exercised, the same kind of oversight repeats.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get_with_cookies, send, setup};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const USER_ID: &str = "11111111-1111-1111-1111-111111111111";
const CLIENT_ID: &str = "c0ffee";

async fn stub_admin(env: &support::WebEnv) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/whoami$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "00000000-0000-7000-8000-000000000001",
            "name": "Admin User",
            "preferred_username": "admin",
            "permissions": ["idp.tenant.admin"]
        })))
        .mount(&env.api)
        .await;
}

fn member() -> serde_json::Value {
    json!({
        "user_id": USER_ID,
        "email": "u@example.com",
        "preferred_username": "u",
        "name": null,
        "membership_type": "HOME",
        "status": "ACTIVE",
        "user_status": "ACTIVE",
        "locked": false
    })
}

fn service_account() -> serde_json::Value {
    json!({
        "client_id": CLIENT_ID,
        "app_name": "夜間同期",
        "status": "ACTIVE",
        "created_at": "2026-09-25T00:00:00Z",
        "note": { "text": "経緯のメモ", "updated_at": "2026-09-25T00:00:00Z" }
    })
}

/// The list is where you find. People and service accounts are in one list, and each row leads to its single-item screen
/// (ADR-0065).
#[tokio::test]
async fn the_account_list_renders_both_kinds_and_links_into_each() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/accounts$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accounts": [
                { "kind": "user", "user": member() },
                { "kind": "service_account", "service_account": service_account() }
            ],
            "kinds": ["user", "service_account"],
            "readable_kinds": ["user", "service_account"],
            "total": 2, "limit": 50, "offset": 0
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/accounts", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "account list does not render"
    );
    let html = body_text(response).await;
    assert!(
        html.contains(&format!("{}/admin/members/{USER_ID}", env.prefix())),
        "list has no link to the single-person screen: {html}"
    );
    assert!(
        html.contains(&format!(
            "{}/admin/service-accounts/{CLIENT_ID}",
            env.prefix()
        )),
        "list has no link to the service account screen: {html}"
    );
}

/// The old member list redirects to the account list filtered to people (do not break bookmarks).
#[tokio::test]
async fn the_old_member_list_forwards_to_the_account_list() {
    let env = setup().await;
    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members?q=abc", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        location,
        format!("{}/admin/accounts?kind=user&q=abc", env.prefix())
    );
}

/// Renders a single service account screen **through the router** (exercises the wiring of 5 api calls).
#[tokio::test]
async fn the_service_account_page_renders_the_same_cards_as_a_member() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/service-accounts/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(service_account()))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"^/[^/]+/admin/service-accounts/[^/]+/applications$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "applications": [], "enforcement": "enforce"
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/clients/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "0197", "client_id": CLIENT_ID, "client_type": "confidential",
            "client_status": "ACTIVE", "app_name": "夜間同期", "redirect_uris": [],
            "grant_types": ["client_credentials"], "response_types": [], "scopes": ["openid"],
            "token_endpoint_auth_method": "client_secret_basic",
            "created_at": "2026-09-25T00:00:00Z", "updated_at": "2026-09-25T00:00:00Z"
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/clients/[^/]+/permissions$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "client_id": CLIENT_ID, "permission_codes": []
        })))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/permissions$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "codes": ["idp.members:read"]
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/service-accounts/{CLIENT_ID}", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    let st = response.status();
    let html = body_text(response).await;
    assert_eq!(st, StatusCode::OK, "{}", &html[..html.len().min(900)]);
    let base = format!("{}/admin/service-accounts/{CLIENT_ID}", env.prefix());
    assert!(
        html.contains(&format!("{base}/note")),
        "note section is missing: {html}"
    );
    assert!(html.contains("経緯のメモ"), "{html}");
    assert!(
        html.contains(&format!(
            "{}/admin/clients/{CLIENT_ID}/delete",
            env.prefix()
        )),
        "{html}"
    );
}

/// ⚠ **This used to return 500.** The route has two params, `{tenant_id}` and `{user_id}`, but
/// the api side took a single `Path<Uuid>` and got the leading tenant ID.
#[tokio::test]
async fn the_member_page_renders_the_actions() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/members/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(member()))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members/{USER_ID}", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    let st = response.status();
    let html = body_text(response).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "single-person screen does not render: {}",
        &html[..html.len().min(900)]
    );
    for action in ["reset-mfa", "reset-password", "reissue-tokens", "delete"] {
        assert!(
            html.contains(&format!(
                "{}/admin/members/{USER_ID}/{action}",
                env.prefix()
            )),
            "{action} is not shown: {html}"
        );
    }
}

/// Non-members are sent back to the list (do not let others infer the existence of members of other tenants).
#[tokio::test]
async fn an_unknown_member_goes_back_to_the_list() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/members/[^/]+$"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members/{USER_ID}", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND, "not redirected");
}

/// task #83: the single-person screen fetches the api's `active-tokens` and shows the number of currently valid refresh tokens.
/// Guests can only be counted by admins of their home tenant (the api returns 404), so it does not ask at all.
#[tokio::test]
async fn the_member_page_shows_the_active_token_count_for_home_members_only() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/members/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(member()))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/users/[^/]+/active-tokens$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": USER_ID,
            "active_refresh_tokens": 2
        })))
        .expect(1)
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members/{USER_ID}", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    let st = response.status();
    let html = body_text(response).await;
    assert_eq!(st, StatusCode::OK, "{}", &html[..html.len().min(900)]);
    assert!(
        html.contains("data-active-refresh-tokens=\"2\""),
        "token count is not shown: {html}"
    );
}

#[tokio::test]
async fn the_guest_member_page_does_not_ask_for_the_token_count() {
    let env = setup().await;
    stub_admin(&env).await;
    let mut guest = member();
    guest["membership_type"] = json!("GUEST");
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/members/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(guest))
        .mount(&env.api)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/users/[^/]+/active-tokens$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": USER_ID,
            "active_refresh_tokens": 2
        })))
        .expect(0)
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/members/{USER_ID}", env.prefix()),
            &format!("{SSO_SESSION_COOKIE}=s"),
        ),
    )
    .await;
    let st = response.status();
    let html = body_text(response).await;
    assert_eq!(st, StatusCode::OK, "{}", &html[..html.len().min(900)]);
    assert!(!html.contains("data-active-refresh-tokens"), "{html}");
}
