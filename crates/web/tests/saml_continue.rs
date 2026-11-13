//! Behaviour of the SAML SSO continue screen (`GET /{tenant_id}/saml/continue`) when refused by app
//! assignment (ADR-0054; task #66).
//!
//! When the api returns `application_not_permitted`, web **does not render the form auto-POSTing to the ACS**
//! and refuses with the same "use of this app is not permitted" screen as the OIDC route. The progress state is
//! already consumed on the api side, so the `saml_request_id` Cookie is also expired.

mod support;

use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use serde_json::json;
use support::{body_text, get, send, setup};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

#[tokio::test]
async fn a_denied_saml_sign_in_is_told_on_the_assay_screen_not_posted_to_the_sp() {
    let env = setup().await;
    Mock::given(method("POST"))
        .and(path("/internal/saml/resume"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "application_not_permitted",
            "application_name": "Example SAML App",
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        get(&format!("{}/saml/continue?handle=h", env.prefix())),
    )
    .await;

    // 403: we know who it is, but this app cannot be used (same as the OIDC route).
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let saml_cookie = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|raw| raw.contains("saml_request_id="))
        .map(str::to_string)
        .expect("the saml_request_id cookie must be expired");
    assert!(
        saml_cookie.contains("Max-Age=0"),
        "the consumed request's cookie must be expired: {saml_cookie}"
    );
    let body = body_text(response).await;
    assert!(
        body.contains("Example SAML App"),
        "the page must name the application: {body}"
    );
    assert!(
        !body.contains("SAMLResponse"),
        "a denied sign-in must not be posted to the SP: {body}"
    );
    assert!(
        body.contains(&format!("{}/settings", env.prefix())),
        "the page must offer a way back to the account screen: {body}"
    );
}
