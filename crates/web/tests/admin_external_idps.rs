//! Router-level integration tests of the external IdP settings screen (AP16; built on G11; SAML support is AP12).
//!
//! The key point of this screen is **handling the client secret**. The api does not return secrets, so
//! the edit form cannot show the current value and the meaning of a blank must be decided. Here we stub the api and
//! check with the actual HTTP body that "blank = unchanged" holds.
//! If this breaks, merely fixing the display name breaks the link with the external IdP.
//!
//! The other key point is **splitting by protocol**. OIDC and SAML need completely different fields, and
//! even if the api accepted a mixed configuration, the error would stay hidden until sign-in.

mod support;

use assay_contracts::cookies::SSO_SESSION_COOKIE;
use assay_web::csrf::console_csrf_token;
use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE};
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use support::{body_text, get_with_cookies, post_form, send, setup, WebEnv};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, ResponseTemplate};

const SSO: &str = "admin-session";
const PROVIDER_ID: &str = "019f8ea8-f5dd-7fc7-ac15-a7d4337e4611";
const SAML_PROVIDER_ID: &str = "019f8ea8-f5dd-7fc7-ac15-a7d4337e4612";

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

fn sample_provider() -> Value {
    json!({
        "id": PROVIDER_ID,
        "provider_code": "corp",
        "display_name": "Corp IdP",
        "issuer": "https://idp.example.com",
        "protocol": "oidc",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
        "client_id": "abc",
        "has_client_secret": true,
        "scopes": ["openid", "email"],
        "enabled": true,
        "allow_auto_link": false,
        "redirect_uri": "https://web.example.com/external/corp/callback",
        "created_at": "2026-08-10T00:00:00Z",
        "updated_at": "2026-08-10T00:00:00Z"
    })
}

/// A SAML provider. The api returns **fields of the unused protocol as `null`** (ADR-0027).
fn sample_saml_provider() -> Value {
    json!({
        "id": SAML_PROVIDER_ID,
        "provider_code": "corp-saml",
        "display_name": "Corp SAML",
        "issuer": "urn:idp:corp",
        "protocol": "saml",
        "authorization_endpoint": Value::Null,
        "token_endpoint": Value::Null,
        "jwks_uri": Value::Null,
        "client_id": Value::Null,
        "has_client_secret": false,
        "scopes": [],
        "saml_sso_url": "https://idp.example.com/sso",
        "saml_certificates": ["MIIBCURRENT==", "MIIBNEXT=="],
        "saml_name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "saml_sp_entity_id": "https://web.example.com/t/saml/sp",
        "saml_acs_url": "https://web.example.com/t/external/corp-saml/saml/acs",
        "enabled": true,
        "allow_auto_link": false,
        "redirect_uri": "https://web.example.com/t/external/corp-saml/callback",
        "created_at": "2026-08-10T00:00:00Z",
        "updated_at": "2026-08-10T00:00:00Z"
    })
}

/// multipart/form-data POST (same shape as the metadata import form).
fn post_multipart(uri: &str, cookies: &str, fields: &[(&str, &str)]) -> Request<Body> {
    const BOUNDARY: &str = "----idp-test-boundary";
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!("--{BOUNDARY}\r\n"));
        // The file field is sent with a file name (to check precedence against the paste field).
        if *name == "metadata_file" {
            body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"; filename=\"metadata.xml\"\r\n\r\n"
            ));
        } else {
            body.push_str(&format!(
                "Content-Disposition: form-data; name=\"{name}\"\r\n\r\n"
            ));
        }
        body.push_str(value);
        body.push_str("\r\n");
    }
    body.push_str(&format!("--{BOUNDARY}--\r\n"));
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .header(COOKIE, cookies)
        .body(Body::from(body))
        .unwrap()
}

async fn stub_list(env: &WebEnv, providers: Value) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(providers))
        .mount(&env.api)
        .await;
}

async fn stub_patch(env: &WebEnv) {
    Mock::given(method("PATCH"))
        .and(path_regex(r"^/[^/]+/admin/external-idps/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_provider()))
        .mount(&env.api)
        .await;
}

/// Body that reached the api on registration (excluding the import endpoint).
async fn posted_body(env: &WebEnv) -> Option<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with("/admin/external-idps")
        })
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
}

/// Body that reached the api on update.
async fn patched_body(env: &WebEnv) -> Option<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| {
            r.method == wiremock::http::Method::PATCH
                && r.url.path().contains("/admin/external-idps/")
        })
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
}

/// Registered external IdPs appear in the list, along with **the redirect URI to register with the external IdP**.
/// Without it, every configuration task would mean re-researching how to build the URL.
#[tokio::test]
async fn the_list_shows_the_redirect_uri_to_register_with_the_provider() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/admin/external-idps", env.prefix()), &cookies()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("corp"), "{html}");
    assert!(
        html.contains("https://web.example.com/external/corp/callback"),
        "redirect uri is missing: {html}"
    );
}

/// **A blank secret is not sent.** The api's partial update does not touch unspecified fields, so this
/// means "unchanged". Including it would break the link merely by fixing the display name.
#[tokio::test]
async fn an_empty_secret_field_leaves_the_stored_secret_alone() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Corp IdP (renamed)"),
                ("issuer", "https://idp.example.com"),
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize",
                ),
                ("token_endpoint", "https://idp.example.com/token"),
                ("jwks_uri", "https://idp.example.com/jwks"),
                ("client_id", "abc"),
                ("client_secret", ""),
                ("scope_email", "1"),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = patched_body(&env)
        .await
        .expect("the update reached the api");
    assert!(
        body.get("client_secret").is_none(),
        "an empty field must not be forwarded: {body}"
    );
    assert_eq!(body["display_name"], json!("Corp IdP (renamed)"));
    assert_eq!(body["scopes"], json!(["openid", "email"]));
    // Unchecked checkboxes are not submitted, but are explicitly sent as `false`.
    // Leaving it unspecified makes the api read it as "unchanged", so unchecking could not disable it.
    assert_eq!(body["allow_auto_link"], json!(false));
}

/// An entered secret is included (replacement).
#[tokio::test]
async fn a_filled_secret_field_replaces_the_stored_secret() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Corp IdP"),
                ("issuer", "https://idp.example.com"),
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize",
                ),
                ("token_endpoint", "https://idp.example.com/token"),
                ("jwks_uri", "https://idp.example.com/jwks"),
                ("client_id", "abc"),
                ("client_secret", "new-secret"),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = patched_body(&env)
        .await
        .expect("the update reached the api");
    assert_eq!(body["client_secret"], json!("new-secret"));
}

/// On CSRF token mismatch the api is not called.
#[tokio::test]
async fn a_bad_csrf_token_never_reaches_the_api() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Hijacked"),
                ("issuer", "https://evil.example.com"),
                ("authorization_endpoint", "https://evil.example.com/a"),
                ("token_endpoint", "https://evil.example.com/t"),
                ("jwks_uri", "https://evil.example.com/j"),
                ("client_id", "abc"),
                ("client_secret", ""),
                ("csrf_token", "wrong"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        patched_body(&env).await.is_none(),
        "the request must not be forwarded when CSRF verification fails"
    );
}

// ── SAML support (AP12) ─────────────────────────────────────────────────────────

/// The screen opens even when SAML providers are mixed into the list. The api returns unused protocol fields as
/// `null`, so failing to handle that means **the whole screen stops opening as soon as one SAML is registered**.
/// ACS URL and SP entityID are shown too (values to register with the external IdP; do not make admins guess the build rule).
#[tokio::test]
async fn the_list_renders_saml_providers_with_the_values_to_register_upstream() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider(), sample_saml_provider()])).await;

    let response = send(
        &env.app,
        get_with_cookies(&format!("{}/admin/external-idps", env.prefix()), &cookies()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("corp-saml"), "{html}");
    assert!(
        html.contains("https://web.example.com/t/external/corp-saml/saml/acs"),
        "the ACS URL to register with the provider is missing: {html}"
    );
    assert!(
        html.contains("https://web.example.com/t/saml/sp"),
        "the SP entityID to register with the provider is missing: {html}"
    );
    // OIDC redirect URIs are listed alongside (columns are not split per protocol).
    assert!(
        html.contains("https://web.example.com/external/corp/callback"),
        "{html}"
    );
}

/// A registration choosing SAML sends **only the SAML fields** to the api. Sending the OIDC fields too would let the api
/// create a half-filled configuration, and the error would stay hidden until sign-in.
#[tokio::test]
async fn registering_a_saml_provider_sends_only_the_saml_fields() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(sample_saml_provider()))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps", env.prefix()),
            Some(&cookies()),
            &[
                ("provider_code", "corp-saml"),
                ("display_name", "Corp SAML"),
                ("protocol", "saml"),
                ("issuer", "urn:idp:corp"),
                // OIDC fields left on screen are also submitted, but not passed to the api.
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize",
                ),
                ("client_id", "abc"),
                ("scope_email", "1"),
                ("saml_sso_url", "https://idp.example.com/sso"),
                // Browsers send textarea newlines as CRLF. Send the same here.
                (
                    "saml_certificates",
                    "MIIB\r\nCURRENT==\r\n\r\nMIIB\r\nNEXT==",
                ),
                (
                    "saml_name_id_format",
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                ),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = posted_body(&env).await.expect("the create reached the api");
    assert_eq!(body["protocol"], json!("saml"));
    assert_eq!(body["saml_sso_url"], json!("https://idp.example.com/sso"));
    // Multiple certificates separated by blank lines. Splitting by line would break one wrapped certificate into several.
    assert_eq!(
        body["saml_certificates"],
        json!(["MIIBCURRENT==", "MIIBNEXT=="])
    );
    assert!(
        body.get("authorization_endpoint").is_none(),
        "OIDC fields must not leak into a SAML registration: {body}"
    );
    assert!(body.get("scopes").is_none(), "{body}");
}

/// Updates **always send `protocol`**. The api replaces protocol-specific settings together "only when `protocol`
/// is specified", so omitting it silently ignores endpoint changes (you think you saved, but
/// nothing changes).
#[tokio::test]
async fn an_update_carries_the_protocol_so_endpoint_edits_are_not_silently_dropped() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;
    stub_patch(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/update", env.prefix()),
            Some(&cookies()),
            &[
                ("display_name", "Corp IdP"),
                ("protocol", "oidc"),
                ("issuer", "https://idp.example.com"),
                (
                    "authorization_endpoint",
                    "https://idp.example.com/authorize2",
                ),
                ("token_endpoint", "https://idp.example.com/token"),
                ("jwks_uri", "https://idp.example.com/jwks"),
                ("client_id", "abc"),
                ("client_secret", ""),
                ("enabled", "1"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);

    let body = patched_body(&env)
        .await
        .expect("the update reached the api");
    assert_eq!(body["protocol"], json!("oidc"));
    assert_eq!(
        body["authorization_endpoint"],
        json!("https://idp.example.com/authorize2")
    );
}

/// Pasted IdP metadata becomes the registration form's initial values. **It does not register** (the admin checks
/// the values before registering). Certificates run several lines of base64, so copying by hand hides mistakes.
#[tokio::test]
async fn imported_metadata_prefills_the_form_without_registering_anything() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps/import-metadata$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "display_name": "Corp SAML",
            "entity_id": "urn:idp:corp",
            "sso_url": "https://idp.example.com/sso",
            "certificates": ["MIIBCURRENT==", "MIIBNEXT=="],
            "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_multipart(
            &format!("{}/admin/external-idps/import", env.prefix()),
            &cookies(),
            &[
                ("csrf_token", &csrf()),
                ("metadata_xml", "<EntityDescriptor/>"),
            ],
        ),
    )
    .await;
    // Import is not registration, so no PRG; the form is redrawn in place.
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("urn:idp:corp"), "{html}");
    assert!(html.contains("https://idp.example.com/sso"), "{html}");
    assert!(html.contains("MIIBCURRENT=="), "{html}");
    // The second certificate during rotation is not dropped either.
    assert!(html.contains("MIIBNEXT=="), "{html}");
    // Nothing has been registered.
    assert!(
        posted_body(&env).await.is_none(),
        "importing metadata must not register a provider"
    );
}

/// On an import CSRF token mismatch the api is not called (metadata import is an admin's screen
/// operation and must not be triggerable from other sites).
#[tokio::test]
async fn a_bad_csrf_token_never_reaches_the_import_endpoint() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;

    let response = send(
        &env.app,
        post_multipart(
            &format!("{}/admin/external-idps/import", env.prefix()),
            &cookies(),
            &[
                ("csrf_token", "wrong"),
                ("metadata_xml", "<EntityDescriptor/>"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        !env.api
            .received_requests()
            .await
            .expect("recorded requests")
            .iter()
            .any(|r| r.url.path().ends_with("/import-metadata")),
        "the import must not be forwarded when CSRF verification fails"
    );
}

/// **The list has no registration form.** Registration starts with "choose a protocol" -- putting OIDC and SAML
/// fields in one form mixes fields to fill with ones not to fill, making it unreadable.
#[tokio::test]
async fn the_list_offers_registration_without_showing_a_form() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(&format!("{}/admin/external-idps", env.prefix()), &cookies()),
        )
        .await,
    )
    .await;
    assert!(
        html.contains(&format!(
            r#"href="{}/admin/external-idps/new""#,
            env.prefix()
        )),
        "the list must lead to the protocol choice: {html}"
    );
    assert!(
        !html.contains(r#"name="provider_code""#),
        "the list must not carry a registration form: {html}"
    );
    // Editing also goes to a dedicated page (the list has no form to open).
    assert!(
        html.contains(&format!(
            r#"href="{}/admin/external-idps/{PROVIDER_ID}/edit""#,
            env.prefix()
        )),
        "{html}"
    );
}

/// The choice screen only branches to the two protocols.
#[tokio::test]
async fn the_entry_point_offers_exactly_the_two_protocols() {
    let env = setup().await;
    stub_admin(&env).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/new", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    for protocol in ["oidc", "saml"] {
        assert!(
            html.contains(&format!(
                r#"href="{}/admin/external-idps/new/{protocol}""#,
                env.prefix()
            )),
            "the {protocol} entry point is missing: {html}"
        );
    }
}

/// **The OIDC form has no SAML fields** (and vice versa). The route decides the protocol, and
/// no JS for toggling is needed -- even without JS, the visible fields are exactly the submitted fields.
///
/// Import differs per protocol: IdP metadata XML for SAML, the issuer's discovery
/// document for OIDC (task #77).
#[tokio::test]
async fn each_protocol_form_shows_only_its_own_fields() {
    let env = setup().await;
    stub_admin(&env).await;

    let oidc = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/new/oidc", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    assert!(oidc.contains(r#"name="jwks_uri""#), "{oidc}");
    assert!(oidc.contains(r#"name="protocol" value="oidc""#), "{oidc}");
    assert!(
        !oidc.contains(r#"name="saml_sso_url""#),
        "SAML fields must not appear on the OIDC form: {oidc}"
    );
    assert!(
        !oidc.contains(r#"name="metadata_xml""#),
        "OIDC has no metadata to import: {oidc}"
    );
    assert!(
        oidc.contains("/admin/external-idps/import-discovery"),
        "the OIDC form offers the discovery import: {oidc}"
    );

    let saml = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/new/saml", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    assert!(saml.contains(r#"name="saml_sso_url""#), "{saml}");
    assert!(saml.contains(r#"name="protocol" value="saml""#), "{saml}");
    assert!(saml.contains(r#"name="metadata_xml""#), "{saml}");
    assert!(
        !saml.contains("/admin/external-idps/import-discovery"),
        "SAML has no discovery document: {saml}"
    );
    assert!(
        !saml.contains(r#"name="jwks_uri""#),
        "OIDC fields must not appear on the SAML form: {saml}"
    );
    // Scopes exist only in OIDC (SAML assertions have no scopes).
    assert!(!saml.contains(r#"name="scope_email""#), "{saml}");
}

/// A misspelled protocol is 404. Rounding to a default would make someone typing the URL fill in a form
/// for a protocol they did not intend.
#[tokio::test]
async fn an_unknown_protocol_is_not_rounded_to_a_default() {
    let env = setup().await;
    stub_admin(&env).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/external-idps/new/ws-fed", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Editing has a fixed protocol and offers no metadata import (overwriting with another IdP's metadata while
/// editing would lose track of what was about to be saved).
#[tokio::test]
async fn editing_pins_the_protocol_and_does_not_offer_metadata_import() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_saml_provider()])).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!(
                    "{}/admin/external-idps/{SAML_PROVIDER_ID}/edit",
                    env.prefix()
                ),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    // The protocol cannot be changed (the api also rejects it). The value is sent as hidden.
    assert!(html.contains(r#"name="protocol" value="saml""#), "{html}");
    assert!(
        !html.contains(r#"name="jwks_uri""#),
        "editing a SAML provider must not offer the OIDC fields: {html}"
    );
    assert!(
        !html.contains(r#"name="metadata_xml""#),
        "editing must not offer to overwrite the form from another provider's metadata: {html}"
    );
    // Saved certificates come back separated by blank lines and can be appended or replaced.
    assert!(html.contains("MIIBCURRENT==\n\nMIIBNEXT=="), "{html}");
}

/// Editing an id not in the list (deleted, other tenant) returns to the list. Showing an empty form would lead
/// to creating a new one while thinking you are editing.
#[tokio::test]
async fn editing_an_unknown_provider_returns_to_the_list() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;

    let response = send(
        &env.app,
        get_with_cookies(
            &format!("{}/admin/external-idps/{PROVIDER_ID}/edit", env.prefix()),
            &cookies(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some(format!("{}/admin/external-idps?error=notfound", env.prefix()).as_str())
    );
}

/// **Requested scopes are entered by choice.** Saved values come back as checked states, and scopes the counterpart
/// defines itself go to free input -- closing the choices to fixed values would drop counterpart-specific scopes like
/// `groups` on every edit.
#[tokio::test]
async fn saved_scopes_come_back_as_checkboxes_and_provider_specific_ones_stay_editable() {
    let env = setup().await;
    stub_admin(&env).await;
    let mut provider = sample_provider();
    provider["scopes"] = json!(["openid", "email", "groups"]);
    stub_list(&env, json!([provider])).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/{PROVIDER_ID}/edit", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    assert!(
        html.contains(r#"name="scope_email" checked"#),
        "a saved scope must come back checked: {html}"
    );
    assert!(
        !html.contains(r#"name="scope_profile" checked"#),
        "a scope that was not saved must not look selected: {html}"
    );
    // Counterpart-specific scopes go to free input. `openid` is always added, so it is not shown here.
    assert!(
        html.contains(r#"id="scopes_extra" name="scopes_extra" value="groups""#),
        "{html}"
    );
}

/// If registration fails with an unknown protocol, **fall back to the list**. `protocol` comes from the form, and
/// the handler passes unknown spellings to the api without rounding (to keep the decision in one place). Inserting it
/// as is into the redirect route would put a URL with no destination, or a query broken by `?`, in
/// the Location.
#[tokio::test]
async fn a_failed_registration_with_an_unknown_protocol_falls_back_to_the_list() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid"})))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps", env.prefix()),
            Some(&cookies()),
            &[
                ("provider_code", "corp"),
                ("display_name", "Corp"),
                ("protocol", "ws-fed?x=1"),
                ("issuer", "https://idp.example.com"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some(format!("{}/admin/external-idps?error=validation", env.prefix()).as_str())
    );
}

/// If registration fails, return to the form of the same protocol (do not make them choose the protocol again).
#[tokio::test]
async fn a_failed_registration_returns_to_the_form_for_the_same_protocol() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([])).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps$"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid"})))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps", env.prefix()),
            Some(&cookies()),
            &[
                ("provider_code", "corp-saml"),
                ("display_name", "Corp SAML"),
                ("protocol", "saml"),
                ("issuer", "urn:idp:corp"),
                ("saml_sso_url", "not-a-url"),
                ("csrf_token", &csrf()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some(
            format!(
                "{}/admin/external-idps/new/saml?error=validation",
                env.prefix()
            )
            .as_str()
        )
    );
}

/// Body of the discovery import that reached the api.
async fn discovery_request(env: &WebEnv) -> Option<Value> {
    env.api
        .received_requests()
        .await
        .expect("recorded requests")
        .iter()
        .find(|r| {
            r.url
                .path()
                .ends_with("/admin/external-idps/import-discovery")
        })
        .map(|r| serde_json::from_slice(&r.body).expect("json body"))
}

/// Values from the discovery document loaded from the issuer become the OIDC registration form's initial values.
/// **It does not register** (the admin checks the values and enters the client ID before registering).
#[tokio::test]
async fn a_discovery_import_prefills_the_oidc_form_without_registering_anything() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps/import-discovery$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": "https://login.corp.example.com/realms/corp",
            "authorization_endpoint": "https://login.corp.example.com/realms/corp/auth",
            "token_endpoint": "https://login.corp.example.com/realms/corp/token",
            "jwks_uri": "https://login.corp.example.com/realms/corp/certs"
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/import-discovery", env.prefix()),
            Some(&cookies()),
            &[
                ("csrf_token", &csrf()),
                ("issuer", " https://login.corp.example.com/realms/corp "),
            ],
        ),
    )
    .await;
    // Import is not registration, so no PRG; the form is redrawn in place.
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains(r#"name="protocol" value="oidc""#), "{html}");
    assert!(
        html.contains(r#"value="https://login.corp.example.com/realms/corp/auth""#),
        "{html}"
    );
    assert!(
        html.contains(r#"value="https://login.corp.example.com/realms/corp/token""#),
        "{html}"
    );
    assert!(
        html.contains(r#"value="https://login.corp.example.com/realms/corp/certs""#),
        "{html}"
    );
    // The entered issuer (trimmed) was passed as is to the api. Destination checks are the api's job.
    assert_eq!(
        discovery_request(&env).await,
        Some(json!({ "issuer": "https://login.corp.example.com/realms/corp" }))
    );
    assert!(
        posted_body(&env).await.is_none(),
        "importing a discovery document must not register a provider"
    );
}

/// If the api refuses (destination check, issuer mismatch, etc.), keep the entered issuer and show the reason.
#[tokio::test]
async fn a_rejected_discovery_import_keeps_the_issuer_and_explains() {
    let env = setup().await;
    stub_admin(&env).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/[^/]+/admin/external-idps/import-discovery$"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_request",
            "message": "the discovery document's issuer \"https://a\" does not match the requested issuer \"https://b\""
        })))
        .mount(&env.api)
        .await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/import-discovery", env.prefix()),
            Some(&cookies()),
            &[
                ("csrf_token", &csrf()),
                ("issuer", "https://idp.example.com/"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains("discovery ドキュメントを読み込めませんでした"),
        "{html}"
    );
    assert!(
        html.contains(r#"value="https://idp.example.com/""#),
        "{html}"
    );
    assert!(posted_body(&env).await.is_none());
}

/// On CSRF token mismatch the api is not called (do not let other sites trigger an operation that makes the api
/// send HTTP outward).
#[tokio::test]
async fn a_bad_csrf_token_never_reaches_the_discovery_import() {
    let env = setup().await;
    stub_admin(&env).await;

    let response = send(
        &env.app,
        post_form(
            &format!("{}/admin/external-idps/import-discovery", env.prefix()),
            Some(&cookies()),
            &[
                ("csrf_token", "wrong"),
                ("issuer", "https://idp.example.com"),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        discovery_request(&env).await.is_none(),
        "the import must not be forwarded when CSRF verification fails"
    );
}

/// While editing, discovery import is not offered either (overwriting with another IdP's values would lose track of
/// what was about to be saved; same as SAML metadata import).
#[tokio::test]
async fn editing_does_not_offer_the_discovery_import() {
    let env = setup().await;
    stub_admin(&env).await;
    stub_list(&env, json!([sample_provider()])).await;

    let html = body_text(
        send(
            &env.app,
            get_with_cookies(
                &format!("{}/admin/external-idps/{PROVIDER_ID}/edit", env.prefix()),
                &cookies(),
            ),
        )
        .await,
    )
    .await;
    assert!(html.contains(r#"name="jwks_uri""#), "{html}");
    assert!(
        !html.contains("/admin/external-idps/import-discovery"),
        "{html}"
    );
}
