//! Integration tests (with DB) for SAML SP (client) registration and SP metadata import.
//! Requires `idp.tenant.admin`.
//!
//! Runs only when `TEST_DATABASE_URL` is set:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test saml_service_providers

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{admin_token, body_json, create_plain_user, delete, get, post, put, send};

const SP_METADATA: &str = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://sp.example.test/saml/metadata">
  <md:SPSSODescriptor AuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBspCERT==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="https://sp.example.test/acs" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"#;

#[tokio::test]
async fn admin_can_register_and_list_saml_clients_but_others_cannot() {
    let Some(env) = support::setup("saml sp register").await else {
        return;
    };
    let uri = format!("/{}/admin/saml-service-providers", env.root_tenant_id);
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    // This test ends without deleting the registered SP (appearing in the list is part of what is checked).
    // `entity_id` is `UNIQUE (tenant_id, entity_id)`, so with a fixed value **a second run against the same DB
    // fails with 409**. Change it per run.
    let entity_id = format!("urn:sp:example:{}", support::unique());

    // User without permission → 403.
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(
        &env.app,
        post(
            &plain_token,
            &uri,
            json!({
                "display_name": "App",
                "entity_id": format!("urn:sp:forbidden:{}", support::unique()),
                "acs_url": "https://sp.example.test/acs",
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no perms -> 403");

    // Admins can register (NameID unspecified defaults to persistent).
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({
                "display_name": "Example SP",
                "entity_id": &entity_id,
                "acs_url": "https://sp.example.test/acs",
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "admin create -> 201");
    let created = body_json(res).await;
    assert_eq!(created["entity_id"], entity_id.as_str());
    assert_eq!(
        created["name_id_format"],
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    );

    // Non-HTTPS ACS URL → 400.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &uri,
            json!({
                "display_name": "Bad",
                "entity_id": format!("urn:sp:bad:{}", support::unique()),
                "acs_url": "http://sp.evil.test/acs",
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "non-https acs -> 400"
    );

    // The list includes the registered one.
    let res = send(&env.app, get(&admin_tok, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let list = body_json(res).await;
    let entities: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["entity_id"].as_str())
        .collect();
    assert!(
        entities.contains(&entity_id.as_str()),
        "list contains created SP"
    );
}

#[tokio::test]
async fn admin_can_update_and_delete_saml_client() {
    let Some(env) = support::setup("saml sp update/delete").await else {
        return;
    };
    let base = format!("/{}/admin/saml-service-providers", env.root_tenant_id);
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;
    // It is deleted at the end, so a fixed value would pass, but **if it fails midway the row remains and this test
    // never passes again** (one failure causes the next run's failure). Change it per run here too.
    let entity_id = format!("urn:sp:editable:{}", support::unique());

    // Register and get the id.
    let res = send(
        &env.app,
        post(
            &admin_tok,
            &base,
            json!({
                "display_name": "Editable SP",
                "entity_id": &entity_id,
                "acs_url": "https://sp.example.test/acs",
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = body_json(res).await;
    let id = created["id"].as_str().expect("id").to_string();
    let item_uri = format!("{base}/{id}");

    // Update: change display name, ACS and enabled.
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &item_uri,
            json!({
                "display_name": "Renamed SP",
                "entity_id": &entity_id,
                "acs_url": "https://sp.example.test/acs2",
                "name_id_format": "",
                "x509_certificate": "MIICERT==",
                "enabled": false
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "admin update -> 200");
    let updated = body_json(res).await;
    assert_eq!(updated["display_name"], "Renamed SP");
    assert_eq!(updated["acs_url"], "https://sp.example.test/acs2");
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["x509_certificate"], "MIICERT==");

    // Updating to a non-HTTPS ACS is 400.
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &item_uri,
            json!({
                "display_name": "Renamed SP",
                "entity_id": &entity_id,
                "acs_url": "http://sp.evil.test/acs",
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "non-https update -> 400"
    );

    // Users without permission cannot delete → 403.
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_token = admin_token(&env.app, &env.pool, &env.root_tenant_id, &plain_user_id).await;
    let res = send(&env.app, delete(&plain_token, &item_uri)).await;
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "no perms delete -> 403"
    );

    // Admins can delete → 204.
    let res = send(&env.app, delete(&admin_tok, &item_uri)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT, "admin delete -> 204");

    // Double deletion and nonexistent ids are 404.
    let res = send(&env.app, delete(&admin_tok, &item_uri)).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "delete missing -> 404");
    let res = send(
        &env.app,
        put(
            &admin_tok,
            &item_uri,
            json!({
                "display_name": "X",
                "entity_id": &entity_id,
                "acs_url": "https://sp.example.test/acs",
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "update missing -> 404");

    // Not included in the list.
    let res = send(&env.app, get(&admin_tok, &base)).await;
    let list = body_json(res).await;
    let entities: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["entity_id"].as_str())
        .collect();
    assert!(
        !entities.contains(&entity_id.as_str()),
        "deleted SP not listed"
    );
}

#[tokio::test]
async fn admin_can_import_sp_metadata() {
    let Some(env) = support::setup("saml sp import").await else {
        return;
    };
    let uri = format!(
        "/{}/admin/saml-service-providers/import-metadata",
        env.root_tenant_id
    );
    let admin_tok = admin_token(&env.app, &env.pool, &env.root_tenant_id, &env.root_admin_id).await;

    let res = send(
        &env.app,
        post(&admin_tok, &uri, json!({ "metadata_xml": SP_METADATA })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "admin import -> 200");
    let parsed = body_json(res).await;
    assert_eq!(parsed["entity_id"], "https://sp.example.test/saml/metadata");
    assert_eq!(parsed["acs_url"], "https://sp.example.test/acs");
    assert_eq!(parsed["x509_certificate"], "MIIBspCERT==");

    // Trying to import IdP metadata (no ACS) as an SP is 400.
    let idp_only = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
    let res = send(
        &env.app,
        post(&admin_tok, &uri, json!({ "metadata_xml": idp_only })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "idp metadata -> 400");
}
