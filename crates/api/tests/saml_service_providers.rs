//! SAML SP（クライアント）登録・SP メタデータ取り込みの統合テスト（DB あり）。
//! `idp.tenant.admin` 必須。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test saml_service_providers

mod support;

use axum::http::StatusCode;
use serde_json::json;
use support::{body_json, create_plain_user, create_sso_session, get, post, send};

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
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;

    // 権限の無い利用者 → 403。
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_cookie = create_sso_session(&env.pool, &plain_user_id).await;
    let res = send(
        &env.app,
        post(
            &plain_cookie,
            &uri,
            json!({
                "display_name": "App",
                "entity_id": "urn:sp:1",
                "acs_url": "https://sp.example.test/acs",
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no perms -> 403");

    // 管理者は登録できる（NameID 未指定は既定 persistent）。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &uri,
            json!({
                "display_name": "Example SP",
                "entity_id": "urn:sp:example",
                "acs_url": "https://sp.example.test/acs",
                "enabled": true
            }),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED, "admin create -> 201");
    let created = body_json(res).await;
    assert_eq!(created["entity_id"], "urn:sp:example");
    assert_eq!(
        created["name_id_format"],
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    );

    // ACS URL が非 HTTPS → 400。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &uri,
            json!({
                "display_name": "Bad",
                "entity_id": "urn:sp:bad",
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

    // 一覧に登録済みが含まれる。
    let res = send(&env.app, get(&admin_cookie, &uri)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let list = body_json(res).await;
    let entities: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["entity_id"].as_str())
        .collect();
    assert!(
        entities.contains(&"urn:sp:example"),
        "list contains created SP"
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
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;

    let res = send(
        &env.app,
        post(&admin_cookie, &uri, json!({ "metadata_xml": SP_METADATA })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "admin import -> 200");
    let parsed = body_json(res).await;
    assert_eq!(parsed["entity_id"], "https://sp.example.test/saml/metadata");
    assert_eq!(parsed["acs_url"], "https://sp.example.test/acs");
    assert_eq!(parsed["x509_certificate"], "MIIBspCERT==");

    // IdP メタデータ（ACS 無し）を SP として取り込もうとすると 400。
    let idp_only = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
    let res = send(
        &env.app,
        post(&admin_cookie, &uri, json!({ "metadata_xml": idp_only })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "idp metadata -> 400");
}
