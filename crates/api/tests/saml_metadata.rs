//! SAML メタデータの統合テスト（DB あり）。SP メタデータ出力（公開）と外部 IdP メタデータ取り込み
//! （`idp.tenant.admin` 必須）を検証する。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test saml_metadata

mod support;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use support::{anonymous, body_json, create_plain_user, create_sso_session, post, send};

const IDP_METADATA: &str = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://external-idp.example.test/metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBimportedCERT==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://external-idp.example.test/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#;

/// SP メタデータは認証不要で公開され、テナント issuer を entityID とする整形式 XML を返す。
#[tokio::test]
async fn sp_metadata_is_public_and_tenant_scoped() {
    let Some(env) = support::setup("saml sp metadata").await else {
        return;
    };
    let uri = format!("/{}/saml/metadata", env.root_tenant_id);
    let response = send(&env.app, anonymous(Method::GET, &uri, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/samlmetadata+xml"),
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let xml = String::from_utf8(bytes.to_vec()).expect("utf8");
    let tenant_issuer = format!("{}/{}", env.issuer, env.root_tenant_id);
    assert!(
        xml.contains(&format!("entityID=\"{tenant_issuer}\"")),
        "entityID must be the tenant issuer: {xml}"
    );
    assert!(
        xml.contains(&format!("{tenant_issuer}/saml/acs")),
        "ACS URL"
    );
    assert!(xml.contains("SPSSODescriptor"));
}

/// 管理者は外部 IdP メタデータ XML を取り込み、登録候補値を得られる。権限が無ければ拒否される。
#[tokio::test]
async fn admin_can_import_idp_metadata_but_others_cannot() {
    let Some(env) = support::setup("saml metadata import").await else {
        return;
    };
    let uri = format!(
        "/{}/admin/saml-providers/import-metadata",
        env.root_tenant_id
    );

    // 未認証 → 401。
    let res = send(
        &env.app,
        Request::builder()
            .method("POST")
            .uri(&uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "metadata_xml": IDP_METADATA }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "no cookie -> 401");

    // 権限の無い利用者 → 403。
    let plain_user_id = create_plain_user(&env.pool, &env.root_tenant_id).await;
    let plain_cookie = create_sso_session(&env.pool, &plain_user_id).await;
    let res = send(
        &env.app,
        post(&plain_cookie, &uri, json!({ "metadata_xml": IDP_METADATA })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "no perms -> 403");

    // 管理者 → 200 で解析結果を返す。
    let admin_cookie = create_sso_session(&env.pool, &env.root_admin_id).await;
    let res = send(
        &env.app,
        post(&admin_cookie, &uri, json!({ "metadata_xml": IDP_METADATA })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "admin import -> 200");
    let parsed = body_json(res).await;
    assert_eq!(
        parsed["entity_id"],
        "https://external-idp.example.test/metadata"
    );
    assert_eq!(parsed["sso_url"], "https://external-idp.example.test/sso");
    assert_eq!(parsed["x509_certificate"], "MIIBimportedCERT==");

    // 不正な XML → 400。
    let res = send(
        &env.app,
        post(
            &admin_cookie,
            &uri,
            json!({ "metadata_xml": "<not-metadata/>" }),
        ),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "invalid metadata -> 400"
    );
}
