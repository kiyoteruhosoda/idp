//! SAML IdP メタデータ出力（公開）の統合テスト（DB あり）。
//!
//! `TEST_DATABASE_URL` 設定時のみ実行:
//!   TEST_DATABASE_URL='mysql://idp:idp@127.0.0.1:3306/idp' cargo test --test saml_metadata

mod support;

use axum::http::header::CONTENT_TYPE;
use axum::http::{Method, StatusCode};
use support::{anonymous, send};

/// IdP メタデータは認証不要で公開され、テナント issuer を entityID とし、ACTIVE 署名鍵を含む
/// 整形式 XML を返す。
#[tokio::test]
async fn idp_metadata_is_public_and_tenant_scoped() {
    let Some(env) = support::setup("saml idp metadata").await else {
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
    // IdP メタデータ（IDPSSODescriptor + SSO）であり、SP メタデータではない。
    assert!(xml.contains("IDPSSODescriptor"), "IDPSSODescriptor: {xml}");
    assert!(!xml.contains("SPSSODescriptor"));
    assert!(
        xml.contains(&format!("{tenant_issuer}/saml/sso")),
        "SSO URL"
    );
    // ブートストラップ済み ACTIVE 署名鍵が RSAKeyValue で埋め込まれる。
    assert!(
        xml.contains("<md:KeyDescriptor use=\"signing\">"),
        "signing KeyDescriptor: {xml}"
    );
    assert!(xml.contains("<ds:RSAKeyValue>"));
}
