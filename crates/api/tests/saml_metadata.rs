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
        Some("application/xml; charset=utf-8"),
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

/// 公開中の鍵をすべて `KeyDescriptor` として並べる（ADR-0039 / T33）。
///
/// ADR-0039 は「公開してから署名」で JWKS 側の断絶を無くしたが、SAML のメタデータは
/// `KeyDescriptor` を 1 本しか出していなかった。**SP からは署名が切り替わる瞬間に証明書が
/// 入れ替わって見え、取り込み直すまで検証が落ちる。**
///
/// JWKS と同じ集合になっていること（＝どちらか片方だけ古くならないこと）を見る。
#[tokio::test]
async fn idp_metadata_publishes_every_key_the_jwks_does() {
    let Some(env) = support::setup("saml idp metadata key window").await else {
        return;
    };

    let jwks_uri = format!("/{}/.well-known/jwks.json", env.root_tenant_id);
    let response = send(&env.app, anonymous(Method::GET, &jwks_uri, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let jwks: serde_json::Value = serde_json::from_slice(&bytes).expect("jwks json");
    let published = jwks["keys"].as_array().expect("keys").len();
    assert!(published >= 1, "少なくとも 1 本は公開されている");

    let uri = format!("/{}/saml/metadata", env.root_tenant_id);
    let response = send(&env.app, anonymous(Method::GET, &uri, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let xml = String::from_utf8(bytes.to_vec()).expect("utf8");

    let descriptors = xml.matches("<md:KeyDescriptor use=\"signing\">").count();
    assert_eq!(
        descriptors, published,
        "JWKS と同じ本数を並べること（JWKS {published} 本 / metadata {descriptors} 本）: {xml}"
    );
}
