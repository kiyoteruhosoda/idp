//! SAML メタデータ XML の解析（外部 IdP メタデータ取り込み）と生成（自身の SP メタデータ出力）。
//!
//! - 取り込み: 外部 SAML IdP が公開する `EntityDescriptor`（`IDPSSODescriptor`）を解析し、登録に必要な
//!   `entity_id` / `sso_url` / `x509_certificate` を抽出する。管理者の手入力を置き換える補助であり、
//!   検証（SSO URL のスキーム等）は登録ユースケース側（[`crate::domain::saml_provider`]）に委ねる。
//! - 出力: 本 IdP が SAML SP として振る舞う際の `EntityDescriptor`（`SPSSODescriptor`）を生成する。
//!   外部 IdP 管理者へ渡してこの SP を登録してもらうためのメタデータで、`.well-known/openid-configuration`
//!   の SAML 版に相当する。
//!
//! 名前空間の接頭辞（`md:` / `saml:` 等）は実装依存のためローカル名で判定する。属性値・要素本文の
//! アンエスケープと、出力時の属性値エスケープは `quick-xml` に委ねる（手書きのエスケープを設けない）。

use crate::domain::error::{DomainError, Result};
use quick_xml::escape::escape;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// SAML 2.0 バインディング識別子。取り込み時の SSO URL 選好・出力時の ACS バインディングに使う。
const BINDING_HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// 外部 IdP メタデータから取り込んだ登録候補値。登録フォームの初期値として提示する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedIdpMetadata {
    pub entity_id: String,
    pub sso_url: String,
    /// 署名用証明書（`<ds:X509Certificate>` の本文。空白を除去した base64）。無ければ空文字。
    pub x509_certificate: String,
    /// `md:Organization` 由来の表示名（あれば）。
    pub display_name: Option<String>,
}

/// 取り込み中に本文テキストを収集する対象。
enum Capture {
    Certificate,
    DisplayName,
}

/// 外部 SAML IdP の `EntityDescriptor` XML を解析し、登録候補値を抽出する。
///
/// - `entityID`（`EntityDescriptor`）と SSO URL（`IDPSSODescriptor/SingleSignOnService`）は必須。
///   欠落時は [`DomainError::InvalidValue`]。
/// - SSO URL は HTTP-Redirect → HTTP-POST → 先頭、の優先順で 1 件を選ぶ。
/// - 証明書は `IDPSSODescriptor` 内の署名用（`use="signing"` または `use` 無し）を優先して 1 件採用する。
pub fn parse_idp_metadata(xml: &str) -> Result<ImportedIdpMetadata> {
    let mut reader = Reader::from_str(xml);

    let mut entity_id: Option<String> = None;
    let mut in_idp = false;
    // (binding, location) の SSO 候補。
    let mut sso_candidates: Vec<(String, String)> = Vec::new();
    // KeyDescriptor の use 属性（"signing" / "encryption" / None）。
    let mut key_use: Option<String> = None;
    let mut signing_cert: Option<String> = None;
    let mut fallback_cert: Option<String> = None;
    let mut display_name: Option<String> = None;

    let mut capture: Option<Capture> = None;
    let mut text_buf = String::new();
    // 集約メタデータ（`EntitiesDescriptor` に複数の `EntityDescriptor`）では最初の `EntityDescriptor`
    // だけを対象にする。異なるエンティティの entityID・SSO・証明書が混在すると認証できない設定に
    // なるため、子要素の収集は最初のエンティティ内（`in_entity`）に限定し、その終了で解析を打ち切る。
    let mut in_entity = false;

    loop {
        match reader
            .read_event()
            .map_err(|e| DomainError::InvalidValue(format!("invalid SAML metadata XML: {e}")))?
        {
            Event::Start(e) => match local(&e) {
                b"EntityDescriptor" if entity_id.is_none() => {
                    entity_id = attribute(&e, b"entityID");
                    in_entity = true;
                }
                b"IDPSSODescriptor" if in_entity => in_idp = true,
                b"KeyDescriptor" if in_entity && in_idp => key_use = attribute(&e, b"use"),
                b"SingleSignOnService" if in_entity && in_idp => push_sso(&e, &mut sso_candidates),
                b"X509Certificate"
                    if in_entity && in_idp && key_use.as_deref() != Some("encryption") =>
                {
                    capture = Some(Capture::Certificate);
                    text_buf.clear();
                }
                b"OrganizationDisplayName" | b"OrganizationName"
                    if in_entity && display_name.is_none() =>
                {
                    capture = Some(Capture::DisplayName);
                    text_buf.clear();
                }
                _ => {}
            },
            // 空要素（自己終了タグ）。子を持たない `EntityDescriptor` は退化ケースとして entityID のみ拾う。
            Event::Empty(e) => match local(&e) {
                b"EntityDescriptor" if entity_id.is_none() => {
                    entity_id = attribute(&e, b"entityID");
                }
                b"KeyDescriptor" if in_entity && in_idp => key_use = attribute(&e, b"use"),
                b"SingleSignOnService" if in_entity && in_idp => push_sso(&e, &mut sso_candidates),
                _ => {}
            },
            Event::Text(e) => {
                if capture.is_some() {
                    let decoded = e.unescape().map_err(|err| {
                        DomainError::InvalidValue(format!("invalid SAML metadata text: {err}"))
                    })?;
                    text_buf.push_str(&decoded);
                }
            }
            Event::End(e) => match local_end(&e) {
                // 最初の EntityDescriptor が閉じたら、後続エンティティを読まずに打ち切る。
                b"EntityDescriptor" if in_entity => break,
                b"IDPSSODescriptor" => in_idp = false,
                b"KeyDescriptor" => key_use = None,
                b"X509Certificate" => {
                    if matches!(capture, Some(Capture::Certificate)) {
                        let normalized = strip_whitespace(&text_buf);
                        if !normalized.is_empty() {
                            if key_use.as_deref() == Some("signing") {
                                signing_cert.get_or_insert(normalized);
                            } else {
                                fallback_cert.get_or_insert(normalized);
                            }
                        }
                    }
                    capture = None;
                }
                b"OrganizationDisplayName" | b"OrganizationName" => {
                    if matches!(capture, Some(Capture::DisplayName)) {
                        let trimmed = text_buf.trim();
                        if !trimmed.is_empty() {
                            display_name.get_or_insert_with(|| trimmed.to_string());
                        }
                    }
                    capture = None;
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }

    let entity_id = entity_id.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
        DomainError::InvalidValue("SAML metadata is missing entityID".to_string())
    })?;
    let sso_url = pick_sso_url(&sso_candidates).ok_or_else(|| {
        DomainError::InvalidValue("SAML metadata is missing an IdP SingleSignOnService".to_string())
    })?;

    Ok(ImportedIdpMetadata {
        entity_id: entity_id.trim().to_string(),
        sso_url,
        x509_certificate: signing_cert.or(fallback_cert).unwrap_or_default(),
        display_name,
    })
}

/// 本 IdP を SAML SP として記述する `EntityDescriptor`（`SPSSODescriptor`）XML を生成する。
///
/// `entity_id` は SP のエンティティ ID（テナント issuer を用いる）、`acs_url` は AssertionConsumerService
/// の URL。現時点では署名鍵（`KeyDescriptor`）は含めない（アサーション受信フローの導入時に追加する）。
pub fn build_sp_metadata_xml(entity_id: &str, acs_url: &str) -> String {
    let entity_id = escape(entity_id);
    let acs_url = escape(acs_url);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="{BINDING_HTTP_POST}" Location="{acs_url}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"#
    )
}

/// `SingleSignOnService` の Binding/Location を SSO 候補へ追加する（両方揃う場合のみ）。
fn push_sso(e: &BytesStart, out: &mut Vec<(String, String)>) {
    if let (Some(binding), Some(location)) = (attribute(e, b"Binding"), attribute(e, b"Location")) {
        out.push((binding, location));
    }
}

/// SSO 候補から 1 件選ぶ。HTTP-Redirect → HTTP-POST → 先頭、の優先順。
fn pick_sso_url(candidates: &[(String, String)]) -> Option<String> {
    let by_binding = |binding: &str| {
        candidates
            .iter()
            .find(|(b, _)| b == binding)
            .map(|(_, loc)| loc.clone())
    };
    by_binding(BINDING_HTTP_REDIRECT)
        .or_else(|| by_binding(BINDING_HTTP_POST))
        .or_else(|| candidates.first().map(|(_, loc)| loc.clone()))
}

/// 開始/空要素のローカル名（名前空間接頭辞を除いた要素名）。
fn local<'a>(e: &'a BytesStart<'a>) -> &'a [u8] {
    // `local_name()` の戻り値は一時値のため、ライフタイムを保つため名前バイト列から末尾を取り出す。
    let name = e.name();
    let full = name.into_inner();
    strip_prefix(full)
}

fn local_end<'a>(e: &'a quick_xml::events::BytesEnd<'a>) -> &'a [u8] {
    let name = e.name();
    strip_prefix(name.into_inner())
}

/// `md:EntityDescriptor` → `EntityDescriptor` のように接頭辞を除く。
fn strip_prefix(name: &[u8]) -> &[u8] {
    match name.iter().position(|&b| b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

/// 属性値（ローカル名一致・アンエスケープ済み）を取り出す。
fn attribute(e: &BytesStart, name: &[u8]) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.local_name().as_ref() == name {
            if let Ok(value) = attr.unescape_value() {
                return Some(value.into_owned());
            }
        }
    }
    None
}

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDP_METADATA: &str = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://idp.example.test/metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
            MIIBsigningCERTdata==
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBencryptONLY==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://idp.example.test/sso/post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp.example.test/sso/redirect"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationDisplayName xml:lang="en">Example IdP</md:OrganizationDisplayName>
  </md:Organization>
</md:EntityDescriptor>"#;

    #[test]
    fn parses_entity_id_signing_cert_and_prefers_redirect_binding() {
        let parsed = parse_idp_metadata(IDP_METADATA).expect("parse");
        assert_eq!(parsed.entity_id, "https://idp.example.test/metadata");
        assert_eq!(parsed.sso_url, "https://idp.example.test/sso/redirect");
        assert_eq!(parsed.x509_certificate, "MIIBsigningCERTdata==");
        assert_eq!(parsed.display_name.as_deref(), Some("Example IdP"));
    }

    #[test]
    fn parses_metadata_without_namespace_prefixes() {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let parsed = parse_idp_metadata(xml).expect("parse");
        assert_eq!(parsed.entity_id, "urn:idp");
        assert_eq!(parsed.sso_url, "https://idp.test/sso");
        assert!(parsed.x509_certificate.is_empty());
        assert_eq!(parsed.display_name, None);
    }

    #[test]
    fn falls_back_to_post_binding_when_redirect_absent() {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/post"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let parsed = parse_idp_metadata(xml).expect("parse");
        assert_eq!(parsed.sso_url, "https://idp.test/post");
    }

    #[test]
    fn aggregate_metadata_uses_only_the_first_entity_descriptor() {
        // 最初のエンティティは POST バインディング、2 番目は Redirect。エンティティ間で混在させず、
        // 最初の EntityDescriptor（entityID・SSO・証明書）のみを採用する。
        let xml = r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <md:EntityDescriptor entityID="https://first.example.test/idp">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing">
        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>FIRSTcert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      </md:KeyDescriptor>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://first.example.test/sso/post"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
  <md:EntityDescriptor entityID="https://second.example.test/idp">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="signing">
        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>SECONDcert==</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      </md:KeyDescriptor>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://second.example.test/sso/redirect"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>"#;
        let parsed = parse_idp_metadata(xml).expect("parse");
        assert_eq!(parsed.entity_id, "https://first.example.test/idp");
        // 2 番目の Redirect ではなく、最初のエンティティの POST を採用する（混在させない）。
        assert_eq!(parsed.sso_url, "https://first.example.test/sso/post");
        assert_eq!(parsed.x509_certificate, "FIRSTcert==");
    }

    #[test]
    fn rejects_metadata_without_entity_id() {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/></IDPSSODescriptor>
</EntityDescriptor>"#;
        assert!(parse_idp_metadata(xml).is_err());
    }

    #[test]
    fn rejects_metadata_without_sso_service() {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</EntityDescriptor>"#;
        assert!(parse_idp_metadata(xml).is_err());
    }

    #[test]
    fn rejects_malformed_xml() {
        assert!(parse_idp_metadata("<EntityDescriptor><oops").is_err());
    }

    #[test]
    fn build_sp_metadata_contains_entity_id_and_acs_and_escapes() {
        let xml = build_sp_metadata_xml(
            "https://idp.example.com/tenant-1",
            "https://idp.example.com/tenant-1/saml/acs?x=1&y=2",
        );
        assert!(xml.contains(r#"entityID="https://idp.example.com/tenant-1""#));
        assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
        // クエリの `&` は属性値としてエスケープされる。
        assert!(xml.contains("saml/acs?x=1&amp;y=2"));
        assert!(!xml.contains("acs?x=1&y=2"));
        // 生成した XML は再パース可能（整形式）である。
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }
}
