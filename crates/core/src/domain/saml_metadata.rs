//! SAML メタデータ XML の解析（SP メタデータ取り込み）と生成（自身の IdP メタデータ出力）。
//!
//! - 取り込み: SP（クライアント）が公開する `EntityDescriptor`（`SPSSODescriptor`）を解析し、登録に必要な
//!   `entity_id` / `acs_url` / `x509_certificate` / NameID を抽出する。管理者の手入力を置き換える補助で、
//!   検証（ACS URL のスキーム等）は登録ユースケース側（[`crate::domain::saml_service_provider`]）に委ねる。
//! - 出力: 本 IdP の `EntityDescriptor`（`IDPSSODescriptor`）を生成する。SP（クライアント）がこの IdP を
//!   信頼するために取り込むメタデータで、`.well-known/openid-configuration` の SAML 版に相当する。
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

/// SP（クライアント）メタデータから取り込んだ登録候補値。登録フォームの初期値として提示する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSpMetadata {
    pub entity_id: String,
    /// AssertionConsumerService の URL（アサーション送信先）。
    pub acs_url: String,
    /// 署名用証明書（`<ds:X509Certificate>` 本文。空白除去した base64）。無ければ空文字。
    pub x509_certificate: String,
    /// `NameIDFormat`（あれば先頭）。
    pub name_id_format: Option<String>,
    /// `md:Organization` 由来の表示名（あれば）。
    pub display_name: Option<String>,
}

/// 取り込み中に本文テキストを収集する対象。
enum Capture {
    Certificate,
    DisplayName,
    NameIdFormat,
}

/// SP（クライアント）の `EntityDescriptor`（`SPSSODescriptor`）XML を解析し、登録候補値を抽出する。
///
/// - `entityID` と ACS URL（`SPSSODescriptor/AssertionConsumerService`）は必須。欠落時は
///   [`DomainError::InvalidValue`]。
/// - ACS URL は HTTP-POST → HTTP-Redirect → 先頭、の優先順で 1 件を選ぶ（アサーションは POST 送信が基本）。
/// - 証明書は `SPSSODescriptor` 内の署名用（`use="signing"` または `use` 無し）を優先して 1 件採用する。
pub fn parse_sp_metadata(xml: &str) -> Result<ImportedSpMetadata> {
    let mut reader = Reader::from_str(xml);

    let mut entity_id: Option<String> = None;
    let mut in_sp = false;
    // (binding, location) の ACS 候補。
    let mut acs_candidates: Vec<(String, String)> = Vec::new();
    let mut key_use: Option<String> = None;
    let mut signing_cert: Option<String> = None;
    let mut fallback_cert: Option<String> = None;
    let mut name_id_format: Option<String> = None;
    let mut display_name: Option<String> = None;

    let mut capture: Option<Capture> = None;
    let mut text_buf = String::new();
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
                b"SPSSODescriptor" if in_entity => in_sp = true,
                b"KeyDescriptor" if in_entity && in_sp => key_use = attribute(&e, b"use"),
                b"AssertionConsumerService" if in_entity && in_sp => {
                    push_sso(&e, &mut acs_candidates)
                }
                b"X509Certificate"
                    if in_entity && in_sp && key_use.as_deref() != Some("encryption") =>
                {
                    capture = Some(Capture::Certificate);
                    text_buf.clear();
                }
                b"NameIDFormat" if in_entity && in_sp && name_id_format.is_none() => {
                    capture = Some(Capture::NameIdFormat);
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
            Event::Empty(e) => match local(&e) {
                b"EntityDescriptor" if entity_id.is_none() => {
                    entity_id = attribute(&e, b"entityID");
                }
                b"KeyDescriptor" if in_entity && in_sp => key_use = attribute(&e, b"use"),
                b"AssertionConsumerService" if in_entity && in_sp => {
                    push_sso(&e, &mut acs_candidates)
                }
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
                b"EntityDescriptor" if in_entity => break,
                b"SPSSODescriptor" => in_sp = false,
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
                b"NameIDFormat" => {
                    if matches!(capture, Some(Capture::NameIdFormat)) {
                        let trimmed = text_buf.trim();
                        if !trimmed.is_empty() {
                            name_id_format.get_or_insert_with(|| trimmed.to_string());
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
    let acs_url = pick_acs_url(&acs_candidates).ok_or_else(|| {
        DomainError::InvalidValue(
            "SAML metadata is missing an SP AssertionConsumerService".to_string(),
        )
    })?;

    Ok(ImportedSpMetadata {
        entity_id: entity_id.trim().to_string(),
        acs_url,
        x509_certificate: signing_cert.or(fallback_cert).unwrap_or_default(),
        name_id_format,
        display_name,
    })
}

/// IdP の署名鍵の公開表現（XML Signature の `KeyValue`）。現状の署名鍵基盤は X.509 証明書を持たず
/// 生の公開鍵のみのため、`RSAKeyValue`（RS256）／`ECKeyValue`（ES256）で表現する。
pub enum IdpSigningKey {
    /// RSA 公開鍵（XMLDSIG `RSAKeyValue`）。値は大端バイト列の base64。
    Rsa {
        modulus_b64: String,
        exponent_b64: String,
    },
    /// EC 公開鍵（XMLDSIG11 `ECKeyValue`）。`named_curve_uri` は曲線の URN、`public_key_b64` は
    /// 非圧縮点（`0x04 || X || Y`）の base64。
    Ec {
        named_curve_uri: String,
        public_key_b64: String,
    },
}

impl IdpSigningKey {
    /// 署名用 `KeyDescriptor` の XML 片を生成する。
    fn to_key_descriptor(&self) -> String {
        let key_value = match self {
            IdpSigningKey::Rsa {
                modulus_b64,
                exponent_b64,
            } => format!(
                r#"<ds:KeyValue>
          <ds:RSAKeyValue>
            <ds:Modulus>{}</ds:Modulus>
            <ds:Exponent>{}</ds:Exponent>
          </ds:RSAKeyValue>
        </ds:KeyValue>"#,
                escape(modulus_b64),
                escape(exponent_b64),
            ),
            IdpSigningKey::Ec {
                named_curve_uri,
                public_key_b64,
            } => format!(
                r#"<ds11:ECKeyValue xmlns:ds11="http://www.w3.org/2009/xmldsig11#">
          <ds11:NamedCurve URI="{}"/>
          <ds11:PublicKey>{}</ds11:PublicKey>
        </ds11:ECKeyValue>"#,
                escape(named_curve_uri),
                escape(public_key_b64),
            ),
        };
        format!(
            r#"
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        {key_value}
      </ds:KeyInfo>
    </md:KeyDescriptor>"#
        )
    }
}

/// 本 IdP の SAML `EntityDescriptor`（`IDPSSODescriptor`）XML を生成する。
///
/// `entity_id` は IdP のエンティティ ID（テナント issuer を用いる）、`sso_url` は SingleSignOnService の
/// URL。`signing_key` があれば署名用 `KeyDescriptor`（`RSAKeyValue`/`ECKeyValue`）を含める。SP
/// （クライアント）はこの metadata を取り込んで本 IdP を信頼する。
pub fn build_idp_metadata_xml(
    entity_id: &str,
    sso_url: &str,
    signing_key: Option<&IdpSigningKey>,
) -> String {
    let entity_id = escape(entity_id);
    let sso_url = escape(sso_url);
    let key_descriptor = signing_key
        .map(IdpSigningKey::to_key_descriptor)
        .unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{key_descriptor}
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="{BINDING_HTTP_REDIRECT}" Location="{sso_url}"/>
    <md:SingleSignOnService Binding="{BINDING_HTTP_POST}" Location="{sso_url}"/>
  </md:IDPSSODescriptor>
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

/// ACS 候補から 1 件選ぶ。HTTP-POST → HTTP-Redirect → 先頭、の優先順（アサーションは POST 送信が基本）。
fn pick_acs_url(candidates: &[(String, String)]) -> Option<String> {
    pick_by_binding(candidates, &[BINDING_HTTP_POST, BINDING_HTTP_REDIRECT])
}

/// `preferred` のバインディング順で URL を選び、いずれも無ければ先頭を返す。
fn pick_by_binding(candidates: &[(String, String)], preferred: &[&str]) -> Option<String> {
    for binding in preferred {
        if let Some((_, loc)) = candidates.iter().find(|(b, _)| b == binding) {
            return Some(loc.clone());
        }
    }
    candidates.first().map(|(_, loc)| loc.clone())
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
    fn rejects_malformed_xml() {
        assert!(parse_sp_metadata("<EntityDescriptor><oops").is_err());
    }

    const SP_METADATA: &str = r#"<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://sp.example.test/saml/metadata">
  <md:SPSSODescriptor AuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>
        MIIBspCERTdata==
      </ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                 Location="https://sp.example.test/acs/redirect" index="1"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="https://sp.example.test/acs/post" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationDisplayName xml:lang="en">Example SP</md:OrganizationDisplayName>
  </md:Organization>
</md:EntityDescriptor>"#;

    #[test]
    fn parses_sp_entity_acs_cert_and_prefers_post_binding() {
        let parsed = parse_sp_metadata(SP_METADATA).expect("parse");
        assert_eq!(parsed.entity_id, "https://sp.example.test/saml/metadata");
        // ACS は POST を優先する。
        assert_eq!(parsed.acs_url, "https://sp.example.test/acs/post");
        assert_eq!(parsed.x509_certificate, "MIIBspCERTdata==");
        assert_eq!(
            parsed.name_id_format.as_deref(),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        );
        assert_eq!(parsed.display_name.as_deref(), Some("Example SP"));
    }

    #[test]
    fn sp_metadata_without_acs_is_rejected() {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:sp">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
</EntityDescriptor>"#;
        assert!(parse_sp_metadata(xml).is_err());
    }

    #[test]
    fn sp_metadata_does_not_pick_idp_sso_service() {
        // IdP メタデータ（SSO のみ・ACS 無し）を SP として取り込もうとすると失敗する。
        assert!(parse_sp_metadata(IDP_METADATA).is_err());
    }

    #[test]
    fn build_idp_metadata_contains_idp_descriptor_sso_and_signing_key() {
        let key = IdpSigningKey::Rsa {
            modulus_b64: "AQABmodulus==".to_string(),
            exponent_b64: "AQAB".to_string(),
        };
        let xml = build_idp_metadata_xml(
            "https://idp.example.com/tenant-1",
            "https://idp.example.com/tenant-1/saml/sso?x=1&y=2",
            Some(&key),
        );
        assert!(xml.contains(r#"entityID="https://idp.example.com/tenant-1""#));
        // IdP メタデータ（IDPSSODescriptor）であり、SP メタデータではない。
        assert!(xml.contains("IDPSSODescriptor"));
        assert!(!xml.contains("SPSSODescriptor"));
        assert!(xml.contains("<md:SingleSignOnService"));
        assert!(!xml.contains("AssertionConsumerService"));
        // 署名鍵は RSAKeyValue で埋め込まれる。
        assert!(xml.contains(r#"<md:KeyDescriptor use="signing">"#));
        assert!(xml.contains("<ds:Modulus>AQABmodulus==</ds:Modulus>"));
        assert!(xml.contains("<ds:Exponent>AQAB</ds:Exponent>"));
        // クエリの `&` は属性値としてエスケープされる。
        assert!(xml.contains("saml/sso?x=1&amp;y=2"));
        // 生成した XML は再パース可能（整形式）である。
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }

    #[test]
    fn build_idp_metadata_embeds_ec_key_as_eckeyvalue() {
        let key = IdpSigningKey::Ec {
            named_curve_uri: "urn:oid:1.2.840.10045.3.1.7".to_string(),
            public_key_b64: "BParbitraryPoint==".to_string(),
        };
        let xml = build_idp_metadata_xml("urn:idp", "https://idp.test/sso", Some(&key));
        assert!(xml.contains(r#"<md:KeyDescriptor use="signing">"#));
        assert!(xml.contains("<ds11:ECKeyValue"));
        assert!(xml.contains(r#"<ds11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/>"#));
        assert!(xml.contains("<ds11:PublicKey>BParbitraryPoint==</ds11:PublicKey>"));
        assert!(!xml.contains("RSAKeyValue"));
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }

    #[test]
    fn build_idp_metadata_omits_key_descriptor_when_no_signing_key() {
        let xml = build_idp_metadata_xml("urn:idp", "https://idp.test/sso", None);
        assert!(xml.contains("IDPSSODescriptor"));
        assert!(!xml.contains("KeyDescriptor"));
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }
}
