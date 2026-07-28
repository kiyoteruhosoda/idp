//! SAML 2.0 AuthnRequest の受信（SP-initiated SSO、`/{tenant_id}/saml/sso`）。
//!
//! - HTTP-Redirect binding: `SAMLRequest` クエリ = base64(raw DEFLATE(XML))
//! - HTTP-POST binding: `SAMLRequest` フォーム値 = base64(XML)
//!
//! ここではデコードと XML 解析（SP の entityID・リクエスト ID・ACS URL の抽出）のみを行い、
//! 登録済み SP との突き合わせ・ACS URL の検証は Application 層
//! （[`crate::application::saml_sso`]）に委ねる。署名付き AuthnRequest の署名検証は行わない
//! （本 IdP のメタデータは `WantAuthnRequestsSigned="false"` を宣言している）。

use crate::domain::error::{DomainError, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::io::Read;

/// デコード後 XML の上限（バイト）。展開爆弾（zip bomb）を遮断する。
const MAX_XML_BYTES: usize = 128 * 1024;

/// 解析済み AuthnRequest。SP の特定と応答（`InResponseTo`）に必要な値のみ抽出する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuthnRequest {
    /// `AuthnRequest/@ID`（応答の `InResponseTo` に使う）。
    pub request_id: Option<String>,
    /// `Issuer` 本文 = SP の entityID（登録済み SP の解決キー）。
    pub issuer: String,
    /// `AuthnRequest/@AssertionConsumerServiceURL`（指定時は登録値との一致を要求する）。
    pub acs_url: Option<String>,
}

/// HTTP-Redirect binding の `SAMLRequest`（base64(raw DEFLATE(XML))）をデコードする。
pub fn decode_redirect_binding(saml_request: &str) -> Result<String> {
    let compressed = decode_base64(saml_request)?;
    let mut decoder = flate2::read::DeflateDecoder::new(compressed.as_slice());
    let mut xml = Vec::new();
    decoder
        .by_ref()
        .take((MAX_XML_BYTES + 1) as u64)
        .read_to_end(&mut xml)
        .map_err(|e| DomainError::InvalidValue(format!("SAMLRequest inflate failed: {e}")))?;
    if xml.len() > MAX_XML_BYTES {
        return Err(DomainError::InvalidValue(
            "SAMLRequest is too large".to_string(),
        ));
    }
    String::from_utf8(xml)
        .map_err(|_| DomainError::InvalidValue("SAMLRequest is not valid UTF-8".to_string()))
}

/// HTTP-POST binding の `SAMLRequest`（base64(XML)）をデコードする。
pub fn decode_post_binding(saml_request: &str) -> Result<String> {
    let xml = decode_base64(saml_request)?;
    if xml.len() > MAX_XML_BYTES {
        return Err(DomainError::InvalidValue(
            "SAMLRequest is too large".to_string(),
        ));
    }
    String::from_utf8(xml)
        .map_err(|_| DomainError::InvalidValue("SAMLRequest is not valid UTF-8".to_string()))
}

/// base64 デコード。スペースは `+` へ戻し（`+` を percent-encode しない SP のクエリは
/// フォームデコードでスペース化する既知の互換問題。スペースは base64 に現れないため安全）、
/// 改行等の空白は除去してから標準アルファベットで復号する。
fn decode_base64(value: &str) -> Result<Vec<u8>> {
    let cleaned: String = value
        .chars()
        .map(|c| if c == ' ' { '+' } else { c })
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| DomainError::InvalidValue(format!("SAMLRequest base64 decode failed: {e}")))
}

/// AuthnRequest XML を解析する。ルート要素が `AuthnRequest` でない・`Issuer` が無い場合はエラー。
/// 名前空間接頭辞は実装依存のためローカル名で判定する（[`crate::domain::saml_metadata`] と同方針）。
pub fn parse_authn_request(xml: &str) -> Result<ParsedAuthnRequest> {
    let mut reader = Reader::from_str(xml);

    let mut request_id: Option<String> = None;
    let mut acs_url: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut root_seen = false;
    let mut capture_issuer = false;
    let mut issuer_buf = String::new();

    loop {
        match reader
            .read_event()
            .map_err(|e| DomainError::InvalidValue(format!("invalid AuthnRequest XML: {e}")))?
        {
            Event::Start(e) | Event::Empty(e) => {
                let name = e.name();
                let local = strip_prefix(name.into_inner());
                if !root_seen {
                    if local != b"AuthnRequest" {
                        return Err(DomainError::InvalidValue(
                            "SAMLRequest is not an AuthnRequest".to_string(),
                        ));
                    }
                    root_seen = true;
                    for attr in e.attributes().flatten() {
                        let value = match attr.unescape_value() {
                            Ok(v) => v.into_owned(),
                            Err(_) => continue,
                        };
                        match attr.key.local_name().as_ref() {
                            b"ID" => request_id = Some(value),
                            b"AssertionConsumerServiceURL" => acs_url = Some(value),
                            _ => {}
                        }
                    }
                } else if local == b"Issuer" && issuer.is_none() {
                    capture_issuer = true;
                    issuer_buf.clear();
                }
            }
            Event::Text(e) => {
                if capture_issuer {
                    let decoded = e.unescape().map_err(|err| {
                        DomainError::InvalidValue(format!("invalid AuthnRequest text: {err}"))
                    })?;
                    issuer_buf.push_str(&decoded);
                }
            }
            Event::End(e) => {
                if capture_issuer && strip_prefix(e.name().into_inner()) == b"Issuer" {
                    let trimmed = issuer_buf.trim();
                    if !trimmed.is_empty() {
                        issuer = Some(trimmed.to_string());
                    }
                    capture_issuer = false;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if !root_seen {
        return Err(DomainError::InvalidValue(
            "SAMLRequest is not an AuthnRequest".to_string(),
        ));
    }
    let issuer = issuer.ok_or_else(|| {
        DomainError::InvalidValue("AuthnRequest is missing an Issuer".to_string())
    })?;

    Ok(ParsedAuthnRequest {
        request_id: request_id.filter(|s| !s.trim().is_empty()),
        issuer,
        acs_url: acs_url.filter(|s| !s.trim().is_empty()),
    })
}

/// `samlp:AuthnRequest` → `AuthnRequest` のように接頭辞を除く。
fn strip_prefix(name: &[u8]) -> &[u8] {
    match name.iter().position(|&b| b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    const AUTHN_REQUEST: &str = r#"<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_abc123" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"
                    AssertionConsumerServiceURL="https://sp.example.test/acs"
                    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://sp.example.test/metadata</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"#;

    fn redirect_encode(xml: &str) -> String {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).expect("deflate");
        STANDARD.encode(encoder.finish().expect("finish"))
    }

    #[test]
    fn parses_id_issuer_and_acs_url() {
        let parsed = parse_authn_request(AUTHN_REQUEST).expect("parse");
        assert_eq!(parsed.request_id.as_deref(), Some("_abc123"));
        assert_eq!(parsed.issuer, "https://sp.example.test/metadata");
        assert_eq!(
            parsed.acs_url.as_deref(),
            Some("https://sp.example.test/acs")
        );
    }

    #[test]
    fn redirect_binding_round_trips_deflate_and_base64() {
        let xml = decode_redirect_binding(&redirect_encode(AUTHN_REQUEST)).expect("decode");
        let parsed = parse_authn_request(&xml).expect("parse");
        assert_eq!(parsed.issuer, "https://sp.example.test/metadata");
    }

    #[test]
    fn post_binding_round_trips_base64() {
        let xml = decode_post_binding(&STANDARD.encode(AUTHN_REQUEST)).expect("decode");
        assert!(xml.contains("AuthnRequest"));
    }

    #[test]
    fn tolerates_plus_decoded_to_space_and_embedded_newlines() {
        // `+` を percent-encode しない SP はクエリのフォームデコードで `+` がスペースになる。
        // スペースは base64 に現れないため `+` へ戻して受理する。改行入り base64（POST binding の
        // 折り返し）も受理する。
        let encoded = redirect_encode(AUTHN_REQUEST);
        let mangled = encoded.replace('+', " ");
        let xml = decode_redirect_binding(&mangled).expect("decode with spaces");
        assert_eq!(
            parse_authn_request(&xml).expect("parse").issuer,
            "https://sp.example.test/metadata"
        );

        let wrapped: String = STANDARD
            .encode(AUTHN_REQUEST)
            .as_bytes()
            .chunks(64)
            .map(|chunk| format!("{}\n", String::from_utf8_lossy(chunk)))
            .collect();
        assert!(decode_post_binding(&wrapped)
            .expect("decode")
            .contains("AuthnRequest"));
    }

    #[test]
    fn rejects_non_authn_request_root() {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x">
  <Issuer>urn:sp</Issuer>
</samlp:LogoutRequest>"#;
        assert!(parse_authn_request(xml).is_err());
    }

    #[test]
    fn rejects_missing_issuer() {
        let xml =
            r#"<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0"/>"#;
        assert!(parse_authn_request(xml).is_err());
    }

    #[test]
    fn rejects_invalid_base64_and_garbage_deflate() {
        assert!(decode_redirect_binding("%%%").is_err());
        assert!(decode_redirect_binding(&STANDARD.encode(b"not deflate")).is_err());
        assert!(decode_post_binding("%%%").is_err());
    }

    #[test]
    fn rejects_oversized_payloads() {
        // 128 KiB 超の XML は Redirect / POST の両バインディングで拒否する（展開爆弾対策）。
        let big = format!(
            "<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\"><Issuer>urn:sp</Issuer><!--{}--></AuthnRequest>",
            "x".repeat(MAX_XML_BYTES)
        );
        assert!(decode_redirect_binding(&redirect_encode(&big)).is_err());
        assert!(decode_post_binding(&STANDARD.encode(&big)).is_err());
    }
}
