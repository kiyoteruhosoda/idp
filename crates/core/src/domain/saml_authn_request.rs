//! Receiving SAML 2.0 AuthnRequests (SP-initiated SSO, `/{tenant_id}/saml/sso`).
//!
//! - HTTP-Redirect binding: `SAMLRequest` query = base64(raw DEFLATE(XML))
//! - HTTP-POST binding: `SAMLRequest` form value = base64(XML)
//!
//! This only decodes and parses XML (extracting the SP entityID, request ID, ACS URL);
//! matching against registered SPs and ACS URL validation are left to the Application layer
//! ([`crate::application::saml_sso`]). Signatures of signed AuthnRequests are not verified
//! (assay's metadata declares `WantAuthnRequestsSigned="false"`).

use crate::domain::error::{DomainError, Result};
use crate::domain::xml_text;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::io::Read;

/// Upper bound (bytes) of the decoded XML. Blocks decompression bombs (zip bombs).
const MAX_XML_BYTES: usize = 128 * 1024;

/// A parsed AuthnRequest. Extracts only the values needed to identify the SP and respond
/// (`InResponseTo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAuthnRequest {
    /// `AuthnRequest/@ID` (used for the response's `InResponseTo`).
    pub request_id: Option<String>,
    /// `Issuer` text = the SP's entityID (key for resolving the registered SP).
    pub issuer: String,
    /// `AuthnRequest/@AssertionConsumerServiceURL` (when given, must match the registered value).
    pub acs_url: Option<String>,
}

/// Decodes the HTTP-Redirect binding `SAMLRequest` (base64(raw DEFLATE(XML))).
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

/// Decodes the HTTP-POST binding `SAMLRequest` (base64(XML)).
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

/// Base64 decoding. Spaces are turned back into `+` (a known compatibility issue: SPs that do not
/// percent-encode `+` get it turned into a space by form decoding; safe because spaces never appear
/// in base64), and whitespace such as newlines is removed before decoding with the standard
/// alphabet.
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

/// Parses AuthnRequest XML. Errors if the root element is not `AuthnRequest` or `Issuer` is
/// missing. Namespace prefixes are implementation-dependent, so local names are used (same policy
/// as [`crate::domain::saml_metadata`]).
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
                    if local != "AuthnRequest" {
                        return Err(DomainError::InvalidValue(
                            "SAMLRequest is not an AuthnRequest".to_string(),
                        ));
                    }
                    root_seen = true;
                    for attr in e.attributes().flatten() {
                        let value = match xml_text::attribute_value(&attr) {
                            Ok(v) => v.into_owned(),
                            Err(_) => continue,
                        };
                        match attr.key.local_name().as_ref() {
                            "ID" => request_id = Some(value),
                            "AssertionConsumerServiceURL" => acs_url = Some(value),
                            _ => {}
                        }
                    }
                } else if local == "Issuer" && issuer.is_none() {
                    capture_issuer = true;
                    issuer_buf.clear();
                }
            }
            Event::Text(e) => {
                if capture_issuer {
                    let decoded = xml_text::text(&e).map_err(|err| {
                        DomainError::InvalidValue(format!("invalid AuthnRequest text: {err}"))
                    })?;
                    issuer_buf.push_str(&decoded);
                }
            }
            Event::GeneralRef(e) => {
                if capture_issuer {
                    let decoded = xml_text::general_ref(&e).map_err(|err| {
                        DomainError::InvalidValue(format!("invalid AuthnRequest text: {err}"))
                    })?;
                    issuer_buf.push_str(&decoded);
                }
            }
            Event::End(e) => {
                if capture_issuer && strip_prefix(e.name().into_inner()) == "Issuer" {
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

/// Strips the prefix, e.g. `samlp:AuthnRequest` → `AuthnRequest`.
fn strip_prefix(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, local)| local)
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
        // For SPs that do not percent-encode `+`, form decoding of the query turns `+` into a
        // space. Spaces never appear in base64, so they are turned back into `+` and accepted.
        // Base64 with newlines (POST binding line wrapping) is accepted too.
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
        // XML over 128 KiB is rejected for both Redirect and POST bindings (against decompression
        // bombs).
        let big = format!(
            "<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\"><Issuer>urn:sp</Issuer><!--{}--></AuthnRequest>",
            "x".repeat(MAX_XML_BYTES)
        );
        assert!(decode_redirect_binding(&redirect_encode(&big)).is_err());
        assert!(decode_post_binding(&STANDARD.encode(&big)).is_err());
    }
}
