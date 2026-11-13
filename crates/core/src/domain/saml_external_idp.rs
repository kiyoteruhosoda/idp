//! Using an external SAML IdP as an authentication source (SP side; AP12; ADR-0027).
//!
//! The side that makes assay act **as a SAML IdP** is in [`crate::domain::saml_response`]. Here the
//! direction is reversed: users are sent to an external SAML IdP, and the returned assertion is
//! verified to extract "who was authenticated".
//!
//! # Differences from OIDC
//!
//! - No server-to-server communication. Everything goes through the browser (sent with
//!   HTTP-Redirect, received with HTTP-POST), so no port like [`crate::domain::external_oidc_port`]
//!   is needed.
//! - Nothing corresponds to `nonce`. Replay prevention relies on `InResponseTo` (ID of the
//!   AuthnRequest sent), single-use `RelayState`, and time checks of `NotBefore` / `NotOnOrAfter`.
//! - Authenticity rests **only on the signature**. It is not carried over TLS (the browser POSTs
//!   it), so values read without checking the signature are indistinguishable from what an attacker
//!   wrote.
//!
//! # Reading order
//!
//! [`consume_response`] enforces "verify, then read" by type. It first verifies the signature,
//! obtains **the ID of the verified element**, and then re-reads only inside the element with that
//! ID. Walking different subtrees for verification and reading invites endless deception by
//! signature wrapping (XSW).

use crate::domain::error::{DomainError, Result};
use crate::domain::xml_signature::verify_enveloped_signature;
use crate::domain::xml_text;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::io::Write as _;

/// Upper bound on received XML (same reason and value as `saml_authn_request`).
const MAX_XML_BYTES: usize = 512 * 1024;
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
/// Allowed skew for time checks. The clocks of the IdP and assay never match perfectly.
const CLOCK_SKEW_SECS: i64 = 120;
/// Default `NameIDFormat`. Can be overridden to match the IdP's settings.
pub const NAME_ID_FORMAT_UNSPECIFIED: &str =
    "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified";
pub const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// Inputs for building an `AuthnRequest`.
pub struct AuthnRequestInput<'a> {
    /// The numbered request ID (store it; it is used to match `InResponseTo`).
    pub request_id: &'a str,
    pub issued_at: DateTime<Utc>,
    /// assay's entityID as an SP.
    pub sp_entity_id: &'a str,
    /// URL receiving the assertion (ACS).
    pub acs_url: &'a str,
    /// The external IdP's SSO endpoint (`Destination`).
    pub sso_url: &'a str,
    /// Requested `NameIDFormat`.
    pub name_id_format: &'a str,
}

/// Builds the `AuthnRequest` XML.
///
/// Not signed (ADR-0027). It would require registering / rotating the SP key at the IdP, while all
/// it gives is "assurance of the request's origin"; assertion authenticity is ensured by verifying
/// the response signature.
pub fn build_authn_request_xml(input: &AuthnRequestInput<'_>) -> String {
    let issued = input.issued_at.format("%Y-%m-%dT%H:%M:%SZ");
    format!(
        concat!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol""#,
            r#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#,
            r#" ID="{id}" Version="2.0" IssueInstant="{issued}""#,
            r#" Destination="{destination}" ProtocolBinding="{binding}""#,
            r#" AssertionConsumerServiceURL="{acs}">"#,
            r#"<saml:Issuer>{issuer}</saml:Issuer>"#,
            r#"<samlp:NameIDPolicy Format="{format}" AllowCreate="true"></samlp:NameIDPolicy>"#,
            r#"</samlp:AuthnRequest>"#
        ),
        id = escape(input.request_id),
        issued = issued,
        destination = escape(input.sso_url),
        binding = BINDING_HTTP_POST,
        acs = escape(input.acs_url),
        issuer = escape(input.sp_entity_id),
        format = escape(input.name_id_format),
    )
}

/// Builds the HTTP-Redirect binding destination URL (`SAMLRequest` = base64(raw DEFLATE(XML))).
///
/// Not signed, so no `SigAlg` / `Signature`.
pub fn redirect_binding_location(
    sso_url: &str,
    authn_request_xml: &str,
    relay_state: &str,
) -> Result<String> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(authn_request_xml.as_bytes())
        .map_err(|e| DomainError::Repository(format!("failed to deflate AuthnRequest: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| DomainError::Repository(format!("failed to deflate AuthnRequest: {e}")))?;
    let encoded = STANDARD.encode(compressed);
    let separator = if sso_url.contains('?') { '&' } else { '?' };
    let encode = |v: &str| utf8_percent_encode(v, NON_ALPHANUMERIC).to_string();
    Ok(format!(
        "{sso_url}{separator}SAMLRequest={}&RelayState={}",
        encode(&encoded),
        encode(relay_state)
    ))
}

/// Claims extracted from a verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// `Issuer` text (the IdP's entityID). Must exactly match the configured `issuer`.
    pub issuer: String,
    /// `Subject/NameID` text. The external identity (equivalent to OIDC's `sub`).
    pub name_id: String,
    /// Email taken from attributes (`email` / `mail` / EduPerson `urn:oid:0.9.2342...`).
    pub email: Option<String>,
    /// Display name taken from attributes.
    pub display_name: Option<String>,
    /// `SubjectConfirmationData/@InResponseTo` (ID of the AuthnRequest sent).
    pub in_response_to: Option<String>,
}

/// Settings and context used to verify the response.
pub struct ResponseVerification<'a> {
    /// The configured IdP's entityID. Must exactly match the assertion's `Issuer`.
    pub expected_issuer: &'a str,
    /// assay's entityID as an SP. Must be included in `AudienceRestriction`.
    pub sp_entity_id: &'a str,
    /// ID of the `AuthnRequest` we sent. Must match `InResponseTo`.
    pub expected_in_response_to: &'a str,
    /// Certificates for signature verification (base64 DER; several allowed = old and new during
    /// rollover).
    pub certificates: &'a [String],
    pub now: DateTime<Utc>,
}

/// Verifies an HTTP-POST binding `SAMLResponse` (base64(XML)) and extracts the claims.
///
/// Verification order is "signature → status → time / audience". Values read before the signature
/// are indistinguishable from what an attacker wrote, so **reading happens only inside elements
/// covered by the signature**.
pub fn consume_response(
    saml_response_b64: &str,
    verification: &ResponseVerification<'_>,
) -> Result<VerifiedAssertion> {
    let xml = decode_post_binding(saml_response_b64)?;
    let outline = outline_response(&xml)?;

    // 1. Exactly one assertion. Zero or two or more are refused (with several, "which was read" and
    //    "which was signed" could diverge = an entry point for XSW).
    if outline.assertion_ids.len() != 1 {
        return Err(DomainError::InvalidValue(format!(
            "the response must carry exactly one assertion, found {}",
            outline.assertion_ids.len()
        )));
    }
    let assertion_id = outline.assertion_ids[0].clone();

    // 2. Signature. It is normally on the assertion itself, but some IdPs sign the whole Response.
    //    When passing via the Response signature, that the assertion is **inside the signed
    //    Response** is ensured by the structure: the Response is signed and the assertion is its
    //    child (`outline` counts only assertions directly under the Response).
    //
    //    When the assertion-side verification fails, return **that** reason (do not overwrite
    //    it with "no signature" from the failed Response-side verification). If the reason for a
    //    tampered assertion showed as "Response has no signature", operators could not trace the
    //    cause.
    if let Err(assertion_error) =
        verify_enveloped_signature(&xml, &assertion_id, verification.certificates)
    {
        let response_signed = outline.response_id.as_deref().is_some_and(|response_id| {
            verify_enveloped_signature(&xml, response_id, verification.certificates).is_ok()
        });
        if !response_signed {
            return Err(assertion_error);
        }
    }

    // 3. Status code. Anything other than `Success` means "the user was refused / the IdP failed",
    //    so drop it before reading the assertion.
    if outline.status_code.as_deref() != Some(STATUS_SUCCESS) {
        return Err(DomainError::InvalidValue(format!(
            "the identity provider returned status {}",
            outline
                .status_code
                .unwrap_or_else(|| "(missing)".to_string())
        )));
    }

    // 4. Re-read only inside the verified assertion.
    let assertion = read_assertion(&xml, &assertion_id)?;

    if assertion.issuer != verification.expected_issuer {
        return Err(DomainError::InvalidValue(
            "the assertion was issued by a different entity than the configured issuer".to_string(),
        ));
    }
    if assertion.name_id.trim().is_empty() {
        return Err(DomainError::InvalidValue(
            "the assertion carries no NameID".to_string(),
        ));
    }
    if !assertion
        .audiences
        .iter()
        .any(|a| a == verification.sp_entity_id)
    {
        return Err(DomainError::InvalidValue(
            "the assertion is not addressed to this service provider".to_string(),
        ));
    }
    match assertion.in_response_to.as_deref() {
        Some(value) if value == verification.expected_in_response_to => {}
        Some(_) => {
            return Err(DomainError::InvalidValue(
                "the assertion answers a different authentication request".to_string(),
            ))
        }
        // IdP-initiated responses (arriving without a request) are not accepted. Accepting them
        // would let an attacker complete a login just by having the victim's browser POST an
        // assertion the attacker prepared.
        None => {
            return Err(DomainError::InvalidValue(
                "unsolicited assertions are not accepted".to_string(),
            ))
        }
    }

    let skew = Duration::seconds(CLOCK_SKEW_SECS);
    if let Some(not_before) = assertion.not_before {
        if verification.now + skew < not_before {
            return Err(DomainError::InvalidValue(
                "the assertion is not valid yet".to_string(),
            ));
        }
    }
    let Some(not_on_or_after) = assertion.not_on_or_after else {
        return Err(DomainError::InvalidValue(
            "the assertion has no expiry".to_string(),
        ));
    };
    if verification.now - skew >= not_on_or_after {
        return Err(DomainError::InvalidValue(
            "the assertion has expired".to_string(),
        ));
    }

    Ok(VerifiedAssertion {
        issuer: assertion.issuer,
        name_id: assertion.name_id,
        email: assertion.email,
        display_name: assertion.display_name,
        in_response_to: assertion.in_response_to,
    })
}

/// Structure-only information read before signature verification. **Values are not used** (they are
/// not covered by the signature).
struct ResponseOutline {
    response_id: Option<String>,
    /// `ID` of the `Assertion` directly under `Response`.
    assertion_ids: Vec<String>,
    status_code: Option<String>,
}

fn outline_response(xml: &str) -> Result<ResponseOutline> {
    let mut reader = Reader::from_reader(xml.as_bytes());
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut depth = 0usize;
    let mut response_depth: Option<usize> = None;
    let mut response_id = None;
    let mut assertion_ids = Vec::new();
    let mut status_code = None;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| DomainError::InvalidValue(format!("malformed SAMLResponse: {e}")))?;
        let (start, is_empty) = match event {
            Event::Eof => break,
            Event::Start(e) => (Some(e.into_owned()), false),
            Event::Empty(e) => (Some(e.into_owned()), true),
            Event::End(_) => {
                if response_depth == Some(depth) {
                    response_depth = None;
                }
                depth = depth.saturating_sub(1);
                buf.clear();
                continue;
            }
            _ => {
                buf.clear();
                continue;
            }
        };
        let Some(e) = start else { continue };
        depth += 1;
        let local = local_name(e.name().as_ref())?;
        match local.as_str() {
            "Response" if response_depth.is_none() => {
                response_depth = Some(depth);
                response_id = attribute(&e, "ID")?;
            }
            "Assertion" if response_depth == Some(depth - 1) => {
                let id = attribute(&e, "ID")?.ok_or_else(|| {
                    DomainError::InvalidValue("the assertion has no ID".to_string())
                })?;
                assertion_ids.push(id);
            }
            "StatusCode" if status_code.is_none() => {
                status_code = attribute(&e, "Value")?;
            }
            _ => {}
        }
        if is_empty {
            if response_depth == Some(depth) {
                response_depth = None;
            }
            depth = depth.saturating_sub(1);
        }
        buf.clear();
    }
    if response_depth.is_some() {
        return Err(DomainError::InvalidValue(
            "malformed SAMLResponse: unterminated Response".to_string(),
        ));
    }
    Ok(ResponseOutline {
        response_id,
        assertion_ids,
        status_code,
    })
}

/// Values read from a verified assertion.
struct AssertionContents {
    issuer: String,
    name_id: String,
    audiences: Vec<String>,
    in_response_to: Option<String>,
    not_before: Option<DateTime<Utc>>,
    not_on_or_after: Option<DateTime<Utc>>,
    email: Option<String>,
    display_name: Option<String>,
}

/// Attribute names treated as email (matched against either `Name` or `FriendlyName`).
const EMAIL_ATTRIBUTES: [&str; 4] = [
    "email",
    "mail",
    "urn:oid:0.9.2342.19200300.100.1.3",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
];
const NAME_ATTRIBUTES: [&str; 4] = [
    "displayName",
    "cn",
    "urn:oid:2.16.840.1.113730.3.1.241",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
];

fn read_assertion(xml: &str, assertion_id: &str) -> Result<AssertionContents> {
    let mut reader = Reader::from_reader(xml.as_bytes());
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut depth = 0usize;
    let mut assertion_depth: Option<usize> = None;
    // Position within the assertion. Only the `Issuer` directly under Assertion is read (not ones
    // inside `Signature` or the Response's `Issuer`).
    let mut path: Vec<String> = Vec::new();
    let mut capture: Option<Capture> = None;
    let mut captured = String::new();

    let mut issuer = None;
    let mut name_id = None;
    let mut audiences = Vec::new();
    let mut in_response_to = None;
    let mut not_before = None;
    let mut not_on_or_after = None;
    let mut email = None;
    let mut display_name = None;
    let mut current_attribute: Option<AttributeKind> = None;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| DomainError::InvalidValue(format!("malformed assertion: {e}")))?;
        let (start, is_empty) = match event {
            Event::Eof => break,
            Event::Start(e) => (Some(e.into_owned()), false),
            Event::Empty(e) => (Some(e.into_owned()), true),
            Event::End(_) => {
                finish_capture(
                    &mut capture,
                    &mut captured,
                    &mut issuer,
                    &mut name_id,
                    &mut audiences,
                    &mut email,
                    &mut display_name,
                    current_attribute,
                );
                if path.last().map(String::as_str) == Some("Attribute") {
                    current_attribute = None;
                }
                path.pop();
                if assertion_depth == Some(depth) {
                    break;
                }
                depth = depth.saturating_sub(1);
                buf.clear();
                continue;
            }
            Event::Text(e) => {
                if capture.is_some() {
                    let text = xml_text::text(&e)
                        .map_err(|err| DomainError::InvalidValue(format!("bad text: {err}")))?;
                    captured.push_str(&text);
                }
                buf.clear();
                continue;
            }
            Event::GeneralRef(e) => {
                if capture.is_some() {
                    let text = xml_text::general_ref(&e)
                        .map_err(|err| DomainError::InvalidValue(format!("bad text: {err}")))?;
                    captured.push_str(&text);
                }
                buf.clear();
                continue;
            }
            _ => {
                buf.clear();
                continue;
            }
        };
        let Some(e) = start else { continue };
        depth += 1;
        let local = local_name(e.name().as_ref())?;
        path.push(local.clone());

        if assertion_depth.is_none() {
            if local == "Assertion" && attribute(&e, "ID")?.as_deref() == Some(assertion_id) {
                assertion_depth = Some(depth);
            }
        } else {
            // Do not read inside the signature (values inside `ds:Signature` are not claims).
            let in_signature = path.iter().any(|p| p == "Signature");
            if !in_signature {
                match local.as_str() {
                    "Issuer" if issuer.is_none() => {
                        capture = Some(Capture::Issuer);
                        captured.clear();
                    }
                    "NameID" if name_id.is_none() => {
                        capture = Some(Capture::NameId);
                        captured.clear();
                    }
                    "Audience" => {
                        capture = Some(Capture::Audience);
                        captured.clear();
                    }
                    "SubjectConfirmationData" => {
                        if in_response_to.is_none() {
                            in_response_to = attribute(&e, "InResponseTo")?;
                        }
                        if not_on_or_after.is_none() {
                            not_on_or_after = parse_instant(attribute(&e, "NotOnOrAfter")?)?;
                        }
                    }
                    "Conditions" => {
                        not_before = parse_instant(attribute(&e, "NotBefore")?)?;
                        if let Some(value) = parse_instant(attribute(&e, "NotOnOrAfter")?)? {
                            not_on_or_after = Some(value);
                        }
                    }
                    "Attribute" => {
                        let name = attribute(&e, "Name")?.unwrap_or_default();
                        let friendly = attribute(&e, "FriendlyName")?.unwrap_or_default();
                        current_attribute = if EMAIL_ATTRIBUTES.iter().any(|a| {
                            a.eq_ignore_ascii_case(&name) || a.eq_ignore_ascii_case(&friendly)
                        }) {
                            Some(AttributeKind::Email)
                        } else if NAME_ATTRIBUTES.iter().any(|a| {
                            a.eq_ignore_ascii_case(&name) || a.eq_ignore_ascii_case(&friendly)
                        }) {
                            Some(AttributeKind::DisplayName)
                        } else {
                            None
                        };
                    }
                    "AttributeValue" if current_attribute.is_some() => {
                        capture = Some(Capture::AttributeValue);
                        captured.clear();
                    }
                    _ => {}
                }
            }
        }

        if is_empty {
            finish_capture(
                &mut capture,
                &mut captured,
                &mut issuer,
                &mut name_id,
                &mut audiences,
                &mut email,
                &mut display_name,
                current_attribute,
            );
            if local == "Attribute" {
                current_attribute = None;
            }
            path.pop();
            if assertion_depth == Some(depth) {
                break;
            }
            depth = depth.saturating_sub(1);
        }
        buf.clear();
    }

    Ok(AssertionContents {
        issuer: issuer.unwrap_or_default(),
        name_id: name_id.unwrap_or_default(),
        audiences,
        in_response_to,
        not_before,
        not_on_or_after,
        email,
        display_name,
    })
}

#[derive(Clone, Copy)]
enum Capture {
    Issuer,
    NameId,
    Audience,
    AttributeValue,
}

#[derive(Clone, Copy)]
enum AttributeKind {
    Email,
    DisplayName,
}

#[allow(clippy::too_many_arguments)]
fn finish_capture(
    capture: &mut Option<Capture>,
    captured: &mut String,
    issuer: &mut Option<String>,
    name_id: &mut Option<String>,
    audiences: &mut Vec<String>,
    email: &mut Option<String>,
    display_name: &mut Option<String>,
    attribute_kind: Option<AttributeKind>,
) {
    let Some(kind) = capture.take() else { return };
    let value = captured.trim().to_string();
    captured.clear();
    if value.is_empty() {
        return;
    }
    match kind {
        Capture::Issuer => *issuer = Some(value),
        Capture::NameId => *name_id = Some(value),
        Capture::Audience => audiences.push(value),
        Capture::AttributeValue => match attribute_kind {
            Some(AttributeKind::Email) if email.is_none() => *email = Some(value),
            Some(AttributeKind::DisplayName) if display_name.is_none() => {
                *display_name = Some(value)
            }
            _ => {}
        },
    }
}

/// Decodes the HTTP-POST binding `SAMLResponse` (base64(XML)).
fn decode_post_binding(value: &str) -> Result<String> {
    let cleaned: String = value
        .chars()
        .map(|c| if c == ' ' { '+' } else { c })
        .filter(|c| !c.is_whitespace())
        .collect();
    let xml = STANDARD.decode(cleaned.as_bytes()).map_err(|e| {
        DomainError::InvalidValue(format!("SAMLResponse base64 decode failed: {e}"))
    })?;
    if xml.len() > MAX_XML_BYTES {
        return Err(DomainError::InvalidValue(
            "SAMLResponse is too large".to_string(),
        ));
    }
    String::from_utf8(xml)
        .map_err(|_| DomainError::InvalidValue("SAMLResponse is not valid UTF-8".to_string()))
}

fn parse_instant(value: Option<String>) -> Result<Option<DateTime<Utc>>> {
    let Some(value) = value else { return Ok(None) };
    let parsed = DateTime::parse_from_rfc3339(value.trim())
        .map_err(|e| DomainError::InvalidValue(format!("invalid SAML instant `{value}`: {e}")))?;
    Ok(Some(parsed.with_timezone(&Utc)))
}

fn local_name(name: &str) -> Result<String> {
    Ok(name
        .rsplit_once(':')
        .map(|(_, l)| l)
        .unwrap_or(name)
        .to_string())
}

fn attribute(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Result<Option<String>> {
    for attr in e.attributes() {
        let attr =
            attr.map_err(|err| DomainError::InvalidValue(format!("bad attribute: {err}")))?;
        if local_name(attr.key.as_ref())? == name {
            let value = xml_text::attribute_value(&attr)
                .map_err(|err| DomainError::InvalidValue(format!("bad attribute value: {err}")))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

fn escape(value: &str) -> String {
    quick_xml::escape::escape(value).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::saml_response::{
        build_signed_response_xml, generate_saml_id, SamlResponseInput, SamlSigner,
    };
    use chrono::TimeZone;

    /// A self-signed certificate for tests only and its key (PKCS#1 PEM). Real ones made with
    /// `openssl req -x509`, **referenced from nowhere in production**. Signatures are made by the
    /// IdP-side generator (`saml_response`) and checked by the SP-side verifier — this also
    /// confirms that canonicalization matches between the two.
    const TEST_KEY_PEM: &str = concat!(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "MIIEpAIBAAKCAQEAtNcidptZa/sP2KxNTbEXiEYxtt4F90gKhG3xx/uAcHlHUdmW\n",
        "AqDzM+oOBgOOGusX5FFBFXZZfZ0QkuK62zEryXs3UujdzdY7zOmbqX+i3nC0CoIe\n",
        "DpkE8ZnFhxQEg1dpTfgYkiJ40bLYv7/eDz6EqU6vQfCytsh78KlkzOsWsrKoqpjw\n",
        "YIA0brZ6kZ+WC6R+tgZL7vJW0goEOtQ33oOclvqPUgLrw7gio5Ojz9qMfVBhNmAt\n",
        "8bC1UoZaw8ZuRWm3HQKakXn9j6wLaXE+VwrzZ1qVwTKzipIiCTzxg8ko7WsgMu0z\n",
        "M2aNjBDztvqw6vvfNJu2O9Dw48vt7fognnr16QIDAQABAoIBAAJwGgdWTczOXCbU\n",
        "H9Cp0ALmy1nHQXZVcsrZPpavFcquX99DGyoa6FxtTdYX6y0CuVY7IDD9YPR4Dxaj\n",
        "1tgIoCn9rr+/4umY90Jqbc5JqbTs+QhhO61/s5jcNVT+WJc6sPE7pH0n2NAe5Jwl\n",
        "JoW3Fou/w04UxBwBtOYIKpM2oh4zk5QWXJs/crAvCFlixednlz8mM88jF+PK04gt\n",
        "K0zEbK5LIZEMpBFOz+XRUQ62gigTpZBj3YXCbOBM00AEiL5b/rIzBS3ULgMNCDG4\n",
        "fdeHGv2bxhhZdN/acNh63Yr05iZM1umbye0yvu80p0CydTfxBPGOl7e6OQ1SuuT+\n",
        "CZA/gQECgYEA247YUvx8kIW8BzGARMxJLwX94ZUfxa4u5wRTQ3wtaFHcd074R2zS\n",
        "kyoG5DwAE01IgJ/WwcG0HQ3SNsDkEM0yTtv90HC2gbK3YorT4FcNOZzNvCYGRN6R\n",
        "RBVYtHetg2YrKXRAMn8Qy9Gi9uvVf3DryLdvH1nRkFkiAZDpDmcvksECgYEA0tsn\n",
        "bBmtBYUX2fkUE+mXGihxB5ciYxoWIWnglMhpMsIOoeI9K6uvdhVgc6caZw2bUpi6\n",
        "/w7THsuG7JGBzOlxMpe89xWBB+TEMwKitaVQAuSNOcUHR1HxTrDliSj0pL8H+qvt\n",
        "m7pes2Y624PN2yiSgvsQHReeqYwH4uHLg22atSkCgYEA1Logardr0XNh7O5PQ1lT\n",
        "hxYdGFYuRJAxrW+JZReJv0uheo+vCzUrCZ9ssfJYeFsm5kj4AR827feYN6jI0Gag\n",
        "WbvYvf6XNi78c6PjCbgOfkWpKKUG6e9jfD3ahnB2U5vIMhAKq2Jl2bUyWl/Bqgq0\n",
        "yPLB3fRekadqxW2sAWKEu4ECgYEAzLRYxHj04fwBWOuY03Ae8xU6Dp1qk/26aHwK\n",
        "vUcH4nBFlmI28tO+B4zfU8hyOIQcPAbs3Dv/ONFszvTAqDgmXnCz0sk8uHYfCErR\n",
        "vjmcwQI0HVasJ1BlTfktDokFYX/YdkM97cb0s4RXNc/zJYZxHtoxHZ1VutKowVpm\n",
        "otTgsmkCgYBliNbW1c/M7blO4m1XeiGeiY1Pvx0S5UF4QBAK4J0GeyhrTs75hfJQ\n",
        "a6LZN9vdOyJgscruyMsLs+f4JyHdRy6+HRLeBAnKJXvJNe+hmWGG1usff1tQPDd6\n",
        "nkc33BX3Yu3ZV6agi/W7wdQOMQHaWNNlR4h76bNOXSF44fFlkh+6/Q==\n",
        "-----END RSA PRIVATE KEY-----\n"
    );

    const TEST_CERTIFICATE: &str = concat!(
        "MIIDEzCCAfugAwIBAgIUS/GBZGhWNXp2jDPH758Z9FfRuTcwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAww",
        "Nc2FtbC10ZXN0LWlkcDAgFw0yNjA4MTAxNzE0MzFaGA8yMTI2MDcxNzE3MTQzMVowGDEWMBQGA1UEAwwNc2",
        "FtbC10ZXN0LWlkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALTXInabWWv7D9isTU2xF4hGM",
        "bbeBfdICoRt8cf7gHB5R1HZlgKg8zPqDgYDjhrrF+RRQRV2WX2dEJLiutsxK8l7N1Lo3c3WO8zpm6l/ot5w",
        "tAqCHg6ZBPGZxYcUBINXaU34GJIieNGy2L+/3g8+hKlOr0HwsrbIe/CpZMzrFrKyqKqY8GCANG62epGflgu",
        "kfrYGS+7yVtIKBDrUN96DnJb6j1IC68O4IqOTo8/ajH1QYTZgLfGwtVKGWsPGbkVptx0CmpF5/Y+sC2lxPl",
        "cK82dalcEys4qSIgk88YPJKO1rIDLtMzNmjYwQ87b6sOr73zSbtjvQ8OPL7e36IJ569ekCAwEAAaNTMFEwH",
        "QYDVR0OBBYEFAT0eeOfZCtp1gyarcLEOGAQMoXQMB8GA1UdIwQYMBaAFAT0eeOfZCtp1gyarcLEOGAQMoXQ",
        "MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHZUr3nBbiOIyA0PShhu3+/PMTr33zEJOw8",
        "eJUb/7DkNdR4lLeBEFpMsNHRErQ/0cZ4DnTBrySDII7egjPF1fzyetqhDXk9vxP3Vr/zWLAT4O2cRuRXYbr",
        "zfeIETSHM321pfpDG4up95+prur3wQMHkEO2k/8/QDoo0/+VYl/9g27E+WRjnEVtWc+JV6VS3QKgCdFXyn/",
        "qvnp13+jU4lsXwADkSparze4ujzLH6H0lkN7sw1pn269DlmPMhR7tENNynNPK0s/pIk/qVPUD9XBcfnfLD5",
        "2lL4Z2nOgIDfG0JCaGV9BNrCl1wn62lzi3FmxRX8gztUNCqYo0WMlG1tDo8="
    );

    const IDP_ENTITY_ID: &str = "https://idp.corp.example.com/saml";
    const SP_ENTITY_ID: &str = "https://idp.example.com/saml/sp";
    const REQUEST_ID: &str = "_request-0123456789abcdef";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 0).unwrap()
    }

    /// Builds a signed response with the IdP-side generator and returns it base64-encoded
    /// (HTTP-POST binding form).
    fn signed_response(in_response_to: Option<&str>, email: Option<&str>) -> String {
        let signer = SamlSigner::from_pem("RS256", TEST_KEY_PEM).expect("signer");
        let xml = build_signed_response_xml(
            &SamlResponseInput {
                response_id: &generate_saml_id(),
                assertion_id: &generate_saml_id(),
                issued_at: now(),
                idp_entity_id: IDP_ENTITY_ID,
                sp_entity_id: SP_ENTITY_ID,
                acs_url: "https://idp.example.com/t/external/corp/saml/acs",
                in_response_to,
                name_id: "external-subject-1",
                name_id_format: NAME_ID_FORMAT_UNSPECIFIED,
                authn_instant: now(),
                session_index: "_session-1",
                not_on_or_after: now() + Duration::minutes(5),
                email,
            },
            &signer,
        )
        .expect("build response");
        STANDARD.encode(xml)
    }

    fn verification<'a>(certificates: &'a [String]) -> ResponseVerification<'a> {
        ResponseVerification {
            expected_issuer: IDP_ENTITY_ID,
            sp_entity_id: SP_ENTITY_ID,
            expected_in_response_to: REQUEST_ID,
            certificates,
            now: now(),
        }
    }

    /// A real signed response (made by the IdP-side generator) verifies and its claims can be
    /// extracted. That this passes also means the generator and verifier **agree on
    /// canonicalization**.
    #[test]
    fn a_signed_response_round_trips_through_the_verifier() {
        let certificates = vec![TEST_CERTIFICATE.to_string()];
        let response = signed_response(Some(REQUEST_ID), Some("user@example.com"));
        let assertion =
            consume_response(&response, &verification(&certificates)).expect("verify response");
        assert_eq!(assertion.issuer, IDP_ENTITY_ID);
        assert_eq!(assertion.name_id, "external-subject-1");
        assert_eq!(assertion.email.as_deref(), Some("user@example.com"));
        assert_eq!(assertion.in_response_to.as_deref(), Some(REQUEST_ID));
    }

    /// Changing even one byte makes it fail (the signature really works).
    #[test]
    fn a_tampered_assertion_is_rejected() {
        let certificates = vec![TEST_CERTIFICATE.to_string()];
        let response = signed_response(Some(REQUEST_ID), Some("user@example.com"));
        let xml = String::from_utf8(STANDARD.decode(&response).unwrap()).unwrap();
        let tampered = xml.replace("external-subject-1", "external-subject-2");
        assert_ne!(tampered, xml, "the tampering did not take effect");
        let err = consume_response(&STANDARD.encode(tampered), &verification(&certificates))
            .expect_err("a tampered assertion must be rejected");
        assert!(format!("{err}").contains("digest"), "{err}");
    }

    /// A response signed with a different key fails (the certificate does not match).
    #[test]
    fn a_response_signed_by_another_key_is_rejected() {
        // A state where a different certificate (unrelated to this key) is configured instead of
        // the real one.
        let (other_private_pem, _) = crate::domain::jwt::generate_rsa_keypair().expect("keypair");
        let signer = SamlSigner::from_pem("RS256", &other_private_pem).expect("signer");
        let xml = build_signed_response_xml(
            &SamlResponseInput {
                response_id: &generate_saml_id(),
                assertion_id: &generate_saml_id(),
                issued_at: now(),
                idp_entity_id: IDP_ENTITY_ID,
                sp_entity_id: SP_ENTITY_ID,
                acs_url: "https://idp.example.com/t/external/corp/saml/acs",
                in_response_to: Some(REQUEST_ID),
                name_id: "external-subject-1",
                name_id_format: NAME_ID_FORMAT_UNSPECIFIED,
                authn_instant: now(),
                session_index: "_session-1",
                not_on_or_after: now() + Duration::minutes(5),
                email: None,
            },
            &signer,
        )
        .expect("build response");
        let certificates = vec![TEST_CERTIFICATE.to_string()];
        assert!(
            consume_response(&STANDARD.encode(xml), &verification(&certificates)).is_err(),
            "a response signed by an unrelated key must be rejected"
        );
    }

    /// Unrequested responses (no `InResponseTo`) are not accepted. Accepting them would let an
    /// attacker complete a login just by having the victim's browser POST an assertion the attacker
    /// prepared.
    #[test]
    fn unsolicited_responses_are_rejected() {
        let certificates = vec![TEST_CERTIFICATE.to_string()];
        let response = signed_response(None, None);
        let err = consume_response(&response, &verification(&certificates))
            .expect_err("unsolicited responses must be rejected");
        assert!(format!("{err}").contains("unsolicited"), "{err}");
    }

    /// A response to a different request cannot be reused.
    #[test]
    fn a_response_to_a_different_request_is_rejected() {
        let certificates = vec![TEST_CERTIFICATE.to_string()];
        let response = signed_response(Some("_some-other-request"), None);
        let err = consume_response(&response, &verification(&certificates))
            .expect_err("a response to another request must be rejected");
        assert!(
            format!("{err}").contains("different authentication request"),
            "{err}"
        );
    }

    /// Expired assertions fail.
    #[test]
    fn an_expired_assertion_is_rejected() {
        let certificates = vec![TEST_CERTIFICATE.to_string()];
        let response = signed_response(Some(REQUEST_ID), None);
        let mut verification = verification(&certificates);
        verification.now = now() + Duration::hours(1);
        let err = consume_response(&response, &verification)
            .expect_err("an expired assertion must be rejected");
        assert!(format!("{err}").contains("expired"), "{err}");
    }

    /// Assertions from an issuer other than the configured one fail (even if the certificate
    /// matches).
    #[test]
    fn an_assertion_from_another_issuer_is_rejected() {
        let certificates = vec![TEST_CERTIFICATE.to_string()];
        let response = signed_response(Some(REQUEST_ID), None);
        let mut verification = verification(&certificates);
        verification.expected_issuer = "https://attacker.example.com/saml";
        assert!(consume_response(&response, &verification).is_err());
    }

    /// Assertions not addressed to us (different `Audience`) fail.
    #[test]
    fn an_assertion_addressed_to_another_service_provider_is_rejected() {
        let certificates = vec![TEST_CERTIFICATE.to_string()];
        let response = signed_response(Some(REQUEST_ID), None);
        let mut verification = verification(&certificates);
        verification.sp_entity_id = "https://other.example.com/saml/sp";
        let err = consume_response(&response, &verification).expect_err("must be rejected");
        assert!(format!("{err}").contains("addressed"), "{err}");
    }

    /// The `AuthnRequest` is put on the destination with DEFLATE + base64 (HTTP-Redirect binding).
    #[test]
    fn the_authn_request_is_deflated_into_the_redirect_location() {
        let xml = build_authn_request_xml(&AuthnRequestInput {
            request_id: REQUEST_ID,
            issued_at: now(),
            sp_entity_id: SP_ENTITY_ID,
            acs_url: "https://idp.example.com/t/external/corp/saml/acs",
            sso_url: "https://idp.corp.example.com/sso",
            name_id_format: NAME_ID_FORMAT_UNSPECIFIED,
        });
        assert!(xml.contains(&format!(r#"ID="{REQUEST_ID}""#)), "{xml}");
        assert!(xml.contains(SP_ENTITY_ID), "{xml}");

        let location =
            redirect_binding_location("https://idp.corp.example.com/sso", &xml, "relay-1")
                .expect("location");
        assert!(location.starts_with("https://idp.corp.example.com/sso?SAMLRequest="));
        assert!(location.contains("&RelayState=relay%2D1"), "{location}");

        // The XML sent is in a form the receiver can inflate and read.
        let encoded = location
            .split("SAMLRequest=")
            .nth(1)
            .and_then(|v| v.split("&RelayState").next())
            .expect("SAMLRequest");
        let decoded = percent_encoding::percent_decode_str(encoded)
            .decode_utf8()
            .expect("percent decode");
        let restored =
            crate::domain::saml_authn_request::decode_redirect_binding(&decoded).expect("inflate");
        assert_eq!(restored, xml);
    }
}
