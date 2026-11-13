//! Parsing SAML metadata XML (importing SP / external IdP metadata) and generating it (our own IdP
//! metadata).
//!
//! - Import (SP): parses the `EntityDescriptor` (`SPSSODescriptor`) published by an SP (client) and
//!   extracts the `entity_id` / `acs_url` / `x509_certificate` / NameID needed for registration. A
//!   helper replacing manual admin input; validation (ACS URL scheme etc.) is left to the
//!   registration use case ([`crate::domain::saml_service_provider`]).
//! - Import (external IdP): parses the `IDPSSODescriptor` published by an external SAML IdP and
//!   extracts `entity_id` / `sso_url` / signing certificates (AP12; candidate values for
//!   [`crate::domain::external_idp`]).
//! - Output: generates assay's `EntityDescriptor` (`IDPSSODescriptor`). The metadata SPs (clients)
//!   import to trust assay; the SAML counterpart of `.well-known/openid-configuration`.
//!
//! **Import never confuses the direction.** SP and IdP metadata are wrapped in the same
//! `EntityDescriptor`, differing only in the role descriptor inside (`SPSSODescriptor` /
//! `IDPSSODescriptor`). Reading without a role would let IdP metadata be registered as an SP (or
//! vice versa), and the mistake would not surface until **a user logs in**. So parsing always
//! carries a role ([`Role`]), and XML without the target descriptor fails.
//!
//! Namespace prefixes (`md:` / `saml:` etc.) are implementation-dependent, so local names are used.
//! Unescaping attribute values / element text and escaping attribute values on output are left to
//! `quick-xml` (no hand-written escaping).

use crate::domain::error::{DomainError, Result};
use crate::domain::xml_text;
use quick_xml::escape::escape;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// SAML 2.0 binding identifiers. Used for SSO URL preference on import and the ACS binding on
/// output.
const BINDING_HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// Candidate registration values imported from SP (client) metadata. Presented as the registration
/// form's initial values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedSpMetadata {
    pub entity_id: String,
    /// URL of the AssertionConsumerService (assertion destination).
    pub acs_url: String,
    /// Signing certificate (`<ds:X509Certificate>` text; base64 with whitespace removed). Empty
    /// string if absent.
    pub x509_certificate: String,
    /// `NameIDFormat` (the first one, if any).
    pub name_id_format: Option<String>,
    /// Display name from `md:Organization` (if any).
    pub display_name: Option<String>,
}

/// Candidate registration values imported from external IdP metadata (AP12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedIdpMetadata {
    /// The IdP's entityID. Becomes the value matched exactly against the assertion's `<Issuer>`.
    pub entity_id: String,
    /// URL of the SingleSignOnService (destination of the `AuthnRequest`).
    pub sso_url: String,
    /// Certificates for signature verification (base64 DER with whitespace removed). **Returns
    /// several** — during an IdP certificate rollover old and new are valid at once and both appear
    /// in the metadata. Keeping one would stop logins at every rollover.
    pub certificates: Vec<String>,
    /// `NameIDFormat` (the first one, if any).
    pub name_id_format: Option<String>,
    /// Display name from `md:Organization` (if any).
    pub display_name: Option<String>,
}

/// Targets whose text is collected during import.
enum Capture {
    Certificate,
    DisplayName,
    NameIdFormat,
}

/// Role descriptor to import. SP and IdP differ only in which elements are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Sp,
    Idp,
}

impl Role {
    /// Local name of the role descriptor.
    fn descriptor(self) -> &'static str {
        match self {
            Self::Sp => "SPSSODescriptor",
            Self::Idp => "IDPSSODescriptor",
        }
    }

    /// Local name of the endpoint element.
    fn endpoint(self) -> &'static str {
        match self {
            Self::Sp => "AssertionConsumerService",
            Self::Idp => "SingleSignOnService",
        }
    }

    /// Picks one endpoint to use from the candidates.
    ///
    /// **The IdP side is limited to HTTP-Redirect.** Login always starts by sending the
    /// `AuthnRequest` with the HTTP-Redirect binding
    /// ([`crate::domain::saml_external_idp::redirect_binding_location`]), so importing endpoints of
    /// other bindings would allow a configuration where "registration succeeds, but every login
    /// sends in a form the other side does not accept". The mistake would not surface until **a
    /// user logs in**. Dropping it here lets the importing admin notice on the spot (manual input
    /// remains available).
    ///
    /// The SP side stays POST → Redirect → first, as before. This is the URL on **the receiving
    /// side**, and assay can choose how to send (assertions are sent by POST).
    fn pick_endpoint(self, candidates: &[(String, String)]) -> Option<String> {
        match self {
            Self::Sp => pick_by_binding(candidates, &[BINDING_HTTP_POST, BINDING_HTTP_REDIRECT]),
            Self::Idp => candidates
                .iter()
                .find(|(binding, _)| binding == BINDING_HTTP_REDIRECT)
                .map(|(_, location)| location.clone()),
        }
    }

    /// Message when no endpoint is found.
    fn missing_endpoint(self) -> &'static str {
        match self {
            Self::Sp => "SAML metadata is missing an SP AssertionConsumerService",
            Self::Idp => {
                "SAML metadata is missing an IdP SingleSignOnService with the HTTP-Redirect binding"
            }
        }
    }
}

/// Raw values read from the role descriptor. An intermediate representation before repacking into
/// per-role types ([`ImportedSpMetadata`] / [`ImportedIdpMetadata`]).
struct ParsedEntity {
    entity_id: String,
    endpoint_url: String,
    /// Certificates explicitly marked `use="signing"` (in order of appearance).
    signing_certificates: Vec<String>,
    /// Certificates without `use` (in order of appearance). In SAML metadata a key without `use`
    /// **can be used for both signing and encryption**, so it is also a signing candidate.
    unspecified_certificates: Vec<String>,
    name_id_format: Option<String>,
    display_name: Option<String>,
}

/// Parses an SP (client) `EntityDescriptor` (`SPSSODescriptor`) XML and extracts candidate
/// registration values.
///
/// - `entityID` and the ACS URL (`SPSSODescriptor/AssertionConsumerService`) are required. If
///   missing, [`DomainError::InvalidValue`].
/// - One ACS URL is picked in the order HTTP-POST → HTTP-Redirect → first (assertions are normally
///   sent by POST).
/// - One certificate is taken, preferring signing ones in `SPSSODescriptor` (`use="signing"` or no
///   `use`).
pub fn parse_sp_metadata(xml: &str) -> Result<ImportedSpMetadata> {
    let parsed = parse_entity(xml, Role::Sp)?;
    Ok(ImportedSpMetadata {
        entity_id: parsed.entity_id,
        acs_url: parsed.endpoint_url,
        x509_certificate: parsed
            .signing_certificates
            .into_iter()
            .chain(parsed.unspecified_certificates)
            .next()
            .unwrap_or_default(),
        name_id_format: parsed.name_id_format,
        display_name: parsed.display_name,
    })
}

/// Parses an external IdP's `EntityDescriptor` (`IDPSSODescriptor`) XML and extracts candidate
/// registration values (AP12).
///
/// - `entityID` and the SSO URL (`IDPSSODescriptor/SingleSignOnService`) are required. If missing,
///   [`DomainError::InvalidValue`].
/// - The SSO URL is limited to **the HTTP-Redirect binding one** (`AuthnRequest` is only sent that
///   way). Metadata with only other bindings is not imported — it would make a configuration where
///   registration succeeds but every login sends in a form the other side does not accept, and the
///   mistake would not surface until a user logs in.
/// - Returns **all** keys usable for signing. Includes **both** those explicitly marked
///   `use="signing"` and those without `use` (which in SAML metadata means usable for both signing
///   and encryption), excluding only `use="encryption"`. Keeping only one kind would stop logins
///   the moment the other side signs with the other key during a rollover.
/// - XML with no certificate at all is **not a failure here**. Whether one is required is decided
///   by the registration use case ([`crate::application::external_idp_management`]); import sticks
///   to "passing on what could be read".
pub fn parse_idp_metadata(xml: &str) -> Result<ImportedIdpMetadata> {
    let parsed = parse_entity(xml, Role::Idp)?;
    let certificates: Vec<String> = parsed
        .signing_certificates
        .into_iter()
        .chain(parsed.unspecified_certificates)
        .collect();
    Ok(ImportedIdpMetadata {
        entity_id: parsed.entity_id,
        sso_url: parsed.endpoint_url,
        certificates,
        name_id_format: parsed.name_id_format,
        display_name: parsed.display_name,
    })
}

/// Reads the `EntityDescriptor` in one pass, picking up only what is inside the descriptor of the
/// given role.
fn parse_entity(xml: &str, role: Role) -> Result<ParsedEntity> {
    let mut reader = Reader::from_str(xml);

    let mut entity_id: Option<String> = None;
    let mut in_role = false;
    // Endpoint candidates as (binding, location).
    let mut endpoints: Vec<(String, String)> = Vec::new();
    let mut key_use: Option<String> = None;
    let mut signing_certificates: Vec<String> = Vec::new();
    let mut unspecified_certificates: Vec<String> = Vec::new();
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
                "EntityDescriptor" if entity_id.is_none() => {
                    entity_id = attribute(&e, "entityID");
                    in_entity = true;
                }
                name if in_entity && name == role.descriptor() => in_role = true,
                "KeyDescriptor" if in_entity && in_role => key_use = attribute(&e, "use"),
                name if in_entity && in_role && name == role.endpoint() => {
                    push_endpoint(&e, &mut endpoints)
                }
                "X509Certificate"
                    if in_entity && in_role && key_use.as_deref() != Some("encryption") =>
                {
                    capture = Some(Capture::Certificate);
                    text_buf.clear();
                }
                "NameIDFormat" if in_entity && in_role && name_id_format.is_none() => {
                    capture = Some(Capture::NameIdFormat);
                    text_buf.clear();
                }
                "OrganizationDisplayName" | "OrganizationName"
                    if in_entity && display_name.is_none() =>
                {
                    capture = Some(Capture::DisplayName);
                    text_buf.clear();
                }
                _ => {}
            },
            Event::Empty(e) => match local(&e) {
                "EntityDescriptor" if entity_id.is_none() => {
                    entity_id = attribute(&e, "entityID");
                }
                "KeyDescriptor" if in_entity && in_role => key_use = attribute(&e, "use"),
                name if in_entity && in_role && name == role.endpoint() => {
                    push_endpoint(&e, &mut endpoints)
                }
                _ => {}
            },
            Event::Text(e) => {
                if capture.is_some() {
                    let decoded = xml_text::text(&e).map_err(|err| {
                        DomainError::InvalidValue(format!("invalid SAML metadata text: {err}"))
                    })?;
                    text_buf.push_str(&decoded);
                }
            }
            Event::GeneralRef(e) => {
                if capture.is_some() {
                    let decoded = xml_text::general_ref(&e).map_err(|err| {
                        DomainError::InvalidValue(format!("invalid SAML metadata text: {err}"))
                    })?;
                    text_buf.push_str(&decoded);
                }
            }
            Event::End(e) => match local_end(&e) {
                "EntityDescriptor" if in_entity => break,
                name if name == role.descriptor() => in_role = false,
                "KeyDescriptor" => key_use = None,
                "X509Certificate" => {
                    if matches!(capture, Some(Capture::Certificate)) {
                        let normalized = strip_whitespace(&text_buf);
                        if !normalized.is_empty() {
                            if key_use.as_deref() == Some("signing") {
                                signing_certificates.push(normalized);
                            } else {
                                unspecified_certificates.push(normalized);
                            }
                        }
                    }
                    capture = None;
                }
                "NameIDFormat" => {
                    if matches!(capture, Some(Capture::NameIdFormat)) {
                        let trimmed = text_buf.trim();
                        if !trimmed.is_empty() {
                            name_id_format.get_or_insert_with(|| trimmed.to_string());
                        }
                    }
                    capture = None;
                }
                "OrganizationDisplayName" | "OrganizationName" => {
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
    let endpoint_url = role
        .pick_endpoint(&endpoints)
        .ok_or_else(|| DomainError::InvalidValue(role.missing_endpoint().to_string()))?;

    Ok(ParsedEntity {
        entity_id: entity_id.trim().to_string(),
        endpoint_url,
        signing_certificates,
        unspecified_certificates,
        name_id_format,
        display_name,
    })
}

/// URN of the P-256 curve (XMLDSIG11 `NamedCurve`).
///
/// **This is the only source of the curve URN mapping.** Unless the metadata's `KeyDescriptor` and
/// the assertion's `KeyInfo` output the same value, the SP cannot match them.
pub const NAMED_CURVE_P256: &str = "urn:oid:1.2.840.10045.3.1.7";
const NAMED_CURVE_P384: &str = "urn:oid:1.3.132.0.34";
const NAMED_CURVE_P521: &str = "urn:oid:1.3.132.0.35";

/// Converts a JWK `crv` to the XMLDSIG11 `NamedCurve` URN. `None` for unsupported curves.
pub fn named_curve_uri(crv: &str) -> Option<&'static str> {
    match crv {
        "P-256" => Some(NAMED_CURVE_P256),
        "P-384" => Some(NAMED_CURVE_P384),
        "P-521" => Some(NAMED_CURVE_P521),
        _ => None,
    }
}

/// Public representation of the IdP's signing key (XML Signature `KeyValue`). The current signing
/// key infrastructure has no X.509 certificates, only raw public keys, so it is expressed as
/// `RSAKeyValue` (RS256) / `ECKeyValue` (ES256).
pub enum IdpSigningKey {
    /// RSA public key (XMLDSIG `RSAKeyValue`). Values are base64 of big-endian bytes.
    Rsa {
        modulus_b64: String,
        exponent_b64: String,
    },
    /// EC public key (XMLDSIG11 `ECKeyValue`). `named_curve_uri` is the curve URN, `public_key_b64`
    /// is the base64 of the uncompressed point (`0x04 || X || Y`).
    Ec {
        named_curve_uri: String,
        public_key_b64: String,
    },
}

impl IdpSigningKey {
    /// Generates the XML fragment of the public key itself (`KeyValue`).
    ///
    /// **The same thing is used for the metadata's `KeyDescriptor` and the assertion's `KeyInfo`.**
    /// Writing them separately could at any time drift into a form where the SP cannot match "the
    /// key received in metadata" with "the key the assertion claims".
    ///
    /// Empty-element tags (`<e/>`) are not used, to match the rule that `saml_response` builds XML
    /// in exclusive canonical form (this fragment is embedded there too).
    pub(crate) fn to_key_value(&self) -> String {
        match self {
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
                r#"<ds:KeyValue>
          <ds11:ECKeyValue xmlns:ds11="http://www.w3.org/2009/xmldsig11#">
            <ds11:NamedCurve URI="{}"></ds11:NamedCurve>
            <ds11:PublicKey>{}</ds11:PublicKey>
          </ds11:ECKeyValue>
        </ds:KeyValue>"#,
                escape(named_curve_uri),
                escape(public_key_b64),
            ),
        }
    }

    /// Generates the XML fragment of a signing `KeyDescriptor`.
    fn to_key_descriptor(&self) -> String {
        let key_value = self.to_key_value();
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

/// Generates assay's SAML `EntityDescriptor` (`IDPSSODescriptor`) XML.
///
/// `entity_id` is the IdP's entity ID (the tenant issuer is used), `sso_url` is the
/// SingleSignOnService URL. SPs (clients) import this metadata to trust assay.
///
/// # List all published keys (ADR-0039)
///
/// Pass **all published keys** in `signing_keys` (the signing key, the successor not yet signing,
/// and retired keys still within their validity). SAML 2.0 metadata can hold several
/// `use="signing"` `KeyDescriptor`s. Emitting only one would swap the certificate SPs see the
/// moment signing switches, and **verification fails until re-import** — the discontinuity ADR-0039
/// removed on the JWKS side would remain only on the SAML side.
///
/// **Ordering is the caller's responsibility: the signing key goes first.** Some SP implementations
/// read only the first `KeyDescriptor`, and passing them in publication order (newest first) would
/// hand them **the successor key that is not signing yet**.
pub fn build_idp_metadata_xml(
    entity_id: &str,
    sso_url: &str,
    signing_keys: &[IdpSigningKey],
) -> String {
    let entity_id = escape(entity_id);
    let sso_url = escape(sso_url);
    let key_descriptor = signing_keys
        .iter()
        .map(IdpSigningKey::to_key_descriptor)
        .collect::<Vec<_>>()
        .join("");
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

/// Adds an endpoint element's Binding/Location to the candidates (only when both are present).
fn push_endpoint(e: &BytesStart, out: &mut Vec<(String, String)>) {
    if let (Some(binding), Some(location)) = (attribute(e, "Binding"), attribute(e, "Location")) {
        out.push((binding, location));
    }
}

/// Picks a URL in the `preferred` binding order, returning the first if none match.
fn pick_by_binding(candidates: &[(String, String)], preferred: &[&str]) -> Option<String> {
    for binding in preferred {
        if let Some((_, loc)) = candidates.iter().find(|(b, _)| b == binding) {
            return Some(loc.clone());
        }
    }
    candidates.first().map(|(_, loc)| loc.clone())
}

/// Local name of a start/empty element (element name without the namespace prefix).
fn local<'a>(e: &'a BytesStart<'a>) -> &'a str {
    // The return value of `local_name()` is temporary, so the tail is taken from the name bytes to
    // keep the lifetime.
    let name = e.name();
    let full = name.into_inner();
    strip_prefix(full)
}

fn local_end<'a>(e: &'a quick_xml::events::BytesEnd<'a>) -> &'a str {
    let name = e.name();
    strip_prefix(name.into_inner())
}

/// Strips the prefix, e.g. `md:EntityDescriptor` → `EntityDescriptor`.
fn strip_prefix(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, local)| local)
}

/// Extracts an attribute value (local name match, unescaped).
fn attribute(e: &BytesStart, name: &str) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.local_name().as_ref() == name {
            if let Ok(value) = xml_text::attribute_value(&attr) {
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
        // ACS prefers POST.
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
        // Trying to import IdP metadata (SSO only, no ACS) as an SP fails.
        assert!(parse_sp_metadata(IDP_METADATA).is_err());
    }

    /// entityID, SSO URL, and signing certificates can be imported from external IdP metadata. The
    /// SSO URL prefers HTTP-Redirect (because `AuthnRequest` is sent with the Redirect binding).
    #[test]
    fn parses_idp_entity_sso_and_signing_certificate() {
        let parsed = parse_idp_metadata(IDP_METADATA).expect("parse");
        assert_eq!(parsed.entity_id, "https://idp.example.test/metadata");
        assert_eq!(parsed.sso_url, "https://idp.example.test/sso/redirect");
        // Encryption certificates are not used for signature verification, so they are not mixed
        // in.
        assert_eq!(parsed.certificates, vec!["MIIBsigningCERTdata=="]);
        assert_eq!(parsed.display_name.as_deref(), Some("Example IdP"));
    }

    /// Metadata during a certificate rollover lists two signing certificates. If **both** cannot be
    /// imported, logins stop the moment it switches.
    #[test]
    fn keeps_every_signing_certificate_for_rotation() {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                       entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>CURRENT==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>NEXT==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let parsed = parse_idp_metadata(xml).expect("parse");
        assert_eq!(parsed.certificates, vec!["CURRENT==", "NEXT=="]);
    }

    /// A `KeyDescriptor` without `use` means usable for both signing and encryption, so it is
    /// returned **alongside the signing ones**. Dropping it just because an explicit signing one
    /// exists would stop logins the moment the other side signs with the `use`-less key during a
    /// rollover. Only `use="encryption"` is excluded.
    #[test]
    fn keeps_certificates_without_a_use_attribute_alongside_signing_ones() {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                                       xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                       entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>SIGNING==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>ANY==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>ENCRYPTION==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        let parsed = parse_idp_metadata(xml).expect("parse");
        assert_eq!(parsed.certificates, vec!["SIGNING==", "ANY=="]);
        assert_eq!(parsed.sso_url, "https://idp.test/sso");
    }

    /// **Only SSO with the HTTP-Redirect binding is imported.** Login always starts by sending the
    /// `AuthnRequest` with HTTP-Redirect, so importing URLs of other bindings would allow a
    /// configuration where "registration succeeds, but every login sends in a form the other side
    /// does not accept". It is dropped at import time.
    #[test]
    fn only_the_http_redirect_sso_endpoint_is_imported() {
        let with_both = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/sso/post"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso/redirect"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        assert_eq!(
            parse_idp_metadata(with_both).expect("parse").sso_url,
            "https://idp.test/sso/redirect"
        );

        // Metadata with only POST, or only unsendable bindings like SOAP, is not imported.
        for unusable in [
            r#"<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/sso"/>"#,
            r#"<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.test/soap"/>"#,
        ] {
            let xml = format!(
                r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{unusable}</IDPSSODescriptor>
</EntityDescriptor>"#
            );
            assert!(
                parse_idp_metadata(&xml).is_err(),
                "a binding the login flow cannot send must not be imported: {unusable}"
            );
        }
    }

    /// **Never confuse the direction.** Trying to import SP metadata as an external IdP fails
    /// (there is no `IDPSSODescriptor`). Letting it through would hide the mistake until login
    /// time.
    #[test]
    fn idp_metadata_does_not_accept_an_sp_descriptor() {
        assert!(parse_idp_metadata(SP_METADATA).is_err());
    }

    #[test]
    fn idp_metadata_without_entity_id_is_rejected() {
        let xml = r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
        assert!(parse_idp_metadata(xml).is_err());
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
            std::slice::from_ref(&key),
        );
        assert!(xml.contains(r#"entityID="https://idp.example.com/tenant-1""#));
        // It is IdP metadata (IDPSSODescriptor), not SP metadata.
        assert!(xml.contains("IDPSSODescriptor"));
        assert!(!xml.contains("SPSSODescriptor"));
        assert!(xml.contains("<md:SingleSignOnService"));
        assert!(!xml.contains("AssertionConsumerService"));
        // The signing key is embedded as RSAKeyValue.
        assert!(xml.contains(r#"<md:KeyDescriptor use="signing">"#));
        assert!(xml.contains("<ds:Modulus>AQABmodulus==</ds:Modulus>"));
        assert!(xml.contains("<ds:Exponent>AQAB</ds:Exponent>"));
        // The `&` in the query is escaped as an attribute value.
        assert!(xml.contains("saml/sso?x=1&amp;y=2"));
        // The generated XML is re-parsable (well-formed).
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }

    #[test]
    fn build_idp_metadata_embeds_ec_key_as_eckeyvalue() {
        let key = IdpSigningKey::Ec {
            named_curve_uri: "urn:oid:1.2.840.10045.3.1.7".to_string(),
            public_key_b64: "BParbitraryPoint==".to_string(),
        };
        let xml = build_idp_metadata_xml(
            "urn:idp",
            "https://idp.test/sso",
            std::slice::from_ref(&key),
        );
        assert!(xml.contains(r#"<md:KeyDescriptor use="signing">"#));
        // XMLDSIG 1.1 places it at `ds:KeyValue/ds11:ECKeyValue`. Unless wrapped in `ds:KeyValue`
        // like the RSA side, SPs that look only under `KeyInfo/KeyValue` cannot pick up EC keys.
        assert!(xml.contains("<ds:KeyValue>"));
        assert!(xml.contains("<ds11:ECKeyValue"));
        assert!(xml
            .contains(r#"<ds11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"></ds11:NamedCurve>"#));
        assert!(xml.contains("<ds11:PublicKey>BParbitraryPoint==</ds11:PublicKey>"));
        assert!(!xml.contains("RSAKeyValue"));
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }

    #[test]
    fn build_idp_metadata_omits_key_descriptor_when_no_signing_key() {
        let xml = build_idp_metadata_xml("urn:idp", "https://idp.test/sso", &[]);
        assert!(xml.contains("IDPSSODescriptor"));
        assert!(!xml.contains("KeyDescriptor"));
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }

    /// Lists all published keys (ADR-0039 / T33).
    ///
    /// Emitting only one would swap the certificate SPs see the moment signing switches, failing
    /// verification until re-import. This is the core that removes, on the SAML side too, the
    /// discontinuity ADR-0039 removed on the JWKS side.
    #[test]
    fn build_idp_metadata_lists_every_published_key_in_order() {
        let signing = IdpSigningKey::Rsa {
            modulus_b64: "AAAAsigning==".to_string(),
            exponent_b64: "AQAB".to_string(),
        };
        let successor = IdpSigningKey::Rsa {
            modulus_b64: "BBBBsuccessor==".to_string(),
            exponent_b64: "AQAB".to_string(),
        };
        let xml = build_idp_metadata_xml("urn:idp", "https://idp.test/sso", &[signing, successor]);

        assert_eq!(
            xml.matches(r#"<md:KeyDescriptor use="signing">"#).count(),
            2
        );
        // Listed in the given order as is (some SPs read only the first KeyDescriptor, so
        // "signing key first" is the caller's responsibility; no reordering here).
        let first = xml.find("AAAAsigning==").expect("signing key present");
        let second = xml.find("BBBBsuccessor==").expect("successor present");
        assert!(first < second, "the given order should be preserved: {xml}");

        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }
}
