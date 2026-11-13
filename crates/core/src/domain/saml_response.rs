//! Generates signed SAML Responses (SSO responses of `IDPSSODescriptor`).
//!
//! # Policy for signing and canonicalization (C14N)
//!
//! XML signatures (XMLDSIG) are computed over "the bytes of a subtree under exclusive
//! canonicalization (exclusive C14N)". This module generates XML **in exclusive canonical form from
//! the start** (it has no canonicalizer of its own):
//!
//! - Never uses empty-element tags (`<e/>`); always outputs start/end tag pairs
//! - Outputs namespace declarations, then attributes (lexical order of local names), for each
//!   element
//! - The signed part (`Assertion`) declares the namespaces it uses on itself, making it
//!   self-contained
//! - Escaping follows canonical rules (attribute values: `& < " TAB LF CR`, text: `& < > CR`)
//!
//! Bytes output this way stay identical even after the verifier (SP) applies exclusive C14N to the
//! subtree. An enveloped signature is inserted into the Assertion, and the signature is over
//! `SignedInfo` serialized with `xmlns:ds` at signing time (= the form matching the SP's C14N
//! result).
//!
//! The signing key is the same ACTIVE signing key as OIDC ID Tokens (RS256 → rsa-sha256, ES256 →
//! ecdsa-sha256).
//!
//! # `KeyInfo` is included (2026-08-28)
//!
//! **The assertion itself states which key signed it.** Since ADR-0039 the metadata lists multiple
//! `KeyDescriptor`s, so without this the SP could only guess "which to verify with" by trying all
//! or taking the first. SAML has no standard marker like JWT's `kid`, so `KeyInfo/KeyValue` plays
//! that role (Entra ID and others take the same form).
//!
//! **`KeyInfo` is outside `SignedInfo`** (not signed), so including it does not change the
//! signature computation. Values are rendered with the same
//! [`crate::domain::saml_metadata::IdpSigningKey::to_key_value`] as the metadata — writing them
//! separately could drift into forms the SP cannot match.

use crate::domain::error::{DomainError, Result};
use crate::domain::saml_metadata::{IdpSigningKey, NAMED_CURVE_P256};
use aws_lc_rs::signature::KeyPair as _;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SIG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
/// `AuthnContextClassRef`. SSO sessions do not keep the authentication means used at establishment
/// (password, TOTP, passkey), so no specific strength (e.g. `PasswordProtectedTransport`) is
/// claimed and `unspecified` is used (no wrong authentication strength is conveyed to the SP).
/// Per-means context requires recording the means in the session.
const AUTHN_CONTEXT_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
const SUBJECT_CONFIRMATION_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// Inputs for building a SAML Response. IDs (`response_id` / `assertion_id`) must be NCNames, so
/// pass values numbered by [`generate_saml_id`].
pub struct SamlResponseInput<'a> {
    pub response_id: &'a str,
    pub assertion_id: &'a str,
    /// Issue time (`IssueInstant` of Response / Assertion).
    pub issued_at: DateTime<Utc>,
    /// assay's entity ID (tenant issuer).
    pub idp_entity_id: &'a str,
    /// Entity ID of the target SP (`Audience`).
    pub sp_entity_id: &'a str,
    /// Assertion destination (`Destination` / `Recipient`).
    pub acs_url: &'a str,
    /// `ID` of the AuthnRequest (`InResponseTo`; `None` for the IdP-initiated equivalent).
    pub in_response_to: Option<&'a str>,
    /// `NameID` value and Format (`name_id_format` of the SP registration).
    pub name_id: &'a str,
    pub name_id_format: &'a str,
    /// Authentication time (`auth_time` of the SSO session).
    pub authn_instant: DateTime<Utc>,
    /// `SessionIndex` (an opaque value derived from the SSO session).
    pub session_index: &'a str,
    /// Assertion expiry (`NotOnOrAfter`).
    pub not_on_or_after: DateTime<Utc>,
    /// email attribute (`AttributeStatement`). If `None`, no attribute is output.
    pub email: Option<&'a str>,
}

/// Signing key for SAML responses. Built from the ACTIVE signing key (PEM).
pub enum SamlSigner {
    Rsa(Box<aws_lc_rs::rsa::KeyPair>),
    P256(Box<p256::ecdsa::SigningKey>),
}

impl SamlSigner {
    /// Builds a signer from the signing key PEM and algorithm (`RS256` / `ES256`). The PEM format
    /// pairs with key generation ([`crate::domain::jwt`]): PKCS#1 for RSA, PKCS#8 for EC.
    pub fn from_pem(algorithm: &str, private_pem: &str) -> Result<Self> {
        match algorithm {
            "RS256" => Self::rsa_from_pkcs1_pem(private_pem).map(|key| Self::Rsa(Box::new(key))),
            "ES256" => {
                use p256::pkcs8::DecodePrivateKey;
                p256::ecdsa::SigningKey::from_pkcs8_pem(private_pem)
                    .map(|key| Self::P256(Box::new(key)))
                    .map_err(|e| DomainError::InvalidValue(format!("invalid EC private key: {e}")))
            }
            other => Err(DomainError::InvalidValue(format!(
                "unsupported SAML signing algorithm: {other}"
            ))),
        }
    }

    fn rsa_from_pkcs1_pem(private_pem: &str) -> Result<aws_lc_rs::rsa::KeyPair> {
        let invalid = |e: &dyn std::fmt::Display| {
            DomainError::InvalidValue(format!("invalid RSA private key: {e}"))
        };
        let (label, der) =
            pkcs8::der::pem::decode_vec(private_pem.as_bytes()).map_err(|e| invalid(&e))?;
        if label != "RSA PRIVATE KEY" {
            return Err(invalid(&format!("expected PKCS#1 PEM, got {label}")));
        }
        aws_lc_rs::rsa::KeyPair::from_der(&der).map_err(|e| invalid(&e))
    }

    fn signature_method_uri(&self) -> &'static str {
        match self {
            Self::Rsa(_) => SIG_RSA_SHA256,
            Self::P256(_) => SIG_ECDSA_SHA256,
        }
    }

    /// Public value of the signing key (in the form put in `KeyInfo/KeyValue`). Same representation
    /// as the metadata's `KeyDescriptor`, so the SP can match the two.
    fn public_key(&self) -> IdpSigningKey {
        match self {
            Self::Rsa(key) => {
                let public = key.public_key();
                IdpSigningKey::Rsa {
                    modulus_b64: STANDARD
                        .encode(public.modulus().big_endian_without_leading_zero()),
                    exponent_b64: STANDARD
                        .encode(public.exponent().big_endian_without_leading_zero()),
                }
            }
            Self::P256(key) => {
                // XMLDSIG ECKeyValue holds the uncompressed point (0x04 || X || Y) in base64.
                let point = key.verifying_key().to_sec1_point(false);
                IdpSigningKey::Ec {
                    named_curve_uri: NAMED_CURVE_P256.to_string(),
                    public_key_b64: STANDARD.encode(point.as_bytes()),
                }
            }
        }
    }

    /// Signs the `SignedInfo` bytes. RSA uses PKCS#1 v1.5, ECDSA uses IEEE P1363 (r||s)
    /// (both the formats XMLDSIG specifies).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Rsa(key) => {
                let mut signature = vec![0; key.public_modulus_len()];
                key.sign(
                    &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                    &aws_lc_rs::rand::SystemRandom::new(),
                    message,
                    &mut signature,
                )
                .map_err(|e| DomainError::InvalidValue(format!("RSA signing failed: {e}")))?;
                Ok(signature)
            }
            Self::P256(key) => {
                use p256::ecdsa::signature::Signer;
                let signature: p256::ecdsa::Signature = key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
        }
    }
}

/// Numbers a random ID safe as an XML ID attribute (NCName: must not start with a digit).
pub fn generate_saml_id() -> String {
    format!("_{}", crate::domain::crypto::random_hex(16))
}

/// Generates signed SAML Response XML (enveloped signature in the Assertion).
pub fn build_signed_response_xml(input: &SamlResponseInput, signer: &SamlSigner) -> Result<String> {
    let assertion = build_assertion(input);
    let signature = build_signature(input.assertion_id, assertion.as_bytes(), signer)?;

    // Insert the enveloped signature right after Issuer (the position the SAML schema specifies).
    let issuer_close = "</saml:Issuer>";
    let insert_at = assertion
        .find(issuer_close)
        .map(|pos| pos + issuer_close.len())
        .ok_or_else(|| DomainError::InvalidValue("assertion is missing an Issuer".to_string()))?;
    let mut signed_assertion = String::with_capacity(assertion.len() + signature.len());
    signed_assertion.push_str(&assertion[..insert_at]);
    signed_assertion.push_str(&signature);
    signed_assertion.push_str(&assertion[insert_at..]);

    let issued_at = format_instant(input.issued_at);
    let in_response_to = input
        .in_response_to
        .map(|id| format!(" InResponseTo=\"{}\"", escape_attr(id)))
        .unwrap_or_default();
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<samlp:Response xmlns:samlp=\"{NS_PROTOCOL}\" Destination=\"{destination}\" ID=\"{id}\"{in_response_to} IssueInstant=\"{issued_at}\" Version=\"2.0\">\
<saml:Issuer xmlns:saml=\"{NS_ASSERTION}\">{issuer}</saml:Issuer>\
<samlp:Status><samlp:StatusCode Value=\"{STATUS_SUCCESS}\"></samlp:StatusCode></samlp:Status>\
{signed_assertion}\
</samlp:Response>",
        destination = escape_attr(input.acs_url),
        id = escape_attr(input.response_id),
        issuer = escape_text(input.idp_entity_id),
    ))
}

/// Builds the unsigned Assertion in exclusive canonical form (exactly what the signature digests).
fn build_assertion(input: &SamlResponseInput) -> String {
    let issued_at = format_instant(input.issued_at);
    let authn_instant = format_instant(input.authn_instant);
    let not_on_or_after = format_instant(input.not_on_or_after);
    // NotBefore is the issue time (allowed skew on the SP side is left to the SP's verification
    // settings).
    let not_before = issued_at.clone();

    let in_response_to = input
        .in_response_to
        .map(|id| format!(" InResponseTo=\"{}\"", escape_attr(id)))
        .unwrap_or_default();
    let attribute_statement = input
        .email
        .map(|email| {
            format!(
                "<saml:AttributeStatement>\
<saml:Attribute Name=\"email\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">\
<saml:AttributeValue>{}</saml:AttributeValue>\
</saml:Attribute>\
</saml:AttributeStatement>",
                escape_text(email)
            )
        })
        .unwrap_or_default();

    // Attributes are output in canonical order (namespace declarations → lexical order of local
    // names).
    format!(
        "<saml:Assertion xmlns:saml=\"{NS_ASSERTION}\" ID=\"{id}\" IssueInstant=\"{issued_at}\" Version=\"2.0\">\
<saml:Issuer>{issuer}</saml:Issuer>\
<saml:Subject>\
<saml:NameID Format=\"{name_id_format}\">{name_id}</saml:NameID>\
<saml:SubjectConfirmation Method=\"{SUBJECT_CONFIRMATION_BEARER}\">\
<saml:SubjectConfirmationData{in_response_to} NotOnOrAfter=\"{not_on_or_after}\" Recipient=\"{recipient}\"></saml:SubjectConfirmationData>\
</saml:SubjectConfirmation>\
</saml:Subject>\
<saml:Conditions NotBefore=\"{not_before}\" NotOnOrAfter=\"{not_on_or_after}\">\
<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>\
</saml:Conditions>\
<saml:AuthnStatement AuthnInstant=\"{authn_instant}\" SessionIndex=\"{session_index}\">\
<saml:AuthnContext><saml:AuthnContextClassRef>{AUTHN_CONTEXT_UNSPECIFIED}</saml:AuthnContextClassRef></saml:AuthnContext>\
</saml:AuthnStatement>\
{attribute_statement}\
</saml:Assertion>",
        id = escape_attr(input.assertion_id),
        issuer = escape_text(input.idp_entity_id),
        name_id_format = escape_attr(input.name_id_format),
        name_id = escape_text(input.name_id),
        recipient = escape_attr(input.acs_url),
        audience = escape_text(input.sp_entity_id),
        session_index = escape_attr(input.session_index),
    )
}

/// Builds the `ds:Signature` element. The digest is computed over "the Assertion before inserting
/// the signature" (identical to the result of the enveloped-signature transform).
fn build_signature(
    assertion_id: &str,
    unsigned_assertion: &[u8],
    signer: &SamlSigner,
) -> Result<String> {
    let digest = STANDARD.encode(Sha256::digest(unsigned_assertion));

    // SignedInfo is signed in the form the SP gets by exclusive C14N (xmlns:ds appears on the apex
    // element).
    let signed_info_canonical = format!(
        "<ds:SignedInfo xmlns:ds=\"{NS_XMLDSIG}\">\
<ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"></ds:CanonicalizationMethod>\
<ds:SignatureMethod Algorithm=\"{sig_method}\"></ds:SignatureMethod>\
<ds:Reference URI=\"#{reference}\">\
<ds:Transforms>\
<ds:Transform Algorithm=\"{ENVELOPED_SIGNATURE}\"></ds:Transform>\
<ds:Transform Algorithm=\"{EXC_C14N}\"></ds:Transform>\
</ds:Transforms>\
<ds:DigestMethod Algorithm=\"{DIGEST_SHA256}\"></ds:DigestMethod>\
<ds:DigestValue>{digest}</ds:DigestValue>\
</ds:Reference>\
</ds:SignedInfo>",
        sig_method = signer.signature_method_uri(),
        reference = escape_attr(assertion_id),
    );
    let signature_value = STANDARD.encode(signer.sign(signed_info_canonical.as_bytes())?);

    // In the document, xmlns:ds is declared on the Signature element (SignedInfo's C14N result
    // matches the above).
    let signed_info_embedded = signed_info_canonical.replacen(
        &format!("<ds:SignedInfo xmlns:ds=\"{NS_XMLDSIG}\">"),
        "<ds:SignedInfo>",
        1,
    );
    // KeyInfo is outside SignedInfo, so it does not affect the signature computation (XMLDSIG
    // schema order is SignedInfo → SignatureValue → KeyInfo).
    let key_value = signer.public_key().to_key_value();
    Ok(format!(
        "<ds:Signature xmlns:ds=\"{NS_XMLDSIG}\">\
{signed_info_embedded}\
<ds:SignatureValue>{signature_value}</ds:SignatureValue>\
<ds:KeyInfo>{key_value}</ds:KeyInfo>\
</ds:Signature>"
    ))
}

/// SAML time representation (xsd:dateTime, UTC, millisecond precision).
fn format_instant(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Canonical escaping of attribute values (Canonical XML: only `&` `<` `"` and TAB/LF/CR; `>` `'`
/// stay as is).
fn escape_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

/// Canonical escaping of text nodes (Canonical XML: only `&` `<` `>` and CR).
fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    fn test_input<'a>() -> SamlResponseInput<'a> {
        SamlResponseInput {
            response_id: "_resp1",
            assertion_id: "_assert1",
            issued_at: Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap(),
            idp_entity_id: "https://idp.example.com/tenant-1",
            sp_entity_id: "https://sp.example.test/metadata",
            acs_url: "https://sp.example.test/acs?x=1&y=2",
            in_response_to: Some("_req1"),
            name_id: "user@example.test",
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            authn_instant: Utc.with_ymd_and_hms(2026, 7, 28, 11, 0, 0).unwrap(),
            session_index: "_session1",
            not_on_or_after: Utc.with_ymd_and_hms(2026, 7, 28, 12, 5, 0).unwrap(),
            email: Some("user@example.test"),
        }
    }

    fn rsa_signer() -> (SamlSigner, aws_lc_rs::rsa::PublicKey) {
        // RSA keys made by aws-lc-rs start at 2048 bits (1024 cannot be made).
        let private =
            aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("keygen");
        let public = private.public_key().clone();
        (SamlSigner::Rsa(Box::new(private)), public)
    }

    /// Extracts the first `<tag ...>...</tag>` substring from a document (for byte-equality
    /// checks).
    fn extract(doc: &str, open: &str, close: &str) -> String {
        let start = doc.find(open).expect("open tag");
        let end = doc.find(close).expect("close tag") + close.len();
        doc[start..end].to_string()
    }

    #[test]
    fn response_contains_success_status_audience_and_subject() {
        let (signer, _) = rsa_signer();
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");
        assert!(xml.contains(STATUS_SUCCESS));
        assert!(xml.contains("<saml:Audience>https://sp.example.test/metadata</saml:Audience>"));
        assert!(xml.contains("user@example.test</saml:NameID>"));
        assert!(xml.contains("InResponseTo=\"_req1\""));
        assert!(xml.contains("SessionIndex=\"_session1\""));
        // The authentication means is not kept, so no specific strength (PasswordProtectedTransport
        // etc.) is claimed.
        assert!(xml.contains(&format!(
            "<saml:AuthnContextClassRef>{AUTHN_CONTEXT_UNSPECIFIED}</saml:AuthnContextClassRef>"
        )));
        assert!(!xml.contains("PasswordProtectedTransport"));
        // The `&` in Destination's query is escaped in canonical form.
        assert!(xml.contains("Destination=\"https://sp.example.test/acs?x=1&amp;y=2\""));
        // The generated XML is well-formed (re-parsable).
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }

    #[test]
    fn digest_covers_the_assertion_without_the_signature() {
        let (signer, _) = rsa_signer();
        let input = test_input();
        let xml = build_signed_response_xml(&input, &signer).expect("build");

        // enveloped-signature transform: the Assertion without the Signature element is what is
        // digested.
        let signed_assertion = extract(&xml, "<saml:Assertion", "</saml:Assertion>");
        let signature = extract(&signed_assertion, "<ds:Signature", "</ds:Signature>");
        let without_signature = signed_assertion.replacen(&signature, "", 1);
        let expected = STANDARD.encode(Sha256::digest(without_signature.as_bytes()));
        assert!(
            xml.contains(&format!("<ds:DigestValue>{expected}</ds:DigestValue>")),
            "digest must match the assertion minus its signature"
        );
        // Identical bytes to the unsigned Assertion (the insertion does not change other parts).
        assert_eq!(without_signature, build_assertion(&input));
    }

    /// The assertion states "which key signed it" (2026-08-28).
    ///
    /// Since ADR-0039 the metadata lists multiple `KeyDescriptor`s, so without this the SP could
    /// only guess by trying all or taking the first. The point is that it uses **the same
    /// representation as the metadata's `KeyDescriptor`**; if this drifts, the SP cannot match
    /// them.
    #[test]
    fn the_assertion_names_the_key_it_was_signed_with() {
        let (signer, public) = rsa_signer();
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");

        let key_info = extract(&xml, "<ds:KeyInfo>", "</ds:KeyInfo>");
        assert!(key_info.contains("<ds:RSAKeyValue>"), "{xml}");

        // The key actually used for signing is included (it does not claim another key).
        let modulus = STANDARD.encode(public.modulus().big_endian_without_leading_zero());
        assert!(
            key_info.contains(&format!("<ds:Modulus>{modulus}</ds:Modulus>")),
            "{key_info}"
        );

        // Rendered the same as the metadata side (the SP matches these two).
        let published = crate::domain::saml_metadata::IdpSigningKey::Rsa {
            modulus_b64: modulus,
            exponent_b64: STANDARD.encode(public.exponent().big_endian_without_leading_zero()),
        };
        assert!(key_info.contains(&published.to_key_value()), "{key_info}");
    }

    /// `KeyInfo` is outside `SignedInfo`, so including it does not change what is signed.
    #[test]
    fn adding_key_info_does_not_change_what_is_signed() {
        let (signer, _) = rsa_signer();
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");
        let signed_info = extract(&xml, "<ds:SignedInfo>", "</ds:SignedInfo>");
        assert!(!signed_info.contains("KeyInfo"), "{signed_info}");
        // Schema order is SignedInfo → SignatureValue → KeyInfo.
        let sv = xml.find("<ds:SignatureValue>").expect("SignatureValue");
        let ki = xml.find("<ds:KeyInfo>").expect("KeyInfo");
        assert!(sv < ki, "{xml}");
    }

    #[test]
    fn signature_verifies_with_the_rsa_public_key_over_canonical_signed_info() {
        let (signer, public) = rsa_signer();
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");

        // Same reconstruction as the SP: take SignedInfo and add xmlns:ds to the apex to get the
        // C14N form.
        let signed_info = extract(&xml, "<ds:SignedInfo>", "</ds:SignedInfo>").replacen(
            "<ds:SignedInfo>",
            &format!("<ds:SignedInfo xmlns:ds=\"{NS_XMLDSIG}\">"),
            1,
        );
        let signature_value = extract(&xml, "<ds:SignatureValue>", "</ds:SignatureValue>")
            .replace("<ds:SignatureValue>", "")
            .replace("</ds:SignatureValue>", "");
        let signature = STANDARD.decode(signature_value).expect("base64");

        aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            public.as_ref(),
        )
        .verify(signed_info.as_bytes(), &signature)
        .expect("signature must verify");
        assert_eq!(public.modulus_len(), signature.len());
    }

    #[test]
    fn ecdsa_signature_is_p1363_and_verifies() {
        use p256::ecdsa::signature::Verifier;
        use p256::elliptic_curve::Generate as _;
        let private = p256::ecdsa::SigningKey::generate_from_rng(&mut rand::rng());
        let verifying = *private.verifying_key();
        let signer = SamlSigner::P256(Box::new(private));
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");
        assert!(xml.contains(SIG_ECDSA_SHA256));

        let signed_info = extract(&xml, "<ds:SignedInfo>", "</ds:SignedInfo>").replacen(
            "<ds:SignedInfo>",
            &format!("<ds:SignedInfo xmlns:ds=\"{NS_XMLDSIG}\">"),
            1,
        );
        let signature_value = extract(&xml, "<ds:SignatureValue>", "</ds:SignatureValue>")
            .replace("<ds:SignatureValue>", "")
            .replace("</ds:SignatureValue>", "");
        let raw = STANDARD.decode(signature_value).expect("base64");
        // The XMLDSIG ECDSA signature value is r||s (64 bytes for P-256).
        assert_eq!(raw.len(), 64);
        let signature = p256::ecdsa::Signature::from_slice(&raw).expect("p1363");
        verifying
            .verify(signed_info.as_bytes(), &signature)
            .expect("signature must verify");
    }

    #[test]
    fn signer_from_pem_matches_key_generation_formats() {
        let (rsa_pem, _) = crate::domain::jwt::generate_rsa_keypair().expect("rsa");
        assert!(matches!(
            SamlSigner::from_pem("RS256", &rsa_pem),
            Ok(SamlSigner::Rsa(_))
        ));
        let (ec_pem, _) = crate::domain::jwt::generate_ec_keypair().expect("ec");
        assert!(matches!(
            SamlSigner::from_pem("ES256", &ec_pem),
            Ok(SamlSigner::P256(_))
        ));
        assert!(SamlSigner::from_pem("HS256", "x").is_err());
        assert!(SamlSigner::from_pem("RS256", "not a pem").is_err());
    }

    #[test]
    fn canonical_form_has_no_self_closing_tags_in_the_signed_subtree() {
        let (signer, _) = rsa_signer();
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");
        let assertion = extract(&xml, "<saml:Assertion", "</saml:Assertion>");
        assert!(
            !assertion.contains("/>"),
            "canonical XML must not use self-closing tags: {assertion}"
        );
    }

    #[test]
    fn omits_in_response_to_and_email_when_absent() {
        let (signer, _) = rsa_signer();
        let mut input = test_input();
        input.in_response_to = None;
        input.email = None;
        let xml = build_signed_response_xml(&input, &signer).expect("build");
        assert!(!xml.contains("InResponseTo"));
        assert!(!xml.contains("AttributeStatement"));
    }

    #[test]
    fn generated_ids_are_ncname_safe() {
        let id = generate_saml_id();
        assert!(id.starts_with('_'));
        assert_eq!(id.len(), 33);
    }
}
