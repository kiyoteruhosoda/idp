//! **Verification** of XML signatures (XMLDSIG) (AP12, ADR-0027).
//!
//! Checks signatures on Responses / Assertions received from external SAML IdPs. Unlike the generating side
//! ([`crate::domain::saml_response`]), the XML is made by the other party, so real canonicalization is needed
//! ([`crate::domain::xml_c14n`]).
//!
//! # Narrowing the supported combinations
//!
//! - Canonicalization: exclusive (`xml-exc-c14n#`) only.
//! - Digest: SHA-256 only.
//! - Signature: RSA-SHA256 / ECDSA-SHA256 only.
//! - Transforms: enveloped signature + exclusive canonicalization only.
//!
//! **Unsupported values are errors, not rounded to a default.** Rounding would create a path that treats a SHA-1
//! signature as "verified".
//!
//! # Signature wrapping (XSW)
//!
//! The typical way SAML SPs break is not the signature itself but the **signed element** and the **element read**
//! being different. An attacker pushes a legitimately signed assertion somewhere else and makes the SP read
//! an unsigned assertion they crafted. Here, verification fails unless:
//!
//! - `Reference URI` is of the `#ID` form only (empty URI = whole document, and external references are rejected).
//! - Exactly **one** element in the whole document has the referenced ID (counted by [`xml_c14n`]).
//! - The signature is **directly under the signed element** (enveloped).
//!
//! all hold. "Which element was verified" is returned to the caller via
//! [`VerifiedSignature::signed_element_id`], and **re-reading from the element with that ID**
//! is the caller's responsibility ([`crate::domain::saml_external_idp`]).

use crate::domain::error::{DomainError, Result};
use crate::domain::xml_c14n::{canonicalize, Target, ALGORITHM_EXC_C14N, NS_XMLDSIG};
use crate::domain::xml_text;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha2::{Digest, Sha256};

const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SIG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// A signature that passed verification. Holds **which element** was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// `ID` of the element the signature covered. Callers re-read values from the element with this ID.
    pub signed_element_id: String,
}

/// Values needed for verification, extracted from `ds:Signature`.
#[derive(Debug, Clone)]
struct SignatureParts {
    reference_id: String,
    digest_value: Vec<u8>,
    signature_value: Vec<u8>,
    signature_algorithm: String,
    inclusive_prefixes: Vec<String>,
}

/// Public key used for signature verification. Extracted from a certificate registered by an admin (base64 DER X.509).
pub enum SigningCertificateKey {
    /// SubjectPublicKeyInfo DER (verified at extraction to be readable as an RSA public key).
    Rsa(Vec<u8>),
    P256(Box<p256::ecdsa::VerifyingKey>),
}

impl SigningCertificateKey {
    /// Extracts the public key from the `<ds:X509Certificate>` body (base64 DER; may contain whitespace).
    ///
    /// **The certificate chain is not verified.** The trust anchor is "an admin registered this certificate as the
    /// external IdP's setting", not a CA (that is how SAML metadata exchange is operated).
    /// Expiry is not checked either -- stopping signatures on an expired certificate would break everyone's login when the
    /// IdP forgets to renew, while key compromise is handled by the admin removing it from the settings.
    pub fn from_base64_certificate(certificate: &str) -> Result<Self> {
        use x509_cert::der::Decode as _;

        let compact: String = certificate.chars().filter(|c| !c.is_whitespace()).collect();
        let der = STANDARD
            .decode(compact.as_bytes())
            .map_err(|e| DomainError::InvalidValue(format!("certificate is not base64: {e}")))?;
        let cert = x509_cert::Certificate::from_der(&der)
            .map_err(|e| DomainError::InvalidValue(format!("certificate is not X.509 DER: {e}")))?;
        let spki = cert.tbs_certificate().subject_public_key_info();

        // Try RSA first, then P-256. Reject anything else (only the 2 kinds SAML IdPs
        // actually use are supported; ADR-0027).
        let spki_der = {
            use x509_cert::der::Encode as _;
            spki.to_der()
                .map_err(|e| DomainError::InvalidValue(format!("bad public key: {e}")))?
        };
        if aws_lc_rs::rsa::PublicKey::from_der(&spki_der).is_ok() {
            return Ok(Self::Rsa(spki_der));
        }
        if let Ok(key) =
            <p256::ecdsa::VerifyingKey as p256::pkcs8::DecodePublicKey>::from_public_key_der(
                &spki_der,
            )
        {
            return Ok(Self::P256(Box::new(key)));
        }
        Err(DomainError::InvalidValue(
            "certificate public key must be RSA or P-256".to_string(),
        ))
    }

    fn verify(&self, algorithm: &str, signed: &[u8], signature: &[u8]) -> Result<()> {
        match (self, algorithm) {
            (Self::Rsa(spki_der), SIG_RSA_SHA256) => {
                // Key sizes from 1024 bits are accepted (so registered external IdP certificates don't start
                // being rejected due to a component swap; same range as before moving RSA to aws-lc-rs).
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                    spki_der,
                )
                .verify(signed, signature)
                .map_err(|_| DomainError::InvalidValue("signature does not verify".to_string()))
            }
            (Self::P256(key), SIG_ECDSA_SHA256) => {
                // XMLDSIG ECDSA signatures are the concatenation r||s (not DER).
                let signature = p256::ecdsa::Signature::from_slice(signature).map_err(|e| {
                    DomainError::InvalidValue(format!("malformed ECDSA signature: {e}"))
                })?;
                use p256::ecdsa::signature::Verifier as _;
                key.verify(signed, &signature)
                    .map_err(|_| DomainError::InvalidValue("signature does not verify".to_string()))
            }
            (_, SIG_RSA_SHA256 | SIG_ECDSA_SHA256) => Err(DomainError::InvalidValue(
                "the signing certificate does not match the signature algorithm".to_string(),
            )),
            (_, other) => Err(DomainError::InvalidValue(format!(
                "unsupported signature algorithm: {other}"
            ))),
        }
    }
}

/// Verifies the enveloped signature on the `element_id` element with **any** of the certificates.
///
/// Multiple certificates are accepted because old and new are both valid during an IdP's certificate rollover (with only
/// one, login would stop at every rollover). Success if any one passes; which one is not returned
/// (it has no operational meaning, and returning it would leak "which key was used" to an attacker).
pub fn verify_enveloped_signature(
    xml: &str,
    element_id: &str,
    certificates: &[String],
) -> Result<VerifiedSignature> {
    if certificates.is_empty() {
        return Err(DomainError::InvalidValue(
            "no signing certificate is configured for this provider".to_string(),
        ));
    }
    let parts = parse_signature(xml, element_id)?;
    if parts.reference_id != element_id {
        return Err(DomainError::InvalidValue(
            "the signature does not reference the element it is attached to".to_string(),
        ));
    }

    // 1. Digest: compare against the canonical form of the target element with the signature removed.
    let canonical = canonicalize(
        xml,
        Target::SignedElement(element_id),
        &parts.inclusive_prefixes,
    )?;
    let digest = Sha256::digest(&canonical);
    if digest[..] != parts.digest_value[..] {
        return Err(DomainError::InvalidValue(
            "the signed element does not match its digest".to_string(),
        ));
    }

    // 2. Signature: verify against the canonical form of `SignedInfo`.
    let signed_info = canonicalize(
        xml,
        Target::SignedInfoOf(element_id),
        &parts.inclusive_prefixes,
    )?;
    let mut last_error = DomainError::InvalidValue("signature does not verify".to_string());
    for certificate in certificates {
        let key = match SigningCertificateKey::from_base64_certificate(certificate) {
            Ok(key) => key,
            Err(e) => {
                last_error = e;
                continue;
            }
        };
        match key.verify(
            &parts.signature_algorithm,
            &signed_info,
            &parts.signature_value,
        ) {
            Ok(()) => {
                return Ok(VerifiedSignature {
                    signed_element_id: element_id.to_string(),
                })
            }
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

/// Reads the `ds:Signature` directly under the `element_id` element.
///
/// The prefix (`ds:`) is implementation-dependent, so local names are compared. Depth is tracked to restrict to
/// **directly under the target element** (picking up another signature deeper down opens the door to signature wrapping).
fn parse_signature(xml: &str, element_id: &str) -> Result<SignatureParts> {
    let mut reader = Reader::from_reader(xml.as_bytes());
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut state = ParseState {
        element_id,
        depth: 0,
        target_depth: None,
        signature_depth: None,
        capture: None,
        captured: String::new(),
        found: Found::default(),
    };

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| DomainError::InvalidValue(format!("malformed XML: {e}")))?;
        match event {
            Event::Eof => break,
            Event::Start(e) => state.on_start(&e)?,
            Event::Empty(e) => {
                // An empty-element tag is both start and end.
                state.on_start(&e)?;
                state.on_end()?;
            }
            Event::End(_) => state.on_end()?,
            Event::Text(e) if state.capture.is_some() => {
                let text = xml_text::text(&e)
                    .map_err(|err| DomainError::InvalidValue(format!("bad text: {err}")))?;
                state.captured.push_str(&text);
            }
            Event::GeneralRef(e) if state.capture.is_some() => {
                let text = xml_text::general_ref(&e)
                    .map_err(|err| DomainError::InvalidValue(format!("bad text: {err}")))?;
                state.captured.push_str(&text);
            }
            _ => {}
        }
        buf.clear();
    }
    state.found.into_parts()
}

/// State while reading `ds:Signature`.
struct ParseState<'a> {
    element_id: &'a str,
    depth: usize,
    target_depth: Option<usize>,
    signature_depth: Option<usize>,
    /// Element whose body is being collected (`DigestValue` / `SignatureValue`).
    capture: Option<Capture>,
    captured: String,
    found: Found,
}

#[derive(Clone, Copy)]
enum Capture {
    Digest,
    Signature,
}

#[derive(Default)]
struct Found {
    reference_id: Option<String>,
    digest_value: Option<Vec<u8>>,
    signature_value: Option<Vec<u8>>,
    signature_algorithm: Option<String>,
    digest_algorithm: Option<String>,
    canonicalization: Option<String>,
    inclusive_prefixes: Vec<String>,
    transforms: Vec<String>,
}

impl ParseState<'_> {
    fn on_start(&mut self, e: &quick_xml::events::BytesStart<'_>) -> Result<()> {
        self.depth += 1;
        let depth = self.depth;
        let local = local_name(e.name().as_ref())?;

        if self.target_depth.is_none() && attribute(e, "ID")?.as_deref() == Some(self.element_id) {
            self.target_depth = Some(depth);
        }
        if local == "Signature"
            && self.target_depth == Some(depth - 1)
            && self.signature_depth.is_none()
        {
            self.signature_depth = Some(depth);
        }
        if self.signature_depth.is_none_or(|d| depth < d) {
            return Ok(());
        }

        let found = &mut self.found;
        match local.as_str() {
            "CanonicalizationMethod" => found.canonicalization = attribute(e, "Algorithm")?,
            "SignatureMethod" => found.signature_algorithm = attribute(e, "Algorithm")?,
            "Reference" if found.reference_id.is_none() => {
                let uri = attribute(e, "URI")?.unwrap_or_default();
                let id = uri.strip_prefix('#').ok_or_else(|| {
                    DomainError::InvalidValue(
                        "signature Reference URI must be a same-document `#ID` reference"
                            .to_string(),
                    )
                })?;
                found.reference_id = Some(id.to_string());
            }
            "Transform" => {
                if let Some(algorithm) = attribute(e, "Algorithm")? {
                    found.transforms.push(algorithm);
                }
            }
            "InclusiveNamespaces" => {
                if let Some(list) = attribute(e, "PrefixList")? {
                    found
                        .inclusive_prefixes
                        .extend(list.split_whitespace().map(str::to_string));
                }
            }
            "DigestMethod" => found.digest_algorithm = attribute(e, "Algorithm")?,
            "DigestValue" => {
                self.capture = Some(Capture::Digest);
                self.captured.clear();
            }
            "SignatureValue" => {
                self.capture = Some(Capture::Signature);
                self.captured.clear();
            }
            _ => {}
        }
        Ok(())
    }

    fn on_end(&mut self) -> Result<()> {
        if let Some(kind) = self.capture.take() {
            let compact: String = self
                .captured
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let decoded = STANDARD.decode(compact.as_bytes()).map_err(|e| {
                DomainError::InvalidValue(format!("signature value is not base64: {e}"))
            })?;
            match kind {
                Capture::Digest => self.found.digest_value = Some(decoded),
                Capture::Signature => self.found.signature_value = Some(decoded),
            }
        }
        if self.signature_depth == Some(self.depth) {
            self.signature_depth = None;
        }
        if self.target_depth == Some(self.depth) {
            self.target_depth = None;
        }
        self.depth = self.depth.saturating_sub(1);
        Ok(())
    }
}

impl Found {
    fn into_parts(self) -> Result<SignatureParts> {
        if self.canonicalization.as_deref() != Some(ALGORITHM_EXC_C14N) {
            return Err(DomainError::InvalidValue(format!(
                "unsupported canonicalization method: {}",
                self.canonicalization
                    .unwrap_or_else(|| "(missing)".to_string())
            )));
        }
        if self.digest_algorithm.as_deref() != Some(DIGEST_SHA256) {
            return Err(DomainError::InvalidValue(format!(
                "unsupported digest method: {}",
                self.digest_algorithm
                    .unwrap_or_else(|| "(missing)".to_string())
            )));
        }
        if !self.transforms.iter().any(|t| t == TRANSFORM_ENVELOPED) {
            return Err(DomainError::InvalidValue(
                "the signature must use the enveloped-signature transform".to_string(),
            ));
        }
        for transform in &self.transforms {
            if transform != TRANSFORM_ENVELOPED && transform != ALGORITHM_EXC_C14N {
                return Err(DomainError::InvalidValue(format!(
                    "unsupported signature transform: {transform}"
                )));
            }
        }
        Ok(SignatureParts {
            reference_id: self.reference_id.ok_or_else(|| {
                DomainError::InvalidValue("the signature has no Reference".to_string())
            })?,
            digest_value: self.digest_value.ok_or_else(|| {
                DomainError::InvalidValue("the signature has no DigestValue".to_string())
            })?,
            signature_value: self.signature_value.ok_or_else(|| {
                DomainError::InvalidValue("the signature has no SignatureValue".to_string())
            })?,
            signature_algorithm: self.signature_algorithm.ok_or_else(|| {
                DomainError::InvalidValue("the signature has no SignatureMethod".to_string())
            })?,
            inclusive_prefixes: self.inclusive_prefixes,
        })
    }
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

/// XMLDSIG `Signature` namespace (re-exported for callers' checks).
pub const NS_SIGNATURE: &str = NS_XMLDSIG;
