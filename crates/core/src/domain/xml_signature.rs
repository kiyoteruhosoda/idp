//! XML 署名（XMLDSIG）の**検証**（AP12。ADR-0027）。
//!
//! 外部 SAML IdP から受け取った Response / Assertion の署名を確かめる。生成側
//! （[`crate::domain::saml_response`]）と違い、XML を作るのは相手なので本物の正準化が要る
//! （[`crate::domain::xml_c14n`]）。
//!
//! # 対応する組み合わせを絞る
//!
//! - 正準化: 排他的（`xml-exc-c14n#`）のみ。
//! - ダイジェスト: SHA-256 のみ。
//! - 署名: RSA-SHA256 / ECDSA-SHA256 のみ。
//! - 変換: enveloped signature + 排他的正準化のみ。
//!
//! **未対応の値は既定へ丸めずエラー**にする。丸めると、SHA-1 の署名を「検証した」ことにして
//! しまう経路が生まれる。
//!
//! # 署名ラッピング（XSW）
//!
//! SAML SP の典型的な破れ方は、署名そのものではなく「**署名された要素**と**読む要素**が違う」
//! ことで起きる。攻撃者は正当な署名付きアサーションを別の場所へ押し込み、自分が作った
//! 無署名のアサーションを SP に読ませる。ここでは:
//!
//! - `Reference URI` は `#ID` 形式のみ（空 URI = 文書全体・外部参照は拒否）。
//! - 参照先 ID を持つ要素が文書全体で**ちょうど 1 つ**であること（[`xml_c14n`] が数える）。
//! - 署名は**署名対象の直下**にあること（enveloped）。
//!
//! を満たさない限り検証は失敗する。「どの要素が検証されたか」は
//! [`VerifiedSignature::signed_element_id`] で呼び出し側へ返し、**その ID の要素から読み直す**
//! ことを呼び出し側の責務にする（[`crate::domain::saml_external_idp`]）。

use crate::domain::error::{DomainError, Result};
use crate::domain::xml_c14n::{canonicalize, Target, ALGORITHM_EXC_C14N, NS_XMLDSIG};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::signature::Verifier as _;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};

const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SIG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SIG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const TRANSFORM_ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// 検証に通った署名。**どの要素が**検証されたかを持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// 署名が覆っていた要素の `ID`。呼び出し側はこの ID の要素から値を読み直す。
    pub signed_element_id: String,
}

/// `ds:Signature` から取り出した、検証に必要な値。
#[derive(Debug, Clone)]
struct SignatureParts {
    reference_id: String,
    digest_value: Vec<u8>,
    signature_value: Vec<u8>,
    signature_algorithm: String,
    inclusive_prefixes: Vec<String>,
}

/// 署名検証に使う公開鍵。管理者が登録した証明書（base64 DER の X.509）から取り出す。
pub enum SigningCertificateKey {
    Rsa(Box<RsaPublicKey>),
    P256(Box<p256::ecdsa::VerifyingKey>),
}

impl SigningCertificateKey {
    /// `<ds:X509Certificate>` 本文（base64 DER。空白を含んでいてよい）から公開鍵を取り出す。
    ///
    /// **証明書チェーンは検証しない。** 信頼の起点は「管理者がこの証明書を外部 IdP の設定として
    /// 登録した」ことであって CA ではない（SAML メタデータの交換はそういう運用になっている）。
    /// 有効期限も見ない——期限切れの証明書で署名を止めると、IdP 側の更新漏れで全員のログインが
    /// 落ちる一方、鍵の危殆化への対処は管理者が設定から外すことで行える。
    pub fn from_base64_certificate(certificate: &str) -> Result<Self> {
        use x509_cert::der::Decode as _;

        let compact: String = certificate.chars().filter(|c| !c.is_whitespace()).collect();
        let der = STANDARD
            .decode(compact.as_bytes())
            .map_err(|e| DomainError::InvalidValue(format!("certificate is not base64: {e}")))?;
        let cert = x509_cert::Certificate::from_der(&der)
            .map_err(|e| DomainError::InvalidValue(format!("certificate is not X.509 DER: {e}")))?;
        let spki = cert.tbs_certificate.subject_public_key_info;

        // RSA を先に試し、駄目なら P-256。どちらでもなければ拒否する（対応するのは SAML IdP が
        // 実際に使う 2 種類だけ。ADR-0027）。
        let spki_der = {
            use x509_cert::der::Encode as _;
            spki.to_der()
                .map_err(|e| DomainError::InvalidValue(format!("bad public key: {e}")))?
        };
        if let Ok(key) =
            <RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(&spki_der)
        {
            return Ok(Self::Rsa(Box::new(key)));
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
            (Self::Rsa(key), SIG_RSA_SHA256) => {
                let verifying = RsaVerifyingKey::<Sha256>::new((**key).clone());
                let signature = RsaSignature::try_from(signature).map_err(|e| {
                    DomainError::InvalidValue(format!("malformed RSA signature: {e}"))
                })?;
                verifying
                    .verify(signed, &signature)
                    .map_err(|_| DomainError::InvalidValue("signature does not verify".to_string()))
            }
            (Self::P256(key), SIG_ECDSA_SHA256) => {
                // XMLDSIG の ECDSA 署名は r||s の連結（DER ではない）。
                let signature = p256::ecdsa::Signature::from_slice(signature).map_err(|e| {
                    DomainError::InvalidValue(format!("malformed ECDSA signature: {e}"))
                })?;
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

/// `element_id` の要素に掛かった enveloped 署名を、**いずれかの**証明書で検証する。
///
/// 証明書を複数受け取るのは、IdP の証明書更新期間に新旧 2 枚が同時に有効になるため（1 枚しか
/// 持てないと更新のたびにログインが止まる）。1 枚でも通れば成功で、どれで通ったかは返さない
/// （運用上の意味が無く、返すと「どの鍵が使われたか」を攻撃者へ教える出口になる）。
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

    // 1. ダイジェスト: 署名を取り除いた対象要素の正準形と突き合わせる。
    let canonical = canonicalize(
        xml,
        Target::SignedElement(element_id),
        &parts.inclusive_prefixes,
    )?;
    let digest = Sha256::digest(&canonical);
    if digest.as_slice() != parts.digest_value.as_slice() {
        return Err(DomainError::InvalidValue(
            "the signed element does not match its digest".to_string(),
        ));
    }

    // 2. 署名: `SignedInfo` の正準形に対して検証する。
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

/// `element_id` の要素の直下にある `ds:Signature` を読む。
///
/// 接頭辞（`ds:`）は実装依存なのでローカル名で判定する。**対象要素の直下**に限るため深さを追う
/// （深い所にある別の署名を拾うと、署名ラッピングの入口になる）。
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
                // 空要素タグは開始と終了を兼ねる。
                state.on_start(&e)?;
                state.on_end()?;
            }
            Event::End(_) => state.on_end()?,
            Event::Text(e) if state.capture.is_some() => {
                let text = e
                    .unescape()
                    .map_err(|err| DomainError::InvalidValue(format!("bad text: {err}")))?;
                state.captured.push_str(&text);
            }
            _ => {}
        }
        buf.clear();
    }
    state.found.into_parts()
}

/// `ds:Signature` を読む間の状態。
struct ParseState<'a> {
    element_id: &'a str,
    depth: usize,
    target_depth: Option<usize>,
    signature_depth: Option<usize>,
    /// 本文を集めている要素（`DigestValue` / `SignatureValue`）。
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

fn local_name(name: &[u8]) -> Result<String> {
    let name = std::str::from_utf8(name)
        .map_err(|e| DomainError::InvalidValue(format!("non-UTF-8 name: {e}")))?;
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
            let value = attr
                .unescape_value()
                .map_err(|err| DomainError::InvalidValue(format!("bad attribute value: {err}")))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

/// XMLDSIG の `Signature` 名前空間（呼び出し側の判定用に再輸出する）。
pub const NS_SIGNATURE: &str = NS_XMLDSIG;
