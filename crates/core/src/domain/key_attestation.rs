//! Android の Key Attestation（鍵の証明）を確かめる（task #892。ADR-0077）。
//!
//! 認証アプリは Keystore の中で鍵を作るときに assay の challenge を入れ、Keystore が出した証明書の
//! 鎖（鍵の証明書 → 中間 → Google の根）をそのまま送ってくる。ここで確かめること:
//!
//! | 項目 | 条件 |
//! |---|---|
//! | 鎖 | 1 枚ずつ上の証明書の鍵で署名がつながり、いちばん上の鍵が信じる根の鍵 |
//! | 拡張 | `KeyDescription`（1.3.6.1.4.1.11129.2.1.17）は鍵の証明書だけにある。上の証明書は CA |
//! | 置き場 | TEE か StrongBox（ソフトウェアは `allow_software` のときだけ。stg の確かめ用） |
//! | challenge | assay が出した値 |
//! | 鍵 | EC P-256・署名用・Keystore の中で作った |
//! | 指紋 | 生体だけで解ける・使うたびに求める（`noAuthRequired` 無し・`authTimeout` 無し） |
//! | 端末 | 起動の検証が Verified でロック済み（`allow_software` のときは見ない） |
//! | アプリ | パッケージ名と署名の証明書の SHA-256 が、assay が信じる値 |
//!
//! ⚠ **ここで確かめないこと**: Google の失効一覧（https://android.googleapis.com/attestation/status）・
//! 証明書の有効期間（鍵の証明書の期間は端末によって当てにならない）。ADR-0077 の「防げないこと」。

use crate::domain::der::{
    self, DerElement, DerError, DerReader, TagClass, TAG_BIT_STRING, TAG_BOOLEAN, TAG_ENUMERATED,
    TAG_INTEGER, TAG_NULL, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET,
};
use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};

const OID_KEY_DESCRIPTION: &str = "1.3.6.1.4.1.11129.2.1.17";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";

/// Google の Key Attestation の根（RSA 4096 と ECDSA P-384「Key Attestation CA1」）。
///
/// 出所は https://android.googleapis.com/attestation/root （2026-11-04 に取得）。本番はこの 2 つだけを信じる。
pub const GOOGLE_ROOTS_PEM: &str = include_str!("key_attestation/google-roots.pem");

/// 鎖の長さの上限（RKP の端末でも 4〜5 枚）。
const MAX_CHAIN_LEN: usize = 8;

// AuthorizationList の印（Android の KeyMint の定義）。
const TAG_PURPOSE: u32 = 1;
const TAG_ALGORITHM: u32 = 2;
const TAG_EC_CURVE: u32 = 10;
const TAG_NO_AUTH_REQUIRED: u32 = 503;
const TAG_USER_AUTH_TYPE: u32 = 504;
const TAG_AUTH_TIMEOUT: u32 = 505;
const TAG_ORIGIN: u32 = 702;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_ATTESTATION_APPLICATION_ID: u32 = 709;

const PURPOSE_SIGN: u64 = 2;
const ALGORITHM_EC: u64 = 3;
const EC_CURVE_P256: u64 = 1;
const ORIGIN_GENERATED: u64 = 0;
/// `HardwareAuthenticatorType` のビット。
const AUTH_TYPE_PASSWORD: u64 = 1;
const AUTH_TYPE_FINGERPRINT: u64 = 2;
const VERIFIED_BOOT_VERIFIED: u64 = 0;

/// 鍵の置き場（`SecurityLevel`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox,
}

impl KeySecurityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::TrustedEnvironment => "tee",
            Self::StrongBox => "strongbox",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "software" => Some(Self::Software),
            "tee" => Some(Self::TrustedEnvironment),
            "strongbox" => Some(Self::StrongBox),
            _ => None,
        }
    }

    fn from_der(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Software),
            1 => Some(Self::TrustedEnvironment),
            2 => Some(Self::StrongBox),
            _ => None,
        }
    }
}

/// assay が信じるもの（環境変数から作る。組織ごとには変えない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPolicy {
    /// 信じる根の公開鍵（SubjectPublicKeyInfo の DER）。
    pub trusted_root_keys: Vec<Vec<u8>>,
    /// 認証アプリのパッケージ名（`com.nolumia.auth`）。
    pub package_name: String,
    /// 認証アプリの署名の証明書の SHA-256（deck の配布鍵）。
    pub signing_cert_digests: Vec<[u8; 32]>,
    /// ソフトウェアの鍵と、検証されていない起動を受けるか（stg の確かめの台本のためだけ）。
    pub allow_software: bool,
}

/// 確かめが通った鍵。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedKey {
    /// 鍵の SubjectPublicKeyInfo（DER）。署名の確かめと鍵の番号に使う。
    pub public_key_spki: Vec<u8>,
    pub security_level: KeySecurityLevel,
}

/// 受け付けなかった理由（監査とアプリへの返事に使う。秘密は載らない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationRejection {
    /// 証明書・拡張の形が崩れている。
    Malformed,
    /// 署名がつながらない・信じる根に届かない・上の証明書が CA でない。
    UntrustedChain,
    /// challenge が assay の出した値でない。
    WrongChallenge,
    /// 鍵がソフトウェアにある。
    InsecureKeyStore,
    /// EC P-256・署名用・Keystore の中で作った鍵でない。
    WrongKeyParameters,
    /// 使うたびに指紋を求める鍵でない。
    NoBiometricRequirement,
    /// 端末の起動が検証されていない・ロックされていない。
    UnverifiedDevice,
    /// パッケージ名か署名の証明書が違う。
    WrongApplication,
}

impl AttestationRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UntrustedChain => "untrusted_chain",
            Self::WrongChallenge => "wrong_challenge",
            Self::InsecureKeyStore => "insecure_key_store",
            Self::WrongKeyParameters => "wrong_key_parameters",
            Self::NoBiometricRequirement => "no_biometric_requirement",
            Self::UnverifiedDevice => "unverified_device",
            Self::WrongApplication => "wrong_application",
        }
    }
}

impl From<DerError> for AttestationRejection {
    fn from(_: DerError) -> Self {
        Self::Malformed
    }
}

/// 証明書の鎖（鍵の証明書が先頭。DER）を確かめる。
pub fn verify_attestation(
    chain: &[Vec<u8>],
    challenge: &[u8],
    policy: &AttestationPolicy,
) -> Result<AttestedKey, AttestationRejection> {
    if chain.len() < 2 || chain.len() > MAX_CHAIN_LEN {
        return Err(AttestationRejection::Malformed);
    }
    let certs = chain
        .iter()
        .map(|der| Certificate::parse(der))
        .collect::<Result<Vec<_>, _>>()?;

    // 1. 鎖: 1 枚ずつ上の鍵で署名がつながり、上の証明書は CA で鍵の証明（拡張）を持たない。
    for pair in certs.windows(2) {
        let (child, parent) = (&pair[0], &pair[1]);
        if child.issuer != parent.subject || !parent.is_ca()? {
            return Err(AttestationRejection::UntrustedChain);
        }
        if parent.extension(OID_KEY_DESCRIPTION).is_some() {
            return Err(AttestationRejection::UntrustedChain);
        }
        if !child.is_signed_by(parent.spki)? {
            return Err(AttestationRejection::UntrustedChain);
        }
    }
    let top = certs.last().ok_or(AttestationRejection::Malformed)?;
    if !policy
        .trusted_root_keys
        .iter()
        .any(|root| root.as_slice() == top.spki)
    {
        return Err(AttestationRejection::UntrustedChain);
    }

    // 2. 鍵の証明（拡張）を読む。
    let leaf = &certs[0];
    let value = leaf
        .extension(OID_KEY_DESCRIPTION)
        .ok_or(AttestationRejection::Malformed)?;
    let description = KeyDescription::parse(value)?;

    if description.challenge != challenge {
        return Err(AttestationRejection::WrongChallenge);
    }
    let level = match (description.attestation_level, description.keymint_level) {
        (a, k) if a == k => a,
        _ => return Err(AttestationRejection::InsecureKeyStore),
    };
    if level == KeySecurityLevel::Software && !policy.allow_software {
        return Err(AttestationRejection::InsecureKeyStore);
    }
    // 守りの条件は、鍵の置き場が守る側の一覧（ソフトウェアならソフトウェアの一覧）で見る。
    let enforced = if level == KeySecurityLevel::Software {
        &description.software_enforced
    } else {
        &description.hardware_enforced
    };

    // 3. 鍵: EC P-256・署名用・Keystore の中で作った。
    if enforced.algorithm != Some(ALGORITHM_EC)
        || enforced.ec_curve != Some(EC_CURVE_P256)
        || !enforced.purposes.contains(&PURPOSE_SIGN)
        || enforced.origin != Some(ORIGIN_GENERATED)
        || !is_p256_key(leaf.spki)?
    {
        return Err(AttestationRejection::WrongKeyParameters);
    }

    // 4. 使うたびに指紋（どちらの一覧にも「認証なし」が無く、生体だけ・時間で解けない）。
    let either_no_auth = description.software_enforced.no_auth_required
        || description.hardware_enforced.no_auth_required;
    let auth_type = enforced.user_auth_type.unwrap_or(0);
    if either_no_auth
        || auth_type & AUTH_TYPE_FINGERPRINT == 0
        || auth_type & AUTH_TYPE_PASSWORD != 0
        || enforced.auth_timeout.is_some_and(|t| t > 0)
        || description
            .software_enforced
            .auth_timeout
            .is_some_and(|t| t > 0)
    {
        return Err(AttestationRejection::NoBiometricRequirement);
    }

    // 5. 端末: 起動が検証され、ロックされている。
    if !policy.allow_software {
        match &description.hardware_enforced.root_of_trust {
            Some(root)
                if root.device_locked && root.verified_boot_state == VERIFIED_BOOT_VERIFIED => {}
            _ => return Err(AttestationRejection::UnverifiedDevice),
        }
    }

    // 6. アプリ: パッケージ名と署名の証明書（どちらの一覧に載っていてもよい。ふつうはソフトウェア側）。
    let application = description
        .software_enforced
        .application_id
        .as_ref()
        .or(description.hardware_enforced.application_id.as_ref())
        .ok_or(AttestationRejection::WrongApplication)?;
    if !application
        .package_names
        .iter()
        .any(|name| name == policy.package_name.as_bytes())
        || application.signature_digests.is_empty()
        || !application.signature_digests.iter().all(|d| {
            policy
                .signing_cert_digests
                .iter()
                .any(|ok| ok.as_slice() == d.as_slice())
        })
    {
        return Err(AttestationRejection::WrongApplication);
    }

    Ok(AttestedKey {
        public_key_spki: leaf.spki.to_vec(),
        security_level: level,
    })
}

/// PEM の証明書（複数可）から公開鍵（SubjectPublicKeyInfo の DER）を取り出す。根の鍵の設定に使う。
pub fn root_keys_from_pem(pem: &str) -> Result<Vec<Vec<u8>>, AttestationRejection> {
    use base64::Engine;
    let mut keys = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            inside = true;
            body.clear();
        } else if line == "-----END CERTIFICATE-----" {
            inside = false;
            let der = base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .map_err(|_| AttestationRejection::Malformed)?;
            keys.push(Certificate::parse(&der)?.spki.to_vec());
        } else if inside {
            body.push_str(line);
        }
    }
    if inside {
        return Err(AttestationRejection::Malformed);
    }
    Ok(keys)
}

/// 証明書の、確かめに要る部分だけ。
struct Certificate<'a> {
    tbs: &'a [u8],
    signature_algorithm: String,
    signature: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    /// (OID, 中身の OCTET STRING の中身)
    extensions: Vec<(String, &'a [u8])>,
}

impl<'a> Certificate<'a> {
    fn parse(der: &'a [u8]) -> Result<Self, AttestationRejection> {
        let cert = der::single(der)?;
        let mut parts = expect_sequence(&cert)?;
        let tbs = parts.expect(TAG_SEQUENCE)?;
        let algorithm = parts.expect(TAG_SEQUENCE)?;
        let signature = parts.expect(TAG_BIT_STRING)?.bit_string_bytes()?;
        if !parts.is_empty() {
            return Err(AttestationRejection::Malformed);
        }
        let signature_algorithm = algorithm.children().expect(TAG_OID)?.oid()?;

        let mut fields = tbs.children();
        fields.optional_context(0)?; // version
        fields.expect(TAG_INTEGER)?; // serialNumber
        fields.expect(TAG_SEQUENCE)?; // signature
        let issuer = fields.expect(TAG_SEQUENCE)?.raw;
        fields.expect(TAG_SEQUENCE)?; // validity
        let subject = fields.expect(TAG_SEQUENCE)?.raw;
        let spki = fields.expect(TAG_SEQUENCE)?.raw;
        fields.optional_context(1)?; // issuerUniqueID
        fields.optional_context(2)?; // subjectUniqueID
        let mut extensions = Vec::new();
        if let Some(wrapper) = fields.optional_context(3)? {
            let list = wrapper.children().expect(TAG_SEQUENCE)?;
            let mut items = list.children();
            while !items.is_empty() {
                let ext = items.expect(TAG_SEQUENCE)?;
                let mut e = ext.children();
                let oid = e.expect(TAG_OID)?.oid()?;
                let mut next = e.next_element()?;
                if next.class == TagClass::Universal && next.number == TAG_BOOLEAN {
                    next = e.next_element()?;
                }
                if next.class != TagClass::Universal || next.number != TAG_OCTET_STRING {
                    return Err(AttestationRejection::Malformed);
                }
                if extensions.iter().any(|(o, _)| o == &oid) {
                    // 同じ拡張が 2 つある証明書は受けない（どちらを読むかで結果が変わる）。
                    return Err(AttestationRejection::Malformed);
                }
                extensions.push((oid, next.contents));
            }
        }
        Ok(Self {
            tbs: tbs.raw,
            signature_algorithm,
            signature,
            issuer,
            subject,
            spki,
            extensions,
        })
    }

    fn extension(&self, oid: &str) -> Option<&'a [u8]> {
        self.extensions
            .iter()
            .find(|(o, _)| o == oid)
            .map(|(_, value)| *value)
    }

    /// 基本制約（basicConstraints）で CA と名乗っているか。
    fn is_ca(&self) -> Result<bool, AttestationRejection> {
        let Some(value) = self.extension(OID_BASIC_CONSTRAINTS) else {
            return Ok(false);
        };
        let constraints = der::single(value)?;
        let mut items = expect_sequence(&constraints)?;
        if items.is_empty() {
            return Ok(false);
        }
        let first = items.next_element()?;
        Ok(first.class == TagClass::Universal && first.number == TAG_BOOLEAN && first.boolean()?)
    }

    /// `issuer_spki` の鍵でこの証明書に署名されているか。
    fn is_signed_by(&self, issuer_spki: &[u8]) -> Result<bool, AttestationRejection> {
        let (key_kind, key_bytes) = public_key_of(issuer_spki)?;
        let algorithm: &'static dyn VerificationAlgorithm =
            match (key_kind, self.signature_algorithm.as_str()) {
                (KeyKind::P256, OID_ECDSA_SHA256) => &signature::ECDSA_P256_SHA256_ASN1,
                (KeyKind::P256, OID_ECDSA_SHA384) => &signature::ECDSA_P256_SHA384_ASN1,
                (KeyKind::P384, OID_ECDSA_SHA256) => &signature::ECDSA_P384_SHA256_ASN1,
                (KeyKind::P384, OID_ECDSA_SHA384) => &signature::ECDSA_P384_SHA384_ASN1,
                (KeyKind::Rsa, OID_RSA_SHA256) => &signature::RSA_PKCS1_2048_8192_SHA256,
                (KeyKind::Rsa, OID_RSA_SHA384) => &signature::RSA_PKCS1_2048_8192_SHA384,
                (KeyKind::Rsa, OID_RSA_SHA512) => &signature::RSA_PKCS1_2048_8192_SHA512,
                _ => return Ok(false),
            };
        Ok(UnparsedPublicKey::new(algorithm, key_bytes)
            .verify(self.tbs, self.signature)
            .is_ok())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    P256,
    P384,
    Rsa,
}

/// SubjectPublicKeyInfo から鍵の種類と、検証に渡す形の鍵（EC は点、RSA は PKCS#1）を取り出す。
fn public_key_of(spki: &[u8]) -> Result<(KeyKind, &[u8]), AttestationRejection> {
    let info = der::single(spki)?;
    let mut parts = expect_sequence(&info)?;
    let algorithm = parts.expect(TAG_SEQUENCE)?;
    let key = parts.expect(TAG_BIT_STRING)?.bit_string_bytes()?;
    let mut alg = algorithm.children();
    let oid = alg.expect(TAG_OID)?.oid()?;
    let kind = match oid.as_str() {
        OID_EC_PUBLIC_KEY => match alg.expect(TAG_OID)?.oid()?.as_str() {
            OID_P256 => KeyKind::P256,
            OID_P384 => KeyKind::P384,
            _ => return Err(AttestationRejection::Malformed),
        },
        OID_RSA_ENCRYPTION => KeyKind::Rsa,
        _ => return Err(AttestationRejection::Malformed),
    };
    Ok((kind, key))
}

fn is_p256_key(spki: &[u8]) -> Result<bool, AttestationRejection> {
    Ok(public_key_of(spki)?.0 == KeyKind::P256)
}

/// 認証アプリの鍵（SubjectPublicKeyInfo）で、`message` への署名（ECDSA P-256・SHA-256・DER）が合うか。
pub fn verify_p256_signature(spki: &[u8], message: &[u8], signature_der: &[u8]) -> bool {
    match public_key_of(spki) {
        Ok((KeyKind::P256, point)) => {
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point)
                .verify(message, signature_der)
                .is_ok()
        }
        _ => false,
    }
}

fn expect_sequence<'a>(element: &DerElement<'a>) -> Result<DerReader<'a>, AttestationRejection> {
    if element.class != TagClass::Universal || element.number != TAG_SEQUENCE {
        return Err(AttestationRejection::Malformed);
    }
    Ok(element.children())
}

/// `KeyDescription`（読むのは確かめに要る項目だけ）。
struct KeyDescription<'a> {
    attestation_level: KeySecurityLevel,
    keymint_level: KeySecurityLevel,
    challenge: &'a [u8],
    software_enforced: AuthorizationList,
    hardware_enforced: AuthorizationList,
}

impl<'a> KeyDescription<'a> {
    fn parse(value: &'a [u8]) -> Result<Self, AttestationRejection> {
        let outer = der::single(value)?;
        let mut items = expect_sequence(&outer)?;
        items.expect(TAG_INTEGER)?; // attestationVersion
        let attestation_level = security_level(&items.expect(TAG_ENUMERATED)?)?;
        items.expect(TAG_INTEGER)?; // keyMintVersion
        let keymint_level = security_level(&items.expect(TAG_ENUMERATED)?)?;
        let challenge = items.expect(TAG_OCTET_STRING)?.contents;
        items.expect(TAG_OCTET_STRING)?; // uniqueId
        let software_enforced = AuthorizationList::parse(&items.expect(TAG_SEQUENCE)?)?;
        let hardware_enforced = AuthorizationList::parse(&items.expect(TAG_SEQUENCE)?)?;
        Ok(Self {
            attestation_level,
            keymint_level,
            challenge,
            software_enforced,
            hardware_enforced,
        })
    }
}

fn security_level(element: &DerElement<'_>) -> Result<KeySecurityLevel, AttestationRejection> {
    KeySecurityLevel::from_der(element.unsigned()?).ok_or(AttestationRejection::Malformed)
}

#[derive(Debug, Default)]
struct AuthorizationList {
    purposes: Vec<u64>,
    algorithm: Option<u64>,
    ec_curve: Option<u64>,
    no_auth_required: bool,
    user_auth_type: Option<u64>,
    auth_timeout: Option<u64>,
    origin: Option<u64>,
    root_of_trust: Option<RootOfTrust>,
    application_id: Option<ApplicationId>,
}

#[derive(Debug)]
struct RootOfTrust {
    device_locked: bool,
    verified_boot_state: u64,
}

#[derive(Debug)]
struct ApplicationId {
    package_names: Vec<Vec<u8>>,
    signature_digests: Vec<Vec<u8>>,
}

impl AuthorizationList {
    fn parse(list: &DerElement<'_>) -> Result<Self, AttestationRejection> {
        let mut out = Self::default();
        let mut items = expect_sequence(list)?;
        while !items.is_empty() {
            let tagged = items.next_element()?;
            if tagged.class != TagClass::ContextSpecific || !tagged.constructed {
                return Err(AttestationRejection::Malformed);
            }
            let inner = der::single(tagged.contents)?;
            match tagged.number {
                TAG_PURPOSE => {
                    if inner.number != TAG_SET {
                        return Err(AttestationRejection::Malformed);
                    }
                    let mut set = inner.children();
                    while !set.is_empty() {
                        out.purposes.push(set.expect(TAG_INTEGER)?.unsigned()?);
                    }
                }
                TAG_ALGORITHM => out.algorithm = Some(integer(&inner)?),
                TAG_EC_CURVE => out.ec_curve = Some(integer(&inner)?),
                TAG_NO_AUTH_REQUIRED => {
                    if inner.number != TAG_NULL {
                        return Err(AttestationRejection::Malformed);
                    }
                    out.no_auth_required = true;
                }
                TAG_USER_AUTH_TYPE => out.user_auth_type = Some(integer(&inner)?),
                TAG_AUTH_TIMEOUT => out.auth_timeout = Some(integer(&inner)?),
                TAG_ORIGIN => out.origin = Some(integer(&inner)?),
                TAG_ROOT_OF_TRUST => out.root_of_trust = Some(RootOfTrust::parse(&inner)?),
                TAG_ATTESTATION_APPLICATION_ID => {
                    if inner.number != TAG_OCTET_STRING {
                        return Err(AttestationRejection::Malformed);
                    }
                    out.application_id = Some(ApplicationId::parse(inner.contents)?);
                }
                // ほかの項目（鍵の長さ・作った時刻・OS の版など）は見ない。
                _ => {}
            }
        }
        Ok(out)
    }
}

fn integer(element: &DerElement<'_>) -> Result<u64, AttestationRejection> {
    if element.class != TagClass::Universal
        || !(element.number == TAG_INTEGER || element.number == TAG_ENUMERATED)
    {
        return Err(AttestationRejection::Malformed);
    }
    Ok(element.unsigned()?)
}

impl RootOfTrust {
    fn parse(element: &DerElement<'_>) -> Result<Self, AttestationRejection> {
        let mut items = expect_sequence(element)?;
        items.expect(TAG_OCTET_STRING)?; // verifiedBootKey
        let device_locked = items.expect(TAG_BOOLEAN)?.boolean()?;
        let verified_boot_state = items.expect(TAG_ENUMERATED)?.unsigned()?;
        Ok(Self {
            device_locked,
            verified_boot_state,
        })
    }
}

impl ApplicationId {
    fn parse(value: &[u8]) -> Result<Self, AttestationRejection> {
        let outer = der::single(value)?;
        let mut items = expect_sequence(&outer)?;
        let packages = items.expect(TAG_SET)?;
        let digests = items.expect(TAG_SET)?;
        let mut package_names = Vec::new();
        let mut list = packages.children();
        while !list.is_empty() {
            let info = list.expect(TAG_SEQUENCE)?;
            let mut fields = info.children();
            package_names.push(fields.expect(TAG_OCTET_STRING)?.contents.to_vec());
        }
        let mut signature_digests = Vec::new();
        let mut list = digests.children();
        while !list.is_empty() {
            signature_digests.push(list.expect(TAG_OCTET_STRING)?.contents.to_vec());
        }
        Ok(Self {
            package_names,
            signature_digests,
        })
    }
}

#[cfg(test)]
mod tests;
