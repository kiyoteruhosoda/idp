//! 署名付き SAML Response（`IDPSSODescriptor` の SSO 応答）を生成する。
//!
//! # 署名と正準化（C14N）の方針
//!
//! XML 署名（XMLDSIG）は「排他的正準化（exclusive C14N）した部分木のバイト列」に対して行う。
//! 本モジュールは XML を**最初から排他的正準形**で生成する（自前の正準化器を持たない）:
//!
//! - 空要素タグ（`<e/>`）を使わず、常に開始・終了タグの対で出力する
//! - 各要素で名前空間宣言 → 属性（ローカル名の辞書順）の順に出力する
//! - 署名対象（`Assertion`）は、使用する名前空間を自要素で宣言し自己完結させる
//! - エスケープは正準形の規則（属性値: `& < " TAB LF CR`、テキスト: `& < > CR`）に従う
//!
//! こうして出力したバイト列は、検証側（SP）が部分木を排他的 C14N しても同一バイト列になる。
//! Assertion に enveloped signature を差し込み、`SignedInfo` は署名時に `xmlns:ds` 付きで
//! 直列化したもの（= SP が C14N した結果と一致する形）へ署名する。
//!
//! 署名鍵は OIDC の ID Token と同じ ACTIVE 署名鍵を使う（RS256 → rsa-sha256、ES256 →
//! ecdsa-sha256）。
//!
//! # `KeyInfo` は載せる（2026-08-28）
//!
//! **どの鍵で署名したかを、アサーション自身が名乗る。** ADR-0039 でメタデータが複数の
//! `KeyDescriptor` を並べるようになったため、名乗らないと SP は「どれで検証すべきか」を
//! 総当たりか先頭かで推測するしかない。SAML には JWT の `kid` にあたる標準の印が無いので、
//! `KeyInfo/KeyValue` がその役目を果たす（Entra ID なども同じ形を採る）。
//!
//! **`KeyInfo` は `SignedInfo` の外**（署名対象ではない）なので、載せても署名計算は変わらない。
//! 値の描画はメタデータと同じ [`crate::domain::saml_metadata::IdpSigningKey::to_key_value`] を
//! 使う —— 別々に書くと、SP が突き合わせられない形にずれ得る。

use crate::domain::error::{DomainError, Result};
use crate::domain::saml_metadata::{IdpSigningKey, NAMED_CURVE_P256};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::Pkcs1v15Sign;
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
/// `AuthnContextClassRef`。SSO セッションは確立時の認証手段（パスワード・TOTP・Passkey）を保持
/// しないため、特定の強度（例: `PasswordProtectedTransport`）を主張せず `unspecified` を用いる
/// （誤った認証強度を SP に伝えない）。手段別のコンテキスト送出はセッションへの手段記録が前提。
const AUTHN_CONTEXT_UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
const SUBJECT_CONFIRMATION_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// SAML Response の組み立て入力。ID（`response_id` / `assertion_id`）は NCName 制約のため
/// [`generate_saml_id`] で採番した値を渡す。
pub struct SamlResponseInput<'a> {
    pub response_id: &'a str,
    pub assertion_id: &'a str,
    /// 発行時刻（Response / Assertion の `IssueInstant`）。
    pub issued_at: DateTime<Utc>,
    /// 本 IdP のエンティティ ID（テナント issuer）。
    pub idp_entity_id: &'a str,
    /// 対象 SP のエンティティ ID（`Audience`）。
    pub sp_entity_id: &'a str,
    /// アサーション送信先（`Destination` / `Recipient`）。
    pub acs_url: &'a str,
    /// AuthnRequest の `ID`（`InResponseTo`。IdP-initiated 相当では `None`）。
    pub in_response_to: Option<&'a str>,
    /// `NameID` の値と Format（SP 登録の `name_id_format`）。
    pub name_id: &'a str,
    pub name_id_format: &'a str,
    /// 認証時刻（SSO セッションの `auth_time`）。
    pub authn_instant: DateTime<Utc>,
    /// `SessionIndex`（SSO セッション由来の不透明値）。
    pub session_index: &'a str,
    /// アサーションの有効期限（`NotOnOrAfter`）。
    pub not_on_or_after: DateTime<Utc>,
    /// email 属性（`AttributeStatement`）。`None` なら属性を出力しない。
    pub email: Option<&'a str>,
}

/// SAML 応答の署名鍵。ACTIVE 署名鍵（PEM）から生成する。
pub enum SamlSigner {
    Rsa(Box<rsa::RsaPrivateKey>),
    P256(Box<p256::ecdsa::SigningKey>),
}

impl SamlSigner {
    /// 署名鍵 PEM とアルゴリズム（`RS256` / `ES256`）から署名器を作る。PEM の形式は
    /// 鍵生成（[`crate::domain::jwt`]）と対にする: RSA は PKCS#1、EC は PKCS#8。
    pub fn from_pem(algorithm: &str, private_pem: &str) -> Result<Self> {
        match algorithm {
            "RS256" => rsa::RsaPrivateKey::from_pkcs1_pem(private_pem)
                .map(|key| Self::Rsa(Box::new(key)))
                .map_err(|e| DomainError::InvalidValue(format!("invalid RSA private key: {e}"))),
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

    fn signature_method_uri(&self) -> &'static str {
        match self {
            Self::Rsa(_) => SIG_RSA_SHA256,
            Self::P256(_) => SIG_ECDSA_SHA256,
        }
    }

    /// 署名に使う鍵の公開値（`KeyInfo/KeyValue` に載せる形）。メタデータの `KeyDescriptor` と
    /// 同じ表現なので、SP は両者を突き合わせられる。
    fn public_key(&self) -> IdpSigningKey {
        match self {
            Self::Rsa(key) => {
                use rsa::traits::PublicKeyParts;
                IdpSigningKey::Rsa {
                    modulus_b64: STANDARD.encode(key.n().to_bytes_be()),
                    exponent_b64: STANDARD.encode(key.e().to_bytes_be()),
                }
            }
            Self::P256(key) => {
                // XMLDSIG の ECKeyValue は非圧縮点（0x04 || X || Y）を base64 で持つ。
                let point = key.verifying_key().to_encoded_point(false);
                IdpSigningKey::Ec {
                    named_curve_uri: NAMED_CURVE_P256.to_string(),
                    public_key_b64: STANDARD.encode(point.as_bytes()),
                }
            }
        }
    }

    /// `SignedInfo` バイト列へ署名する。RSA は PKCS#1 v1.5、ECDSA は IEEE P1363（r||s）形式
    /// （どちらも XMLDSIG の規定形式）。
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Rsa(key) => {
                let digest = Sha256::digest(message);
                key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
                    .map_err(|e| DomainError::InvalidValue(format!("RSA signing failed: {e}")))
            }
            Self::P256(key) => {
                use p256::ecdsa::signature::Signer;
                let signature: p256::ecdsa::Signature = key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
        }
    }
}

/// XML の ID 属性（NCName: 先頭が数字不可）として安全なランダム ID を採番する。
pub fn generate_saml_id() -> String {
    format!("_{}", crate::domain::crypto::random_hex(16))
}

/// 署名付き SAML Response XML を生成する（Assertion に enveloped signature）。
pub fn build_signed_response_xml(input: &SamlResponseInput, signer: &SamlSigner) -> Result<String> {
    let assertion = build_assertion(input);
    let signature = build_signature(input.assertion_id, assertion.as_bytes(), signer)?;

    // enveloped signature を Issuer の直後（SAML スキーマの規定位置）へ差し込む。
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

/// 未署名の Assertion を排他的正準形で組み立てる（署名のダイジェスト対象そのもの）。
fn build_assertion(input: &SamlResponseInput) -> String {
    let issued_at = format_instant(input.issued_at);
    let authn_instant = format_instant(input.authn_instant);
    let not_on_or_after = format_instant(input.not_on_or_after);
    // NotBefore は発行時刻とする（SP 側の許容スキューは SP の検証設定に委ねる）。
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

    // 属性は正準形の順（名前空間宣言 → ローカル名の辞書順）で出力している。
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

/// `ds:Signature` 要素を組み立てる。ダイジェストは「署名を差し込む前の Assertion」
/// （enveloped-signature transform 適用後と同一）に対して計算する。
fn build_signature(
    assertion_id: &str,
    unsigned_assertion: &[u8],
    signer: &SamlSigner,
) -> Result<String> {
    let digest = STANDARD.encode(Sha256::digest(unsigned_assertion));

    // SignedInfo は SP が排他的 C14N した結果（apex 要素に xmlns:ds が現れる形）へ署名する。
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

    // 文書へは xmlns:ds を Signature 要素で宣言して埋め込む（SignedInfo の C14N 結果は上と一致する）。
    let signed_info_embedded = signed_info_canonical.replacen(
        &format!("<ds:SignedInfo xmlns:ds=\"{NS_XMLDSIG}\">"),
        "<ds:SignedInfo>",
        1,
    );
    // KeyInfo は SignedInfo の外なので、署名計算には影響しない（XMLDSIG のスキーマ順は
    // SignedInfo → SignatureValue → KeyInfo）。
    let key_value = signer.public_key().to_key_value();
    Ok(format!(
        "<ds:Signature xmlns:ds=\"{NS_XMLDSIG}\">\
{signed_info_embedded}\
<ds:SignatureValue>{signature_value}</ds:SignatureValue>\
<ds:KeyInfo>{key_value}</ds:KeyInfo>\
</ds:Signature>"
    ))
}

/// SAML の時刻表現（xsd:dateTime、UTC・ミリ秒精度）。
fn format_instant(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// 属性値の正準形エスケープ（Canonical XML: `&` `<` `"` と TAB/LF/CR のみ。`>` `'` はそのまま）。
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

/// テキストノードの正準形エスケープ（Canonical XML: `&` `<` `>` と CR のみ）。
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
    use rsa::traits::PublicKeyParts;

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

    fn rsa_signer() -> (SamlSigner, rsa::RsaPublicKey) {
        // テストの高速化のため鍵長は 2048 ではなく 1024 を使う（署名方式の検証には十分）。
        let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).expect("keygen");
        let public = rsa::RsaPublicKey::from(&private);
        (SamlSigner::Rsa(Box::new(private)), public)
    }

    /// 文書から最初の `<tag ...>...</tag>` 部分文字列を取り出す（バイト等価の検証用）。
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
        // 認証手段を保持しないため、特定の認証強度（PasswordProtectedTransport 等）を主張しない。
        assert!(xml.contains(&format!(
            "<saml:AuthnContextClassRef>{AUTHN_CONTEXT_UNSPECIFIED}</saml:AuthnContextClassRef>"
        )));
        assert!(!xml.contains("PasswordProtectedTransport"));
        // Destination のクエリ `&` は正準形でエスケープされる。
        assert!(xml.contains("Destination=\"https://sp.example.test/acs?x=1&amp;y=2\""));
        // 生成 XML は整形式（再パース可能）である。
        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }

    #[test]
    fn digest_covers_the_assertion_without_the_signature() {
        let (signer, _) = rsa_signer();
        let input = test_input();
        let xml = build_signed_response_xml(&input, &signer).expect("build");

        // enveloped-signature transform: Signature 要素を除いた Assertion がダイジェスト対象。
        let signed_assertion = extract(&xml, "<saml:Assertion", "</saml:Assertion>");
        let signature = extract(&signed_assertion, "<ds:Signature", "</ds:Signature>");
        let without_signature = signed_assertion.replacen(&signature, "", 1);
        let expected = STANDARD.encode(Sha256::digest(without_signature.as_bytes()));
        assert!(
            xml.contains(&format!("<ds:DigestValue>{expected}</ds:DigestValue>")),
            "digest must match the assertion minus its signature"
        );
        // 未署名 Assertion と同一バイト列である（差し込みが他の部分を変えない）。
        assert_eq!(without_signature, build_assertion(&input));
    }

    /// アサーションが「どの鍵で署名したか」を名乗る（2026-08-28）。
    ///
    /// ADR-0039 でメタデータが複数の `KeyDescriptor` を並べるようになったため、名乗らないと
    /// SP は総当たりか先頭かで推測するしかない。**メタデータの `KeyDescriptor` と同じ表現**で
    /// あることが要点で、ここがずれると SP は突き合わせられない。
    #[test]
    fn the_assertion_names_the_key_it_was_signed_with() {
        let (signer, public) = rsa_signer();
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");

        let key_info = extract(&xml, "<ds:KeyInfo>", "</ds:KeyInfo>");
        assert!(key_info.contains("<ds:RSAKeyValue>"), "{xml}");

        // 署名に使った鍵そのものが載っていること（別の鍵を名乗らない）。
        use rsa::traits::PublicKeyParts;
        let modulus = STANDARD.encode(public.n().to_bytes_be());
        assert!(
            key_info.contains(&format!("<ds:Modulus>{modulus}</ds:Modulus>")),
            "{key_info}"
        );

        // メタデータ側と同じ描画であること（SP はこの 2 つを突き合わせる）。
        let published = crate::domain::saml_metadata::IdpSigningKey::Rsa {
            modulus_b64: modulus,
            exponent_b64: STANDARD.encode(public.e().to_bytes_be()),
        };
        assert!(key_info.contains(&published.to_key_value()), "{key_info}");
    }

    /// `KeyInfo` は `SignedInfo` の外なので、載せても署名対象は変わらない。
    #[test]
    fn adding_key_info_does_not_change_what_is_signed() {
        let (signer, _) = rsa_signer();
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");
        let signed_info = extract(&xml, "<ds:SignedInfo>", "</ds:SignedInfo>");
        assert!(!signed_info.contains("KeyInfo"), "{signed_info}");
        // スキーマ順は SignedInfo → SignatureValue → KeyInfo。
        let sv = xml.find("<ds:SignatureValue>").expect("SignatureValue");
        let ki = xml.find("<ds:KeyInfo>").expect("KeyInfo");
        assert!(sv < ki, "{xml}");
    }

    #[test]
    fn signature_verifies_with_the_rsa_public_key_over_canonical_signed_info() {
        let (signer, public) = rsa_signer();
        let xml = build_signed_response_xml(&test_input(), &signer).expect("build");

        // SP と同じ再構成: SignedInfo を取り出し、apex に xmlns:ds を補って C14N 形にする。
        let signed_info = extract(&xml, "<ds:SignedInfo>", "</ds:SignedInfo>").replacen(
            "<ds:SignedInfo>",
            &format!("<ds:SignedInfo xmlns:ds=\"{NS_XMLDSIG}\">"),
            1,
        );
        let signature_value = extract(&xml, "<ds:SignatureValue>", "</ds:SignatureValue>")
            .replace("<ds:SignatureValue>", "")
            .replace("</ds:SignatureValue>", "");
        let signature = STANDARD.decode(signature_value).expect("base64");

        let digest = Sha256::digest(signed_info.as_bytes());
        public
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &signature)
            .expect("signature must verify");
        assert_eq!(public.size(), signature.len());
    }

    #[test]
    fn ecdsa_signature_is_p1363_and_verifies() {
        use p256::ecdsa::signature::Verifier;
        let private = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
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
        // XMLDSIG の ECDSA 署名値は r||s（P-256 では 64 バイト）。
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
