//! SAML メタデータ XML の解析（SP / 外部 IdP のメタデータ取り込み）と生成（自身の IdP メタデータ出力）。
//!
//! - 取り込み（SP）: SP（クライアント）が公開する `EntityDescriptor`（`SPSSODescriptor`）を解析し、登録に必要な
//!   `entity_id` / `acs_url` / `x509_certificate` / NameID を抽出する。管理者の手入力を置き換える補助で、
//!   検証（ACS URL のスキーム等）は登録ユースケース側（[`crate::domain::saml_service_provider`]）に委ねる。
//! - 取り込み（外部 IdP）: 外部の SAML IdP が公開する `IDPSSODescriptor` を解析し、
//!   `entity_id` / `sso_url` / 署名証明書を抽出する（AP12。[`crate::domain::external_idp`] の登録候補値）。
//! - 出力: 本 IdP の `EntityDescriptor`（`IDPSSODescriptor`）を生成する。SP（クライアント）がこの IdP を
//!   信頼するために取り込むメタデータで、`.well-known/openid-configuration` の SAML 版に相当する。
//!
//! **取り込みは向きを取り違えない。** SP と IdP のメタデータは同じ `EntityDescriptor` で包まれ、
//! 中の役割記述子（`SPSSODescriptor` / `IDPSSODescriptor`）だけが違う。役割を指定せずに読むと、
//! IdP のメタデータを SP として（あるいはその逆で）登録でき、誤りは**利用者のログイン時**まで
//! 表に出ない。そのため解析は役割（[`Role`]）を必ず伴い、目的の記述子が無い XML は失敗させる。
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

/// 外部 IdP のメタデータから取り込んだ登録候補値（AP12）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedIdpMetadata {
    /// IdP の entityID。アサーションの `<Issuer>` と完全一致で照合する値になる。
    pub entity_id: String,
    /// SingleSignOnService の URL（`AuthnRequest` の送信先）。
    pub sso_url: String,
    /// 署名検証に使う証明書（空白除去した base64 DER）。**複数返す**——IdP の証明書更新期間は
    /// 新旧 2 枚が同時に有効で、メタデータにも 2 枚並ぶ。1 枚に絞ると更新のたびにログインが止まる。
    pub certificates: Vec<String>,
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

/// 取り込む役割記述子。SP と IdP でどの要素を読むかだけが違う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Sp,
    Idp,
}

impl Role {
    /// 役割記述子のローカル名。
    fn descriptor(self) -> &'static [u8] {
        match self {
            Self::Sp => b"SPSSODescriptor",
            Self::Idp => b"IDPSSODescriptor",
        }
    }

    /// エンドポイント要素のローカル名。
    fn endpoint(self) -> &'static [u8] {
        match self {
            Self::Sp => b"AssertionConsumerService",
            Self::Idp => b"SingleSignOnService",
        }
    }

    /// 候補から使うエンドポイントを 1 件選ぶ。
    ///
    /// **IdP 側は HTTP-Redirect に限る。** ログイン開始は必ず HTTP-Redirect binding で
    /// `AuthnRequest` を送る（[`crate::domain::saml_external_idp::redirect_binding_location`]）ため、
    /// 他のバインディングのエンドポイントを取り込むと「登録は通るのに、ログインのたびに相手が
    /// 受け付けない形式で送る」設定ができてしまう。誤りは**利用者のログイン時**まで表に出ない。
    /// ここで落とせば、取り込んだ管理者がその場で気づける（手入力の道は残っている）。
    ///
    /// SP 側は POST → Redirect → 先頭の従来どおり。こちらは**相手が受け取る**側の URL で、
    /// 本 IdP が送信方式を選べる（アサーションは POST で送る）。
    fn pick_endpoint(self, candidates: &[(String, String)]) -> Option<String> {
        match self {
            Self::Sp => pick_by_binding(candidates, &[BINDING_HTTP_POST, BINDING_HTTP_REDIRECT]),
            Self::Idp => candidates
                .iter()
                .find(|(binding, _)| binding == BINDING_HTTP_REDIRECT)
                .map(|(_, location)| location.clone()),
        }
    }

    /// エンドポイントが見つからないときのメッセージ。
    fn missing_endpoint(self) -> &'static str {
        match self {
            Self::Sp => "SAML metadata is missing an SP AssertionConsumerService",
            Self::Idp => {
                "SAML metadata is missing an IdP SingleSignOnService with the HTTP-Redirect binding"
            }
        }
    }
}

/// 役割記述子から読み取った生の値。役割ごとの型（[`ImportedSpMetadata`] / [`ImportedIdpMetadata`]）へ
/// 詰め替える前の中間表現。
struct ParsedEntity {
    entity_id: String,
    endpoint_url: String,
    /// `use="signing"` が明示された証明書（出現順）。
    signing_certificates: Vec<String>,
    /// `use` の無い証明書（出現順）。SAML メタデータで `use` を書かない鍵は**署名にも暗号化にも
    /// 使える**意味なので、署名用の候補でもある。
    unspecified_certificates: Vec<String>,
    name_id_format: Option<String>,
    display_name: Option<String>,
}

/// SP（クライアント）の `EntityDescriptor`（`SPSSODescriptor`）XML を解析し、登録候補値を抽出する。
///
/// - `entityID` と ACS URL（`SPSSODescriptor/AssertionConsumerService`）は必須。欠落時は
///   [`DomainError::InvalidValue`]。
/// - ACS URL は HTTP-POST → HTTP-Redirect → 先頭、の優先順で 1 件を選ぶ（アサーションは POST 送信が基本）。
/// - 証明書は `SPSSODescriptor` 内の署名用（`use="signing"` または `use` 無し）を優先して 1 件採用する。
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

/// 外部 IdP の `EntityDescriptor`（`IDPSSODescriptor`）XML を解析し、登録候補値を抽出する（AP12）。
///
/// - `entityID` と SSO URL（`IDPSSODescriptor/SingleSignOnService`）は必須。欠落時は
///   [`DomainError::InvalidValue`]。
/// - SSO URL は **HTTP-Redirect binding のもの**に限る（`AuthnRequest` はその形でしか送らない）。
///   他のバインディングしか無いメタデータは取り込まない——登録は通るのにログインのたびに
///   相手が受け付けない形式で送る設定になり、誤りが利用者のログイン時まで表に出ない。
/// - 証明書は署名に使える鍵を**すべて**返す。`use="signing"` の明示があるものと、`use` の無いもの
///   （SAML メタデータでは署名にも暗号化にも使える意味）を**両方**含め、`use="encryption"` だけを
///   除く。片方に絞ると、更新期間に相手がもう一方の鍵で署名した瞬間にログインが止まる。
/// - 証明書が 1 枚も無い XML も**ここでは失敗にしない**。必須かどうかを決めるのは登録ユースケース
///   （[`crate::application::external_idp_management`]）であり、取り込みは「読めたものを渡す」に徹する。
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

/// `EntityDescriptor` を 1 パスで読み、指定した役割の記述子の中だけを拾う。
fn parse_entity(xml: &str, role: Role) -> Result<ParsedEntity> {
    let mut reader = Reader::from_str(xml);

    let mut entity_id: Option<String> = None;
    let mut in_role = false;
    // (binding, location) のエンドポイント候補。
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
                b"EntityDescriptor" if entity_id.is_none() => {
                    entity_id = attribute(&e, b"entityID");
                    in_entity = true;
                }
                name if in_entity && name == role.descriptor() => in_role = true,
                b"KeyDescriptor" if in_entity && in_role => key_use = attribute(&e, b"use"),
                name if in_entity && in_role && name == role.endpoint() => {
                    push_endpoint(&e, &mut endpoints)
                }
                b"X509Certificate"
                    if in_entity && in_role && key_use.as_deref() != Some("encryption") =>
                {
                    capture = Some(Capture::Certificate);
                    text_buf.clear();
                }
                b"NameIDFormat" if in_entity && in_role && name_id_format.is_none() => {
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
                b"KeyDescriptor" if in_entity && in_role => key_use = attribute(&e, b"use"),
                name if in_entity && in_role && name == role.endpoint() => {
                    push_endpoint(&e, &mut endpoints)
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
                name if name == role.descriptor() => in_role = false,
                b"KeyDescriptor" => key_use = None,
                b"X509Certificate" => {
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

/// P-256 の曲線 URN（XMLDSIG11 `NamedCurve`）。
///
/// **曲線 URN の対応表はここが唯一の出所である。** メタデータの `KeyDescriptor` と
/// アサーションの `KeyInfo` が同じ値を出さないと、SP は両者を突き合わせられない。
pub const NAMED_CURVE_P256: &str = "urn:oid:1.2.840.10045.3.1.7";
const NAMED_CURVE_P384: &str = "urn:oid:1.3.132.0.34";
const NAMED_CURVE_P521: &str = "urn:oid:1.3.132.0.35";

/// JWK の `crv` を XMLDSIG11 `NamedCurve` の URN へ変換する。未対応の曲線は `None`。
pub fn named_curve_uri(crv: &str) -> Option<&'static str> {
    match crv {
        "P-256" => Some(NAMED_CURVE_P256),
        "P-384" => Some(NAMED_CURVE_P384),
        "P-521" => Some(NAMED_CURVE_P521),
        _ => None,
    }
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
    /// 公開鍵そのものの XML 片（`KeyValue`）を生成する。
    ///
    /// **メタデータの `KeyDescriptor` と、アサーションの `KeyInfo` で同じものを使う。** 別々に
    /// 書くと、SP が「メタデータで受け取った鍵」と「アサーションが名乗る鍵」を突き合わせられなく
    /// なる形にいつでもずれ得る。
    ///
    /// 空要素タグ（`<e/>`）を使わないのは、`saml_response` が排他的正準形で XML を組み立てる
    /// 規則に合わせるため（この片はそちらへも埋め込まれる）。
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

    /// 署名用 `KeyDescriptor` の XML 片を生成する。
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

/// 本 IdP の SAML `EntityDescriptor`（`IDPSSODescriptor`）XML を生成する。
///
/// `entity_id` は IdP のエンティティ ID（テナント issuer を用いる）、`sso_url` は SingleSignOnService の
/// URL。SP（クライアント）はこの metadata を取り込んで本 IdP を信頼する。
///
/// # 公開中の鍵をすべて並べる（ADR-0039）
///
/// `signing_keys` には**公開中の鍵をすべて**渡す（署名中の鍵と、まだ署名しない後継鍵、および
/// 有効期間内の退役鍵）。SAML 2.0 のメタデータは `use="signing"` の `KeyDescriptor` を複数持てる。
/// 1 本しか出さないと、署名が切り替わる瞬間に SP から見える証明書が入れ替わり、**取り込み直すまで
/// 検証が落ちる** —— ADR-0039 が JWKS 側で無くした断絶が、SAML 側にだけ残る。
///
/// **並び順は呼び出し側の責務で、署名中の鍵を先頭にする。** SP の実装には先頭の
/// `KeyDescriptor` だけを読むものがあり、公開順（新しい鍵が先）のまま渡すと**まだ署名していない
/// 後継鍵**を掴ませることになる。
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

/// エンドポイント要素の Binding/Location を候補へ追加する（両方揃う場合のみ）。
fn push_endpoint(e: &BytesStart, out: &mut Vec<(String, String)>) {
    if let (Some(binding), Some(location)) = (attribute(e, b"Binding"), attribute(e, b"Location")) {
        out.push((binding, location));
    }
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

    /// 外部 IdP のメタデータから entityID・SSO URL・署名証明書を取り込める。SSO URL は
    /// HTTP-Redirect を優先する（`AuthnRequest` は Redirect binding で送るため）。
    #[test]
    fn parses_idp_entity_sso_and_signing_certificate() {
        let parsed = parse_idp_metadata(IDP_METADATA).expect("parse");
        assert_eq!(parsed.entity_id, "https://idp.example.test/metadata");
        assert_eq!(parsed.sso_url, "https://idp.example.test/sso/redirect");
        // 暗号化用の証明書は署名検証に使わないので混ぜない。
        assert_eq!(parsed.certificates, vec!["MIIBsigningCERTdata=="]);
        assert_eq!(parsed.display_name.as_deref(), Some("Example IdP"));
    }

    /// 証明書更新期間のメタデータには署名用が 2 枚並ぶ。**両方**取り込めないと、
    /// 切り替わった瞬間にログインが止まる。
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

    /// `use` の無い `KeyDescriptor` は署名にも暗号化にも使える意味なので、**署名用と並べて**返す。
    /// 明示された署名用があるからといって落とすと、更新期間に相手が `use` 無しの鍵で署名した
    /// 瞬間にログインが止まる。`use="encryption"` だけは除く。
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

    /// **HTTP-Redirect binding の SSO しか取り込まない。** ログイン開始は必ず HTTP-Redirect で
    /// `AuthnRequest` を送るので、他のバインディングの URL を取り込むと「登録は通るのに、
    /// ログインのたびに相手が受け付けない形式で送る」設定ができる。取り込みの時点で落とす。
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

        // POST しか無い・SOAP のような送れないバインディングしか無いメタデータは取り込まない。
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

    /// **向きを取り違えない。** SP のメタデータを外部 IdP として取り込もうとすると失敗する
    /// （`IDPSSODescriptor` が無い）。ここを通してしまうと、誤りはログイン時まで表に出ない。
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
        let xml = build_idp_metadata_xml(
            "urn:idp",
            "https://idp.test/sso",
            std::slice::from_ref(&key),
        );
        assert!(xml.contains(r#"<md:KeyDescriptor use="signing">"#));
        // XMLDSIG 1.1 の置き場所は `ds:KeyValue/ds11:ECKeyValue`。RSA 側と同じく `ds:KeyValue`
        // で包まないと、`KeyInfo/KeyValue` の下だけを見る SP が EC 鍵を拾えない。
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

    /// 公開中の鍵をすべて並べる（ADR-0039 / T33）。
    ///
    /// 1 本しか出さないと、署名が切り替わる瞬間に SP から見える証明書が入れ替わり、取り込み直す
    /// まで検証が落ちる。ADR-0039 が JWKS 側で無くした断絶を、SAML 側にも無くすための本体。
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
        // 渡された順にそのまま並ぶ（先頭の KeyDescriptor だけを読む SP があるため、
        // 「署名中の鍵を先頭に」は呼び出し側が守る責務であり、ここは並べ替えない）。
        let first = xml.find("AAAAsigning==").expect("signing key present");
        let second = xml.find("BBBBsuccessor==").expect("successor present");
        assert!(first < second, "渡した順序が保たれること: {xml}");

        let mut reader = Reader::from_str(&xml);
        while !matches!(reader.read_event().expect("well-formed"), Event::Eof) {}
    }
}
