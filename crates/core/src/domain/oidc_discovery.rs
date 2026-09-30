//! 外部 OpenID Provider の discovery ドキュメントの取り込み（task #77。OIDC Discovery 1.0）。
//!
//! 外部 IdP（OIDC）を登録するには `authorization_endpoint` / `token_endpoint` / `jwks_uri` を
//! 相手の文書から 1 項目ずつ写す必要がある。相手はそれを `{issuer}/.well-known/openid-configuration`
//! に公開しているので、issuer だけを入れれば残りを埋められる。SAML の IdP メタデータ取り込み
//! （[`crate::domain::saml_metadata`]）と同じく、**取り込みは登録ではない**——ここで作るのは登録
//! フォームの初期値で、管理者が確かめてから登録する。
//!
//! SAML の取り込みと違い、**assay のサーバが管理者の入れた URL へ自ら HTTP を出す。** そのため:
//!
//! - 取りに行く先は [`DiscoveryUrl`] でしか表せない。この型は issuer を ADR-0023 決定 5 の検査
//!   （https のみ・内部宛先を拒否。[`ExternalIdentityProvider::validate_endpoint`]）に通したときにしか
//!   作れず、取得のポート（[`crate::domain::external_oidc_port::OidcDiscoveryClient`]）はこの型しか
//!   受け取らない。検査を通していない URL を取りに行く経路は型の上で作れない。
//! - 文書に書かれた `issuer` が入力と 1 文字でも違えば断る（OIDC Discovery §4.3）。違う issuer の
//!   文書を受け入れると、ID Token の `iss` 照合（完全一致）がログインのたびに失敗するか、別の
//!   発行者の値を登録してしまう。
//! - 文書から得たエンドポイントも登録時と同じ検査に通す。相手の文書は管理者の入力ではないが、
//!   登録すれば assay がそこへつなぐ先になる（フォームに内部宛先を埋めて見せない）。

use crate::domain::error::DomainError;
use crate::domain::external_idp::ExternalIdentityProvider;

/// discovery ドキュメントの置き場所（OIDC Discovery §4）。
pub const WELL_KNOWN_PATH: &str = "/.well-known/openid-configuration";

/// 宛先の検査を通した discovery ドキュメントの URL。
///
/// **検査を通さずに作る口を持たない**（`#[cfg(test)]` の試験用を除く）。取得の実装はこの型しか
/// 受け取らないので、SSRF の検査を呼び忘れる経路を作れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryUrl {
    /// 取り込みを求められた issuer（前後の空白を除いた値）。§4.3 の照合に使う。
    issuer: String,
    url: String,
}

impl DiscoveryUrl {
    /// issuer から discovery ドキュメントの URL を組み立てる。
    ///
    /// issuer は https で内部宛先でないこと（登録時の `issuer` の検査と同じ）。クエリ・フラグメントを
    /// 持つ issuer は OIDC では不正なので断る（OIDC Discovery §2 / Core §2 の `iss`）。
    /// 末尾の `/` は除いてから `/.well-known/openid-configuration` を足す（§4.1）。
    pub fn for_issuer(issuer: &str) -> Result<Self, DomainError> {
        let issuer = issuer.trim();
        ExternalIdentityProvider::validate_endpoint(issuer, "issuer")?;
        let parsed = url::Url::parse(issuer)
            .map_err(|_| DomainError::InvalidValue("issuer must be a valid URL".to_string()))?;
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(DomainError::InvalidValue(
                "issuer must not contain a query or fragment".to_string(),
            ));
        }
        let url = format!("{}{WELL_KNOWN_PATH}", issuer.trim_end_matches('/'));
        // 組み立てた後の URL も同じ検査に通す（文字列を足したことで宛先の解釈が変わらないことを、
        // 組み立て方の推論ではなく検査で保証する）。
        ExternalIdentityProvider::validate_endpoint(&url, "issuer")?;
        Ok(Self {
            issuer: issuer.to_string(),
            url,
        })
    }

    /// 試験用: 宛先の検査を通さずに作る（wiremock は `http://127.0.0.1` で待つため）。
    #[cfg(test)]
    pub(crate) fn unchecked_for_test(issuer: &str, url: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            url: url.to_string(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn as_str(&self) -> &str {
        &self.url
    }
}

/// discovery ドキュメントのうち、外部 IdP の登録に使う項目（取得したそのままの値。未検証）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OidcDiscoveryDocument {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
}

/// 取り込んだ登録候補値（検証済み）。登録フォームの初期値として提示する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedOidcProvider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

impl OidcDiscoveryDocument {
    /// 取り込みを求めた issuer に対して文書を検証し、登録候補値を返す。
    ///
    /// 1. 文書の `issuer` が求めた issuer と**完全一致**（§4.3。末尾の `/` も区別する——ID Token の
    ///    `iss` もこの値と完全一致で照合するため、ここで丸めると登録後のログインが全部落ちる）
    /// 2. 3 つのエンドポイントがすべてある（assay は authorization code + JWKS 検証しか使わない）
    /// 3. 各エンドポイントが登録時と同じ検査（https のみ・内部宛先を拒否）を通る
    pub fn verify_for(self, requested: &DiscoveryUrl) -> Result<ImportedOidcProvider, DomainError> {
        let issuer = self.issuer.unwrap_or_default();
        if issuer != requested.issuer() {
            return Err(DomainError::InvalidValue(format!(
                "the discovery document's issuer \"{issuer}\" does not match the requested issuer \"{}\"",
                requested.issuer()
            )));
        }
        let required = |value: Option<String>, field: &str| -> Result<String, DomainError> {
            let value = value
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    DomainError::InvalidValue(format!("the discovery document has no {field}"))
                })?;
            ExternalIdentityProvider::validate_endpoint(&value, field)?;
            Ok(value)
        };
        Ok(ImportedOidcProvider {
            authorization_endpoint: required(
                self.authorization_endpoint,
                "authorization_endpoint",
            )?,
            token_endpoint: required(self.token_endpoint, "token_endpoint")?,
            jwks_uri: required(self.jwks_uri, "jwks_uri")?,
            issuer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(issuer: &str) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: Some(issuer.to_string()),
            authorization_endpoint: Some("https://idp.example.com/authorize".to_string()),
            token_endpoint: Some("https://idp.example.com/token".to_string()),
            jwks_uri: Some("https://idp.example.com/jwks".to_string()),
        }
    }

    /// 末尾の `/` を除いてから well-known を足す（§4.1）。パスを持つ issuer（テナント別の IdP）でも
    /// パスの後ろに付く。
    #[test]
    fn the_discovery_url_is_built_under_the_issuer() {
        assert_eq!(
            DiscoveryUrl::for_issuer("https://idp.example.com")
                .unwrap()
                .as_str(),
            "https://idp.example.com/.well-known/openid-configuration"
        );
        assert_eq!(
            DiscoveryUrl::for_issuer(" https://idp.example.com/tenant-a/ ")
                .unwrap()
                .as_str(),
            "https://idp.example.com/tenant-a/.well-known/openid-configuration"
        );
    }

    /// **取りに行く前に**宛先を検査する（SSRF の踏み台にしない。ADR-0023 決定 5）。
    #[test]
    fn internal_or_plain_http_issuers_are_rejected_before_any_request() {
        for bad in [
            "http://idp.example.com",
            "https://127.0.0.1",
            "https://localhost",
            "https://169.254.169.254/latest",
            "https://10.0.0.5",
            "https://[::1]",
            "https://idp.example.com?x=1",
            "https://idp.example.com#frag",
            "not a url",
            "",
        ] {
            assert!(
                DiscoveryUrl::for_issuer(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn a_matching_document_yields_the_registration_values() {
        let url = DiscoveryUrl::for_issuer("https://idp.example.com").unwrap();
        let imported = document("https://idp.example.com")
            .verify_for(&url)
            .unwrap();
        assert_eq!(imported.issuer, "https://idp.example.com");
        assert_eq!(
            imported.authorization_endpoint,
            "https://idp.example.com/authorize"
        );
        assert_eq!(imported.token_endpoint, "https://idp.example.com/token");
        assert_eq!(imported.jwks_uri, "https://idp.example.com/jwks");
    }

    /// 文書の `issuer` が入力と違えば断る（§4.3）。末尾の `/` の違いも違いとして扱う。
    #[test]
    fn an_issuer_mismatch_is_rejected() {
        let url = DiscoveryUrl::for_issuer("https://idp.example.com").unwrap();
        for other in [
            "https://evil.example.com",
            "https://idp.example.com/",
            "https://IDP.example.com",
        ] {
            let err = document(other).verify_for(&url).unwrap_err();
            assert!(err.to_string().contains("does not match"), "{other}: {err}");
        }
        let missing = OidcDiscoveryDocument {
            issuer: None,
            ..document("https://idp.example.com")
        };
        assert!(missing.verify_for(&url).is_err());
    }

    /// 文書から得たエンドポイントも登録時と同じ検査に通す（内部宛先をフォームに埋めない）。
    #[test]
    fn endpoints_from_the_document_must_be_public_https() {
        let url = DiscoveryUrl::for_issuer("https://idp.example.com").unwrap();
        let internal = OidcDiscoveryDocument {
            token_endpoint: Some("https://10.0.0.5/token".to_string()),
            ..document("https://idp.example.com")
        };
        assert!(internal.verify_for(&url).is_err());
        let plain = OidcDiscoveryDocument {
            jwks_uri: Some("http://idp.example.com/jwks".to_string()),
            ..document("https://idp.example.com")
        };
        assert!(plain.verify_for(&url).is_err());
        let missing = OidcDiscoveryDocument {
            jwks_uri: None,
            ..document("https://idp.example.com")
        };
        assert!(missing.verify_for(&url).is_err());
    }
}
