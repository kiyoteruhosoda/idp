//! 外部 IdP 認証（AP10。ユーザー認証・認証ポリシー仕様書 §13）。
//!
//! 外部の OpenID Provider での認証結果を、assay のログインとして引き受けるための型。
//!
//! # 同一性の根拠は `iss` + `sub` だけ
//!
//! 外部アカウントと assay の利用者を結び付ける根拠は `iss` + `sub` に限る（§13.2）。
//! メールアドレスで結び付ける設計にしないのは、外部 IdP 側でメールを変更・再利用できる場合に
//! **別人が同じメールを名乗って既存アカウントへ入れてしまう**ため。初回だけメール一致で自動連携
//! したい要求はあるので、それはプロバイダ単位の明示的な設定（`allow_auto_link`）にし、
//! 「外部 IdP がメールの所有を検証していること」を運用者が引き受ける形にする。
#![allow(dead_code)]

use crate::domain::error::DomainError;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// 外部 IdP へ既定で要求する scope。
pub const DEFAULT_SCOPES: [&str; 3] = ["openid", "profile", "email"];

/// 外部 IdP のプロトコル（ADR-0027）。許可値の単一の出所。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExternalIdpProtocol {
    #[default]
    Oidc,
    Saml,
}

impl ExternalIdpProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }

    /// 保存値・入力値を解釈する。未知の値は**既定へ丸めずエラー**にする。丸めると、SAML の
    /// つもりで登録した設定が OIDC として扱われ、検証の要件ごと変わってしまう。
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw.trim() {
            "oidc" => Ok(Self::Oidc),
            "saml" => Ok(Self::Saml),
            other => Err(DomainError::InvalidValue(format!(
                "unsupported external IdP protocol: {other}"
            ))),
        }
    }
}

/// OIDC の外部 IdP 固有設定。
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    /// クライアントシークレット（暗号文）。public クライアントとして登録した場合は `None`。
    pub client_secret_encrypted: Option<String>,
    pub scopes: Vec<String>,
}

impl OidcProviderConfig {
    /// 認可要求に載せる scope（未設定なら既定）。`openid` は必ず含める（ID Token が要るため）。
    pub fn effective_scopes(&self) -> Vec<String> {
        let mut scopes: Vec<String> = if self.scopes.is_empty() {
            DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()
        } else {
            self.scopes.clone()
        };
        if !scopes.iter().any(|s| s == "openid") {
            scopes.insert(0, "openid".to_string());
        }
        scopes
    }
}

/// SAML の外部 IdP 固有設定（SP 側。ADR-0027）。
#[derive(Debug, Clone)]
pub struct SamlProviderConfig {
    /// IdP の `SingleSignOnService` URL（HTTP-Redirect binding で AuthnRequest を送る先）。
    pub sso_url: String,
    /// 署名検証に使う X.509 証明書（base64 DER）。**複数持てる**——IdP の証明書更新期間は
    /// 新旧 2 枚が同時に有効で、1 枚しか持てないと更新のたびにログインが止まる。
    pub certificates: Vec<String>,
    /// `AuthnRequest` で要求する `NameIDFormat`。
    pub name_id_format: String,
}

/// プロトコル固有の設定。**どの組み合わせが妥当か**をここで表す（DB は使わない列を NULL に
/// するだけなので、妥当性の単一の出所はこの enum になる）。
#[derive(Debug, Clone)]
pub enum ExternalIdpConfig {
    Oidc(OidcProviderConfig),
    Saml(SamlProviderConfig),
}

impl ExternalIdpConfig {
    pub fn protocol(&self) -> ExternalIdpProtocol {
        match self {
            Self::Oidc(_) => ExternalIdpProtocol::Oidc,
            Self::Saml(_) => ExternalIdpProtocol::Saml,
        }
    }

    pub fn as_oidc(&self) -> Option<&OidcProviderConfig> {
        match self {
            Self::Oidc(c) => Some(c),
            Self::Saml(_) => None,
        }
    }

    pub fn as_saml(&self) -> Option<&SamlProviderConfig> {
        match self {
            Self::Saml(c) => Some(c),
            Self::Oidc(_) => None,
        }
    }
}

/// テナントに設定された外部 IdP 1 件。
///
/// `issuer` は**両プロトコル共通の信頼の起点**である（ADR-0027）。OIDC では ID Token の `iss`、
/// SAML では Response / Assertion の `<Issuer>`（IdP の entityID）で、どちらも「その主張を
/// 出した発行者の識別子」なので、`user_external_identities.external_issuer` は同じ形で使える。
#[derive(Debug, Clone)]
pub struct ExternalIdentityProvider {
    pub id: Uuid,
    pub tenant_id: TenantId,
    /// テナント内一意の識別コード（URL パスに載る）。
    pub provider_code: String,
    pub display_name: String,
    /// 外部 IdP の issuer（OIDC: ID Token の `iss` / SAML: IdP の entityID）。完全一致で照合する。
    pub issuer: String,
    /// プロトコル固有の設定。
    pub config: ExternalIdpConfig,
    pub enabled: bool,
    /// 検証済みメール一致で既存利用者へ自動連携するか。
    pub allow_auto_link: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ExternalIdentityProvider {
    /// `provider_code` の形式検証（英数字・`-`・`_`・`.`、1〜100 文字）。
    /// URL パスセグメント・監査ログにそのまま載せられる文字に限る
    /// （`AuthenticationPolicy::validate_code` と同じ基準）。
    pub fn validate_code(code: &str) -> Result<(), DomainError> {
        if code.is_empty() || code.len() > 100 {
            return Err(DomainError::InvalidValue(
                "provider code must be 1-100 characters".to_string(),
            ));
        }
        if !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(DomainError::InvalidValue(
                "provider code must contain only ASCII alphanumerics, '-', '_' or '.'".to_string(),
            ));
        }
        Ok(())
    }

    /// エンドポイント URL の検証。
    ///
    /// `https` に限り、内部宛先（loopback・プライベート IP 等）を拒む。外部 IdP のエンドポイントは
    /// assay のサーバが自ら取りに行く先なので、ここを緩めると管理 API が SSRF の踏み台になる
    /// （back-channel logout URI と同じ理由。SEC2）。
    pub fn validate_endpoint(url: &str, field: &str) -> Result<(), DomainError> {
        let parsed = url::Url::parse(url.trim())
            .map_err(|_| DomainError::InvalidValue(format!("{field} must be a valid URL")))?;
        if parsed.scheme() != "https" {
            return Err(DomainError::InvalidValue(format!("{field} must use https")));
        }
        if crate::domain::outbound_uri::is_internal_destination(url) {
            return Err(DomainError::InvalidValue(format!(
                "{field} must not point at an internal destination"
            )));
        }
        Ok(())
    }

    pub fn protocol(&self) -> ExternalIdpProtocol {
        self.config.protocol()
    }
}

/// 外部 IdP 上の同一性と assay 利用者の対応。
#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_id: Uuid,
    pub external_issuer: String,
    pub external_subject: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// 外部 IdP へのリダイレクトからコールバックまでの進行状態。
#[derive(Debug, Clone)]
pub struct ExternalLoginRequest {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub provider_id: Uuid,
    /// `state`（SAML では `RelayState`）の SHA-256。生値は外部 IdP から戻る値としてのみ扱う。
    pub state_hash: String,
    /// こちらが作り、相手が返してくる値。**リプレイ検出の要**である。
    /// OIDC では ID Token の `nonce`、SAML では `AuthnRequest` の `ID`（応答の `InResponseTo` と
    /// 照合する）。役割が同じなので 1 つの列で持つ。
    pub nonce: String,
    /// PKCE の `code_verifier`（暗号文）。**SAML では `None`**（PKCE に当たるものが無い）。
    pub code_verifier_encrypted: Option<String>,
    /// 呼び出し元の OIDC auth_session の `id_hash`（ポータル経由なら `None`）。
    /// auth_session_id は bearer credential なので、写しもハッシュで持つ（SEC6）。
    pub auth_session_id_hash: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl ExternalLoginRequest {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// 外部 IdP の ID Token から取り出した、連携に必要な主張。
#[derive(Debug, Clone)]
pub struct ExternalClaims {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    /// 外部 IdP がメールの所有を検証したと主張しているか。自動連携の前提。
    pub email_verified: bool,
    pub name: Option<String>,
    /// ID Token の `nonce`（リプレイ検出のため保存値と照合する）。
    pub nonce: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(scopes: Vec<String>) -> OidcProviderConfig {
        OidcProviderConfig {
            authorization_endpoint: "https://idp.corp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.corp.example.com/token".to_string(),
            jwks_uri: "https://idp.corp.example.com/jwks".to_string(),
            client_id: "client".to_string(),
            client_secret_encrypted: None,
            scopes,
        }
    }

    #[test]
    fn provider_code_validation_rejects_unsafe_values() {
        assert!(ExternalIdentityProvider::validate_code("corp-sso.v2").is_ok());
        assert!(ExternalIdentityProvider::validate_code("").is_err());
        assert!(ExternalIdentityProvider::validate_code(&"a".repeat(101)).is_err());
        assert!(ExternalIdentityProvider::validate_code("slash/code").is_err());
        assert!(ExternalIdentityProvider::validate_code("スペース あり").is_err());
    }

    /// エンドポイントは https のみ、内部宛先は拒否（SSRF の踏み台にしない）。
    #[test]
    fn endpoints_must_be_public_https_urls() {
        assert!(ExternalIdentityProvider::validate_endpoint(
            "https://idp.example.com/authorize",
            "authorization_endpoint"
        )
        .is_ok());
        for bad in [
            "http://idp.example.com/authorize",
            "https://127.0.0.1/authorize",
            "https://localhost/authorize",
            "https://10.0.0.5/authorize",
            "not-a-url",
        ] {
            assert!(
                ExternalIdentityProvider::validate_endpoint(bad, "authorization_endpoint").is_err(),
                "{bad} must be rejected"
            );
        }
    }

    /// `openid` は必ず要求する（ID Token が無いと `iss`+`sub` を得られない）。
    #[test]
    fn openid_scope_is_always_requested() {
        assert_eq!(
            provider(Vec::new()).effective_scopes(),
            vec!["openid", "profile", "email"]
        );
        assert_eq!(
            provider(vec!["email".to_string()]).effective_scopes(),
            vec!["openid", "email"]
        );
        assert_eq!(
            provider(vec!["openid".to_string(), "groups".to_string()]).effective_scopes(),
            vec!["openid", "groups"]
        );
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    /// 未知のプロトコルは既定へ丸めずエラーにする。丸めると、SAML のつもりで登録した設定が
    /// OIDC として扱われ、検証の要件ごと変わってしまう。
    #[test]
    fn unknown_protocols_are_rejected_not_defaulted() {
        assert_eq!(
            ExternalIdpProtocol::parse("oidc").unwrap(),
            ExternalIdpProtocol::Oidc
        );
        assert_eq!(
            ExternalIdpProtocol::parse("saml").unwrap(),
            ExternalIdpProtocol::Saml
        );
        assert!(ExternalIdpProtocol::parse("ws-fed").is_err());
        assert!(ExternalIdpProtocol::parse("").is_err());
    }
}
