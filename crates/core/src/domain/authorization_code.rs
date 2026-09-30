//! AuthorizationCode 集約（設計仕様 §3.5）。
//!
//! 認可要求に対して、完了した認証の結果として発行する単回使用の code。DB には平文ではなく
//! `code_hash = SHA-256(code)` を保存する。
//!
//! # 作り方と使い方
//!
//! - 発行は [`AuthorizationCode::issue`] だけ（認可要求と認証から作り、平文の code も生成する）
//! - `/token` での交換は、リポジトリが原子的に消費した code に対して
//!   [`AuthorizationCode::redeem`] で「出してきた相手・`redirect_uri`・PKCE」を照合する
//!
//! code が覚えておくのは、トークンを組み立てるのに要るものだけである: 誰に（`client_id`）、
//! どこへ返したか（`redirect_uri`）、何を（`scope`・`nonce`）、どの PKCE で（`code_challenge`）、
//! そして誰がどう認証したか（[`Authentication`]）。

use crate::domain::auth_session::Authentication;
use crate::domain::authorization_request::{AuthorizationRequest, PkceChallenge};
use crate::domain::crypto;
use crate::domain::pkce;
use crate::domain::tenant::TenantId;
use crate::domain::values::Scope;
use chrono::{DateTime, Duration, Utc};

/// code の平文（RP が `/token` へ持ってくる値）。bearer credential なので `Debug` に出さない。
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationCodeValue(String);

impl AuthorizationCodeValue {
    fn generate() -> Self {
        Self(crypto::random_token(32))
    }

    /// RP から提示された値を受け取る。空は「持っていない」と同じ。
    pub fn from_presented(raw: &str) -> Option<Self> {
        (!raw.is_empty()).then(|| Self(raw.to_string()))
    }

    pub fn hash(&self) -> AuthorizationCodeHash {
        AuthorizationCodeHash(crypto::sha256_hex(&self.0))
    }

    /// RP へ返す平文（認可応答に載る）。
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for AuthorizationCodeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizationCodeValue(<redacted>)")
    }
}

/// code の SHA-256。DB の主キーであり、この code から始まるトークンファミリの鍵（SEC8）でもある。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizationCodeHash(String);

impl AuthorizationCodeHash {
    pub fn from_stored(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// code が認めた認可の中身（認可要求のうち、トークン交換で要るもの）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeGrant {
    client_id: String,
    redirect_uri: String,
    scope: Vec<String>,
    /// 空文字 = 認可要求に `nonce` が無かった（ID Token にクレームごと載せない。ADR-0049）。
    nonce: String,
    pkce: PkceChallenge,
}

impl CodeGrant {
    fn of(request: &AuthorizationRequest) -> Self {
        Self {
            client_id: request.client_id().to_string(),
            redirect_uri: request.redirect_uri().to_string(),
            scope: request.scope().to_vec(),
            nonce: request.nonce().to_string(),
            pkce: request.pkce().clone(),
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn pkce(&self) -> &PkceChallenge {
        &self.pkce
    }

    /// その scope が認められているか。
    pub fn includes(&self, scope: Scope) -> bool {
        self.scope.iter().any(|s| s == scope.as_str())
    }

    /// 空白区切りの scope（トークン応答・アクセストークンの `scope`）。
    pub fn scope_string(&self) -> String {
        self.scope.join(" ")
    }
}

/// 交換を断る理由（照合の順に並べてある）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeRedemptionRejection {
    /// code は別のクライアントに発行された。
    IssuedToAnotherClient,
    /// `redirect_uri` が認可要求のものと一致しない（未指定を含む）。
    RedirectUriMismatch,
    /// `code_verifier` が `code_challenge` に合わない。
    PkceMismatch,
}

/// AuthorizationCode 集約。
#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    hash: AuthorizationCodeHash,
    /// code を発行したテナント（ADR-0009 §8。トークン交換は同一テナントに限る）。
    tenant_id: TenantId,
    grant: CodeGrant,
    authentication: Authentication,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// 永続化から [`AuthorizationCode`] を組み立て直すための部品（列の並びそのまま）。
///
/// ⚠ **Infrastructure 層（リポジトリ実装）と試験のためだけ**にある。
#[derive(Debug, Clone)]
pub struct AuthorizationCodeParts {
    pub hash: AuthorizationCodeHash,
    pub tenant_id: TenantId,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub pkce: PkceChallenge,
    pub authentication: Authentication,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthorizationCode {
    /// 認可要求に、完了した認証の結果として code を発行する。平文は RP へ返すためだけに返す。
    pub fn issue(
        tenant_id: TenantId,
        request: &AuthorizationRequest,
        authentication: Authentication,
        now: DateTime<Utc>,
        lifetime: Duration,
    ) -> (Self, AuthorizationCodeValue) {
        let value = AuthorizationCodeValue::generate();
        let code = Self {
            hash: value.hash(),
            tenant_id,
            grant: CodeGrant::of(request),
            authentication,
            expires_at: now + lifetime,
            used_at: None,
            created_at: now,
            updated_at: now,
        };
        (code, value)
    }

    pub fn reconstitute(parts: AuthorizationCodeParts) -> Self {
        Self {
            hash: parts.hash,
            tenant_id: parts.tenant_id,
            grant: CodeGrant {
                client_id: parts.client_id,
                redirect_uri: parts.redirect_uri,
                scope: parts.scope,
                nonce: parts.nonce,
                pkce: parts.pkce,
            },
            authentication: parts.authentication,
            expires_at: parts.expires_at,
            used_at: parts.used_at,
            created_at: parts.created_at,
            updated_at: parts.updated_at,
        }
    }

    pub fn hash(&self) -> &AuthorizationCodeHash {
        &self.hash
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn grant(&self) -> &CodeGrant {
        &self.grant
    }

    /// この code を与えた認証（ID Token の `sub` / `auth_time` / `sid` / `acr` / `amr` の出所）。
    pub fn authentication(&self) -> &Authentication {
        &self.authentication
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn used_at(&self) -> Option<DateTime<Utc>> {
        self.used_at
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// 交換の照合（RFC 6749 §4.1.3・RFC 7636 §4.6）。消費（単回使用・期限・テナント）はリポジトリが
    /// 済ませた後に呼ぶ。照合の順はクライアント → `redirect_uri` → PKCE。
    pub fn redeem(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        code_verifier: &str,
    ) -> Result<(), CodeRedemptionRejection> {
        if self.grant.client_id != client_id {
            return Err(CodeRedemptionRejection::IssuedToAnotherClient);
        }
        if redirect_uri != Some(self.grant.redirect_uri.as_str()) {
            return Err(CodeRedemptionRejection::RedirectUriMismatch);
        }
        if !pkce::verify_s256(code_verifier, self.grant.pkce.challenge()) {
            return Err(CodeRedemptionRejection::PkceMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::authorization_request::test_support::request;
    use crate::domain::values::AuthenticationMethod;
    use uuid::Uuid;

    /// RFC 7636 付録 B の組（`test_support::request` の challenge とは別に、照合が通る組を使う）。
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn issued(now: DateTime<Utc>) -> (AuthorizationCode, AuthorizationCodeValue) {
        let code = AuthorizationCode::issue(
            Uuid::now_v7().into(),
            &request("app", "https://client.example.com/cb"),
            Authentication::new(
                Uuid::now_v7(),
                now,
                Some("sid".to_string()),
                Some(vec![AuthenticationMethod::Password]),
            ),
            now,
            Duration::seconds(60),
        );
        // challenge を照合が通る値に差し替える（発行の口はそのまま使う）。
        let (code, value) = code;
        let mut parts = to_parts(&code);
        parts.pkce = PkceChallenge::reconstitute(
            CHALLENGE.to_string(),
            crate::domain::values::CodeChallengeMethod::S256,
        );
        (AuthorizationCode::reconstitute(parts), value)
    }

    fn to_parts(code: &AuthorizationCode) -> AuthorizationCodeParts {
        AuthorizationCodeParts {
            hash: code.hash.clone(),
            tenant_id: code.tenant_id,
            client_id: code.grant.client_id.clone(),
            redirect_uri: code.grant.redirect_uri.clone(),
            scope: code.grant.scope.clone(),
            nonce: code.grant.nonce.clone(),
            pkce: code.grant.pkce.clone(),
            authentication: code.authentication.clone(),
            expires_at: code.expires_at,
            used_at: code.used_at,
            created_at: code.created_at,
            updated_at: code.updated_at,
        }
    }

    #[test]
    fn an_issued_code_is_stored_only_as_its_hash_and_carries_the_request() {
        let now = Utc::now();
        let (code, value) = issued(now);
        assert_eq!(code.hash(), &value.hash());
        assert!(!format!("{value:?}").contains(&value.clone().into_string()));
        assert_eq!(code.grant().client_id(), "app");
        assert_eq!(code.grant().redirect_uri(), "https://client.example.com/cb");
        assert_eq!(code.grant().nonce(), "nonce-1");
        assert!(code.grant().includes(Scope::OpenId));
        assert!(!code.grant().includes(Scope::OfflineAccess));
        assert_eq!(code.grant().scope_string(), "openid");
        assert!(!code.is_used());
        assert!(!code.is_expired_at(now));
        assert!(code.is_expired_at(now + Duration::seconds(60)));
    }

    #[test]
    fn redeem_checks_client_then_redirect_uri_then_pkce() {
        let (code, _) = issued(Utc::now());
        let cb = Some("https://client.example.com/cb");
        assert_eq!(code.redeem("app", cb, VERIFIER), Ok(()));
        // 順序: 相手が違えば、他の項目が合っていなくても「別の相手」と答える。
        assert_eq!(
            code.redeem("other", None, "x"),
            Err(CodeRedemptionRejection::IssuedToAnotherClient)
        );
        assert_eq!(
            code.redeem("app", None, VERIFIER),
            Err(CodeRedemptionRejection::RedirectUriMismatch)
        );
        assert_eq!(
            code.redeem("app", Some("https://client.example.com/other"), VERIFIER),
            Err(CodeRedemptionRejection::RedirectUriMismatch)
        );
        assert_eq!(
            code.redeem("app", cb, "wrong-verifier-wrong-verifier-wrong-verifier-1"),
            Err(CodeRedemptionRejection::PkceMismatch)
        );
    }

    #[test]
    fn presented_values_must_not_be_empty() {
        assert!(AuthorizationCodeValue::from_presented("").is_none());
        let v = AuthorizationCodeValue::from_presented("abc").expect("present");
        assert_eq!(v.hash().as_str(), crypto::sha256_hex("abc"));
    }
}
