//! Clients エンティティ（設計仕様 §3.2）。
#![allow(dead_code)]

use crate::domain::client_jwks::ClientJwks;
use crate::domain::tenant::TenantId;
use crate::domain::values::{ClientStatus, ClientType, GrantType, TokenEndpointAuthMethod};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Client {
    pub id: Uuid,
    /// クライアントが属するテナント（ADR-0009 §2。`client_id` はテナント内一意）。
    pub tenant_id: TenantId,
    pub client_id: String,
    /// confidential クライアントのみ。ハッシュ化して保存する。
    pub client_secret_hash: Option<String>,
    pub client_type: ClientType,
    pub client_status: ClientStatus,
    pub app_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// `private_key_jwt` の client assertion を検証する公開鍵（ADR-0030）。それ以外の方式では
    /// `None`。検証はこの集合だけを見る（クライアントの `jwks_uri` は取りに行かない）。
    pub jwks: Option<ClientJwks>,
    /// RP-initiated logout 後のリダイレクト先として登録済みの URI 群（F4）。
    pub post_logout_redirect_uris: Vec<String>,
    /// front-channel logout 用 iframe URI（F4）。
    pub frontchannel_logout_uri: Option<String>,
    /// back-channel logout 用 HTTP POST 先 URI（F4）。
    pub backchannel_logout_uri: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Client {
    pub fn is_active(&self) -> bool {
        self.client_status == ClientStatus::Active
    }

    /// 論理削除済みか（ADR-0035）。一覧・取得から外し、更新も受け付けないための判定。
    ///
    /// 認可・トークン経路は `is_active()` で既に拒んでいるので、この判定を足す必要は無い。
    pub fn is_deleted(&self) -> bool {
        self.client_status == ClientStatus::Deleted
    }

    /// `redirect_uri` が登録値と完全一致するか（設計仕様 §2.3・§4.2）。
    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == redirect_uri)
    }

    /// `post_logout_redirect_uri` が登録値と完全一致するか（F4 RP-initiated logout）。
    pub fn allows_post_logout_redirect_uri(&self, uri: &str) -> bool {
        self.post_logout_redirect_uris.iter().any(|u| u == uri)
    }

    /// 要求 scope がすべて登録 scope の部分集合か（設計仕様 §4.2）。
    pub fn allows_scopes(&self, requested: &[String]) -> bool {
        requested.iter().all(|s| self.scopes.contains(s))
    }

    /// 指定の grant_type が登録済みか（G4）。
    ///
    /// `client_credentials` は利用者不在でアクセストークンを取れる強い許可のため、テナント管理者が
    /// クライアント単位で明示的に有効化したものだけに限る（confidential であることは別途要求する）。
    pub fn allows_grant_type(&self, grant_type: GrantType) -> bool {
        self.grant_types.iter().any(|g| g == grant_type.as_str())
    }

    /// `private_key_jwt`（署名済み assertion）で認証するクライアントか（ADR-0030）。
    ///
    /// public client では常に false —— 秘密鍵を秘匿できない以上、鍵ペアによる認証も成立しない。
    pub fn uses_private_key_jwt(&self) -> bool {
        self.client_type == ClientType::Confidential
            && self.token_endpoint_auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
    }

    /// サーバ間（M2M）でのトークン取得を許可されているか（G4）。
    /// public client は資格情報を秘匿できないため、登録上許可されていても常に不可とする。
    pub fn allows_client_credentials(&self) -> bool {
        self.client_type == ClientType::Confidential
            && self.allows_grant_type(GrantType::ClientCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn client(client_type: ClientType, grant_types: &[&str]) -> Client {
        let now = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        Client {
            id: Uuid::from_u128(1),
            tenant_id: TenantId::from(Uuid::from_u128(2)),
            client_id: "c".to_string(),
            client_secret_hash: None,
            client_type,
            client_status: ClientStatus::Active,
            app_name: "app".to_string(),
            redirect_uris: vec![],
            grant_types: grant_types.iter().map(|s| s.to_string()).collect(),
            response_types: vec!["code".to_string()],
            scopes: vec![],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            jwks: None,
            post_logout_redirect_uris: vec![],
            frontchannel_logout_uri: None,
            backchannel_logout_uri: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// public client は登録上許可されていても M2M を使えない（秘密を秘匿できないため）。
    #[test]
    fn client_credentials_requires_a_confidential_client_and_an_explicit_grant() {
        assert!(client(
            ClientType::Confidential,
            &["authorization_code", "client_credentials"]
        )
        .allows_client_credentials());
        assert!(
            !client(ClientType::Confidential, &["authorization_code"]).allows_client_credentials()
        );
        assert!(!client(
            ClientType::Public,
            &["authorization_code", "client_credentials"]
        )
        .allows_client_credentials());
    }
}
