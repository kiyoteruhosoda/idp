//! Clients エンティティ（設計仕様 §3.2）。
#![allow(dead_code)]

use crate::domain::values::{ClientStatus, ClientType, TokenEndpointAuthMethod};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Client {
    pub id: Uuid,
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
    pub require_pkce: bool,
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
}
