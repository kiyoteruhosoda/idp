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

    /// 要求 scope がすべて登録 scope の部分集合か（設計仕様 §4.2）。
    pub fn allows_scopes(&self, requested: &[String]) -> bool {
        requested.iter().all(|s| self.scopes.contains(s))
    }
}
