//! SAML SP-initiated SSO の進行状態（`saml_sso_requests`。OIDC の
//! [`crate::domain::auth_session`] に相当する一時状態）。
//!
//! `/{tenant_id}/saml/sso` が AuthnRequest を検証して作成し、単回・短命のハンドルで web へ
//! ハンドオフする（ADR-0018 のハンドオフ方式を SAML にも適用）。SSO 未確立の間は行 id
//! （web の host-only `saml_request_id` Cookie）で再開し、応答発行時に削除する。

use crate::domain::crypto;
use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// `saml_request_id`（web が host-only Cookie に持つランダム値）の SHA-256。
/// auth_session_id と同じく bearer credential なので DB へはハッシュだけを保存する（SEC6）。
pub fn id_hash(saml_request_id: &str) -> String {
    crypto::sha256_hex(saml_request_id)
}

#[derive(Debug, Clone)]
pub struct SamlSsoRequest {
    /// `saml_request_id` の SHA-256（[`id_hash`]）。平文はここには入らない。
    pub id_hash: String,
    /// フローを開始したテナント（`/{tenant_id}/saml/sso`。ADR-0009 §8）。
    pub tenant_id: TenantId,
    /// 解決済みの登録 SP。
    pub service_provider_id: Uuid,
    /// AuthnRequest の Issuer（登録 SP の entity_id。応答の `Audience`）。
    pub sp_entity_id: String,
    /// 検証済みのアサーション送信先（登録 SP の acs_url）。
    pub acs_url: String,
    /// AuthnRequest の ID（応答の `InResponseTo`。省略時は `None`）。
    pub request_id: Option<String>,
    /// SP が送った RelayState（応答フォームで透過返却する）。
    pub relay_state: Option<String>,
    /// web ハンドオフ用ハンドルの SHA-256（単回使用。交換時に `None` へ消費）。
    pub handle_hash: Option<String>,
    /// ハンドルの有効期限（本体の `expires_at` より短命）。
    pub handle_expires_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl SamlSsoRequest {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// web ハンドオフ用ハンドルが `now` 時点で交換可能か（未消費かつ期限内）。
    pub fn handle_is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.handle_hash.is_some() && self.handle_expires_at.is_some_and(|exp| exp > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn handle_validity_requires_both_hash_and_deadline() {
        let now = Utc::now();
        let mut request = SamlSsoRequest {
            id_hash: id_hash("r"),
            tenant_id: Uuid::now_v7().into(),
            service_provider_id: Uuid::nil(),
            sp_entity_id: "urn:sp".to_string(),
            acs_url: "https://sp.example.test/acs".to_string(),
            request_id: None,
            relay_state: None,
            handle_hash: Some("h".to_string()),
            handle_expires_at: Some(now + Duration::seconds(60)),
            expires_at: now + Duration::minutes(10),
            created_at: now,
        };
        assert!(request.handle_is_valid_at(now));
        assert!(!request.handle_is_valid_at(now + Duration::seconds(61)));
        // 消費済み（NULL）は無効（単回使用）。
        request.handle_hash = None;
        assert!(!request.handle_is_valid_at(now));
        // 本体の期限。
        assert!(!request.is_expired_at(now));
        assert!(request.is_expired_at(now + Duration::minutes(10)));
    }
}
