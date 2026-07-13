//! ClientConsent エンティティ（F3: 同意画面）。
//!
//! ユーザーがクライアント（RP）に付与した同意済み scope を表す。
//! `(user_id, tenant_id, client_id)` の複合主キーで管理し、UPSERT でスコープを上書きする。

use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// ユーザーがクライアントに付与した同意レコード。
#[derive(Debug, Clone)]
pub struct ClientConsent {
    pub user_id: Uuid,
    /// クライアント実体はテナント内一意のため `(tenant_id, client_id)` で特定する（ADR-0009 §2）。
    pub tenant_id: TenantId,
    pub client_id: String,
    /// 同意済み scope のリスト（保存時は JSON 配列）。
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ClientConsent {
    /// `required_scopes` がすべて同意済みか（`prompt=consent` の場合は強制的に `false`）。
    pub fn covers(&self, required_scopes: &[String]) -> bool {
        required_scopes.iter().all(|s| self.scopes.contains(s))
    }
}
