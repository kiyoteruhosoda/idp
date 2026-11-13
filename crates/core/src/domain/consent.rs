//! ClientConsent entity (F3: consent screen).
//!
//! Represents the scopes a user has consented to grant a client (RP).
//! Managed by the composite primary key `(user_id, tenant_id, client_id)`; scopes are overwritten via UPSERT.

use crate::domain::tenant::TenantId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A consent record a user granted to a client.
#[derive(Debug, Clone)]
pub struct ClientConsent {
    pub user_id: Uuid,
    /// Client entities are unique within a tenant, so they are identified by `(tenant_id, client_id)` (ADR-0009 §2).
    pub tenant_id: TenantId,
    pub client_id: String,
    /// List of consented scopes (stored as a JSON array).
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ClientConsent {
    /// Whether all `required_scopes` are already consented (forced to `false` for `prompt=consent`).
    pub fn covers(&self, required_scopes: &[String]) -> bool {
        required_scopes.iter().all(|s| self.scopes.contains(s))
    }
}
