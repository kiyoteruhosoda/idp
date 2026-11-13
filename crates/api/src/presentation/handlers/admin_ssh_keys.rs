//! List of SSH keys read by the distributing machine (`GET /{tenant_id}/admin/ssh-keys`, task #885, ADR-0072).
//!
//! Protected by `idp.ssh-keys:read`. ⚠ **Only machine client tokens** pass (a human's admin token gets 403
//! even if `idp.tenant.admin` implies this code). The decision is in the application layer
//! (`SshKeyRegistryService::distributable`).

use crate::application::ssh_key_registry::SshKeyDistributionError;
use crate::presentation::admin::{RequirePerms, SshKeysRead};
use crate::presentation::dto::{SshKeyListResponse, SshKeyResponse};
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::Json;

/// Lists the organization's active SSH keys (`GET /{tenant_id}/admin/ssh-keys`).
///
/// Keys that were revoked, or belong to disabled users, users removed from the org or users without a username, are omitted.
/// If `SSH_KEYS_ENABLED` is off for the org, `keys` is empty.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/ssh-keys",
    tag = "admin",
    responses(
        (status = 200, description = "有効な SSH の鍵の一覧（無効の組織では空）", body = SshKeyListResponse),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.ssh-keys:read 必須）、または人のトークン（機械クライアントだけ）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_ssh_keys(
    RequirePerms(caller, _): RequirePerms<SshKeysRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<SshKeyListResponse>, ApiError> {
    let keys = state
        .ssh_keys
        .distributable(tenant.context(), &caller.actor)
        .await
        .map_err(|e| match e {
            SshKeyDistributionError::NotAMachine => {
                ApiError::Forbidden(ApiMessages::new(locale).get("api-ssh-keys-machine-only"))
            }
            SshKeyDistributionError::Internal(m) => ApiError::Internal(m),
        })?;
    Ok(Json(SshKeyListResponse {
        keys: keys
            .into_iter()
            .map(|k| SshKeyResponse {
                username: k.username,
                name: k.name,
                public_key: k.key.authorized_key(),
                fingerprint: k.key.fingerprint().to_string(),
                created_at: k
                    .created_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            })
            .collect(),
    }))
}
