//! 配る機械が読む SSH の鍵の一覧（`GET /{tenant_id}/admin/ssh-keys`。task #885。ADR-0072）。
//!
//! 保護は `idp.ssh-keys:read`。⚠ **機械クライアントのトークンだけ**を通す（人の管理トークンは
//! `idp.tenant.admin` がこのコードを含意していても 403）。判定は Application 層
//! （`SshKeyRegistryService::distributable`）。

use crate::application::ssh_key_registry::SshKeyDistributionError;
use crate::presentation::admin::{RequirePerms, SshKeysRead};
use crate::presentation::dto::{SshKeyListResponse, SshKeyResponse};
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::Json;

/// 組織の有効な SSH の鍵を一覧する（`GET /{tenant_id}/admin/ssh-keys`）。
///
/// 取り消した鍵・止めた利用者・組織から外れた利用者・利用者名の無い利用者の鍵は出ない。
/// 組織で `SSH_KEYS_ENABLED` が無効なら `keys` は空。
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
