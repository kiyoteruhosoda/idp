//! The "SSH keys" section (`/internal/account/ssh-keys*`, task #885, ADR-0072).
//!
//! All are internal endpoints called only by web (behind the service token). Decisions are in the application layer
//! (`SshKeyRegistryService`); this only repacks DTOs. The endpoint read by the distributing machine is
//! in `admin_ssh_keys` (admin API).

use crate::application::audit::RequestContext;
use crate::application::ssh_key_registry::{
    RegisterSshKeyOutcome, RevokeSshKeyOutcome, SshKeyOverviewOutcome,
};
use crate::domain::ssh_key::SshKeyRejection;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    AccountSshKeySummary, InternalAccountRegisterSshKeyRequest,
    InternalAccountRegisterSshKeyResponse, InternalAccountRevokeSshKeyRequest,
    InternalAccountRevokeSshKeyResponse, InternalAccountSshKeysRequest,
    InternalAccountSshKeysResponse,
};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use uuid::Uuid;

/// The "SSH keys" section (`POST /internal/account/ssh-keys`).
pub async fn account_ssh_keys(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSshKeysRequest>,
) -> Result<Json<InternalAccountSshKeysResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state.ssh_keys.overview(tenant, &req.sso_session_id).await;
    Ok(Json(match outcome {
        SshKeyOverviewOutcome::Ok(view) => InternalAccountSshKeysResponse::Ok {
            enabled: view.enabled,
            passkey_fresh: view.passkey_fresh,
            keys: view
                .keys
                .iter()
                .map(|k| AccountSshKeySummary {
                    id: k.id.to_string(),
                    name: k.name.clone(),
                    key_type: k.key.key_type().as_str().to_string(),
                    fingerprint: k.key.fingerprint().to_string(),
                    created_at: k.created_at.to_rfc3339(),
                })
                .collect(),
        },
        SshKeyOverviewOutcome::SessionExpired => InternalAccountSshKeysResponse::SessionExpired,
        SshKeyOverviewOutcome::Internal(e) => {
            tracing::error!(error = %e, "ssh key overview failed with internal error");
            InternalAccountSshKeysResponse::Internal
        }
    }))
}

/// Registers an SSH public key (`POST /internal/account/ssh-keys/register`).
pub async fn account_register_ssh_key(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRegisterSshKeyRequest>,
) -> Result<Json<InternalAccountRegisterSshKeyResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .ssh_keys
        .register(
            tenant,
            &req.sso_session_id,
            &req.public_key,
            &req.name,
            &ctx,
        )
        .await;
    Ok(Json(match outcome {
        RegisterSshKeyOutcome::Registered { fingerprint } => {
            InternalAccountRegisterSshKeyResponse::Registered { fingerprint }
        }
        RegisterSshKeyOutcome::Disabled => InternalAccountRegisterSshKeyResponse::Disabled,
        RegisterSshKeyOutcome::PasskeyRequired => {
            InternalAccountRegisterSshKeyResponse::PasskeyRequired
        }
        RegisterSshKeyOutcome::InvalidName => InternalAccountRegisterSshKeyResponse::InvalidName,
        RegisterSshKeyOutcome::Rejected(SshKeyRejection::LooksLikePrivateKey) => {
            // ⚠ The pasted value is never logged either.
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "ssh key registration refused: a private key was pasted"
            );
            InternalAccountRegisterSshKeyResponse::PrivateKey
        }
        RegisterSshKeyOutcome::Rejected(SshKeyRejection::NotSecurityKeyType) => {
            InternalAccountRegisterSshKeyResponse::NotSecurityKey
        }
        RegisterSshKeyOutcome::Rejected(SshKeyRejection::Malformed) => {
            InternalAccountRegisterSshKeyResponse::Malformed
        }
        RegisterSshKeyOutcome::AlreadyRegistered => {
            InternalAccountRegisterSshKeyResponse::AlreadyRegistered
        }
        RegisterSshKeyOutcome::TooMany => InternalAccountRegisterSshKeyResponse::TooMany,
        RegisterSshKeyOutcome::SessionExpired => {
            InternalAccountRegisterSshKeyResponse::SessionExpired
        }
        RegisterSshKeyOutcome::Internal(e) => {
            tracing::error!(error = %e, "ssh key registration failed with internal error");
            InternalAccountRegisterSshKeyResponse::Internal
        }
    }))
}

/// Revokes an SSH public key (`POST /internal/account/ssh-keys/revoke`).
pub async fn account_revoke_ssh_key(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountRevokeSshKeyRequest>,
) -> Result<Json<InternalAccountRevokeSshKeyResponse>, Response> {
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Ok(key_id) = Uuid::parse_str(&req.key_id) else {
        return Ok(Json(InternalAccountRevokeSshKeyResponse::NotFound));
    };
    let outcome = state
        .ssh_keys
        .revoke(tenant, &req.sso_session_id, key_id, &ctx)
        .await;
    Ok(Json(match outcome {
        RevokeSshKeyOutcome::Revoked => InternalAccountRevokeSshKeyResponse::Revoked,
        RevokeSshKeyOutcome::PasskeyRequired => {
            InternalAccountRevokeSshKeyResponse::PasskeyRequired
        }
        RevokeSshKeyOutcome::NotFound => InternalAccountRevokeSshKeyResponse::NotFound,
        RevokeSshKeyOutcome::SessionExpired => InternalAccountRevokeSshKeyResponse::SessionExpired,
        RevokeSshKeyOutcome::Internal(e) => {
            tracing::error!(error = %e, "ssh key revocation failed with internal error");
            InternalAccountRevokeSshKeyResponse::Internal
        }
    }))
}
