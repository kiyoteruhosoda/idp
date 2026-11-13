//! Internal API for account setup links (`/internal/account-setup/*`, ADR-0062).
//!
//! Called by the screen (web) that opened the one-time link issued by an admin. ⚠ **`describe` only reads and
//! does not consume** -- links are often passed over chat, and a preview bot fetches them before the recipient.
//! Only operations that actually set a credential (completing a passkey, setting a password) consume it.
//!
//! There is no dedicated password-setting path. ⚠ **It is the same token table, so the forgotten-password
//! reset (`/internal/password-reset/complete`) works as is** -- with two endpoints doing the same thing,
//! one of policy validation, session revocation or auditing would go stale on one side.
//!
//! All belong to the `/internal/*` router and are protected by the service auth token.

use crate::application::account_setup::AccountSetupError;
use crate::application::audit::RequestContext;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    InternalAccountSetupDescribeRequest, InternalAccountSetupDescribeResponse,
    InternalAccountSetupPasskeyBeginRequest, InternalAccountSetupPasskeyBeginResponse,
    InternalAccountSetupPasskeyCompleteRequest, InternalAccountSetupPasskeyCompleteResponse,
};
use axum::extract::{Extension, State};
use axum::response::Response;
use axum::Json;
use uuid::Uuid;

/// Reads the link's contents (`POST /internal/account-setup/describe`). Does not consume it.
pub async fn describe(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSetupDescribeRequest>,
) -> Result<Json<InternalAccountSetupDescribeResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state.account_setup.describe(tenant, &req.token).await {
            Ok(view) => InternalAccountSetupDescribeResponse::Ok {
                allows_passkey: view.allows_passkey_registration(),
                expires_at: view.expires_at.to_rfc3339(),
                email: view.email,
            },
            Err(AccountSetupError::InvalidOrExpired | AccountSetupError::NotAllowed) => {
                InternalAccountSetupDescribeResponse::InvalidOrExpired
            }
            Err(e) => {
                tracing::error!(error = %e, "account setup describe error");
                InternalAccountSetupDescribeResponse::Internal
            }
        },
    ))
}

/// Starts passkey registration (`POST /internal/account-setup/passkey/begin`).
pub async fn passkey_begin(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSetupPasskeyBeginRequest>,
) -> Result<Json<InternalAccountSetupPasskeyBeginResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    Ok(Json(
        match state.account_setup.begin_passkey(tenant, &req.token).await {
            Ok((challenge_id, options)) => InternalAccountSetupPasskeyBeginResponse::Ok {
                challenge_id: challenge_id.to_string(),
                options,
            },
            Err(AccountSetupError::InvalidOrExpired) => {
                InternalAccountSetupPasskeyBeginResponse::InvalidOrExpired
            }
            Err(AccountSetupError::NotAllowed) => {
                InternalAccountSetupPasskeyBeginResponse::NotAllowed
            }
            Err(e) => {
                tracing::error!(error = %e, "account setup passkey begin error");
                InternalAccountSetupPasskeyBeginResponse::Internal
            }
        },
    ))
}

/// Completes passkey registration (`POST /internal/account-setup/passkey/complete`). Consumes the link on success.
pub async fn passkey_complete(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Json(req): Json<InternalAccountSetupPasskeyCompleteRequest>,
) -> Result<Json<InternalAccountSetupPasskeyCompleteResponse>, Response> {
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let Ok(challenge_id) = Uuid::parse_str(&req.challenge_id) else {
        // A malformed value is treated like an expired challenge (gives no hint).
        return Ok(Json(
            InternalAccountSetupPasskeyCompleteResponse::InvalidOrExpired,
        ));
    };
    let ctx = RequestContext {
        correlation_id: correlation.0,
        ip_address: req.ip_address,
        user_agent: req.user_agent,
    };
    Ok(Json(
        match state
            .account_setup
            .complete_passkey(
                tenant,
                &req.token,
                challenge_id,
                &req.name,
                req.credential,
                &ctx,
            )
            .await
        {
            Ok(()) => InternalAccountSetupPasskeyCompleteResponse::Ok,
            Err(AccountSetupError::InvalidOrExpired) => {
                InternalAccountSetupPasskeyCompleteResponse::InvalidOrExpired
            }
            Err(AccountSetupError::NotAllowed) => {
                InternalAccountSetupPasskeyCompleteResponse::NotAllowed
            }
            Err(AccountSetupError::InvalidCredential(reason)) => {
                tracing::warn!(reason = %reason, "account setup passkey rejected");
                InternalAccountSetupPasskeyCompleteResponse::InvalidCredential
            }
            Err(e) => {
                tracing::error!(error = %e, "account setup passkey complete error");
                InternalAccountSetupPasskeyCompleteResponse::Internal
            }
        },
    ))
}
