//! The user's own sign-in history (`POST /internal/account/sign-in-history`, task #879, ADR-0073).
//!
//! Internal endpoint called only by web (behind the service token). The user is determined by the SSO session's owner;
//! no user id is accepted. Decisions are in the application layer (`SignInHistoryService`); this only
//! repacks DTOs.

use crate::application::sign_in_history::{SignInHistoryEntry, SignInHistoryOutcome};
use crate::domain::sign_in_history::{RefreshState, SIGN_IN_HISTORY_PAGE_MAX};
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    AccountRefreshUsage, AccountSignInApp, AccountSignInEntry, InternalAccountSignInHistoryRequest,
    InternalAccountSignInHistoryResponse,
};
use axum::extract::State;
use axum::response::Response;
use axum::Json;

pub async fn account_sign_in_history(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSignInHistoryRequest>,
) -> Result<Json<InternalAccountSignInHistoryResponse>, Response> {
    // Tenant is required (fail-closed like the other `/internal/account/*`).
    let _tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .sign_in_history
        .history(
            &req.sso_session_id,
            req.before,
            req.limit.unwrap_or(SIGN_IN_HISTORY_PAGE_MAX),
        )
        .await;
    Ok(Json(match outcome {
        SignInHistoryOutcome::Ok(page) => InternalAccountSignInHistoryResponse::Ok {
            entries: page.entries.iter().map(entry).collect(),
            next_before: page.next_before,
        },
        SignInHistoryOutcome::SessionExpired => {
            InternalAccountSignInHistoryResponse::SessionExpired
        }
        SignInHistoryOutcome::Internal(e) => {
            tracing::error!(error = %e, "sign-in history failed with internal error");
            InternalAccountSignInHistoryResponse::Internal
        }
    }))
}

fn entry(e: &SignInHistoryEntry) -> AccountSignInEntry {
    let r = &e.record;
    AccountSignInEntry {
        id: r.id,
        occurred_at: r.occurred_at.to_rfc3339(),
        outcome: r.outcome.as_str().to_string(),
        failure_kind: r.failure_kind.map(|k| k.as_str().to_string()),
        ip_address: r.ip_address.clone(),
        user_agent: r.user_agent.clone(),
        country: r.country.as_ref().map(|c| c.as_str().to_string()),
        methods: r.methods.iter().map(|m| m.as_str().to_string()).collect(),
        app_name: r.app_name.clone(),
        client_id: r.client_id.clone(),
        device_registered: r.device_registered,
        current: e.current,
        apps: e
            .apps
            .iter()
            .map(|a| AccountSignInApp {
                client_id: a.client_id.clone(),
                app_name: a.app_name.clone(),
                first_issued_at: a.first_issued_at.to_rfc3339(),
                last_issued_at: a.last_issued_at.to_rfc3339(),
                refresh: a.refresh.as_ref().map(|u| {
                    let (state, revoked_at) = match u.state {
                        RefreshState::Active => ("active", None),
                        RefreshState::Revoked { at } => ("revoked", at.map(|t| t.to_rfc3339())),
                        RefreshState::Expired => ("expired", None),
                    };
                    AccountRefreshUsage {
                        use_count: u.use_count,
                        last_used_at: u.last_used_at.map(|t| t.to_rfc3339()),
                        last_ip_address: u.last_ip_address.clone(),
                        last_user_agent: u.last_user_agent.clone(),
                        reuse_detected_at: u.reuse_detected_at.map(|t| t.to_rfc3339()),
                        state: state.to_string(),
                        revoked_at,
                    }
                }),
            })
            .collect(),
    }
}
