//! 本人が見る「状況」（`POST /internal/account/security/status`。task #896。ADR-0078）。
//!
//! web だけが呼ぶ内部の口（サービストークンの内側）。利用者は SSO セッションの持ち主で決まり、
//! 利用者 id は受け取らない。組み立ては Application 層（`SecurityStatusService`）にあり、ここは DTO の
//! 詰め替えだけを行う。

use crate::application::security_status::{
    Belonging, PolicyStatus, SecurityStatusOutcome, SessionStatus,
};
use crate::domain::security_status::{
    AppTokenStatus, Occurrences, SecurityWarnings, WARNING_WINDOW_DAYS,
};
use crate::domain::session_key::SessionBinding;
use crate::presentation::state::AppState;
use crate::presentation::tenant::require_internal_tenant;
use assay_contracts::auth::{
    AccountAppTokens, AccountBelonging, AccountFailureDay, AccountOccurrences,
    AccountSecurityPolicy, AccountSecurityWarnings, AccountSessionStatus,
    InternalAccountSecurityStatusRequest, InternalAccountSecurityStatusResponse,
};
use axum::extract::State;
use axum::response::Response;
use axum::Json;
use chrono::{DateTime, Utc};

pub async fn account_security_status(
    State(state): State<AppState>,
    Json(req): Json<InternalAccountSecurityStatusRequest>,
) -> Result<Json<InternalAccountSecurityStatusResponse>, Response> {
    // テナントは必須（他の `/internal/account/*` と同じ fail-closed）。
    let tenant =
        require_internal_tenant(&state.tenant_resolution, req.tenant_id.as_deref()).await?;
    let outcome = state
        .security_status
        .status(tenant, &req.sso_session_id)
        .await;
    Ok(Json(match outcome {
        SecurityStatusOutcome::Ok(status) => InternalAccountSecurityStatusResponse::Ok {
            sessions: status.sessions.iter().map(session).collect(),
            belongings: status.belongings.iter().map(belonging).collect(),
            apps: status.apps.iter().map(app).collect(),
            policy: policy(&status.policy),
            warnings: Box::new(warnings(&status.warnings)),
        },
        SecurityStatusOutcome::SessionExpired => {
            InternalAccountSecurityStatusResponse::SessionExpired
        }
        SecurityStatusOutcome::Internal(e) => {
            tracing::error!(error = %e, "security status failed with internal error");
            InternalAccountSecurityStatusResponse::Internal
        }
    }))
}

fn time(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

fn opt_time(t: Option<DateTime<Utc>>) -> Option<String> {
    t.map(time)
}

fn binding(b: SessionBinding) -> &'static str {
    match b {
        SessionBinding::Unbound => "unbound",
        SessionBinding::DeviceKey => "device_key",
        SessionBinding::AppApproval => "app_approval",
    }
}

fn session(s: &SessionStatus) -> AccountSessionStatus {
    let device = s.registered_device.as_ref();
    let key = s.key.as_ref();
    let approver = s.approver.as_ref();
    AccountSessionStatus {
        id: s.id.clone(),
        current: s.current,
        auth_time: time(s.auth_time),
        created_at: time(s.created_at),
        expires_at: time(s.expires_at),
        methods: s.methods.iter().map(|m| m.as_str().to_string()).collect(),
        multi_factor: s.multi_factor,
        user_agent: s.user_agent.clone(),
        ip_address: s.ip_address.clone(),
        country: s.country.as_ref().map(|c| c.as_str().to_string()),
        device_identified: s.device_identified,
        device_name: device.map(|d| d.name.clone()),
        device_registered_at: device.map(|d| time(d.registered_at)),
        device_last_used_at: device.map(|d| time(d.last_used_at)),
        binding: binding(s.binding).to_string(),
        lifetime_basis: s.lifetime_basis.as_str().to_string(),
        key_algorithm: key.map(|k| k.algorithm.clone()),
        key_thumbprint: key.map(|k| k.thumbprint.clone()),
        key_bound_at: key.map(|k| time(k.bound_at)),
        key_refreshed_at: key.and_then(|k| opt_time(k.refreshed_at)),
        approver_device_name: approver.map(|a| a.device_name.clone()),
        approver_security_level: approver.map(|a| a.security_level.clone()),
        passkey_fresh_until: opt_time(s.passkey_fresh_until),
    }
}

fn belonging(b: &Belonging) -> AccountBelonging {
    AccountBelonging {
        kind: b.kind.as_str().to_string(),
        name: b.name.clone(),
        detail: b.detail.clone(),
        registered_at: time(b.registered_at),
        last_used_at: opt_time(b.last_used_at),
        expires_at: opt_time(b.expires_at),
    }
}

fn app(a: &AppTokenStatus) -> AccountAppTokens {
    AccountAppTokens {
        client_id: a.client_id.clone(),
        app_name: a.app_name.clone(),
        scopes: a.scopes.clone(),
        active_refresh_tokens: a.active_refresh_tokens,
        dpop_bound_refresh_tokens: a.dpop_bound_refresh_tokens,
        last_issued_at: opt_time(a.last_issued_at),
        refresh_use_count: a.refresh_use_count,
        refresh_last_used_at: opt_time(a.refresh_last_used_at),
        refresh_last_ip: a.refresh_last_ip.clone(),
        refresh_last_user_agent: a.refresh_last_user_agent.clone(),
        refresh_reuse_detected_at: opt_time(a.refresh_reuse_detected_at),
    }
}

fn policy(p: &PolicyStatus) -> AccountSecurityPolicy {
    AccountSecurityPolicy {
        unregistered_device_alerts: p.unregistered_device_alerts,
        ssh_keys_enabled: p.ssh_keys_enabled,
        idle_ttl_secs: p.idle_ttl_secs,
        absolute_ttl_secs: p.absolute_ttl_secs,
        bound_ttl_secs: p.bound_ttl_secs,
        device_expiry_days: p.device_expiry_days,
    }
}

fn occurrences(o: &Occurrences) -> AccountOccurrences {
    AccountOccurrences {
        count: o.count,
        last_at: opt_time(o.last_at),
    }
}

fn warnings(w: &SecurityWarnings) -> AccountSecurityWarnings {
    AccountSecurityWarnings {
        window_days: WARNING_WINDOW_DAYS,
        refresh_reuse: occurrences(&w.refresh_reuse),
        session_key_mismatch: occurrences(&w.session_key_mismatch),
        dpop_key_mismatch: occurrences(&w.dpop_key_mismatch),
        unregistered_sign_ins: occurrences(&w.unregistered_sign_ins),
        failure_days: w
            .failure_days
            .iter()
            .map(|(day, count)| AccountFailureDay {
                day: day.format("%Y-%m-%d").to_string(),
                count: *count,
            })
            .collect(),
    }
}
