//! Read model of the "status" the user sees (task #896; ADR-0078).
//!
//! At the top of "Account security", shows sign-in states, possessions, app tokens, organization
//! rules, and warnings in one place. Everything just reads existing tables (`sso_sessions`,
//! `sso_session_contexts`, `user_devices`, `app_approver_keys`, `refresh_tokens`,
//! `sign_in_history`, `sign_in_app_usage`, `audit_log`); nothing new is written.

use crate::domain::user_device::CountryCode;
use chrono::{DateTime, NaiveDate, Utc};

/// Period (days) over which warnings are counted.
pub const WARNING_WINDOW_DAYS: i64 = 30;

/// A day with at least this many refused sign-ins is shown as a "day with many failures".
pub const FAILURE_DAY_THRESHOLD: u32 = 5;

/// Period (days) within which apps that recently got tokens are listed in the app token list.
pub const RECENT_APP_DAYS: i64 = 30;

/// Context of one sign-in state (`sso_session_contexts` and the device / authenticator app key
/// reachable from it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionContextStatus {
    pub session_hash: String,
    /// Whether the device mark of the browser that created this sign-in state is known.
    pub device_identified: bool,
    /// The registration, if that device is registered.
    pub registered_device: Option<RegisteredDeviceStatus>,
    /// Country when the sign-in state was created.
    pub country: Option<CountryCode>,
    /// Binding to the device key (DBSC).
    pub key: Option<SessionKeyStatus>,
    /// The approving authenticator app key (when signed in by approval).
    pub approver: Option<ApproverStatus>,
    /// Time a passkey re-verification last passed in this sign-in state.
    pub passkey_verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredDeviceStatus {
    pub name: String,
    pub registered_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeyStatus {
    /// `ES256` / `RS256`.
    pub algorithm: String,
    /// Public key thumbprint (RFC 7638, base64url).
    pub thumbprint: String,
    pub bound_at: DateTime<Utc>,
    /// Last time it was refreshed with a signature by the key.
    pub refreshed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverStatus {
    pub device_name: String,
    /// `tee` / `strongbox` / `software`.
    pub security_level: String,
}

/// Kinds of tokens currently valid for one app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTokenStatus {
    pub client_id: String,
    pub app_name: String,
    /// Consented scope (empty if there is no consent record).
    pub scopes: Vec<String>,
    /// Number of refresh tokens unexpired and not revoked.
    pub active_refresh_tokens: u32,
    /// How many of them are bound to a device key via DPoP.
    pub dpop_bound_refresh_tokens: u32,
    /// Last time a token was issued to this app (if recorded).
    pub last_issued_at: Option<DateTime<Utc>>,
    /// Number of refreshes with refresh tokens (total over sign-ins whose records remain).
    pub refresh_use_count: u32,
    /// Last refresh time and who sent it then.
    pub refresh_last_used_at: Option<DateTime<Utc>>,
    pub refresh_last_ip: Option<String>,
    pub refresh_last_user_agent: Option<String>,
    /// Last time a used-up refresh token came again.
    pub refresh_reuse_detected_at: Option<DateTime<Utc>>,
}

/// Recent warnings ([`WARNING_WINDOW_DAYS`] days).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityWarnings {
    /// Count and last time of detected refresh token reuse.
    pub refresh_reuse: Occurrences,
    /// Count and last time a signature from another key came for a sign-in state (suspected cookie
    /// theft).
    pub session_key_mismatch: Occurrences,
    /// Count and last time a DPoP from another key came for an app token.
    pub dpop_key_mismatch: Occurrences,
    /// Count and last time of sign-ins from unregistered devices.
    pub unregistered_sign_ins: Occurrences,
    /// Days (UTC dates) with at least [`FAILURE_DAY_THRESHOLD`] refused sign-ins, and their counts.
    /// Newest first.
    pub failure_days: Vec<(NaiveDate, u32)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Occurrences {
    pub count: u32,
    pub last_at: Option<DateTime<Utc>>,
}

impl SecurityWarnings {
    /// Whether there is nothing to show.
    pub fn is_empty(&self) -> bool {
        self.refresh_reuse.count == 0
            && self.session_key_mismatch.count == 0
            && self.dpop_key_mismatch.count == 0
            && self.unregistered_sign_ins.count == 0
            && self.failure_days.is_empty()
    }
}
