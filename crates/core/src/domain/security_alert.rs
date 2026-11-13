//! Security alerts (task #872; ADR-0071).
//!
//! Sends "signed in from an unregistered device" and "registered / revoked a device, registration
//! expired" to the operators' alert destination. **Failure to send never stops the original
//! operation** (a login is not refused because an alert failed). The same event is always recorded
//! in the audit log too, so the alert is a copy meant to "notice sooner".
//!
//! Alerts carry only display material (time, country, browser's self-identification, sign-in
//! method, device name); device marks, session ids, and email addresses are not included.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::tenant::TenantId;
use crate::domain::user_device::CountryCode;
use crate::domain::values::AuthenticationMethod;

/// The event to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityAlertKind {
    /// Signed in from an unregistered device.
    UnregisteredDeviceSignIn {
        /// Whether this is the first sign-in seen on that device (`false` if there was an earlier
        /// sign-in with the same mark).
        first_seen: bool,
        methods: Vec<AuthenticationMethod>,
    },
    /// In an organization limited to registered devices, authentication succeeded on an
    /// unregistered device (may signal a leaked password). The sign-in was not completed (task
    /// #916).
    UnregisteredDeviceRefused {
        methods: Vec<AuthenticationMethod>,
    },
    /// Registered a device.
    DeviceRegistered {
        device_name: String,
    },
    /// The user revoked a device registration.
    DeviceRevoked {
        device_name: String,
    },
    /// The device registration expired after going unused past its deadline.
    DeviceExpired {
        device_name: String,
    },
    /// Registered an SSH public key (task #885).
    SshKeyRegistered {
        key_name: String,
        fingerprint: String,
    },
    /// Revoked an SSH public key (task #885).
    SshKeyRevoked {
        key_name: String,
        fingerprint: String,
    },
    /// A signature from a different key arrived for a sign-in state bound to a device key
    /// (suspected cookie theft; task #887). That sign-in state has been ended.
    SessionKeyMismatch,
    /// Registered / revoked an authenticator app key (task #892).
    ApproverKeyRegistered {
        device_name: String,
    },
    ApproverKeyRevoked {
        device_name: String,
    },
    /// A sign-in approved in the authenticator app was being completed in a different browser than
    /// the one that started the request (suspected of being tricked into approving a request
    /// started on another device). The sign-in was not allowed.
    AppApprovalFromAnotherBrowser {
        device_name: String,
    },
}

impl SecurityAlertKind {
    /// Severity of the alert. Unregistered-device sign-ins and registration/revocation are
    /// "warning"; expiry is "info".
    pub fn severity(&self) -> SecurityAlertSeverity {
        match self {
            Self::UnregisteredDeviceSignIn { .. }
            | Self::UnregisteredDeviceRefused { .. }
            | Self::DeviceRegistered { .. }
            | Self::DeviceRevoked { .. }
            | Self::SshKeyRegistered { .. }
            | Self::SshKeyRevoked { .. }
            | Self::SessionKeyMismatch
            | Self::ApproverKeyRegistered { .. }
            | Self::ApproverKeyRevoked { .. }
            | Self::AppApprovalFromAnotherBrowser { .. } => SecurityAlertSeverity::Warning,
            Self::DeviceExpired { .. } => SecurityAlertSeverity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityAlertSeverity {
    Info,
    Warning,
}

/// One alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAlert {
    pub kind: SecurityAlertKind,
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    /// The user's display name (login id). Lets the reader know "who this is about".
    pub username: String,
    pub occurred_at: DateTime<Utc>,
    pub country: Option<CountryCode>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// Key for bundling alerts of the same device into one (prefix of the device mark's
    /// fingerprint, not the mark itself).
    pub group_key: String,
}

/// Sender for alerts. Implementations do not make the caller wait (sending and retries happen in
/// the background).
#[async_trait]
pub trait SecurityAlertSink: Send + Sync {
    async fn send(&self, alert: SecurityAlert);
}

/// Sender used when no destination is configured (does nothing).
pub struct DisabledSecurityAlertSink;

#[async_trait]
impl SecurityAlertSink for DisabledSecurityAlertSink {
    async fn send(&self, _alert: SecurityAlert) {}
}
