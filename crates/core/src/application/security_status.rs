//! The "status" the user sees (task #896. ADR-0078).
//!
//! At the top of "Account security", returns the following gathered in one place. Read only; writes nothing.
//!
//! | Group | Contents |
//! |---|---|
//! | Signed-in states | How signed in, device (registered or not), device key binding (DBSC), authenticator app approval, lifetime and its basis |
//! | Possessions | Passkeys, TOTP, authenticator app keys, registered devices, SSH keys, and the last time each was used |
//! | Apps and tokens | Whether there is a refresh token and its DPoP binding, refresh count, reuse detection, consented scope |
//! | Organization rules | Notifications, SSH keys, lifetime, device expiry (the values in effect for oneself) |
//! | Warnings | Reuse, signatures from a different key, sign-ins on unregistered devices, days with many failures in the last 30 days |
//!
//! The lifetime basis is taken from `session_key::lifetime_basis` (the same decision that sets the lifetime), so that the
//! screen's explanation and the actual lifetime do not diverge through separate decisions.
//!
//! Only the user's own. The user is determined by the SSO session's owner; no user id is accepted from outside.

use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    ApproverKeyRepository, SecurityStatusQuery, SsoSessionRepository, UserAuthenticatorRepository,
    UserDeviceRepository, UserRepository, UserSshKeyRepository,
};
use crate::domain::security_status::{
    AppTokenStatus, ApproverStatus, RegisteredDeviceStatus, SecurityWarnings, SessionContextStatus,
    SessionKeyStatus, RECENT_APP_DAYS, WARNING_WINDOW_DAYS,
};
use crate::domain::session_key::{lifetime_basis, LifetimeBasis, SessionBinding};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user_authenticator::{AuthenticatorStatus, AuthenticatorType};
use crate::domain::user_device::{
    CountryCode, REGISTRATION_PASSKEY_MAX_AGE_SECS, UNUSED_DEVICE_EXPIRY_DAYS,
};
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;

/// Status of one signed-in state.
#[derive(Debug, Clone)]
pub struct SessionStatus {
    /// Identifier on screen (`SsoSession::display_id`. Same value as the existing "signed-in state" rows).
    pub id: String,
    /// Whether this is the signed-in state currently being viewed.
    pub current: bool,
    pub auth_time: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Expiry time (the earlier of idle and absolute).
    pub expires_at: DateTime<Utc>,
    pub methods: Vec<AuthenticationMethod>,
    pub multi_factor: bool,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub country: Option<CountryCode>,
    pub device_identified: bool,
    pub registered_device: Option<RegisteredDeviceStatus>,
    pub key: Option<SessionKeyStatus>,
    pub approver: Option<ApproverStatus>,
    pub binding: SessionBinding,
    pub lifetime_basis: LifetimeBasis,
    /// Deadline while the passkey verification is fresh (device registration and SSH key operations allowed). `None` if past.
    pub passkey_fresh_until: Option<DateTime<Utc>>,
}

/// Kind of possession.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BelongingKind {
    Passkey,
    Totp,
    ApproverKey,
    Device,
    SshKey,
}

impl BelongingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passkey => "passkey",
            Self::Totp => "totp",
            Self::ApproverKey => "approver_key",
            Self::Device => "device",
            Self::SshKey => "ssh_key",
        }
    }
}

/// One trusted possession.
#[derive(Debug, Clone)]
pub struct Belonging {
    pub kind: BelongingKind,
    pub name: String,
    /// Per-kind detail (where the authenticator app key is, the device's name, the SSH key type).
    pub detail: Option<String>,
    pub registered_at: DateTime<Utc>,
    /// Last used time. Always `None` for things whose use assay cannot see (SSH keys).
    pub last_used_at: Option<DateTime<Utc>>,
    /// Expiry (registered devices only. 180 days after last use).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Organization rules in effect for oneself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatus {
    /// Whether sign-ins on unregistered devices are notified (home organization).
    pub unregistered_device_alerts: bool,
    /// Whether SSH keys can be registered (current organization).
    pub ssh_keys_enabled: bool,
    /// Lifetime of the signed-in state (seconds. home organization).
    pub idle_ttl_secs: i64,
    pub absolute_ttl_secs: i64,
    pub bound_ttl_secs: i64,
    /// Expiry of registered devices (days since last use).
    pub device_expiry_days: i64,
}

#[derive(Debug, Clone)]
pub struct SecurityStatus {
    pub sessions: Vec<SessionStatus>,
    pub belongings: Vec<Belonging>,
    pub apps: Vec<AppTokenStatus>,
    pub policy: PolicyStatus,
    pub warnings: SecurityWarnings,
}

impl SecurityStatus {
    /// The signed-in state currently being viewed.
    pub fn current(&self) -> Option<&SessionStatus> {
        self.sessions.iter().find(|s| s.current)
    }
}

#[derive(Debug)]
pub enum SecurityStatusOutcome {
    Ok(Box<SecurityStatus>),
    SessionExpired,
    Internal(String),
}

pub struct SecurityStatusService {
    query: Arc<dyn SecurityStatusQuery>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    devices: Arc<dyn UserDeviceRepository>,
    approver_keys: Arc<dyn ApproverKeyRepository>,
    ssh_keys: Arc<dyn UserSshKeyRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    clock: Arc<dyn Clock>,
}

/// Bundle of dependencies (passed by name to avoid mixing up too many arguments).
pub struct SecurityStatusDeps {
    pub query: Arc<dyn SecurityStatusQuery>,
    pub sso_sessions: Arc<dyn SsoSessionRepository>,
    pub users: Arc<dyn UserRepository>,
    pub authenticators: Arc<dyn UserAuthenticatorRepository>,
    pub devices: Arc<dyn UserDeviceRepository>,
    pub approver_keys: Arc<dyn ApproverKeyRepository>,
    pub ssh_keys: Arc<dyn UserSshKeyRepository>,
    pub settings: Arc<dyn EffectiveTenantSettings>,
    pub clock: Arc<dyn Clock>,
}

impl SecurityStatusService {
    pub fn new(deps: SecurityStatusDeps) -> Self {
        Self {
            query: deps.query,
            sso_sessions: deps.sso_sessions,
            users: deps.users,
            authenticators: deps.authenticators,
            devices: deps.devices,
            approver_keys: deps.approver_keys,
            ssh_keys: deps.ssh_keys,
            settings: deps.settings,
            clock: deps.clock,
        }
    }

    /// Returns the "status" of the signed-in state's owner. `tenant` is the currently open organization (SSH keys are viewed here).
    pub async fn status(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
    ) -> SecurityStatusOutcome {
        match self.build(tenant, sso_session_id).await {
            Ok(Some(status)) => SecurityStatusOutcome::Ok(Box::new(status)),
            Ok(None) => SecurityStatusOutcome::SessionExpired,
            Err(e) => SecurityStatusOutcome::Internal(e.to_string()),
        }
    }

    async fn build(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
    ) -> Result<Option<SecurityStatus>, DomainError> {
        let now = self.clock.now();
        let current_hash = crypto::sha256_hex(sso_session_id);
        let Some(current) = self.sso_sessions.find_by_hash(&current_hash).await? else {
            return Ok(None);
        };
        if !current.is_valid_at(now) {
            return Ok(None);
        }
        let Some(user) = self.users.find_by_id(current.user_id).await? else {
            return Ok(None);
        };
        if !user.is_active() {
            return Ok(None);
        }

        let lifetime = self.settings.sso_session_lifetime(user.tenant_id).await?;
        let alerts = self
            .settings
            .unregistered_device_alerts_enabled(user.tenant_id)
            .await?;
        let ssh_enabled = self.settings.ssh_keys_enabled(tenant.tenant_id()).await?;
        let policy = PolicyStatus {
            unregistered_device_alerts: alerts,
            ssh_keys_enabled: ssh_enabled,
            idle_ttl_secs: lifetime.idle.num_seconds(),
            absolute_ttl_secs: lifetime.absolute.num_seconds(),
            bound_ttl_secs: lifetime.bound.num_seconds(),
            device_expiry_days: UNUSED_DEVICE_EXPIRY_DAYS,
        };

        // Signed-in states (expired ones are dropped without waiting for GC). The current one first, then newest first.
        let mut contexts: HashMap<String, SessionContextStatus> = self
            .query
            .session_contexts(user.id)
            .await?
            .into_iter()
            .map(|c| (c.session_hash.clone(), c))
            .collect();
        let mut sessions: Vec<SessionStatus> = self
            .sso_sessions
            .list_for_user(user.id)
            .await?
            .into_iter()
            .filter(|s| s.is_valid_at(now))
            .map(|s| {
                let context = contexts.remove(&s.session_hash).unwrap_or_default();
                session_status(
                    &s,
                    context,
                    &current_hash,
                    lifetime.absolute,
                    lifetime.bound,
                    now,
                )
            })
            .collect();
        sessions.sort_by(|a, b| {
            b.current
                .cmp(&a.current)
                .then(b.created_at.cmp(&a.created_at))
        });

        let belongings = self.belongings(&tenant, user.id, ssh_enabled, now).await?;
        let apps = self
            .query
            .app_tokens(user.id, now, now - Duration::days(RECENT_APP_DAYS))
            .await?;
        let warnings = self
            .query
            .warnings(user.id, now - Duration::days(WARNING_WINDOW_DAYS))
            .await?;

        Ok(Some(SecurityStatus {
            sessions,
            belongings,
            apps,
            policy,
            warnings,
        }))
    }

    async fn belongings(
        &self,
        tenant: &TenantContext,
        user_id: uuid::Uuid,
        ssh_enabled: bool,
        now: DateTime<Utc>,
    ) -> Result<Vec<Belonging>, DomainError> {
        let mut list = Vec::new();
        for a in self.authenticators.list_for_user(user_id).await? {
            if a.status != AuthenticatorStatus::Active {
                continue;
            }
            let kind = match a.authenticator_type {
                AuthenticatorType::WebAuthn => BelongingKind::Passkey,
                AuthenticatorType::Totp => BelongingKind::Totp,
                _ => continue,
            };
            list.push(Belonging {
                kind,
                name: a.label,
                detail: None,
                registered_at: a.confirmed_at.unwrap_or(a.created_at),
                last_used_at: a.last_used_at,
                expires_at: None,
            });
        }
        for k in self.approver_keys.list_for_user(user_id).await? {
            list.push(Belonging {
                kind: BelongingKind::ApproverKey,
                name: k.device_name,
                detail: Some(k.security_level.as_str().to_string()),
                registered_at: k.registered_at,
                last_used_at: k.last_used_at,
                expires_at: None,
            });
        }
        let expiry = Duration::days(UNUSED_DEVICE_EXPIRY_DAYS);
        for d in self.devices.list_for_user(user_id).await? {
            // Devices past their expiry are dropped without waiting for the sweep (do not show them as "still trusted").
            if d.last_used_at + expiry <= now {
                continue;
            }
            list.push(Belonging {
                kind: BelongingKind::Device,
                name: d.name,
                detail: d.user_agent,
                registered_at: d.registered_at,
                last_used_at: Some(d.last_used_at),
                expires_at: Some(d.last_used_at + expiry),
            });
        }
        if ssh_enabled {
            for k in self
                .ssh_keys
                .list_for_user(tenant.tenant_id(), user_id)
                .await?
            {
                list.push(Belonging {
                    kind: BelongingKind::SshKey,
                    name: k.name,
                    detail: Some(k.key.key_type().as_str().to_string()),
                    registered_at: k.created_at,
                    last_used_at: None,
                    expires_at: None,
                });
            }
        }
        Ok(list)
    }
}

/// Builds the status of one signed-in state (the part that does not touch the DB; split out for testability).
fn session_status(
    s: &SsoSession,
    context: SessionContextStatus,
    current_hash: &str,
    absolute_ttl: Duration,
    bound_ttl: Duration,
    now: DateTime<Utc>,
) -> SessionStatus {
    let binding = binding_of(&context);
    let basis = lifetime_basis(
        binding,
        context.registered_device.is_some(),
        absolute_ttl,
        bound_ttl,
    );
    SessionStatus {
        id: s.display_id(),
        current: s.session_hash == current_hash,
        auth_time: s.auth_time,
        created_at: s.created_at,
        expires_at: s.idle_expires_at.min(s.absolute_expires_at),
        methods: s.authentication_methods.clone(),
        multi_factor: s.authentication_strength == AuthenticationStrength::MultiFactor,
        user_agent: s.user_agent.clone(),
        ip_address: s.ip_address.clone(),
        country: context.country,
        device_identified: context.device_identified,
        registered_device: context.registered_device,
        key: context.key,
        approver: context.approver,
        binding,
        lifetime_basis: basis,
        passkey_fresh_until: passkey_fresh_until(s, context.passkey_verified_at, now),
    }
}

/// Kind of binding. Authenticator app approval is decided at establishment, and DBSC binds afterwards. If both, approval wins
/// (because approval decided the lifetime at establishment).
fn binding_of(context: &SessionContextStatus) -> SessionBinding {
    if context.approver.is_some() {
        SessionBinding::AppApproval
    } else if context.key.is_some() {
        SessionBinding::DeviceKey
    } else {
        SessionBinding::Unbound
    }
}

/// Deadline while passkey verification is fresh (same basis as `user_device::passkey_verified_recently`).
fn passkey_fresh_until(
    s: &SsoSession,
    passkey_verified_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let max_age = Duration::seconds(REGISTRATION_PASSKEY_MAX_AGE_SECS);
    let signed_in = s
        .used_method(AuthenticationMethod::WebAuthn)
        .then_some(s.auth_time);
    let latest = match (signed_in, passkey_verified_at) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }?;
    let until = latest + max_age;
    (until > now).then_some(until)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn session(methods: Vec<AuthenticationMethod>, created: DateTime<Utc>) -> SsoSession {
        SsoSession::establish(
            "hash-a".to_string(),
            Uuid::nil(),
            created,
            Duration::hours(8),
            Duration::days(7),
            methods,
            Some("Mozilla/5.0 (Windows NT 10.0) Chrome/140".to_string()),
            Some("203.0.113.5".to_string()),
        )
    }

    fn at(h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 5, h, m, 0).unwrap()
    }

    fn device() -> RegisteredDeviceStatus {
        RegisteredDeviceStatus {
            name: "家の PC".to_string(),
            registered_at: at(0, 0),
            last_used_at: at(0, 0),
        }
    }

    fn key() -> SessionKeyStatus {
        SessionKeyStatus {
            algorithm: "ES256".to_string(),
            thumbprint: "abc".to_string(),
            bound_at: at(1, 0),
            refreshed_at: None,
        }
    }

    #[test]
    fn a_bound_session_on_a_registered_device_says_why_it_is_long() {
        let s = session(vec![AuthenticationMethod::WebAuthn], at(1, 0));
        let status = session_status(
            &s,
            SessionContextStatus {
                session_hash: "hash-a".to_string(),
                device_identified: true,
                registered_device: Some(device()),
                key: Some(key()),
                ..Default::default()
            },
            "hash-a",
            Duration::days(7),
            Duration::days(30),
            at(1, 2),
        );
        assert!(status.current);
        assert_eq!(status.binding, SessionBinding::DeviceKey);
        assert_eq!(
            status.lifetime_basis,
            LifetimeBasis::BoundOnRegisteredDevice
        );
        // Signed in with a passkey 2 minutes ago -> 3 minutes left.
        assert_eq!(status.passkey_fresh_until, Some(at(1, 5)));
    }

    #[test]
    fn a_session_with_nothing_is_unbound_and_short() {
        let s = session(vec![AuthenticationMethod::Password], at(1, 0));
        let status = session_status(
            &s,
            SessionContextStatus::default(),
            "other",
            Duration::days(7),
            Duration::days(30),
            at(1, 2),
        );
        assert!(!status.current);
        assert!(!status.device_identified);
        assert_eq!(status.binding, SessionBinding::Unbound);
        assert_eq!(status.lifetime_basis, LifetimeBasis::Unbound);
        assert_eq!(status.passkey_fresh_until, None);
    }

    #[test]
    fn a_bound_session_on_an_unregistered_device_says_so() {
        let s = session(vec![AuthenticationMethod::Password], at(1, 0));
        let status = session_status(
            &s,
            SessionContextStatus {
                device_identified: true,
                key: Some(key()),
                ..Default::default()
            },
            "hash-a",
            Duration::days(7),
            Duration::days(30),
            at(1, 2),
        );
        assert_eq!(
            status.lifetime_basis,
            LifetimeBasis::BoundOnUnregisteredDevice
        );
    }

    #[test]
    fn an_approved_session_is_long_even_if_also_bound() {
        let s = session(vec![AuthenticationMethod::AppApproval], at(1, 0));
        let status = session_status(
            &s,
            SessionContextStatus {
                key: Some(key()),
                approver: Some(ApproverStatus {
                    device_name: "Pixel 9".to_string(),
                    security_level: "strongbox".to_string(),
                }),
                ..Default::default()
            },
            "hash-a",
            Duration::days(7),
            Duration::days(30),
            at(1, 2),
        );
        assert_eq!(status.binding, SessionBinding::AppApproval);
        assert_eq!(status.lifetime_basis, LifetimeBasis::AppApproval);
    }

    #[test]
    fn a_passkey_check_after_sign_in_counts_and_old_ones_do_not() {
        let s = session(vec![AuthenticationMethod::Password], at(1, 0));
        assert_eq!(
            passkey_fresh_until(&s, Some(at(2, 0)), at(2, 1)),
            Some(at(2, 5))
        );
        assert_eq!(passkey_fresh_until(&s, Some(at(2, 0)), at(2, 6)), None);
        assert_eq!(passkey_fresh_until(&s, None, at(1, 1)), None);
    }
}
