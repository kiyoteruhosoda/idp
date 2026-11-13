//! The user's device list, and alerts for logins from unregistered devices (task #872. ADR-0071).
//!
//! # Flow
//!
//! 1. **Login**: all five login paths end with web setting the SSO session cookie. web attaches the device marker
//!    (cookie) to that response and calls [`DeviceRegistryService::observe_sign_in`]. This binds the device to the
//!    session, checks whether it is registered, and if not, records it in the audit log and sends an alert.
//! 2. **Registration**: the user calls [`DeviceRegistryService::register`] from "Devices" in "Account security".
//!    Allowed only **within 5 minutes after verifying the person with a passkey** (password confirmation doesn't count).
//! 3. **Revocation**: [`DeviceRegistryService::revoke`]. Also ends the login state created on that device.
//! 4. **Expiry**: devices unused for 180 days are removed by [`DeviceRegistryService::purge_unused`].
//!
//! Alerts ([`SecurityAlertSink`]) are sent only when `UNREGISTERED_DEVICE_ALERTS_ENABLED` of the user's home tenant
//! is enabled. The audit log records it regardless.
//!
//! # Don't block the login
//!
//! Whether binding, checking or alerting fails, the login has already succeeded (web has returned its response).
//! There is no way to refuse here, and it shouldn't. Failures are returned as errors and web logs them.

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{
    RefreshTokenRepository, SsoSessionRepository, UserDeviceRepository, UserRepository,
};
use crate::domain::security_alert::{SecurityAlert, SecurityAlertKind, SecurityAlertSink};
use crate::domain::sso_session::{self, SsoSession};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::user_device::{
    normalize_device_name, passkey_verified_recently, unused_device_cutoff, CountryCode, DeviceRef,
    UserDevice, OBSERVATION_WINDOW_SECS,
};
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// Request to bind a login (from web).
pub struct ObserveSignIn<'a> {
    /// Value of the SSO session cookie web just set (plaintext).
    pub sso_session_id: &'a str,
    /// Device marker (cookie value). `None` if it didn't arrive.
    pub device_token: Option<&'a str>,
    /// `CF-IPCountry` (only values web judged trustworthy).
    pub country: Option<&'a str>,
}

/// Result of binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveOutcome {
    /// It was a registered device.
    Registered,
    /// It was an unregistered device (recorded in the audit log and alerted if enabled).
    Unregistered,
    /// Did nothing (no session, stale, or already bound).
    Ignored,
}

/// What is shown in the "Devices" section.
#[derive(Debug, Clone)]
pub struct DeviceOverview {
    /// Registration of the browser being used now (`None` if not registered).
    pub current_device_id: Option<Uuid>,
    /// Whether the current browser has a device marker (without one it can't be registered).
    pub current_device_identified: bool,
    /// Whether the passkey identity verification is still valid (if so, "register this device" can be pressed directly).
    pub passkey_fresh: bool,
    pub devices: Vec<UserDevice>,
    /// Whether alerts for "unregistered devices" are enabled in this organization (to vary guidance on screen).
    pub alerts_enabled: bool,
}

#[derive(Debug)]
pub enum DeviceOverviewOutcome {
    Ok(Box<DeviceOverview>),
    SessionExpired,
    Internal(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterDeviceOutcome {
    Registered,
    /// More than 5 minutes since verifying with a passkey (or never verified with a passkey).
    PasskeyRequired,
    /// This browser is already registered.
    AlreadyRegistered,
    /// Name empty, too long, or containing control characters.
    InvalidName,
    /// This browser has no device marker (doesn't accept cookies, etc.).
    DeviceUnidentified,
    SessionExpired,
    Internal(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeDeviceOutcome {
    /// Revoked (ended `sessions` login states created on that device).
    Revoked {
        sessions: usize,
    },
    NotFound,
    SessionExpired,
    Internal(String),
}

pub struct DeviceRegistryService {
    devices: Arc<dyn UserDeviceRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    alerts: Arc<dyn SecurityAlertSink>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

/// The current authenticated session and user.
struct ActiveSession {
    session: SsoSession,
    user: User,
}

impl DeviceRegistryService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        devices: Arc<dyn UserDeviceRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        alerts: Arc<dyn SecurityAlertSink>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            devices,
            sso_sessions,
            users,
            refresh_tokens,
            settings,
            alerts,
            audit,
            clock,
        }
    }

    pub fn tenant_context(tenant_id: TenantId) -> TenantContext {
        TenantContext::new(tenant_id)
    }

    /// Binds the device to a session that just logged in and checks whether it is registered.
    pub async fn observe_sign_in(
        &self,
        cmd: ObserveSignIn<'_>,
        ctx: &RequestContext,
    ) -> Result<ObserveOutcome, DomainError> {
        let now = self.clock.now();
        let session_hash = crypto::sha256_hex(cmd.sso_session_id);
        let Some(session) = self.sso_sessions.find_by_hash(&session_hash).await? else {
            return Ok(ObserveOutcome::Ignored);
        };
        // Only handle sessions that were just created (don't let a device be bound to an old session afterwards).
        if !session.is_valid_at(now)
            || now - session.created_at > Duration::seconds(OBSERVATION_WINDOW_SECS)
        {
            return Ok(ObserveOutcome::Ignored);
        }
        let Some(user) = self.users.find_by_id(session.user_id).await? else {
            return Ok(ObserveOutcome::Ignored);
        };
        let country = cmd.country.and_then(CountryCode::parse);
        let device = cmd.device_token.and_then(DeviceRef::from_token);

        let registered = match &device {
            Some(device) => {
                if !self
                    .devices
                    .link_session(&session_hash, device, country.as_ref(), now)
                    .await?
                {
                    // Already bound (a duplicate request for the same login). Don't alert twice.
                    return Ok(ObserveOutcome::Ignored);
                }
                self.devices.find(user.id, device).await?
            }
            None => None,
        };

        if let Some(registered) = registered {
            self.devices
                .touch(
                    registered.id,
                    now,
                    country.as_ref(),
                    ctx.ip_address.as_deref(),
                )
                .await?;
            return Ok(ObserveOutcome::Registered);
        }

        let first_seen = match &device {
            Some(device) => {
                !self
                    .devices
                    .seen_before(user.id, device, &session_hash)
                    .await?
            }
            None => true,
        };
        self.audit
            .record(
                AuditEventType::UnregisteredDeviceSignIn,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some(&format!(
                    "first_seen={first_seen} device_cookie={} country={}",
                    device.is_some(),
                    country.as_ref().map(CountryCode::as_str).unwrap_or("-")
                )),
                ctx,
            )
            .await;
        self.alert(
            &user,
            SecurityAlertKind::UnregisteredDeviceSignIn {
                first_seen,
                methods: session.authentication_methods.clone(),
            },
            now,
            country,
            ctx,
            device.as_ref(),
        )
        .await;
        Ok(ObserveOutcome::Unregistered)
    }

    /// Contents of the "Devices" section.
    pub async fn overview(
        &self,
        sso_session_id: &str,
        device_token: Option<&str>,
    ) -> DeviceOverviewOutcome {
        let now = self.clock.now();
        let active = match self.active_session(sso_session_id, now).await {
            Ok(Some(active)) => active,
            Ok(None) => return DeviceOverviewOutcome::SessionExpired,
            Err(e) => return DeviceOverviewOutcome::Internal(e),
        };
        let devices = match self.devices.list_for_user(active.user.id).await {
            Ok(rows) => rows,
            Err(e) => return DeviceOverviewOutcome::Internal(e.to_string()),
        };
        let current = device_token.and_then(DeviceRef::from_token);
        let current_device_id = current
            .as_ref()
            .and_then(|c| devices.iter().find(|d| &d.device == c))
            .map(|d| d.id);
        let passkey_fresh = match self.passkey_is_fresh(&active.session, now).await {
            Ok(fresh) => fresh,
            Err(e) => return DeviceOverviewOutcome::Internal(e.to_string()),
        };
        let alerts_enabled = match self
            .settings
            .unregistered_device_alerts_enabled(active.user.tenant_id)
            .await
        {
            Ok(enabled) => enabled,
            Err(e) => return DeviceOverviewOutcome::Internal(e.to_string()),
        };
        DeviceOverviewOutcome::Ok(Box::new(DeviceOverview {
            current_device_id,
            current_device_identified: current.is_some(),
            passkey_fresh,
            devices,
            alerts_enabled,
        }))
    }

    /// Registers the current browser as a device.
    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        device_token: Option<&str>,
        name: &str,
        country: Option<&str>,
        ctx: &RequestContext,
    ) -> RegisterDeviceOutcome {
        let now = self.clock.now();
        let active = match self.active_session(sso_session_id, now).await {
            Ok(Some(active)) => active,
            Ok(None) => return RegisterDeviceOutcome::SessionExpired,
            Err(e) => return RegisterDeviceOutcome::Internal(e),
        };
        let Some(device) = device_token.and_then(DeviceRef::from_token) else {
            return RegisterDeviceOutcome::DeviceUnidentified;
        };
        let Some(name) = normalize_device_name(name) else {
            return RegisterDeviceOutcome::InvalidName;
        };
        match self.passkey_is_fresh(&active.session, now).await {
            Ok(true) => {}
            Ok(false) => return RegisterDeviceOutcome::PasskeyRequired,
            Err(e) => return RegisterDeviceOutcome::Internal(e.to_string()),
        }
        let country = country.and_then(CountryCode::parse);
        let registered = UserDevice::register(
            Uuid::now_v7(),
            active.user.id,
            device.clone(),
            name.clone(),
            ctx.user_agent.clone(),
            country.clone(),
            ctx.ip_address.clone(),
            now,
        );
        match self.devices.insert(&registered).await {
            Ok(()) => {}
            Err(DomainError::Conflict(_)) => return RegisterDeviceOutcome::AlreadyRegistered,
            Err(e) => return RegisterDeviceOutcome::Internal(e.to_string()),
        }
        self.audit
            .record(
                AuditEventType::DeviceRegistered,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(active.user.id),
                None,
                Some(&format!("device_id={}", registered.id)),
                ctx,
            )
            .await;
        self.alert(
            &active.user,
            SecurityAlertKind::DeviceRegistered { device_name: name },
            now,
            country,
            ctx,
            Some(&device),
        )
        .await;
        RegisterDeviceOutcome::Registered
    }

    /// Revokes a device registration and ends the login states created on that device.
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        device_id: Uuid,
        ctx: &RequestContext,
    ) -> RevokeDeviceOutcome {
        let now = self.clock.now();
        let active = match self.active_session(sso_session_id, now).await {
            Ok(Some(active)) => active,
            Ok(None) => return RevokeDeviceOutcome::SessionExpired,
            Err(e) => return RevokeDeviceOutcome::Internal(e),
        };
        let removed = match self.devices.delete(active.user.id, device_id).await {
            Ok(Some(device)) => device,
            Ok(None) => return RevokeDeviceOutcome::NotFound,
            Err(e) => return RevokeDeviceOutcome::Internal(e.to_string()),
        };
        let sessions = match self
            .end_device_sessions(&active, &removed.device, now)
            .await
        {
            Ok(count) => count,
            Err(e) => return RevokeDeviceOutcome::Internal(e.to_string()),
        };
        self.audit
            .record(
                AuditEventType::DeviceRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(active.user.id),
                None,
                Some(&format!("device_id={} sessions={sessions}", removed.id)),
                ctx,
            )
            .await;
        self.alert(
            &active.user,
            SecurityAlertKind::DeviceRevoked {
                device_name: removed.name.clone(),
            },
            now,
            None,
            ctx,
            Some(&removed.device),
        )
        .await;
        RevokeDeviceOutcome::Revoked { sessions }
    }

    /// Deletes registrations of devices unused for 180 days. Returns the number deleted.
    pub async fn purge_unused(&self) -> Result<usize, DomainError> {
        let now = self.clock.now();
        let expired = self
            .devices
            .delete_unused_before(unused_device_cutoff(now))
            .await?;
        let ctx = RequestContext {
            correlation_id: format!("device-expiry-{}", now.timestamp()),
            ip_address: None,
            user_agent: None,
        };
        for device in &expired {
            let Some(user) = self.users.find_by_id(device.user_id).await? else {
                continue;
            };
            self.audit
                .record(
                    AuditEventType::DeviceExpired,
                    AuditResult::Success,
                    Some(user.tenant_id),
                    Some(user.id),
                    None,
                    Some(&format!("device_id={}", device.id)),
                    &ctx,
                )
                .await;
            self.alert(
                &user,
                SecurityAlertKind::DeviceExpired {
                    device_name: device.name.clone(),
                },
                now,
                None,
                &ctx,
                Some(&device.device),
            )
            .await;
        }
        Ok(expired.len())
    }

    /// Ends the current user's login states created on that device (excluding the session being viewed now).
    async fn end_device_sessions(
        &self,
        active: &ActiveSession,
        device: &DeviceRef,
        now: DateTime<Utc>,
    ) -> Result<usize, DomainError> {
        let hashes = self
            .devices
            .sessions_for_device(active.user.id, device)
            .await?;
        let mut ended = 0;
        for hash in hashes {
            // Keep the current screen's session (don't kick the user off right after revoking their own device;
            // from then on that session is treated as "an unregistered device").
            if hash == active.session.session_hash {
                continue;
            }
            self.sso_sessions.delete(&hash).await?;
            // Also drop refresh tokens issued from those sessions (ADR-0044; deleting only the session rows would
            // let apps keep refreshing).
            self.refresh_tokens
                .revoke_all_for_session(active.user.id, &sso_session::sid_of(&hash), now)
                .await?;
            ended += 1;
        }
        Ok(ended)
    }

    /// Whether within 5 minutes after verifying with a passkey (right after a passkey login or passkey step-up).
    async fn passkey_is_fresh(
        &self,
        session: &SsoSession,
        now: DateTime<Utc>,
    ) -> Result<bool, DomainError> {
        let verified_at = self
            .sso_sessions
            .passkey_verified_at(&session.session_hash)
            .await?;
        Ok(passkey_verified_recently(session, verified_at, now))
    }

    async fn active_session(
        &self,
        sso_session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ActiveSession>, String> {
        let hash = crypto::sha256_hex(sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        match self.users.find_by_id(session.user_id).await {
            Ok(Some(user)) if user.is_active() => Ok(Some(ActiveSession { session, user })),
            Ok(_) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Sends an alert (when alerts are enabled in the home tenant, or the organization is limited to registered devices. task #916).
    /// If the setting can't be read, falls to the side of alerting.
    async fn alert(
        &self,
        user: &User,
        kind: SecurityAlertKind,
        now: DateTime<Utc>,
        country: Option<CountryCode>,
        ctx: &RequestContext,
        device: Option<&DeviceRef>,
    ) {
        let alerts = self
            .settings
            .unregistered_device_alerts_enabled(user.tenant_id)
            .await;
        let required = self
            .settings
            .registered_device_required(user.tenant_id)
            .await;
        let enabled = match (alerts, required) {
            (Ok(alerts), Ok(required)) => Ok(alerts || required),
            (Err(e), _) | (_, Err(e)) => Err(e),
        };
        let enabled = match enabled {
            Ok(enabled) => enabled,
            Err(e) => {
                tracing::warn!(error = %e, "device alert setting could not be read; sending anyway");
                true
            }
        };
        if !enabled {
            return;
        }
        let username = user
            .preferred_username
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| format!("利用者 {}", &user.sub.simple().to_string()[..8]));
        self.alerts
            .send(SecurityAlert {
                kind,
                tenant_id: user.tenant_id,
                user_id: user.id,
                username,
                occurred_at: now,
                country,
                ip_address: ctx.ip_address.clone(),
                user_agent: ctx.user_agent.clone(),
                group_key: device
                    .map(|d| d.as_str()[..16].to_string())
                    .unwrap_or_else(|| "no-device-cookie".to_string()),
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::tenant_settings::testing::{audit, tenant_settings, CapturingSink};
    use crate::domain::error::Result as DomainResult;
    use crate::domain::refresh_token::RefreshToken;
    use crate::domain::values::{AuthenticationMethod, UserStatus};
    use async_trait::async_trait;
    use chrono::TimeZone;
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 4, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    fn tenant_id() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0001))
    }

    fn user_id() -> Uuid {
        Uuid::from_u128(42)
    }

    const COOKIE: &str = "sso-cookie";

    fn token(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    fn session(
        raw: &str,
        methods: Vec<AuthenticationMethod>,
        created: DateTime<Utc>,
    ) -> SsoSession {
        SsoSession::establish(
            crypto::sha256_hex(raw),
            user_id(),
            created,
            Duration::hours(8),
            Duration::hours(24),
            methods,
            Some("Mozilla/5.0".to_string()),
            Some("203.0.113.10".to_string()),
        )
    }

    #[derive(Default)]
    struct FakeSessions {
        rows: Mutex<Vec<SsoSession>>,
        passkey_at: Mutex<Option<DateTime<Utc>>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSessions {
        async fn create(&self, s: &SsoSession) -> DomainResult<()> {
            self.rows.lock().unwrap().push(s.clone());
            Ok(())
        }
        async fn find_by_hash(&self, hash: &str) -> DomainResult<Option<SsoSession>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.session_hash == hash)
                .cloned())
        }
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn passkey_verified_at(&self, _h: &str) -> DomainResult<Option<DateTime<Utc>>> {
            Ok(*self.passkey_at.lock().unwrap())
        }
        async fn delete(&self, hash: &str) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|s| s.session_hash != hash);
            Ok(())
        }
        async fn delete_all_for_user(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeDevices {
        rows: Mutex<Vec<UserDevice>>,
        /// session_hash -> device
        links: Mutex<Vec<(String, DeviceRef)>>,
    }
    #[async_trait]
    impl UserDeviceRepository for FakeDevices {
        async fn home_members_without_trusted_device(
            &self,
            _tenant_id: TenantId,
        ) -> DomainResult<Vec<String>> {
            Ok(Vec::new())
        }
        async fn find(&self, u: Uuid, d: &DeviceRef) -> DomainResult<Option<UserDevice>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.user_id == u && &r.device == d)
                .cloned())
        }
        async fn list_for_user(&self, u: Uuid) -> DomainResult<Vec<UserDevice>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.user_id == u)
                .cloned()
                .collect())
        }
        async fn insert(&self, d: &UserDevice) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if rows
                .iter()
                .any(|r| r.user_id == d.user_id && r.device == d.device)
            {
                return Err(DomainError::Conflict("dup".into()));
            }
            rows.push(d.clone());
            Ok(())
        }
        async fn delete(&self, u: Uuid, id: Uuid) -> DomainResult<Option<UserDevice>> {
            let mut rows = self.rows.lock().unwrap();
            let found = rows.iter().position(|r| r.user_id == u && r.id == id);
            Ok(found.map(|i| rows.remove(i)))
        }
        async fn touch(
            &self,
            id: Uuid,
            at: DateTime<Utc>,
            country: Option<&CountryCode>,
            _ip: Option<&str>,
        ) -> DomainResult<()> {
            for r in self.rows.lock().unwrap().iter_mut().filter(|r| r.id == id) {
                r.last_used_at = at;
                r.last_country = country.cloned();
            }
            Ok(())
        }
        async fn delete_unused_before(
            &self,
            cutoff: DateTime<Utc>,
        ) -> DomainResult<Vec<UserDevice>> {
            let mut rows = self.rows.lock().unwrap();
            let (gone, kept): (Vec<_>, Vec<_>) =
                rows.drain(..).partition(|r| r.last_used_at < cutoff);
            *rows = kept;
            Ok(gone)
        }
        async fn link_session(
            &self,
            hash: &str,
            d: &DeviceRef,
            _c: Option<&CountryCode>,
            _at: DateTime<Utc>,
        ) -> DomainResult<bool> {
            let mut links = self.links.lock().unwrap();
            if links.iter().any(|(h, _)| h == hash) {
                return Ok(false);
            }
            links.push((hash.to_string(), d.clone()));
            Ok(true)
        }
        async fn session_device(&self, hash: &str) -> DomainResult<Option<DeviceRef>> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .iter()
                .find(|(h, _)| h == hash)
                .map(|(_, d)| d.clone()))
        }
        async fn seen_before(&self, _u: Uuid, d: &DeviceRef, except: &str) -> DomainResult<bool> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .iter()
                .any(|(h, x)| x == d && h != except))
        }
        async fn sessions_for_device(&self, _u: Uuid, d: &DeviceRef) -> DomainResult<Vec<String>> {
            Ok(self
                .links
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, x)| x == d)
                .map(|(h, _)| h.clone())
                .collect())
        }
    }

    struct FakeUsers;
    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: DateTime<Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(Some(User {
                id,
                tenant_id: tenant_id(),
                sub: Uuid::from_u128(7),
                email: "user@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("kyon".to_string()),
                name: None,
                language: None,
                theme: None,
                password_hash: String::new(),
                must_change_password: false,
                password_changed_at: None,
                status: UserStatus::Active,
                pending_setup: false,
                failed_login_count: 0,
                locked_until: None,
                created_at: now(),
                updated_at: now(),
            }))
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(&self, _t: TenantId, _n: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _c: i32,
            _l: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_password(&self, _id: Uuid, _e: &str, _p: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(&self, _id: Uuid, _e: &str, _p: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _s: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _l: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeRefreshTokens {
        revoked_sessions: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl RefreshTokenRepository for FakeRefreshTokens {
        async fn revoke_family(
            &self,
            _t: TenantId,
            _f: &str,
            _a: DateTime<Utc>,
        ) -> DomainResult<u64> {
            unreachable!()
        }
        async fn create(&self, _t: &RefreshToken) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, _t: TenantId, _h: &str) -> DomainResult<Option<RefreshToken>> {
            unreachable!()
        }
        async fn revoke(&self, _h: &str, _a: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn exists_by_parent_hash(&self, _h: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn revoke_all_for_user(&self, _u: Uuid, _a: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn count_active_for_user(&self, _u: Uuid, _n: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn revoke_all_for_session(
            &self,
            _u: Uuid,
            sid: &str,
            _a: DateTime<Utc>,
        ) -> DomainResult<u64> {
            self.revoked_sessions.lock().unwrap().push(sid.to_string());
            Ok(1)
        }
        async fn revoke_all_for_user_in_tenant(
            &self,
            _t: TenantId,
            _u: Uuid,
            _a: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke_all_for_user_and_client(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
            _a: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct CapturingAlerts {
        sent: Mutex<Vec<SecurityAlert>>,
    }
    #[async_trait]
    impl SecurityAlertSink for CapturingAlerts {
        async fn send(&self, alert: SecurityAlert) {
            self.sent.lock().unwrap().push(alert);
        }
    }

    struct Harness {
        service: DeviceRegistryService,
        sessions: Arc<FakeSessions>,
        devices: Arc<FakeDevices>,
        refresh: Arc<FakeRefreshTokens>,
        alerts: Arc<CapturingAlerts>,
        audit_events: Arc<CapturingSink>,
    }

    fn harness(alerts_enabled: bool) -> Harness {
        let settings = tenant_settings();
        if alerts_enabled {
            settings.set_tenant(tenant_id(), "UNREGISTERED_DEVICE_ALERTS_ENABLED", "true");
        }
        let sessions = Arc::new(FakeSessions::default());
        let devices = Arc::new(FakeDevices::default());
        let refresh = Arc::new(FakeRefreshTokens::default());
        let alerts = Arc::new(CapturingAlerts::default());
        let audit_events = Arc::new(CapturingSink::default());
        let service = DeviceRegistryService::new(
            devices.clone(),
            sessions.clone(),
            Arc::new(FakeUsers),
            refresh.clone(),
            settings.service.clone(),
            alerts.clone(),
            audit(audit_events.clone()),
            Arc::new(FixedClock),
        );
        Harness {
            service,
            sessions,
            devices,
            refresh,
            alerts,
            audit_events,
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "c".to_string(),
            ip_address: Some("203.0.113.10".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        }
    }

    fn events(h: &Harness) -> Vec<AuditEventType> {
        h.audit_events
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type)
            .collect()
    }

    fn registered(h: &Harness, c: char, name: &str) -> UserDevice {
        let d = UserDevice::register(
            Uuid::now_v7(),
            user_id(),
            DeviceRef::from_token(&token(c)).unwrap(),
            name.to_string(),
            None,
            None,
            None,
            now() - Duration::days(1),
        );
        h.devices.rows.lock().unwrap().push(d.clone());
        d
    }

    async fn sign_in(h: &Harness, raw: &str, device: Option<&str>) -> ObserveOutcome {
        h.sessions.rows.lock().unwrap().push(session(
            raw,
            vec![AuthenticationMethod::Password],
            now(),
        ));
        h.service
            .observe_sign_in(
                ObserveSignIn {
                    sso_session_id: raw,
                    device_token: device,
                    country: Some("jp"),
                },
                &ctx(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_registered_device_signs_in_quietly() {
        let h = harness(true);
        registered(&h, 'a', "kyon-pc");
        assert_eq!(
            sign_in(&h, COOKIE, Some(&token('a'))).await,
            ObserveOutcome::Registered
        );
        assert!(h.alerts.sent.lock().unwrap().is_empty());
        assert!(!events(&h).contains(&AuditEventType::UnregisteredDeviceSignIn));
        let row = h.devices.rows.lock().unwrap()[0].clone();
        assert_eq!(row.last_used_at, now());
        assert_eq!(row.last_country.unwrap().as_str(), "JP");
    }

    #[tokio::test]
    async fn an_unregistered_device_is_recorded_and_alerted() {
        let h = harness(true);
        registered(&h, 'a', "kyon-pc");
        assert_eq!(
            sign_in(&h, COOKIE, Some(&token('b'))).await,
            ObserveOutcome::Unregistered
        );
        assert!(events(&h).contains(&AuditEventType::UnregisteredDeviceSignIn));
        let sent = h.alerts.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].username, "kyon");
        assert_eq!(sent[0].country.as_ref().unwrap().as_str(), "JP");
        assert!(matches!(
            sent[0].kind,
            SecurityAlertKind::UnregisteredDeviceSignIn {
                first_seen: true,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn the_same_unregistered_device_is_no_longer_first_seen() {
        let h = harness(true);
        sign_in(&h, "first", Some(&token('b'))).await;
        sign_in(&h, "second", Some(&token('b'))).await;
        let sent = h.alerts.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "every sign-in from it is reported");
        assert!(matches!(
            sent[1].kind,
            SecurityAlertKind::UnregisteredDeviceSignIn {
                first_seen: false,
                ..
            }
        ));
        assert_eq!(sent[0].group_key, sent[1].group_key);
    }

    #[tokio::test]
    async fn a_missing_device_cookie_counts_as_unregistered() {
        let h = harness(true);
        assert_eq!(
            sign_in(&h, COOKIE, None).await,
            ObserveOutcome::Unregistered
        );
        assert_eq!(h.alerts.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn alerts_are_off_unless_the_tenant_enables_them_but_audit_still_records() {
        let h = harness(false);
        assert_eq!(
            sign_in(&h, COOKIE, Some(&token('b'))).await,
            ObserveOutcome::Unregistered
        );
        assert!(h.alerts.sent.lock().unwrap().is_empty());
        assert!(events(&h).contains(&AuditEventType::UnregisteredDeviceSignIn));
    }

    #[tokio::test]
    async fn an_old_session_cannot_be_linked_afterwards() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().push(session(
            COOKIE,
            vec![AuthenticationMethod::Password],
            now() - Duration::minutes(10),
        ));
        let outcome = h
            .service
            .observe_sign_in(
                ObserveSignIn {
                    sso_session_id: COOKIE,
                    device_token: Some(&token('b')),
                    country: None,
                },
                &ctx(),
            )
            .await
            .unwrap();
        assert_eq!(outcome, ObserveOutcome::Ignored);
        assert!(h.alerts.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_same_sign_in_is_reported_once() {
        let h = harness(true);
        sign_in(&h, COOKIE, Some(&token('b'))).await;
        let again = h
            .service
            .observe_sign_in(
                ObserveSignIn {
                    sso_session_id: COOKIE,
                    device_token: Some(&token('c')),
                    country: None,
                },
                &ctx(),
            )
            .await
            .unwrap();
        assert_eq!(again, ObserveOutcome::Ignored);
        assert_eq!(h.alerts.sent.lock().unwrap().len(), 1);
    }

    async fn register(h: &Harness, name: &str) -> RegisterDeviceOutcome {
        h.service
            .register(
                DeviceRegistryService::tenant_context(tenant_id()),
                COOKIE,
                Some(&token('a')),
                name,
                Some("JP"),
                &ctx(),
            )
            .await
    }

    #[tokio::test]
    async fn registering_needs_a_fresh_passkey() {
        let h = harness(true);
        // Just signed in with a password: not verified with a passkey, so refused.
        h.sessions.rows.lock().unwrap().push(session(
            COOKIE,
            vec![AuthenticationMethod::Password],
            now(),
        ));
        assert_eq!(
            register(&h, "pc").await,
            RegisterDeviceOutcome::PasskeyRequired
        );

        // 6 minutes after a passkey step-up: too old, so refused.
        *h.sessions.passkey_at.lock().unwrap() = Some(now() - Duration::minutes(6));
        assert_eq!(
            register(&h, "pc").await,
            RegisterDeviceOutcome::PasskeyRequired
        );

        // 4 minutes ago: passes.
        *h.sessions.passkey_at.lock().unwrap() = Some(now() - Duration::minutes(4));
        assert_eq!(
            register(&h, " pc ").await,
            RegisterDeviceOutcome::Registered
        );
        let rows = h.devices.rows.lock().unwrap().clone();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "pc");
        assert!(events(&h).contains(&AuditEventType::DeviceRegistered));
        assert!(matches!(
            h.alerts.sent.lock().unwrap()[0].kind,
            SecurityAlertKind::DeviceRegistered { .. }
        ));
    }

    #[tokio::test]
    async fn signing_in_with_a_passkey_just_now_is_enough() {
        let h = harness(false);
        h.sessions.rows.lock().unwrap().push(session(
            COOKIE,
            vec![AuthenticationMethod::WebAuthn],
            now(),
        ));
        assert_eq!(register(&h, "pc").await, RegisterDeviceOutcome::Registered);
        assert_eq!(
            register(&h, "pc").await,
            RegisterDeviceOutcome::AlreadyRegistered
        );
    }

    #[tokio::test]
    async fn a_passkey_sign_in_from_long_ago_is_not_enough() {
        let h = harness(false);
        h.sessions.rows.lock().unwrap().push(session(
            COOKIE,
            vec![AuthenticationMethod::WebAuthn],
            now() - Duration::minutes(30),
        ));
        assert_eq!(
            register(&h, "pc").await,
            RegisterDeviceOutcome::PasskeyRequired
        );
    }

    #[tokio::test]
    async fn registering_needs_a_name_and_a_device_cookie() {
        let h = harness(false);
        h.sessions.rows.lock().unwrap().push(session(
            COOKIE,
            vec![AuthenticationMethod::WebAuthn],
            now(),
        ));
        assert_eq!(register(&h, "  ").await, RegisterDeviceOutcome::InvalidName);
        let outcome = h
            .service
            .register(
                DeviceRegistryService::tenant_context(tenant_id()),
                COOKIE,
                None,
                "pc",
                None,
                &ctx(),
            )
            .await;
        assert_eq!(outcome, RegisterDeviceOutcome::DeviceUnidentified);
    }

    #[tokio::test]
    async fn revoking_ends_that_devices_sessions_but_not_the_current_one() {
        let h = harness(true);
        let phone = registered(&h, 'b', "phone");
        // Session of the current screen (PC).
        h.sessions.rows.lock().unwrap().push(session(
            COOKIE,
            vec![AuthenticationMethod::WebAuthn],
            now(),
        ));
        // Session created on a phone.
        sign_in(&h, "phone-session", Some(&token('b'))).await;
        let outcome = h
            .service
            .revoke(
                DeviceRegistryService::tenant_context(tenant_id()),
                COOKIE,
                phone.id,
                &ctx(),
            )
            .await;
        assert_eq!(outcome, RevokeDeviceOutcome::Revoked { sessions: 1 });
        assert!(h.devices.rows.lock().unwrap().is_empty());
        let remaining: Vec<String> = h
            .sessions
            .rows
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.session_hash.clone())
            .collect();
        assert_eq!(remaining, vec![crypto::sha256_hex(COOKIE)]);
        assert_eq!(h.refresh.revoked_sessions.lock().unwrap().len(), 1);
        assert!(events(&h).contains(&AuditEventType::DeviceRevoked));

        // The next login from the revoked device alerts again.
        h.alerts.sent.lock().unwrap().clear();
        assert_eq!(
            sign_in(&h, "phone-again", Some(&token('b'))).await,
            ObserveOutcome::Unregistered
        );
        assert_eq!(h.alerts.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn revoking_someone_elses_device_is_not_found() {
        let h = harness(false);
        h.sessions.rows.lock().unwrap().push(session(
            COOKIE,
            vec![AuthenticationMethod::WebAuthn],
            now(),
        ));
        let outcome = h
            .service
            .revoke(
                DeviceRegistryService::tenant_context(tenant_id()),
                COOKIE,
                Uuid::now_v7(),
                &ctx(),
            )
            .await;
        assert_eq!(outcome, RevokeDeviceOutcome::NotFound);
    }

    #[tokio::test]
    async fn devices_unused_for_180_days_expire_and_are_recorded() {
        let h = harness(true);
        let old = registered(&h, 'a', "old-pc");
        h.devices.rows.lock().unwrap()[0].last_used_at = now() - Duration::days(181);
        registered(&h, 'b', "phone");
        assert_eq!(h.service.purge_unused().await.unwrap(), 1);
        let rows = h.devices.rows.lock().unwrap().clone();
        assert_eq!(rows.len(), 1);
        assert_ne!(rows[0].id, old.id);
        assert!(events(&h).contains(&AuditEventType::DeviceExpired));
        assert!(matches!(
            h.alerts.sent.lock().unwrap()[0].kind,
            SecurityAlertKind::DeviceExpired { .. }
        ));
    }

    #[tokio::test]
    async fn the_overview_marks_the_current_device() {
        let h = harness(true);
        let pc = registered(&h, 'a', "kyon-pc");
        h.sessions.rows.lock().unwrap().push(session(
            COOKIE,
            vec![AuthenticationMethod::Password],
            now(),
        ));
        let DeviceOverviewOutcome::Ok(view) = h.service.overview(COOKIE, Some(&token('a'))).await
        else {
            panic!("expected an overview");
        };
        assert_eq!(view.current_device_id, Some(pc.id));
        assert!(view.current_device_identified);
        assert!(!view.passkey_fresh);
        assert!(view.alerts_enabled);
        assert_eq!(view.devices.len(), 1);
    }
}
