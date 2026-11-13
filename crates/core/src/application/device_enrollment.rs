//! Complete logins only from registered devices (task #916. ADR-0079).
//!
//! # Flow
//!
//! 1. **Gate** ([`DeviceGate::admit`]): every login path passes here after verifying the user and before creating
//!    the SSO session. If `REGISTERED_DEVICE_REQUIRED` of the user's home tenant is enabled and the current browser's
//!    device marker is not one of that person's registered devices, **no SSO session is created** and a 10-minute
//!    "enrollment ticket" is returned. Logins approved in the authenticator app (ADR-0077) pass (the approving key is the key of a device registered with a passkey).
//! 2. **Enrollment** ([`DeviceEnrollmentService`]): in the browser holding the ticket, verifying with the ticket user's passkey
//!    registers that browser as a device, and only then is the SSO session created.
//!
//! # Ticket
//!
//! The ticket is a signed value not stored in the DB (HMAC with a purpose-specific key derived from `CSRF_SECRET`). It contains
//! the requested tenant, the user, the fingerprint of the device marker, the verified methods and the expiry. **The ticket alone
//! can do nothing** (enrollment needs that person's passkey), so it is not single-use. It includes the device marker's fingerprint, so it cannot be used if taken to another browser.
//!
//! # Inside or outside the home
//!
//! Not distinguished (owner's decision 11/06: "treat inside the home the same as outside"). Network location is not used in the decision.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::passkey_assertion::{
    PasskeyAssertionError, PasskeyAssertionService, PasskeyFlow,
};
use crate::application::sign_in_completion::{
    EstablishedSso, Establishment, SignIn, SignInCompletion,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{UserDeviceRepository, UserRepository};
use crate::domain::security_alert::{SecurityAlert, SecurityAlertKind, SecurityAlertSink};
use crate::domain::sign_in_history::RequestCountry;
use crate::domain::tenant::TenantId;
use crate::domain::user::User;
use crate::domain::user_device::{
    normalize_device_name, CountryCode, DeviceRef, RequestDevice, UserDevice,
};
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Lifetime of the enrollment ticket (seconds).
pub const ENROLLMENT_TICKET_TTL_SECS: i64 = 600;

/// Purpose label for the ticket signature (separates the key from other HMACs).
const TICKET_PURPOSE: &str = "assay-device-enrollment-v1";

/// A login attempt passed to the gate.
pub struct AdmissionAttempt<'a> {
    /// The authenticated tenant (the flow's tenant; destination of the ticket and audit).
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    /// The user's home tenant (the setting is decided here).
    pub home_tenant_id: TenantId,
    /// Verified methods.
    pub methods: &'a [AuthenticationMethod],
    pub client_id: Option<&'a str>,
    /// Whether the login was approved in the authenticator app (passes).
    pub app_approved: bool,
}

/// The gate's conclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The SSO session may be created.
    Admitted,
    /// Not created. Continuing is possible by registering this browser (`ticket` is plaintext that web puts in a cookie).
    EnrollmentRequired { ticket: String },
}

pub struct DeviceGate {
    devices: Arc<dyn UserDeviceRepository>,
    users: Arc<dyn UserRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    request_device: Arc<dyn RequestDevice>,
    request_country: Arc<dyn RequestCountry>,
    alerts: Arc<dyn SecurityAlertSink>,
    audit: Arc<AuditService>,
    ticket_key: [u8; 32],
}

impl DeviceGate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        devices: Arc<dyn UserDeviceRepository>,
        users: Arc<dyn UserRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        request_device: Arc<dyn RequestDevice>,
        request_country: Arc<dyn RequestCountry>,
        alerts: Arc<dyn SecurityAlertSink>,
        audit: Arc<AuditService>,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            devices,
            users,
            settings,
            request_device,
            request_country,
            alerts,
            audit,
            ticket_key: derive_ticket_key(&csrf_secret),
        }
    }

    /// Decides whether the SSO session may be created.
    ///
    /// ⚠ Returns an error when the setting cannot be read or devices cannot be looked up (falls to the side where login does not succeed).
    pub async fn admit(
        &self,
        attempt: AdmissionAttempt<'_>,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<Admission, DomainError> {
        if attempt.app_approved {
            return Ok(Admission::Admitted);
        }
        if !self
            .settings
            .registered_device_required(attempt.home_tenant_id)
            .await?
        {
            return Ok(Admission::Admitted);
        }
        let device = self.request_device.current();
        if let Some(device) = &device {
            if self.devices.find(attempt.user_id, device).await?.is_some() {
                return Ok(Admission::Admitted);
            }
        }

        self.audit
            .record(
                AuditEventType::UnregisteredDeviceRefused,
                AuditResult::Failure,
                Some(attempt.tenant_id),
                Some(attempt.user_id),
                attempt.client_id,
                Some(&format!(
                    "methods={} device_cookie={}",
                    method_codes(attempt.methods),
                    device.is_some()
                )),
                ctx,
            )
            .await;
        if let Some(user) = self.users.find_by_id(attempt.user_id).await? {
            send_alert(
                self.alerts.as_ref(),
                &user,
                SecurityAlertKind::UnregisteredDeviceRefused {
                    methods: attempt.methods.to_vec(),
                },
                now,
                self.request_country.current(),
                ctx,
                device.as_ref(),
            )
            .await;
        }
        let ticket = EnrollmentTicket {
            tenant_id: attempt.tenant_id,
            user_id: attempt.user_id,
            device: device.map(|d| d.as_str().to_string()).unwrap_or_default(),
            methods: attempt.methods.to_vec(),
            expires_at: now.timestamp() + ENROLLMENT_TICKET_TTL_SECS,
        };
        Ok(Admission::EnrollmentRequired {
            ticket: ticket.sign(&self.ticket_key),
        })
    }

    /// Verifies the ticket (signature, expiry, tenant, and **whether it matches the current browser's marker**).
    fn open_ticket(
        &self,
        tenant_id: TenantId,
        raw: &str,
        now: DateTime<Utc>,
    ) -> Option<EnrollmentTicket> {
        let ticket = EnrollmentTicket::verify(&self.ticket_key, raw, now.timestamp())?;
        if ticket.tenant_id != tenant_id || ticket.device.is_empty() {
            return None;
        }
        let current = self.request_device.current()?;
        (current.as_str() == ticket.device).then_some(ticket)
    }

    /// Names of the people in this organization who "would be locked out if enabled" (active, with neither a registered device nor an authenticator app key).
    pub async fn members_without_trusted_device(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<String>, DomainError> {
        self.devices
            .home_members_without_trusted_device(tenant_id)
            .await
    }
}

/// Contents of the ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrollmentTicket {
    tenant_id: TenantId,
    user_id: Uuid,
    /// SHA-256 of the device marker (empty when there was no marker; an empty ticket cannot enroll).
    device: String,
    methods: Vec<AuthenticationMethod>,
    /// Expiry (UNIX seconds).
    expires_at: i64,
}

impl EnrollmentTicket {
    fn payload(&self) -> String {
        format!(
            "{}.{}.{}.{}.{}",
            self.tenant_id.as_uuid(),
            self.user_id,
            if self.device.is_empty() {
                "-"
            } else {
                &self.device
            },
            method_codes(&self.methods),
            self.expires_at
        )
    }

    fn sign(&self, key: &[u8; 32]) -> String {
        let payload = self.payload();
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        format!("{payload}.{}", hex::encode(mac.finalize().into_bytes()))
    }

    fn verify(key: &[u8; 32], raw: &str, now_ts: i64) -> Option<Self> {
        if raw.len() > 512 {
            return None;
        }
        let (payload, sig) = raw.rsplit_once('.')?;
        let sig = hex::decode(sig).ok()?;
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        mac.verify_slice(&sig).ok()?;
        let mut parts = payload.split('.');
        let tenant = Uuid::parse_str(parts.next()?).ok()?;
        let user_id = Uuid::parse_str(parts.next()?).ok()?;
        let device = parts.next()?;
        let methods = parts.next()?;
        let expires_at: i64 = parts.next()?.parse().ok()?;
        if parts.next().is_some() || now_ts > expires_at {
            return None;
        }
        let methods = if methods == "-" {
            Vec::new()
        } else {
            methods
                .split('+')
                .map(AuthenticationMethod::parse)
                .collect::<Result<Vec<_>, _>>()
                .ok()?
        };
        Some(Self {
            tenant_id: TenantId::from(tenant),
            user_id,
            device: if device == "-" {
                String::new()
            } else {
                device.to_string()
            },
            methods,
            expires_at,
        })
    }
}

fn derive_ticket_key(csrf_secret: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(csrf_secret).expect("HMAC accepts any key length");
    mac.update(TICKET_PURPOSE.as_bytes());
    mac.finalize().into_bytes().into()
}

fn method_codes(methods: &[AuthenticationMethod]) -> String {
    if methods.is_empty() {
        return "-".to_string();
    }
    methods
        .iter()
        .map(AuthenticationMethod::as_str)
        .collect::<Vec<_>>()
        .join("+")
}

/// Sends an alert (in organizations limited to registered devices, sent regardless of the `UNREGISTERED_DEVICE_ALERTS_ENABLED` setting).
async fn send_alert(
    alerts: &dyn SecurityAlertSink,
    user: &User,
    kind: SecurityAlertKind,
    now: DateTime<Utc>,
    country: Option<CountryCode>,
    ctx: &RequestContext,
    device: Option<&DeviceRef>,
) {
    let username = user
        .preferred_username
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("利用者 {}", &user.sub.simple().to_string()[..8]));
    alerts
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

/// What is shown on the ticket screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentView {
    /// Whose login it is (the screen shows "continue as <name>").
    pub username: String,
}

#[derive(Debug)]
pub enum DescribeEnrollmentOutcome {
    Ok(EnrollmentView),
    /// No ticket, expired, or another browser (start over from login).
    TicketInvalid,
    Internal(String),
}

#[derive(Debug)]
pub enum BeginEnrollmentOutcome {
    Ok {
        challenge_id: Uuid,
        options: serde_json::Value,
    },
    TicketInvalid,
    Internal(String),
}

pub struct CompleteEnrollment<'a> {
    pub ticket: &'a str,
    pub challenge_id: Uuid,
    pub credential: serde_json::Value,
    pub device_name: &'a str,
}

pub enum CompleteEnrollmentOutcome {
    /// Enrolled and created the SSO session.
    Enrolled(EstablishedSso),
    TicketInvalid,
    /// The passkey failed, or it is not the ticket user's passkey.
    PasskeyRejected,
    InvalidName,
    /// The account cannot be used (disabled, locked, etc.).
    AccountUnavailable,
    Internal(String),
}

/// Verifies the browser holding the ticket with a passkey and registers it as a device.
pub struct DeviceEnrollmentService {
    gate: Arc<DeviceGate>,
    devices: Arc<dyn UserDeviceRepository>,
    users: Arc<dyn UserRepository>,
    passkey_assertion: Arc<PasskeyAssertionService>,
    sign_in: Arc<SignInCompletion>,
    alerts: Arc<dyn SecurityAlertSink>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl DeviceEnrollmentService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gate: Arc<DeviceGate>,
        devices: Arc<dyn UserDeviceRepository>,
        users: Arc<dyn UserRepository>,
        passkey_assertion: Arc<PasskeyAssertionService>,
        sign_in: Arc<SignInCompletion>,
        alerts: Arc<dyn SecurityAlertSink>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            gate,
            devices,
            users,
            passkey_assertion,
            sign_in,
            alerts,
            audit,
            clock,
        }
    }

    async fn active_user(&self, user_id: Uuid) -> Result<Option<User>, DomainError> {
        Ok(self
            .users
            .find_by_id(user_id)
            .await?
            .filter(User::is_active))
    }

    pub async fn describe(&self, tenant_id: TenantId, ticket: &str) -> DescribeEnrollmentOutcome {
        let now = self.clock.now();
        let Some(ticket) = self.gate.open_ticket(tenant_id, ticket, now) else {
            return DescribeEnrollmentOutcome::TicketInvalid;
        };
        match self.active_user(ticket.user_id).await {
            Ok(Some(user)) => DescribeEnrollmentOutcome::Ok(EnrollmentView {
                username: user.preferred_username.unwrap_or_default(),
            }),
            Ok(None) => DescribeEnrollmentOutcome::TicketInvalid,
            Err(e) => DescribeEnrollmentOutcome::Internal(e.to_string()),
        }
    }

    /// Starts passkey verification (a challenge of the identity-verification kind; cannot be used for login).
    pub async fn begin(&self, tenant_id: TenantId, ticket: &str) -> BeginEnrollmentOutcome {
        let now = self.clock.now();
        if self.gate.open_ticket(tenant_id, ticket, now).is_none() {
            return BeginEnrollmentOutcome::TicketInvalid;
        }
        match self.passkey_assertion.begin_step_up().await {
            Ok((challenge_id, options)) => BeginEnrollmentOutcome::Ok {
                challenge_id,
                options,
            },
            Err(e) => BeginEnrollmentOutcome::Internal(e),
        }
    }

    /// Verifies with the passkey, registers the device and creates the SSO session.
    pub async fn complete(
        &self,
        tenant_id: TenantId,
        cmd: CompleteEnrollment<'_>,
        ctx: &RequestContext,
    ) -> CompleteEnrollmentOutcome {
        let now = self.clock.now();
        let Some(ticket) = self.gate.open_ticket(tenant_id, cmd.ticket, now) else {
            return CompleteEnrollmentOutcome::TicketInvalid;
        };
        let Some(name) = normalize_device_name(cmd.device_name) else {
            return CompleteEnrollmentOutcome::InvalidName;
        };
        let verified = match self
            .passkey_assertion
            .verify(
                tenant_id,
                cmd.challenge_id,
                cmd.credential,
                PasskeyFlow::StepUp,
                ctx,
            )
            .await
        {
            Ok(v) => v,
            Err(PasskeyAssertionError::Internal(e)) => {
                return CompleteEnrollmentOutcome::Internal(e)
            }
            Err(_) => return CompleteEnrollmentOutcome::PasskeyRejected,
        };
        // ⚠ Only the ticket user's passkey passes (don't let someone's passkey enroll your ticket).
        if verified.user_id != ticket.user_id {
            return CompleteEnrollmentOutcome::PasskeyRejected;
        }
        let user = match self.active_user(ticket.user_id).await {
            Ok(Some(user)) => user,
            Ok(None) => return CompleteEnrollmentOutcome::AccountUnavailable,
            Err(e) => return CompleteEnrollmentOutcome::Internal(e.to_string()),
        };
        let device = DeviceRef::from_hash(ticket.device.clone());
        let device_id = match self.devices.find(user.id, &device).await {
            Ok(Some(existing)) => existing.id,
            Ok(None) => {
                let registered = UserDevice::register(
                    Uuid::now_v7(),
                    user.id,
                    device.clone(),
                    name.clone(),
                    ctx.user_agent.clone(),
                    self.gate.request_country.current(),
                    ctx.ip_address.clone(),
                    now,
                );
                match self.devices.insert(&registered).await {
                    Ok(()) | Err(DomainError::Conflict(_)) => {}
                    Err(e) => return CompleteEnrollmentOutcome::Internal(e.to_string()),
                }
                self.audit
                    .record(
                        AuditEventType::DeviceRegistered,
                        AuditResult::Success,
                        Some(user.tenant_id),
                        Some(user.id),
                        None,
                        Some(&format!("device_id={} via=sign_in", registered.id)),
                        ctx,
                    )
                    .await;
                send_alert(
                    self.alerts.as_ref(),
                    &user,
                    SecurityAlertKind::DeviceRegistered { device_name: name },
                    now,
                    self.gate.request_country.current(),
                    ctx,
                    Some(&device),
                )
                .await;
                registered.id
            }
            Err(e) => return CompleteEnrollmentOutcome::Internal(e.to_string()),
        };
        tracing::info!(%device_id, "device enrolled during sign-in");

        let mut methods = ticket.methods.clone();
        if !methods.contains(&AuthenticationMethod::WebAuthn) {
            methods.push(AuthenticationMethod::WebAuthn);
        }
        match self
            .sign_in
            .establish_sso(
                SignIn {
                    tenant_id,
                    user_id: user.id,
                    home_tenant_id: user.tenant_id,
                    methods,
                    client_id: None,
                    success_event: AuditEventType::LoginSucceeded,
                    success_detail: Some("device_enrolled".to_string()),
                },
                ctx,
                now,
            )
            .await
        {
            Ok(Establishment::Established(sso)) => CompleteEnrollmentOutcome::Enrolled(sso),
            // Just enrolled, so this should pass. If not (the marker changed midway, etc.), make them start over from the ticket.
            Ok(Establishment::DeviceEnrollmentRequired { .. }) => {
                CompleteEnrollmentOutcome::TicketInvalid
            }
            Err(e) => CompleteEnrollmentOutcome::Internal(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        derive_ticket_key(&[7u8; 32])
    }

    fn ticket() -> EnrollmentTicket {
        EnrollmentTicket {
            tenant_id: TenantId::from(Uuid::from_u128(1)),
            user_id: Uuid::from_u128(2),
            device: "ab".repeat(32),
            methods: vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            expires_at: 1_000,
        }
    }

    #[test]
    fn a_signed_ticket_opens_with_the_same_contents() {
        let signed = ticket().sign(&key());
        assert_eq!(
            EnrollmentTicket::verify(&key(), &signed, 999),
            Some(ticket())
        );
    }

    #[test]
    fn an_expired_ticket_does_not_open() {
        let signed = ticket().sign(&key());
        assert_eq!(EnrollmentTicket::verify(&key(), &signed, 1_001), None);
    }

    #[test]
    fn a_ticket_with_a_changed_user_or_device_does_not_open() {
        let signed = ticket().sign(&key());
        let other_user = signed.replacen(
            &Uuid::from_u128(2).to_string(),
            &Uuid::from_u128(3).to_string(),
            1,
        );
        assert_eq!(EnrollmentTicket::verify(&key(), &other_user, 999), None);
        let other_device = signed.replacen(&"ab".repeat(32), &"cd".repeat(32), 1);
        assert_eq!(EnrollmentTicket::verify(&key(), &other_device, 999), None);
    }

    #[test]
    fn a_ticket_signed_with_another_key_does_not_open() {
        let signed = ticket().sign(&derive_ticket_key(&[8u8; 32]));
        assert_eq!(EnrollmentTicket::verify(&key(), &signed, 999), None);
    }

    #[test]
    fn a_ticket_without_a_device_round_trips_as_empty() {
        let mut t = ticket();
        t.device = String::new();
        t.methods = Vec::new();
        let signed = t.sign(&key());
        assert_eq!(EnrollmentTicket::verify(&key(), &signed, 0), Some(t));
    }
}
