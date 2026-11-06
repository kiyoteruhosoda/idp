//! 登録した端末からだけログインを終わらせる（task #916。ADR-0079）。
//!
//! # 流れ
//!
//! 1. **関門**（[`DeviceGate::admit`]）: どのログインの経路も、利用者を確かめた後に SSO セッションを作る前に
//!    ここを通る。利用者の所属元テナントの `REGISTERED_DEVICE_REQUIRED` が有効で、今のブラウザの端末の印が
//!    その人の登録済みの端末でなければ、**SSO セッションを作らず**、10 分だけの「登録の札」を返す。
//!    認証アプリで承認したログイン（ADR-0077）は通す（承認した鍵がパスキーで登録した端末の鍵なので）。
//! 2. **登録**（[`DeviceEnrollmentService`]）: 札を持つブラウザで、札の利用者のパスキーで確かめると、
//!    そのブラウザを端末として登録し、そこで初めて SSO セッションを作る。
//!
//! # 札
//!
//! 札は DB に置かない署名付きの値（`CSRF_SECRET` から用途で分けた鍵の HMAC）。中身は要求のテナント・
//! 利用者・端末の印の指紋・確かめた方式・期限。**札だけでは何もできない**（登録にはその人のパスキーが
//! 要る）ので、使い切りにはしない。端末の印の指紋を入れるので、別のブラウザへ持ち出しても使えない。
//!
//! # 家の中か外か
//!
//! 見分けない（持ち主の決定 11/06「家の中も外と同じ扱い」）。ネットワークの場所は判定に使わない。

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

/// 登録の札の有効期間（秒）。
pub const ENROLLMENT_TICKET_TTL_SECS: i64 = 600;

/// 札の署名の用途の印（他の HMAC と鍵を分ける）。
const TICKET_PURPOSE: &str = "assay-device-enrollment-v1";

/// 関門に渡すログインの試み。
pub struct AdmissionAttempt<'a> {
    /// 認証したテナント（フローのテナント。札と監査の宛先）。
    pub tenant_id: TenantId,
    pub user_id: Uuid,
    /// 利用者の所属元テナント（設定はこちらで決まる）。
    pub home_tenant_id: TenantId,
    /// 確かめた方式。
    pub methods: &'a [AuthenticationMethod],
    pub client_id: Option<&'a str>,
    /// 認証アプリで承認したログインか（通す）。
    pub app_approved: bool,
}

/// 関門の結論。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// SSO セッションを作ってよい。
    Admitted,
    /// 作らない。このブラウザを登録すれば続けられる（`ticket` は web が Cookie に置く平文）。
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

    /// SSO セッションを作ってよいかを決める。
    ///
    /// ⚠ 設定を読めない・端末を引けないときはエラーを返す（ログインは成立しない側へ倒す）。
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

    /// 札を確かめる（署名・期限・テナント・**今のブラウザの印と同じか**）。
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

    /// この組織で「有効にすると入れなくなる人」（登録した端末も認証アプリの鍵も無い、有効な人）の名前。
    pub async fn members_without_trusted_device(
        &self,
        tenant_id: TenantId,
    ) -> Result<Vec<String>, DomainError> {
        self.devices
            .home_members_without_trusted_device(tenant_id)
            .await
    }
}

/// 札の中身。
#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrollmentTicket {
    tenant_id: TenantId,
    user_id: Uuid,
    /// 端末の印の SHA-256（印が無かったときは空。空の札では登録できない）。
    device: String,
    methods: Vec<AuthenticationMethod>,
    /// 期限（UNIX 秒）。
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

/// 知らせる（登録した端末に限る組織では、設定の `UNREGISTERED_DEVICE_ALERTS_ENABLED` に関わらず送る）。
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

/// 札の画面に出すもの。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentView {
    /// だれのログインか（画面で「〇〇さんとして続けます」と見せる）。
    pub username: String,
}

#[derive(Debug)]
pub enum DescribeEnrollmentOutcome {
    Ok(EnrollmentView),
    /// 札が無い・期限切れ・別のブラウザ（ログインからやり直す）。
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
    /// 登録して SSO セッションを作った。
    Enrolled(EstablishedSso),
    TicketInvalid,
    /// パスキーが通らない・札の利用者のパスキーではない。
    PasskeyRejected,
    InvalidName,
    /// アカウントが使えない（無効・ロック等）。
    AccountUnavailable,
    Internal(String),
}

/// 札を持つブラウザを、パスキーで確かめて端末として登録する。
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

    /// パスキーの確かめを始める（本人確認の種別のチャレンジ。ログインには使えない）。
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

    /// パスキーで確かめ、端末を登録して SSO セッションを作る。
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
        // ⚠ 札の利用者のパスキーでなければ通さない（他人のパスキーで自分の札を登録させない）。
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
            // 登録した直後なので通るはず。通らなければ（印が途中で変わった等）札からやり直させる。
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
