//! Unified authenticator management use case (AP9. User authentication & authentication policy spec §5).
//!
//! It handles three things:
//!
//! 1. **Listing and state management** — returns "the authenticators this person can use" in one place regardless
//!    of kind, and suspends, resumes and revokes them. Suspension exists to offer an answer other than deletion
//!    for "I lost my device but it may come back".
//! 2. **Recovery codes** — self-help for users who lost all their authenticators. Issued as a set (10 by default),
//!    each used once. The plaintext is only shown at issuance; the DB holds only SHA-256.
//! 3. **email OTP / SMS OTP** — a second factor for users who can't have an authenticator app. A short-lived code is
//!    sent and recorded in the registry as a one-time authenticator. email goes to `users.email` so needs no registration,
//!    but SMS requires the destination phone number to be **registered and confirmed first** (AP13).
//!
//! All of these use the registry (`user_authenticators`) as the single source, so the login side only needs to query
//! the registry instead of branching per kind.

use crate::application::audit::{AuditService, RequestContext};
use crate::application::system_settings::SystemSettingsService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::id_generator::IdGenerator;
use crate::domain::login_identifier::LoginIdentifierType;
use crate::domain::mailer::{Mailer, OutgoingEmail};
use crate::domain::repositories::{UserAuthenticatorRepository, UserRepository};
use crate::domain::sms::{OutgoingSms, SmsSender};
use crate::domain::user_authenticator::{
    AuthenticatorStatus, AuthenticatorType, UserAuthenticator, OTP_SEND_WINDOW_SECS,
};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

/// Number of recovery codes issued at once.
///
/// Too few and they run out mid-recovery; too many and printing/storage gets sloppy (making leaks likelier).
/// We use 10, like typical IdPs.
const RECOVERY_CODE_COUNT: usize = 10;
/// Random bytes per recovery code (80 bits). A compromise between a length people can copy and unguessability.
const RECOVERY_CODE_BYTES: usize = 10;
/// Number of digits in an email OTP code.
const EMAIL_OTP_DIGITS: u32 = 6;
/// Validity period of an email OTP.
const EMAIL_OTP_TTL_SECS: i64 = 600;
/// Number of digits in an SMS OTP code (AP13). Same as email OTP.
const SMS_OTP_DIGITS: u32 = 6;
/// Validity period of an SMS OTP. Shorter than email because SMS stays on the device and is easily forwarded.
const SMS_OTP_TTL_SECS: i64 = 300;
/// Interval before an OTP can be resent (task #749). ⚠ When not sending, the previous code is not revoked, so a delivered code still works.
const OTP_RESEND_INTERVAL_SECS: i64 = 30;
/// OTPs that can be sent to one person per hour (per kind). So someone who knows the password can't push SMS charges or mail at people.
const OTP_SENDS_PER_HOUR: usize = 10;
/// Validity period of the phone number registration confirmation code. Longer than OTP, assuming input may take a while.
const PHONE_CONFIRMATION_TTL_SECS: i64 = 900;

/// One authenticator in the list (no secrets).
#[derive(Debug, Clone)]
pub struct AuthenticatorSummary {
    pub id: Uuid,
    pub authenticator_type: AuthenticatorType,
    pub status: AuthenticatorStatus,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorManagementError {
    #[error("authenticator not found")]
    NotFound,
    #[error("transition is not allowed")]
    InvalidTransition,
    #[error("email delivery is not configured")]
    MailUnavailable,
    /// SMS gateway not configured (AP13). The caller treats it as "SMS unavailable" and falls back to another factor.
    #[error("sms delivery is not configured")]
    SmsUnavailable,
    /// The SMS OTP destination phone number is not registered or not confirmed (AP13).
    #[error("no confirmed phone number is registered")]
    PhoneNotRegistered,
    /// Input that cannot be read as a phone number (AP13).
    #[error("invalid phone number")]
    InvalidPhoneNumber,
    /// OTP resent too soon or too often (task #749). The previous code stays valid.
    #[error("otp was sent too recently or too often")]
    OtpRateLimited,
    #[error("internal error: {0}")]
    Internal(String),
}

/// Whether an OTP may be sent now. Counted from the rows of issued codes (rows with an expiry).
///
/// This can be counted without a new table because code rows are only marked revoked and cleanup doesn't delete
/// them within the window (`OTP_SEND_WINDOW_SECS`). Rows of registered phone numbers have no expiry, so they are not counted.
fn may_send_otp(
    rows: &[UserAuthenticator],
    authenticator_type: AuthenticatorType,
    now: DateTime<Utc>,
) -> bool {
    let sent: Vec<DateTime<Utc>> = rows
        .iter()
        .filter(|r| r.authenticator_type == authenticator_type && r.expires_at.is_some())
        .map(|r| r.created_at)
        .filter(|at| now - *at < Duration::seconds(OTP_SEND_WINDOW_SECS))
        .collect();
    sent.len() < OTP_SENDS_PER_HOUR
        && sent
            .iter()
            .all(|at| now - *at >= Duration::seconds(OTP_RESEND_INTERVAL_SECS))
}

/// Folds repository errors into internal errors (doesn't leak DB details to the caller).
fn internal(e: crate::domain::error::DomainError) -> AuthenticatorManagementError {
    AuthenticatorManagementError::Internal(e.to_string())
}

/// Result of issuing recovery codes. **The plaintext is only available from this return value** (the DB has hashes only).
pub struct IssuedRecoveryCodes {
    pub codes: Vec<String>,
}

pub struct AuthenticatorManagementService {
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    users: Arc<dyn UserRepository>,
    system_settings: Arc<SystemSettingsService>,
    mailer: Arc<dyn Mailer>,
    /// Port for sending SMS (AP13). Gateway connection info is taken from system settings for each send.
    sms: Arc<dyn SmsSender>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl AuthenticatorManagementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        users: Arc<dyn UserRepository>,
        system_settings: Arc<SystemSettingsService>,
        mailer: Arc<dyn Mailer>,
        sms: Arc<dyn SmsSender>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            authenticators,
            users,
            system_settings,
            mailer,
            sms,
            audit,
            clock,
            ids,
        }
    }

    /// Lists the user's authenticators (revoked ones are omitted — listing them on screen allows no action and only adds clutter).
    ///
    /// Recovery codes are one row each, so listing them as-is fills 10 rows. So the caller can fold them into
    /// "n remaining", the per-kind count is fetched separately with [`Self::usable_recovery_code_count`].
    pub async fn list(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AuthenticatorSummary>, AuthenticatorManagementError> {
        let rows = self
            .authenticators
            .list_for_user(user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .filter(|a| a.status != AuthenticatorStatus::Revoked)
            .filter(|a| a.authenticator_type != AuthenticatorType::RecoveryCode)
            // An issued one-time code (a row with both a secret and an expiry) is not an authenticator but
            // **a sent code**. Listing it would add "authenticators that vanish in 10 minutes" to the list,
            // which the user can't act on (while adding SMS OTP in AP13 we found this also happened with
            // email OTP, so it is dropped here together).
            .filter(|a| !(a.secret_encrypted.is_some() && a.expires_at.is_some()))
            .map(|a| AuthenticatorSummary {
                id: a.id,
                authenticator_type: a.authenticator_type,
                status: a.status,
                label: a.label,
                created_at: a.created_at,
                last_used_at: a.last_used_at,
            })
            .collect())
    }

    /// Number of remaining (unused, unrevoked) recovery codes.
    pub async fn usable_recovery_code_count(
        &self,
        user_id: Uuid,
    ) -> Result<usize, AuthenticatorManagementError> {
        let rows = self
            .authenticators
            .list_usable_for_user(
                user_id,
                Some(AuthenticatorType::RecoveryCode),
                self.clock.now(),
            )
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        Ok(rows.len())
    }

    /// Changes the state (suspend, resume, revoke). Whether the transition is allowed is decided by domain rules.
    pub async fn set_status(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        authenticator_id: Uuid,
        next: AuthenticatorStatus,
        ctx: &RequestContext,
    ) -> Result<(), AuthenticatorManagementError> {
        let current = self
            .authenticators
            .find_by_id(authenticator_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?
            .filter(|a| a.user_id == user_id)
            .ok_or(AuthenticatorManagementError::NotFound)?;

        if !current.status.can_transition_to(next) {
            return Err(AuthenticatorManagementError::InvalidTransition);
        }

        let now = self.clock.now();
        let updated = self
            .authenticators
            .update_status(authenticator_id, user_id, next, now)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        if !updated {
            return Err(AuthenticatorManagementError::NotFound);
        }

        self.audit
            .record(
                AuditEventType::AuthenticatorStatusChanged,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                Some(&format!(
                    "type={} status={next}",
                    current.authenticator_type
                )),
                ctx,
            )
            .await;
        Ok(())
    }

    /// (Re)issues recovery codes. **The existing set is always revoked.**
    ///
    /// Issuing a new set while keeping the old one would leave codes that were printed and thrown away valid forever.
    /// Unless "the paper in hand is the only set", the user cannot manage what is valid.
    pub async fn issue_recovery_codes(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<IssuedRecoveryCodes, AuthenticatorManagementError> {
        let now = self.clock.now();
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::RecoveryCode, now)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;

        let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let code = crypto::random_hex(RECOVERY_CODE_BYTES);
            let row = UserAuthenticator {
                id: self.ids.new_id(),
                user_id,
                authenticator_type: AuthenticatorType::RecoveryCode,
                status: AuthenticatorStatus::Active,
                label: String::new(),
                // The plaintext only goes out in the return value. The DB holds hashes only (same as other bearer credentials).
                secret_encrypted: Some(crypto::sha256_hex(&code)),
                target: None,
                confirmed_at: Some(now),
                last_used_at: None,
                // Recovery codes have no expiry (they are used "when everything else failed", so
                // being expired at that point would leave no way in).
                expires_at: None,
                revoked_at: None,
                created_at: now,
                updated_at: now,
            };
            self.authenticators
                .create(&row)
                .await
                .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
            codes.push(code);
        }

        self.audit
            .record(
                AuditEventType::RecoveryCodesIssued,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                Some(&format!("count={RECOVERY_CODE_COUNT}")),
                ctx,
            )
            .await;
        Ok(IssuedRecoveryCodes { codes })
    }

    /// Verifies and consumes a recovery code (one-time). `true` on success.
    pub async fn consume_recovery_code(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        code: &str,
        ctx: &RequestContext,
    ) -> Result<bool, AuthenticatorManagementError> {
        let now = self.clock.now();
        let used = consume_single_use_code(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::RecoveryCode,
            code,
            now,
        )
        .await
        .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        self.audit
            .record(
                AuditEventType::RecoveryCodeUsed,
                if used {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                Some(tenant_id),
                Some(user_id),
                None,
                // Keeping the remaining count lets operations track "how many are left" (the codes themselves are not recorded).
                Some(&format!(
                    "remaining={}",
                    self.remaining_after(user_id).await
                )),
                ctx,
            )
            .await;
        Ok(used)
    }

    /// Issues and sends an email OTP. The destination is the registered email address.
    pub async fn send_email_otp(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), AuthenticatorManagementError> {
        let user = self
            .users
            .find_by_id(user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?
            .ok_or(AuthenticatorManagementError::NotFound)?;

        // Authenticators belong to the user and are managed by the home tenant (ADR-0009). Codes are also
        // sent through the home tenant's channel (ADR-0058 §8). Not decided by the login screen's tenant (guest membership).
        let server = self
            .system_settings
            .smtp_server_for(user.tenant_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?
            .ok_or(AuthenticatorManagementError::MailUnavailable)?;

        let now = self.clock.now();
        self.ensure_may_send_otp(user_id, AuthenticatorType::EmailOtp, now)
            .await?;
        // Always revoke the previous code. With several valid codes at once, brute force success rate multiplies by their number.
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::EmailOtp, now)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;

        let code = numeric_code(EMAIL_OTP_DIGITS);
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::EmailOtp,
            status: AuthenticatorStatus::Active,
            label: String::new(),
            secret_encrypted: Some(crypto::sha256_hex(&code)),
            target: Some(user.email.clone()),
            confirmed_at: Some(now),
            last_used_at: None,
            expires_at: Some(now + Duration::seconds(EMAIL_OTP_TTL_SECS)),
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators
            .create(&row)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;

        // The body is for users, not in the operations language (English), so translation should belong to Presentation,
        // but sending mail must complete in the Application layer (the send result is used in the decision).
        // Same as the existing mail texts (invitation, password reset): built in English here.
        let mail = OutgoingEmail {
            to: user.email.clone(),
            subject: "Your verification code".to_string(),
            body_text: format!(
                "Your verification code is {code}.\n\n\
                 It expires in {} minutes. If you did not request it, you can ignore this email.\n",
                EMAIL_OTP_TTL_SECS / 60
            ),
        };
        self.mailer
            .send(&server, &mail)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;

        self.audit
            .record(
                AuditEventType::EmailOtpSent,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                // The destination address is PII, so it is not recorded.
                None,
                ctx,
            )
            .await;
        Ok(())
    }

    // ── SMS OTP (AP13) ─────────────────────────────────────────────────────
    //
    // Unlike email OTP, SMS requires **the destination to be registered and confirmed first**. `users` has no phone
    // number column, and even if it did, "contact info" and "second-factor destination" are different things (if changing
    // contact info silently changed the second-factor destination, it would be a takeover path). So the registry's
    // (`user_authenticators`) `sms_otp` row itself holds the registered phone number:
    //
    // | row | status | target | secret_encrypted | expires_at |
    // |---|---|---|---|---|
    // | registration awaiting confirmation | pending | phone number | SHA-256 of confirmation code | set (GC deletes it if abandoned) |
    // | confirmed registration | active | phone number | NULL | **NULL** (never deleted) |
    // | issued OTP | active | phone number | SHA-256 of code | set |
    //
    // Dropping the expiry from the confirmed registration is the point; if kept, GC deletes the row and the registration is silently lost.

    /// Starts registering a phone number (sends a confirmation code by SMS). AP13.
    ///
    /// Existing registrations (including confirmed ones) are revoked. One number per user, because with several,
    /// neither the user nor operations could see "which one it was sent to". To change the number,
    /// register again.
    pub async fn start_phone_registration(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        raw_phone: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthenticatorManagementError> {
        // Format checking and normalization use the same rules as login identifier phone numbers (with two checks,
        // "numbers that can be registered but not sent to" would appear).
        let phone = LoginIdentifierType::PhoneNumber
            .normalize_checked(raw_phone)
            .map_err(|_| AuthenticatorManagementError::InvalidPhoneNumber)?;

        let gateway = self.usable_sms_gateway().await?;

        let now = self.clock.now();
        // This is a re-registration, so replace it along with any confirmed registration.
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::SmsOtp, now)
            .await
            .map_err(internal)?;

        let code = numeric_code(SMS_OTP_DIGITS);
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::SmsOtp,
            status: AuthenticatorStatus::Pending,
            label: String::new(),
            secret_encrypted: Some(crypto::sha256_hex(&code)),
            target: Some(phone.clone()),
            confirmed_at: None,
            last_used_at: None,
            expires_at: Some(now + Duration::seconds(PHONE_CONFIRMATION_TTL_SECS)),
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators.create(&row).await.map_err(internal)?;

        self.send_code(&gateway, &phone, &code, PHONE_CONFIRMATION_TTL_SECS)
            .await?;
        self.record_sms_sent(tenant_id, user_id, "phone_confirmation", ctx)
            .await;
        Ok(())
    }

    /// Confirms the phone number registration with the sent confirmation code (AP13). `true` on success.
    pub async fn confirm_phone_registration(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        code: &str,
        ctx: &RequestContext,
    ) -> Result<bool, AuthenticatorManagementError> {
        let normalized = code.trim().replace([' ', '-'], "");
        if normalized.is_empty() {
            return Ok(false);
        }
        let confirmed = self
            .authenticators
            .confirm_pending(
                user_id,
                AuthenticatorType::SmsOtp,
                &crypto::sha256_hex(&normalized),
                self.clock.now(),
            )
            .await
            .map_err(internal)?
            .is_some();

        if confirmed {
            self.audit
                .record(
                    AuditEventType::AuthenticatorStatusChanged,
                    AuditResult::Success,
                    Some(tenant_id),
                    Some(user_id),
                    None,
                    // The phone number is PII, so it is not recorded (only the kind is kept).
                    Some("type=sms_otp status=active"),
                    ctx,
                )
                .await;
        }
        Ok(confirmed)
    }

    /// Whether a registered phone number exists (used by the screen to show "register" vs "registered").
    /// Returns only presence, not the number itself (don't carry PII around more than needed).
    pub async fn has_confirmed_phone(
        &self,
        user_id: Uuid,
    ) -> Result<bool, AuthenticatorManagementError> {
        Ok(self.confirmed_phone(user_id).await?.is_some())
    }

    /// Issues an SMS OTP and sends it to the registered phone number (AP13).
    pub async fn send_sms_otp(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), AuthenticatorManagementError> {
        let gateway = self.usable_sms_gateway().await?;
        let phone = self
            .confirmed_phone(user_id)
            .await?
            .ok_or(AuthenticatorManagementError::PhoneNotRegistered)?;

        let now = self.clock.now();
        self.ensure_may_send_otp(user_id, AuthenticatorType::SmsOtp, now)
            .await?;
        // Revoke only the previous code. `revoke_all_of_type` would also wipe the registered phone number
        // and sending would no longer work afterwards.
        self.authenticators
            .revoke_issued_codes_of_type(user_id, AuthenticatorType::SmsOtp, now)
            .await
            .map_err(internal)?;

        let code = numeric_code(SMS_OTP_DIGITS);
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::SmsOtp,
            status: AuthenticatorStatus::Active,
            label: String::new(),
            secret_encrypted: Some(crypto::sha256_hex(&code)),
            target: Some(phone.clone()),
            confirmed_at: Some(now),
            last_used_at: None,
            expires_at: Some(now + Duration::seconds(SMS_OTP_TTL_SECS)),
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators.create(&row).await.map_err(internal)?;

        self.send_code(&gateway, &phone, &code, SMS_OTP_TTL_SECS)
            .await?;
        self.record_sms_sent(tenant_id, user_id, "sms_otp", ctx)
            .await;
        Ok(())
    }

    /// Verifies and consumes an SMS OTP (one-time). `true` on success.
    pub async fn consume_sms_otp(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, AuthenticatorManagementError> {
        consume_single_use_code(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::SmsOtp,
            code,
            self.clock.now(),
        )
        .await
        .map_err(internal)
    }

    /// Checks the OTP resend interval and count (task #749). ⚠ Call before revoking the previous code.
    async fn ensure_may_send_otp(
        &self,
        user_id: Uuid,
        authenticator_type: AuthenticatorType,
        now: DateTime<Utc>,
    ) -> Result<(), AuthenticatorManagementError> {
        let rows = self
            .authenticators
            .list_for_user(user_id)
            .await
            .map_err(internal)?;
        if may_send_otp(&rows, authenticator_type, now) {
            Ok(())
        } else {
            Err(AuthenticatorManagementError::OtpRateLimited)
        }
    }

    /// SMS gateway settings usable for sending. `SmsUnavailable` if not configured.
    async fn usable_sms_gateway(
        &self,
    ) -> Result<crate::domain::sms::SmsGatewayConfig, AuthenticatorManagementError> {
        self.system_settings
            .sms_gateway()
            .await
            .map_err(internal)?
            .filter(|g| g.is_usable())
            .ok_or(AuthenticatorManagementError::SmsUnavailable)
    }

    /// Extracts the phone number from the confirmed registration (`active` with no expiry).
    async fn confirmed_phone(
        &self,
        user_id: Uuid,
    ) -> Result<Option<String>, AuthenticatorManagementError> {
        let rows = self
            .authenticators
            .list_usable_for_user(user_id, Some(AuthenticatorType::SmsOtp), self.clock.now())
            .await
            .map_err(internal)?;
        // Rows of issued codes have the same kind, so only look at **rows without an expiry** (= the registration).
        Ok(rows
            .into_iter()
            .find(|r| r.expires_at.is_none())
            .and_then(|r| r.target))
    }

    /// Builds and sends the code body. The body is for users, but like email OTP it is in English
    /// (sending must complete in the Application layer, and there is no translation hook here).
    async fn send_code(
        &self,
        gateway: &crate::domain::sms::SmsGatewayConfig,
        phone: &str,
        code: &str,
        ttl_secs: i64,
    ) -> Result<(), AuthenticatorManagementError> {
        let sms = OutgoingSms {
            to: phone.to_string(),
            body_text: format!(
                "Your verification code is {code}. It expires in {} minutes.",
                ttl_secs / 60
            ),
        };
        self.sms.send(gateway, &sms).await.map_err(internal)
    }

    /// Audit of the send. **Neither the phone number nor the code is recorded** (only the purpose is kept).
    async fn record_sms_sent(
        &self,
        tenant_id: crate::domain::tenant::TenantId,
        user_id: Uuid,
        purpose: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::SmsOtpSent,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                Some(&format!("purpose={purpose}")),
                ctx,
            )
            .await;
    }

    /// Verifies and consumes an email OTP (one-time). `true` on success.
    pub async fn consume_email_otp(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, AuthenticatorManagementError> {
        consume_single_use_code(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::EmailOtp,
            code,
            self.clock.now(),
        )
        .await
        .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    // ── Registry sync (TOTP, WebAuthn) ──────────────────────────────────────
    //
    // The secrets still live in the old tables (expand phase), so every registration/deletion mirrors the same
    // event into the registry. If this is missed, the registry becomes "a list including authenticators that can't
    // actually be used", trustworthy neither as a list nor as what the authentication policy refers to.

    /// Records a provisional TOTP registration in the registry (revokes existing TOTP rows to keep just one).
    pub async fn register_totp_pending(
        &self,
        user_id: Uuid,
    ) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::Totp, now)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::Totp,
            status: AuthenticatorStatus::Pending,
            label: String::new(),
            // The shared key is put onto this row right after by `TotpSecretRepository::upsert` (AP11b;
            // that's why the row is created first —— in the reverse order there'd be nowhere to put it).
            secret_encrypted: None,
            target: None,
            confirmed_at: None,
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators
            .create(&row)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// Reflects TOTP confirmation in the registry (`pending` -> `active`).
    pub async fn activate_totp(&self, user_id: Uuid) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        let rows = self
            .authenticators
            .list_for_user(user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        let Some(pending) = rows.into_iter().find(|a| {
            a.authenticator_type == AuthenticatorType::Totp
                && a.status == AuthenticatorStatus::Pending
        }) else {
            // No provisional row from before the registry was introduced. Recreate it as a confirmed row.
            return self.create_active_totp(user_id, now).await;
        };
        self.authenticators
            .update_status(pending.id, user_id, AuthenticatorStatus::Active, now)
            .await
            .map(|_| ())
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// Reflects TOTP deletion in the registry.
    pub async fn revoke_totp(&self, user_id: Uuid) -> Result<(), AuthenticatorManagementError> {
        self.authenticators
            .revoke_all_of_type(user_id, AuthenticatorType::Totp, self.clock.now())
            .await
            .map(|_| ())
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// Row ids of suspended passkeys (AP9). The decision lives in [`suspended_passkey_ids`].
    pub async fn suspended_passkey_ids(
        &self,
        user_id: Uuid,
    ) -> Result<HashSet<Uuid>, AuthenticatorManagementError> {
        suspended_passkey_ids(self.authenticators.as_ref(), user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// Reflects revocation of a WebAuthn credential in the registry (does nothing if there is no target).
    ///
    /// `credential_id` is the registry row id = the identifier of one passkey. AP11b dropped the original table,
    /// so the ambiguity of "which table does the caller's id belong to" is gone.
    pub async fn revoke_webauthn(
        &self,
        user_id: Uuid,
        credential_id: Uuid,
    ) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        let rows = self
            .authenticators
            .list_for_user(user_id)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        let Some(target) = rows.into_iter().find(|a| a.id == credential_id) else {
            return Ok(());
        };
        self.authenticators
            .update_status(target.id, user_id, AuthenticatorStatus::Revoked, now)
            .await
            .map(|_| ())
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// Reflects an admin MFA reset (MT21) in the registry (revokes TOTP, WebAuthn and recovery codes).
    ///
    /// Recovery codes are dropped too because this is the admin rebuilding the recovery means of a user who lost their device.
    /// If the old set survived, "reset done, yet the old paper still gets in" would be possible.
    pub async fn revoke_all_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<(), AuthenticatorManagementError> {
        let now = self.clock.now();
        for authenticator_type in [
            AuthenticatorType::Totp,
            AuthenticatorType::WebAuthn,
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::EmailOtp,
        ] {
            self.authenticators
                .revoke_all_of_type(user_id, authenticator_type, now)
                .await
                .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    async fn create_active_totp(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), AuthenticatorManagementError> {
        let row = UserAuthenticator {
            id: self.ids.new_id(),
            user_id,
            authenticator_type: AuthenticatorType::Totp,
            status: AuthenticatorStatus::Active,
            label: String::new(),
            secret_encrypted: None,
            target: None,
            confirmed_at: Some(now),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        self.authenticators
            .create(&row)
            .await
            .map_err(|e| AuthenticatorManagementError::Internal(e.to_string()))
    }

    /// Remaining count for the audit (falls back to `-1` so a failed lookup doesn't drop the audit).
    async fn remaining_after(&self, user_id: Uuid) -> i64 {
        match self.usable_recovery_code_count(user_id).await {
            Ok(n) => n as i64,
            Err(_) => -1,
        }
    }
}

/// Decides whether an authenticator is **stopped** in the registry (AP9; the gate on authentication paths).
///
/// Secrets and state are both in the registry (AP11b), but the paths that fetch secrets (`TotpSecretRepository` /
/// `WebAuthnCredentialRepository`) only look at "not revoked rows". **Suspension** passes through
/// there, so unless authentication paths go through this check, "suspended on screen yet still gets in"
/// happens. This function closes that one gap.
///
/// The check is limited to "is there a stopped row". If there's no row or it's `pending`, the decision is left
/// to the existing path (presence of `confirmed_at` etc.).
///
/// Passing `credential_id` (registry row id) looks only at that one passkey (stopping one leaves
/// the others usable). With `None`, rows of the same kind are checked (TOTP is one per user).
pub async fn is_blocked_in_registry(
    repository: &dyn UserAuthenticatorRepository,
    user_id: Uuid,
    authenticator_type: AuthenticatorType,
    credential_id: Option<Uuid>,
) -> Result<bool, crate::domain::error::DomainError> {
    let rows = repository.list_for_user(user_id).await?;
    Ok(rows
        .iter()
        .filter(|a| a.authenticator_type == authenticator_type)
        .filter(|a| credential_id.is_none_or(|id| a.id == id))
        .any(|a| a.is_blocked()))
}

/// Row ids of suspended passkeys (AP9).
///
/// Suspension only exists in the registry's `status`, and the key-fetching path (`WebAuthnCredentialRepository`) only
/// drops revoked rows. **Suspended passkeys still appear in the list**, so the screen needs this set to mark them.
pub async fn suspended_passkey_ids(
    repository: &dyn UserAuthenticatorRepository,
    user_id: Uuid,
) -> Result<HashSet<Uuid>, crate::domain::error::DomainError> {
    Ok(passkey_rows(repository, user_id)
        .await?
        .filter(|a| a.status == AuthenticatorStatus::Suspended)
        .map(|a| a.id)
        .collect())
}

/// Whether the user has at least one passkey **usable now**.
///
/// A passkey row is `active` from the moment it is registered; deletion moves it to `revoked`, suspension to
/// `suspended`. So an `active` row is exactly "a passkey that works when pressed". Used to decide whether the
/// identity verification (AP5) screen offers the passkey path —— showing the button to users without one makes the
/// browser dialog appear and then fail.
pub async fn has_usable_passkey(
    repository: &dyn UserAuthenticatorRepository,
    user_id: Uuid,
) -> Result<bool, crate::domain::error::DomainError> {
    Ok(passkey_rows(repository, user_id)
        .await?
        .any(|a| a.status == AuthenticatorStatus::Active))
}

/// Passkey rows in the registry (revoked rows excluded).
async fn passkey_rows(
    repository: &dyn UserAuthenticatorRepository,
    user_id: Uuid,
) -> Result<impl Iterator<Item = UserAuthenticator>, crate::domain::error::DomainError> {
    let rows = repository.list_for_user(user_id).await?;
    Ok(rows.into_iter().filter(|a| {
        a.authenticator_type == AuthenticatorType::WebAuthn
            && a.status != AuthenticatorStatus::Revoked
    }))
}

/// Normalizes and consumes a one-time code (recovery code, OTP) (AP9).
///
/// Called from both the login path (`MfaLoginService`) and admin use cases, so the purpose of this function is
/// **keeping the normalization rules in one place**. If normalization drifts, "same string as issued, yet no match" happens.
/// Strips whitespace and `-`, and ignores case for recovery codes (values assumed to be copied from paper).
pub async fn consume_single_use_code(
    repository: &dyn UserAuthenticatorRepository,
    user_id: Uuid,
    authenticator_type: AuthenticatorType,
    code: &str,
    now: DateTime<Utc>,
) -> Result<bool, crate::domain::error::DomainError> {
    let stripped = code.trim().replace([' ', '-'], "");
    let normalized = if authenticator_type == AuthenticatorType::RecoveryCode {
        stripped.to_lowercase()
    } else {
        stripped
    };
    if normalized.is_empty() {
        return Ok(false);
    }
    let consumed = repository
        .consume_single_use(
            user_id,
            authenticator_type,
            &crypto::sha256_hex(&normalized),
            now,
        )
        .await?;
    Ok(consumed.is_some())
}

/// Makes a digits-only one-time code (assumed to be read aloud or copied from mail/SMS).
///
/// Zero-padded so digits aren't lost (turning `012345` into `12345` makes the length vary and the verifier
/// would need normalization = a source of accidents).
fn numeric_code(digits: u32) -> String {
    let modulus = 10u64.pow(digits);
    // Take 64 bits from a cryptographic RNG and reduce by modulo. 10^6 doesn't divide 2^64, so it isn't strictly
    // uniform, but the bias is below 2^-44 and doesn't affect brute-force resistance.
    let bytes = crypto::random_hex(8);
    let value = u64::from_str_radix(&bytes, 16).unwrap_or(0) % modulus;
    format!("{value:0width$}", width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::DomainError;
    use async_trait::async_trait;

    #[test]
    fn numeric_codes_keep_their_width() {
        for _ in 0..200 {
            let code = numeric_code(6);
            assert_eq!(code.len(), 6, "{code}");
            assert!(code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        }
    }

    /// Generated codes differ every time (the same value would mean the wrong random source).
    #[test]
    fn numeric_codes_are_not_constant() {
        let first = numeric_code(6);
        assert!((0..50).any(|_| numeric_code(6) != first));
    }

    /// A fake returning only the registry (checking the authentication path gate doesn't need the secret tables).
    struct FakeRegistry(Vec<UserAuthenticator>);

    #[async_trait]
    impl UserAuthenticatorRepository for FakeRegistry {
        async fn create(&self, _a: &UserAuthenticator) -> Result<(), DomainError> {
            unreachable!()
        }
        async fn list_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<UserAuthenticator>, DomainError> {
            Ok(self
                .0
                .iter()
                .filter(|a| a.user_id == user_id)
                .cloned()
                .collect())
        }
    }

    fn user() -> Uuid {
        Uuid::from_u128(1)
    }

    /// `id` is the registry row id = the identifier of one authenticator (AP11b made it the only identifier).
    fn row(
        authenticator_type: AuthenticatorType,
        status: AuthenticatorStatus,
        id: Option<Uuid>,
    ) -> UserAuthenticator {
        let at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        UserAuthenticator {
            id: id.unwrap_or_else(|| Uuid::from_u128(900)),
            user_id: user(),
            authenticator_type,
            status,
            label: String::new(),
            secret_encrypted: None,
            target: None,
            confirmed_at: Some(at),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            created_at: at,
            updated_at: at,
        }
    }

    fn issued(
        authenticator_type: AuthenticatorType,
        seconds_ago: i64,
        now: DateTime<Utc>,
    ) -> UserAuthenticator {
        let mut r = row(authenticator_type, AuthenticatorStatus::Revoked, None);
        r.created_at = now - Duration::seconds(seconds_ago);
        r.expires_at = Some(r.created_at + Duration::seconds(300));
        r
    }

    /// Resends must be 30 seconds apart. Different kinds are not counted.
    #[test]
    fn otp_cannot_be_sent_again_too_soon() {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let email = AuthenticatorType::EmailOtp;
        assert!(may_send_otp(&[], email, now));
        assert!(!may_send_otp(&[issued(email, 29, now)], email, now));
        assert!(may_send_otp(&[issued(email, 30, now)], email, now));
        assert!(may_send_otp(
            &[issued(AuthenticatorType::SmsOtp, 1, now)],
            email,
            now
        ));
    }

    /// Up to 10 per hour. Sends older than one hour are not counted.
    #[test]
    fn otp_sends_per_hour_are_limited() {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let sms = AuthenticatorType::SmsOtp;
        let nine: Vec<_> = (1..=9).map(|n| issued(sms, n * 60, now)).collect();
        assert!(may_send_otp(&nine, sms, now));
        let mut ten = nine.clone();
        ten.push(issued(sms, 3000, now));
        assert!(!may_send_otp(&ten, sms, now));
        let mut old = nine;
        old.push(issued(sms, 3600, now));
        assert!(may_send_otp(&old, sms, now));
    }

    /// Rows of registered phone numbers (no expiry) are not counted as sends.
    #[test]
    fn a_registered_phone_is_not_counted_as_a_send() {
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let mut phone = row(AuthenticatorType::SmsOtp, AuthenticatorStatus::Active, None);
        phone.created_at = now;
        assert!(may_send_otp(&[phone], AuthenticatorType::SmsOtp, now));
    }

    /// Suspended or revoked TOTP can't be used for authentication. The secret-fetching path looks at "not revoked rows",
    /// so this check is the only thing blocking **suspension**.
    #[tokio::test]
    async fn a_stopped_totp_is_blocked_even_though_its_secret_still_exists() {
        for status in [AuthenticatorStatus::Suspended, AuthenticatorStatus::Revoked] {
            let repo = FakeRegistry(vec![row(AuthenticatorType::Totp, status, None)]);
            assert!(
                is_blocked_in_registry(&repo, user(), AuthenticatorType::Totp, None)
                    .await
                    .unwrap(),
                "{status} should block"
            );
        }
    }

    /// `active` / `pending` are not blocked (`pending` means "unconfirmed", not stopped).
    #[tokio::test]
    async fn active_and_pending_authenticators_are_not_blocked() {
        for status in [AuthenticatorStatus::Active, AuthenticatorStatus::Pending] {
            let repo = FakeRegistry(vec![row(AuthenticatorType::Totp, status, None)]);
            assert!(
                !is_blocked_in_registry(&repo, user(), AuthenticatorType::Totp, None)
                    .await
                    .unwrap(),
                "{status} should not block"
            );
        }
    }

    /// With no row in the registry, nothing is blocked (no row = no authenticator at all, so the secret-fetching side
    /// finds nothing and ends there. No need to layer a blocking decision here).
    #[tokio::test]
    async fn a_missing_registry_row_does_not_block() {
        let repo = FakeRegistry(Vec::new());
        assert!(
            !is_blocked_in_registry(&repo, user(), AuthenticatorType::Totp, None)
                .await
                .unwrap()
        );
    }

    /// A user can have several passkeys. Stopping one must leave the others usable.
    #[tokio::test]
    async fn stopping_one_passkey_leaves_the_others_usable() {
        let stopped = Uuid::from_u128(10);
        let alive = Uuid::from_u128(11);
        let repo = FakeRegistry(vec![
            row(
                AuthenticatorType::WebAuthn,
                AuthenticatorStatus::Revoked,
                Some(stopped),
            ),
            row(
                AuthenticatorType::WebAuthn,
                AuthenticatorStatus::Active,
                Some(alive),
            ),
        ]);
        assert!(
            is_blocked_in_registry(&repo, user(), AuthenticatorType::WebAuthn, Some(stopped))
                .await
                .unwrap()
        );
        assert!(
            !is_blocked_in_registry(&repo, user(), AuthenticatorType::WebAuthn, Some(alive))
                .await
                .unwrap()
        );
    }

    /// Different kinds don't interfere (stopping TOTP leaves passkeys usable).
    #[tokio::test]
    async fn stopping_one_type_does_not_block_another() {
        let repo = FakeRegistry(vec![row(
            AuthenticatorType::Totp,
            AuthenticatorStatus::Suspended,
            None,
        )]);
        assert!(
            !is_blocked_in_registry(&repo, user(), AuthenticatorType::WebAuthn, None)
                .await
                .unwrap()
        );
    }
}
