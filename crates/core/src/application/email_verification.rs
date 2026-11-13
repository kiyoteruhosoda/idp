//! Email verification use case for self-registered accounts (SEC6b).
//!
//! Accounts created by self-registration (SEC6) start with `email_verified = false`. This service
//! sends an email with a confirmation link (sending infrastructure is MT17's [`Mailer`]; SMTP reuses system settings MT14),
//! and sets `email_verified` when the link's plaintext token is consumed. Until verified, the account cannot log in
//! (`LoginService` checks `email_verified`. SEC6b).
//!
//! Security policy:
//! - **Token**: 32 random bytes. Stored only as SHA-256 hex, with a TTL (default 24 hours), consumed once.
//!   On resend, the user's unused tokens are revoked (the valid link is always the single latest one).
//! - Tokens and email addresses never appear in logs or audit (PII policy).
//! - Sending is best-effort (registration itself succeeds even if SMTP is unset or sending fails; verification can follow later).

use crate::application::audit::{AuditService, RequestContext};
use crate::application::system_settings::SystemSettingsService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::email_verification::EmailVerificationToken;
use crate::domain::mailer::{Mailer, OutgoingEmail};
use crate::domain::repositories::{EmailVerificationTokenRepository, UserRepository};
#[cfg(test)]
use crate::domain::system_setting::DeploymentState;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;
use uuid::Uuid;

/// Byte length of the verification token (about 43 chars in base64url).
const VERIFICATION_TOKEN_BYTES: usize = 32;

/// Result of consuming a verification link.
pub enum VerifyEmailOutcome {
    Ok,
    /// The token is invalid, expired, used, or for another tenant.
    InvalidOrExpired,
    Internal(String),
}

pub struct EmailVerificationService {
    users: Arc<dyn UserRepository>,
    tokens: Arc<dyn EmailVerificationTokenRepository>,
    system_settings: Arc<SystemSettingsService>,
    mailer: Arc<dyn Mailer>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    /// Resolution of settings tenants can override (ADR-0058). Looked up every time.
    settings: Arc<dyn EffectiveTenantSettings>,
    /// Public base URL the verification link is built on (web screens; no trailing slash).
    console_base_url: String,
}

impl EmailVerificationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        tokens: Arc<dyn EmailVerificationTokenRepository>,
        system_settings: Arc<SystemSettingsService>,
        mailer: Arc<dyn Mailer>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        settings: Arc<dyn EffectiveTenantSettings>,
        console_base_url: String,
    ) -> Self {
        Self {
            users,
            tokens,
            system_settings,
            mailer,
            audit,
            clock,
            settings,
            console_base_url: console_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Sends the verification email (best-effort). The caller's processing continues even if SMTP is unset or sending fails.
    /// Returns `true` only if an email was sent (so the caller can say "check your email").
    pub async fn send_verification(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        user_email: &str,
        ctx: &RequestContext,
    ) -> bool {
        // Can't send if SMTP is unset (the account is already created; verification can follow later).
        // Sent through the verifying tenant's channel (ADR-0058 §8; the global channel if it has none).
        let server = match self.system_settings.smtp_server_for(tenant_id).await {
            Ok(Some(server)) => server,
            Ok(None) => return false,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load SMTP settings for email verification");
                return false;
            }
        };

        // The lifetime is the value of the user's home tenant (`tenant_id` is the registering tenant = home, and the link
        // points here too. ADR-0058). The consuming side looks at the stored `expires_at`.
        // Looked up before revoking old tokens (so a failed lookup doesn't leave no valid link at all).
        let verification_ttl = match self.settings.email_verification_ttl(tenant_id).await {
            Ok(ttl) => ttl,
            Err(e) => {
                tracing::warn!(error = %e, "failed to resolve the email verification TTL");
                return false;
            }
        };
        let now = self.clock.now();
        // On resend, revoke old tokens so the valid verification link is always the single latest one.
        if let Err(e) = self.tokens.invalidate_all_for_user(user_id, now).await {
            tracing::warn!(error = %e, "failed to invalidate previous verification tokens");
            return false;
        }

        let token = crypto::random_token(VERIFICATION_TOKEN_BYTES);
        let expires_at = now + verification_ttl;
        let record = EmailVerificationToken {
            token_hash: crypto::sha256_hex(&token),
            user_id,
            expires_at,
            used_at: None,
            created_at: now,
        };
        if let Err(e) = self.tokens.create(&record).await {
            tracing::warn!(error = %e, "failed to store email verification token");
            return false;
        }

        // Only internal IDs are recorded in the audit (no tokens or email addresses).
        self.audit
            .record(
                AuditEventType::EmailVerificationRequested,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                None,
                None,
                ctx,
            )
            .await;

        // The token is base64url (URL-safe), so it can be concatenated as-is.
        // Until MT19 (API i18n), the wording is fixed text in both Japanese and English.
        let verify_url = format!(
            "{}/{}/verify-email?token={}",
            self.console_base_url, tenant_id, token
        );
        let mail = OutgoingEmail {
            to: user_email.to_string(),
            subject: "メールアドレスの確認 / Verify your email".to_string(),
            body_text: format!(
                "アカウント登録ありがとうございます。\n\
                 次のリンクを開いてメールアドレスを確認してください。確認が済むまではログインできません。\n\
                 心当たりがない場合は、このメールを破棄してください。\n\
                 \n\
                 Thanks for registering. Open the link below to verify your email address.\n\
                 You will not be able to sign in until your email is verified.\n\
                 If you did not request this, you can safely ignore this email.\n\
                 \n\
                 {verify_url}\n\
                 \n\
                 有効期限 / Expires at: {}\n",
                expires_at.to_rfc3339()
            ),
        };
        if let Err(e) = self.mailer.send(&server, &mail).await {
            // PII such as the destination is not logged.
            tracing::warn!(error = %e, "email verification delivery failed");
            return false;
        }
        true
    }

    /// Consumes the verification link's plaintext token and sets `email_verified`. Resolves the token's owner and
    /// confirms the link's tenant (the screen's route) matches the home tenant (so a token can't be carried to
    /// another tenant's verification screen).
    pub async fn verify(
        &self,
        tenant: TenantContext,
        token: &str,
        ctx: &RequestContext,
    ) -> VerifyEmailOutcome {
        if token.is_empty() {
            return VerifyEmailOutcome::InvalidOrExpired;
        }
        let now = self.clock.now();
        let record = match self.tokens.consume(&crypto::sha256_hex(token), now).await {
            Ok(Some(record)) => record,
            Ok(None) => return VerifyEmailOutcome::InvalidOrExpired,
            Err(e) => return VerifyEmailOutcome::Internal(e.to_string()),
        };

        let user = match self.users.find_by_id(record.user_id).await {
            Ok(Some(user)) if user.tenant_id == tenant.tenant_id() => user,
            Ok(_) => return VerifyEmailOutcome::InvalidOrExpired,
            Err(e) => return VerifyEmailOutcome::Internal(e.to_string()),
        };

        if let Err(e) = self.users.mark_email_verified(user.id).await {
            return VerifyEmailOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::EmailVerified,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;
        VerifyEmailOutcome::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::mailer::SmtpServerConfig;
    use crate::domain::repositories::{AuditLogSink, SystemSettingsRepository};
    use crate::domain::system_setting::SystemSetting;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    const TEST_KEY: [u8; 32] = *b"unit-test-key-0123456789abcdef!!";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<crate::domain::audit::AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeUsers {
        rows: Mutex<Vec<User>>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// The production sqlx implementation increments in a single UPDATE (SEC13). The fake only runs in
        /// single-threaded tests, so a naive increment giving the same result is enough.
        async fn record_login_failure(
            &self,
            id: Uuid,
            lockout: crate::domain::authentication_policy::LockoutPolicy,
            now: DateTime<Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            let mut rows = self.rows.lock().unwrap();
            let Some(row) = rows.iter_mut().find(|u| u.id == id) else {
                return Ok(crate::domain::user::LoginFailureRecord {
                    failed_login_count: 0,
                    locked_until: None,
                });
            };
            row.failed_login_count += 1;
            if let Some(until) = lockout.locked_until_after_failure(row.failed_login_count, now) {
                row.locked_until = Some(until);
            }
            Ok(crate::domain::user::LoginFailureRecord {
                failed_login_count: row.failed_login_count,
                locked_until: row.locked_until.filter(|u| *u > now),
            })
        }
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.id == id)
                .cloned())
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
        async fn update_password(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _status: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, id: Uuid) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(user) = rows.iter_mut().find(|u| u.id == id) {
                user.email_verified = true;
            }
            Ok(())
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeTokens {
        rows: Mutex<Vec<EmailVerificationToken>>,
    }
    #[async_trait]
    impl EmailVerificationTokenRepository for FakeTokens {
        async fn create(&self, token: &EmailVerificationToken) -> DomainResult<()> {
            self.rows.lock().unwrap().push(token.clone());
            Ok(())
        }
        async fn consume(
            &self,
            token_hash: &str,
            used_at: DateTime<Utc>,
        ) -> DomainResult<Option<EmailVerificationToken>> {
            let mut rows = self.rows.lock().unwrap();
            match rows.iter_mut().find(|t| {
                t.token_hash == token_hash && t.used_at.is_none() && t.expires_at > used_at
            }) {
                Some(row) => {
                    row.used_at = Some(used_at);
                    Ok(Some(row.clone()))
                }
                None => Ok(None),
            }
        }
        async fn invalidate_all_for_user(
            &self,
            user_id: Uuid,
            now: DateTime<Utc>,
        ) -> DomainResult<()> {
            for row in self.rows.lock().unwrap().iter_mut() {
                if row.user_id == user_id && row.used_at.is_none() {
                    row.used_at = Some(now);
                }
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeSettingsRepo {
        rows: Mutex<Vec<SystemSetting>>,
    }
    #[async_trait]
    impl SystemSettingsRepository for FakeSettingsRepo {
        async fn load_all(&self) -> DomainResult<Vec<SystemSetting>> {
            Ok(self.rows.lock().unwrap().clone())
        }
        async fn upsert(&self, setting: &SystemSetting) -> DomainResult<()> {
            self.rows.lock().unwrap().push(setting.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeMailer {
        sent: Mutex<Vec<(SmtpServerConfig, OutgoingEmail)>>,
    }
    #[async_trait]
    impl Mailer for FakeMailer {
        async fn send(&self, server: &SmtpServerConfig, mail: &OutgoingEmail) -> DomainResult<()> {
            self.sent
                .lock()
                .unwrap()
                .push((server.clone(), mail.clone()));
            Ok(())
        }
    }

    fn smtp_settings(repo: &FakeSettingsRepo) {
        *repo.rows.lock().unwrap() = [
            ("smtp.host", "smtp.example.com"),
            ("smtp.from_address", "noreply@example.com"),
        ]
        .into_iter()
        .map(|(k, v)| SystemSetting {
            key: k.to_string(),
            value: v.to_string(),
            is_secret: false,
        })
        .collect();
    }

    fn test_user(id: Uuid, tenant: TenantId, email: &str) -> User {
        User {
            id,
            tenant_id: tenant,
            sub: Uuid::new_v4(),
            email: email.to_string(),
            email_verified: false,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            password_changed_at: None,
            status: UserStatus::Active,
            pending_setup: false,
            failed_login_count: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    struct Harness {
        svc: EmailVerificationService,
        users: Arc<FakeUsers>,
        tokens: Arc<FakeTokens>,
        mailer: Arc<FakeMailer>,
        sink: Arc<CapturingSink>,
    }

    fn harness(smtp_configured: bool) -> Harness {
        let users = Arc::new(FakeUsers::default());
        let tokens = Arc::new(FakeTokens::default());
        let mailer = Arc::new(FakeMailer::default());
        let sink = Arc::new(CapturingSink::default());
        let settings_repo = Arc::new(FakeSettingsRepo::default());
        if smtp_configured {
            smtp_settings(&settings_repo);
        }
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock)));
        let system_settings = Arc::new(SystemSettingsService::new(
            settings_repo,
            Arc::new(crate::application::system_settings::NoTenantSettings),
            TEST_KEY,
            DeploymentState::default(),
            audit.clone(),
            Arc::new(FixedClock),
        ));
        let svc = EmailVerificationService::new(
            users.clone(),
            tokens.clone(),
            system_settings,
            mailer.clone(),
            audit,
            Arc::new(FixedClock),
            crate::application::tenant_settings::testing::tenant_settings().service,
            "https://idp.example.com".to_string(),
        );
        Harness {
            svc,
            users,
            tokens,
            mailer,
            sink,
        }
    }

    fn token_from_mail(mail: &OutgoingEmail) -> String {
        let body = &mail.body_text;
        let start = body.find("token=").expect("token in body") + "token=".len();
        body[start..]
            .split_whitespace()
            .next()
            .expect("token value")
            .to_string()
    }

    #[tokio::test]
    async fn send_stores_hash_only_and_mails_link() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true);
        let sent = h
            .svc
            .send_verification(tenant, user, "u@example.com", &ctx())
            .await;
        assert!(sent);
        let mails = h.mailer.sent.lock().unwrap();
        assert_eq!(mails.len(), 1);
        assert_eq!(mails[0].1.to, "u@example.com");
        assert!(mails[0].1.body_text.contains(&format!(
            "https://idp.example.com/{tenant}/verify-email?token="
        )));
        let token = token_from_mail(&mails[0].1);
        let rows = h.tokens.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_hash, crypto::sha256_hex(&token));
        assert_ne!(rows[0].token_hash, token);
    }

    #[tokio::test]
    async fn send_is_noop_without_smtp() {
        let tenant: TenantId = Uuid::now_v7().into();
        let h = harness(false);
        let sent = h
            .svc
            .send_verification(tenant, Uuid::new_v4(), "u@example.com", &ctx())
            .await;
        assert!(!sent);
        assert!(h.mailer.sent.lock().unwrap().is_empty());
        assert!(h.tokens.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn verify_sets_flag_and_is_single_use() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));
        h.svc
            .send_verification(tenant, user, "u@example.com", &ctx())
            .await;
        let token = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);

        assert!(matches!(
            h.svc
                .verify(TenantContext::new(tenant), &token, &ctx())
                .await,
            VerifyEmailOutcome::Ok
        ));
        assert!(h.users.rows.lock().unwrap()[0].email_verified);
        // requested + verified are recorded in the audit, and the token doesn't leak.
        {
            let events = h.sink.events.lock().unwrap();
            assert!(events
                .iter()
                .any(|e| e.event_type == AuditEventType::EmailVerificationRequested));
            assert!(events
                .iter()
                .any(|e| e.event_type == AuditEventType::EmailVerified));
            assert!(events.iter().all(|e| e
                .reason
                .as_deref()
                .map(|r| !r.contains(&token))
                .unwrap_or(true)));
        }
        // Reuse is refused (consumed once).
        assert!(matches!(
            h.svc
                .verify(TenantContext::new(tenant), &token, &ctx())
                .await,
            VerifyEmailOutcome::InvalidOrExpired
        ));
    }

    #[tokio::test]
    async fn verify_rejects_other_tenant() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));
        h.svc
            .send_verification(tenant, user, "u@example.com", &ctx())
            .await;
        let token = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);

        let other: TenantId = Uuid::now_v7().into();
        assert!(matches!(
            h.svc
                .verify(TenantContext::new(other), &token, &ctx())
                .await,
            VerifyEmailOutcome::InvalidOrExpired
        ));
        assert!(!h.users.rows.lock().unwrap()[0].email_verified);
    }

    #[tokio::test]
    async fn resend_invalidates_previous_token() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));
        h.svc
            .send_verification(tenant, user, "u@example.com", &ctx())
            .await;
        let first = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);
        h.svc
            .send_verification(tenant, user, "u@example.com", &ctx())
            .await;
        let second = token_from_mail(&h.mailer.sent.lock().unwrap()[1].1);

        assert!(matches!(
            h.svc
                .verify(TenantContext::new(tenant), &first, &ctx())
                .await,
            VerifyEmailOutcome::InvalidOrExpired
        ));
        assert!(matches!(
            h.svc
                .verify(TenantContext::new(tenant), &second, &ctx())
                .await,
            VerifyEmailOutcome::Ok
        ));
    }
}
