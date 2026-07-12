//! 自己登録アカウントのメール検証ユースケース（SEC6b）。
//!
//! 自己登録（SEC6）で作成されるアカウントは `email_verified = false` の状態で作られる。本サービスは
//! 確認リンク付きメールを送り（送信基盤は MT17 の [`Mailer`]・SMTP はシステム設定 MT14 を再利用）、
//! リンクの平文トークン消費で `email_verified` を立てる。検証が済むまでは当該アカウントでログイン
//! できない（`LoginService` が `email_verified` を判定。SEC6b）。
//!
//! セキュリティ方針:
//! - **トークン**: 32 バイトのランダム値。保存は SHA-256 hex のみ・TTL 付き（既定 24 時間）・単回消費。
//!   再送時は当該ユーザーの未使用トークンを失効させる（有効リンクは常に最新の 1 本）。
//! - トークン・メールアドレスはログ・監査に出さない（PII 方針）。
//! - 送信は best-effort（SMTP 未設定・送信失敗でも登録自体は成立する。検証は後追いで可能）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::system_settings::SystemSettingsService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::email_verification::EmailVerificationToken;
use crate::domain::mailer::{Mailer, OutgoingEmail};
use crate::domain::repositories::{EmailVerificationTokenRepository, UserRepository};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::infrastructure::crypto;
use std::sync::Arc;
use uuid::Uuid;

/// 検証トークンのバイト長（base64url で 43 文字程度）。
const VERIFICATION_TOKEN_BYTES: usize = 32;

/// 検証リンク消費の結果。
pub enum VerifyEmailOutcome {
    Ok,
    /// トークンが無効・期限切れ・使用済み・別テナント。
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
    verification_ttl: chrono::Duration,
    /// 検証リンクの土台となる公開ベース URL（web 画面。末尾スラッシュ無し）。
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
        verification_ttl: std::time::Duration,
        console_base_url: String,
    ) -> Self {
        Self {
            users,
            tokens,
            system_settings,
            mailer,
            audit,
            clock,
            verification_ttl: chrono::Duration::from_std(verification_ttl)
                .expect("verification TTL out of range"),
            console_base_url: console_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// 検証メールを送る（best-effort）。SMTP 未設定・送信失敗でも呼び出し元の処理は継続する。
    /// メールを送出した場合のみ `true` を返す（呼び出し側が「メールを確認して」と案内するため）。
    pub async fn send_verification(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        user_email: &str,
        ctx: &RequestContext,
    ) -> bool {
        // SMTP 未設定なら送れない（アカウントは作成済み。検証は後追いで行える）。
        let server = match self.system_settings.smtp_server().await {
            Ok(Some(server)) => server,
            Ok(None) => return false,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load SMTP settings for email verification");
                return false;
            }
        };

        let now = self.clock.now();
        // 再送時は旧トークンを失効させ、有効な検証リンクを常に最新の 1 本にする。
        if let Err(e) = self.tokens.invalidate_all_for_user(user_id, now).await {
            tracing::warn!(error = %e, "failed to invalidate previous verification tokens");
            return false;
        }

        let token = crypto::random_token(VERIFICATION_TOKEN_BYTES);
        let expires_at = now + self.verification_ttl;
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

        // 監査には内部 ID のみ記録する（トークン・メールアドレスは出さない）。
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

        // トークンは base64url（URL 安全）なのでそのまま連結できる。
        // 文言は MT19（API の多言語化）まで日英併記の固定文とする。
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
            // 宛先等の PII はログに出さない。
            tracing::warn!(error = %e, "email verification delivery failed");
            return false;
        }
        true
    }

    /// 検証リンクの平文トークンを消費して `email_verified` を立てる。トークンの所有者を解決し、
    /// リンクのテナント（画面の経路）と所属元が一致することを確認する（他テナントの検証画面へ
    /// トークンを持ち込ませない）。
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
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self.rows.lock().unwrap().iter().find(|u| u.id == id).cloned())
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
        async fn update_password(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
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
            self.sent.lock().unwrap().push((server.clone(), mail.clone()));
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
            password_hash: "x".to_string(),
            must_change_password: false,
            status: UserStatus::Active,
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
            TEST_KEY,
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
            std::time::Duration::from_secs(86_400),
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
        assert!(mails[0]
            .1
            .body_text
            .contains(&format!("https://idp.example.com/{tenant}/verify-email?token=")));
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
            h.svc.verify(TenantContext::new(tenant), &token, &ctx()).await,
            VerifyEmailOutcome::Ok
        ));
        assert!(h.users.rows.lock().unwrap()[0].email_verified);
        // 監査に requested + verified が記録され、トークンは漏れない。
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
        // 再利用は拒否（単回消費）。
        assert!(matches!(
            h.svc.verify(TenantContext::new(tenant), &token, &ctx()).await,
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
            h.svc.verify(TenantContext::new(other), &token, &ctx()).await,
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
            h.svc.verify(TenantContext::new(tenant), &first, &ctx()).await,
            VerifyEmailOutcome::InvalidOrExpired
        ));
        assert!(matches!(
            h.svc.verify(TenantContext::new(tenant), &second, &ctx()).await,
            VerifyEmailOutcome::Ok
        ));
    }
}
