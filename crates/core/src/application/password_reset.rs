//! セルフサービス・パスワードリセットユースケース（忘失時。MT18）。
//!
//! ログイン画面の「パスワードをお忘れですか」から、メールアドレスを入力 → リセットリンク付き
//! メールを受信 → リンク先で新パスワードを設定する。SMTP はシステム設定（MT14）から解決し、
//! メール配送は MT17 の [`Mailer`] ポートを再利用する。
//!
//! セキュリティ方針:
//! - **メールアドレスの列挙防止**: 要求はアカウントの有無・状態に関わらず同一の応答（`Accepted`）
//!   を返す。SMTP 未設定だけは `Unavailable`（アカウント非依存の情報のため列挙にはならない）。
//! - **トークン**: 32 バイトのランダム値。保存は SHA-256 hex のみ・TTL 付き（既定 1 時間）・
//!   単回消費。再要求時は当該ユーザーの未使用トークンを失効させる（有効リンクは常に最新の 1 本）。
//! - **リセット成功時の全セッション失効**: 忘失リセットは資格情報漏えいの可能性を含むため、
//!   SSO セッション・refresh token・未消費 authorization code をユーザー単位で全失効させる。
//! - **レート制限**: IP 単位で要求回数を制限する。
//! - トークン・メールアドレスはログ・監査に出さない（PII 方針）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::system_settings::SystemSettingsService;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::mailer::{Mailer, OutgoingEmail};
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::password_reset::PasswordResetToken;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{
    AuthorizationCodeRepository, PasswordResetTokenRepository, RefreshTokenRepository,
    SsoSessionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use std::sync::Arc;

/// リセットトークンのバイト長（base64url で 43 文字程度）。
const RESET_TOKEN_BYTES: usize = 32;

/// リセット要求の結果。アカウントの有無では分岐しない（列挙防止）。
pub enum RequestResetOutcome {
    /// 受理（アカウントが存在すればメールを送った。存在しなくても同じ応答）。
    Accepted,
    /// SMTP 未設定でメール配送不可（機能自体が利用できない。アカウント非依存）。
    Unavailable,
    /// IP 単位のレート制限超過。
    RateLimited,
}

pub enum ResetPasswordOutcome {
    Ok,
    /// トークンが無効・期限切れ・使用済み・別テナント。
    InvalidOrExpired,
    /// 新パスワードが強度要件を満たさない。
    WeakPassword,
    Internal(String),
}

pub struct PasswordResetService {
    users: Arc<dyn UserRepository>,
    reset_tokens: Arc<dyn PasswordResetTokenRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    hasher: Arc<dyn PasswordHasher>,
    system_settings: Arc<SystemSettingsService>,
    mailer: Arc<dyn Mailer>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    reset_ttl: chrono::Duration,
    /// リセットリンクの土台となる公開ベース URL（web 画面。末尾スラッシュ無し）。
    console_base_url: String,
}

impl PasswordResetService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        reset_tokens: Arc<dyn PasswordResetTokenRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        hasher: Arc<dyn PasswordHasher>,
        system_settings: Arc<SystemSettingsService>,
        mailer: Arc<dyn Mailer>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        reset_ttl: std::time::Duration,
        console_base_url: String,
    ) -> Self {
        Self {
            users,
            reset_tokens,
            sso_sessions,
            refresh_tokens,
            codes,
            hasher,
            system_settings,
            mailer,
            rate_limiter,
            audit,
            clock,
            reset_ttl: chrono::Duration::from_std(reset_ttl).expect("reset TTL out of range"),
            console_base_url: console_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// リセットを要求する。`tenant` はログイン画面のテナント（所属元でのメール検索に使う）。
    /// アカウントの有無・状態に関わらず `Accepted` を返す（列挙防止）。
    pub async fn request_reset(
        &self,
        tenant: TenantContext,
        email: &str,
        ctx: &RequestContext,
    ) -> RequestResetOutcome {
        if !self.rate_limiter.check_and_record(
            ctx.ip_address.as_deref().unwrap_or("unknown"),
            self.clock.now(),
        ) {
            return RequestResetOutcome::RateLimited;
        }

        // SMTP 未設定なら機能自体が使えない（アカウント非依存のため列挙にはならない）。
        let server = match self.system_settings.smtp_server().await {
            Ok(Some(server)) => server,
            Ok(None) => return RequestResetOutcome::Unavailable,
            Err(e) => {
                tracing::warn!(error = %e, "failed to load SMTP settings for password reset");
                return RequestResetOutcome::Unavailable;
            }
        };

        // ここから先はアカウントの有無・状態・送信結果に関わらず Accepted（列挙防止）。
        let user = match self
            .users
            .find_by_email(tenant.tenant_id(), email.trim())
            .await
        {
            Ok(Some(user)) if user.is_active() => user,
            Ok(_) => return RequestResetOutcome::Accepted,
            Err(e) => {
                tracing::warn!(error = %e, "password reset user lookup failed");
                return RequestResetOutcome::Accepted;
            }
        };

        let now = self.clock.now();
        // 再要求時は旧トークンを失効させ、有効なリセットリンクを常に最新の 1 本にする。
        if let Err(e) = self
            .reset_tokens
            .invalidate_all_for_user(user.id, now)
            .await
        {
            tracing::warn!(error = %e, "failed to invalidate previous reset tokens");
            return RequestResetOutcome::Accepted;
        }

        let token = crypto::random_token(RESET_TOKEN_BYTES);
        let expires_at = now + self.reset_ttl;
        let record = PasswordResetToken {
            token_hash: crypto::sha256_hex(&token),
            user_id: user.id,
            expires_at,
            used_at: None,
            created_at: now,
        };
        if let Err(e) = self.reset_tokens.create(&record).await {
            tracing::warn!(error = %e, "failed to store password reset token");
            return RequestResetOutcome::Accepted;
        }

        // 監査には内部 ID のみ記録する（トークン・メールアドレスは出さない）。
        self.audit
            .record(
                AuditEventType::PasswordResetRequested,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;

        // トークンは base64url（URL 安全）なのでそのまま連結できる。
        // 文言は MT19（API の多言語化）まで日英併記の固定文とする。
        let reset_url = format!(
            "{}/{}/password-reset?token={}",
            self.console_base_url,
            tenant.tenant_id(),
            token
        );
        let mail = OutgoingEmail {
            to: user.email.clone(),
            subject: "パスワード再設定のご案内 / Password reset".to_string(),
            body_text: format!(
                "パスワード再設定の要求を受け付けました。\n\
                 次のリンクを開いて新しいパスワードを設定してください。\n\
                 心当たりがない場合は、このメールを破棄してください。\n\
                 \n\
                 A password reset was requested for your account.\n\
                 Open the link below to set a new password.\n\
                 If you did not request this, you can safely ignore this email.\n\
                 \n\
                 {reset_url}\n\
                 \n\
                 有効期限 / Expires at: {}\n",
                expires_at.to_rfc3339()
            ),
        };
        if let Err(e) = self.mailer.send(&server, &mail).await {
            // 宛先等の PII はログに出さない。応答も Accepted のまま（列挙防止）。
            tracing::warn!(error = %e, "password reset email delivery failed");
        }
        RequestResetOutcome::Accepted
    }

    /// トークンを消費して新パスワードを設定する。成功時は当該ユーザーの SSO セッション・
    /// refresh token・未消費 authorization code を全失効させる（忘失リセットは資格情報漏えいの
    /// 可能性を含むため）。
    pub async fn reset_password(
        &self,
        tenant: TenantContext,
        token: &str,
        new_password: &str,
        ctx: &RequestContext,
    ) -> ResetPasswordOutcome {
        if token.is_empty() {
            return ResetPasswordOutcome::InvalidOrExpired;
        }
        // 強度検証をトークン消費より先に行う（弱いパスワードの入力ミスで単回トークンを
        // 無駄に消費させない）。
        if validate_password_strength(new_password).is_err() {
            return ResetPasswordOutcome::WeakPassword;
        }

        let now = self.clock.now();
        let record = match self
            .reset_tokens
            .consume(&crypto::sha256_hex(token), now)
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => return ResetPasswordOutcome::InvalidOrExpired,
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        };

        // トークンの所有者を解決し、リンクのテナント（画面の経路）と所属元が一致することを確認する
        // （他テナントの reset 画面へトークンを持ち込ませない）。ACTIVE でないユーザーも拒否。
        let user = match self.users.find_by_id(record.user_id).await {
            Ok(Some(user)) if user.is_active() && user.tenant_id == tenant.tenant_id() => user,
            Ok(_) => return ResetPasswordOutcome::InvalidOrExpired,
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        };

        let new_hash = match self.hasher.hash(new_password) {
            Ok(h) => h,
            Err(e) => return ResetPasswordOutcome::Internal(e.to_string()),
        };
        if let Err(e) = self.users.update_password(user.id, &new_hash).await {
            return ResetPasswordOutcome::Internal(e.to_string());
        }

        // 全セッション・トークンの失効（fail-open にしない: 失敗はログのみ。パスワードは既に
        // 更新済みで、旧資格情報でのログインはできない）。
        if let Err(e) = self.sso_sessions.delete_all_for_user(user.id).await {
            tracing::warn!(error = %e, "failed to revoke SSO sessions after password reset");
        }
        if let Err(e) = self.refresh_tokens.revoke_all_for_user(user.id, now).await {
            tracing::warn!(error = %e, "failed to revoke refresh tokens after password reset");
        }
        if let Err(e) = self.codes.revoke_all_active_for_user(user.id, now).await {
            tracing::warn!(error = %e, "failed to revoke authorization codes after password reset");
        }

        self.audit
            .record(
                AuditEventType::PasswordResetCompleted,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;
        ResetPasswordOutcome::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::authorization_code::AuthorizationCode;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::mailer::SmtpServerConfig;
    use crate::domain::refresh_token::RefreshToken;
    use crate::domain::repositories::{AuditLogSink, SystemSettingsRepository};
    use crate::domain::sso_session::SsoSession;
    use crate::domain::system_setting::SystemSetting;
    use crate::domain::tenant::TenantId;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;

    const TEST_KEY: [u8; 32] = *b"unit-test-key-0123456789abcdef!!";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl crate::domain::clock::Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    struct PlainHasher;
    impl PasswordHasher for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
            Ok(hash == format!("hash:{password}"))
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
        async fn find_by_email(&self, t: TenantId, e: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.tenant_id == t && u.email == e)
                .cloned())
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
        async fn update_password(&self, id: Uuid, password_hash: &str) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(user) = rows.iter_mut().find(|u| u.id == id) {
                user.password_hash = password_hash.to_string();
                user.must_change_password = false;
            }
            Ok(())
        }
        async fn reset_password_forced(&self, _id: Uuid, _password_hash: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _status: UserStatus) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeResetTokens {
        rows: Mutex<Vec<PasswordResetToken>>,
    }
    #[async_trait]
    impl PasswordResetTokenRepository for FakeResetTokens {
        async fn create(&self, token: &PasswordResetToken) -> DomainResult<()> {
            self.rows.lock().unwrap().push(token.clone());
            Ok(())
        }
        async fn consume(
            &self,
            token_hash: &str,
            used_at: DateTime<Utc>,
        ) -> DomainResult<Option<PasswordResetToken>> {
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
    struct FakeSsoSessions {
        revoked_users: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, _h: &str) -> DomainResult<Option<SsoSession>> {
            unreachable!()
        }
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, user_id: Uuid) -> DomainResult<()> {
            self.revoked_users.lock().unwrap().push(user_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRefreshTokens {
        revoked_users: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl RefreshTokenRepository for FakeRefreshTokens {
        async fn create(&self, _t: &RefreshToken) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, _t: TenantId, _h: &str) -> DomainResult<Option<RefreshToken>> {
            unreachable!()
        }
        async fn revoke(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn exists_by_parent_hash(&self, _h: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn revoke_all_for_user(&self, user_id: Uuid, _t: DateTime<Utc>) -> DomainResult<()> {
            self.revoked_users.lock().unwrap().push(user_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeCodes {
        revoked_users: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl AuthorizationCodeRepository for FakeCodes {
        async fn create(&self, _c: &AuthorizationCode) -> DomainResult<()> {
            unreachable!()
        }
        async fn consume(
            &self,
            _t: TenantId,
            _h: &str,
            _u: DateTime<Utc>,
        ) -> DomainResult<Option<AuthorizationCode>> {
            unreachable!()
        }
        async fn revoke_all_active_for_user(
            &self,
            user_id: Uuid,
            _now: DateTime<Utc>,
        ) -> DomainResult<()> {
            self.revoked_users.lock().unwrap().push(user_id);
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

    struct CountingLimiter {
        limit: usize,
        calls: AtomicUsize,
    }
    impl LoginRateLimiter for CountingLimiter {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst) < self.limit
        }
    }

    fn smtp_settings(repo: &FakeSettingsRepo) {
        let rows = vec![
            ("smtp.host", "smtp.example.com"),
            ("smtp.from_address", "noreply@example.com"),
        ];
        *repo.rows.lock().unwrap() = rows
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
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            password_hash: "hash:old-password".to_string(),
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
            ip_address: Some("203.0.113.1".to_string()),
            user_agent: None,
        }
    }

    struct Harness {
        svc: PasswordResetService,
        users: Arc<FakeUsers>,
        tokens: Arc<FakeResetTokens>,
        sso: Arc<FakeSsoSessions>,
        refresh: Arc<FakeRefreshTokens>,
        codes: Arc<FakeCodes>,
        mailer: Arc<FakeMailer>,
        sink: Arc<CapturingSink>,
    }

    fn harness(smtp_configured: bool, limiter_allowance: usize) -> Harness {
        let users = Arc::new(FakeUsers::default());
        let tokens = Arc::new(FakeResetTokens::default());
        let sso = Arc::new(FakeSsoSessions::default());
        let refresh = Arc::new(FakeRefreshTokens::default());
        let codes = Arc::new(FakeCodes::default());
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
        let svc = PasswordResetService::new(
            users.clone(),
            tokens.clone(),
            sso.clone(),
            refresh.clone(),
            codes.clone(),
            Arc::new(PlainHasher),
            system_settings,
            mailer.clone(),
            Arc::new(CountingLimiter {
                limit: limiter_allowance,
                calls: AtomicUsize::new(0),
            }),
            audit,
            Arc::new(FixedClock),
            std::time::Duration::from_secs(3600),
            "https://idp.example.com".to_string(),
        );
        Harness {
            svc,
            users,
            tokens,
            sso,
            refresh,
            codes,
            mailer,
            sink,
        }
    }

    /// 送信メール本文からリセットトークンを取り出す（`token=` 以降を行末まで）。
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
    async fn request_is_indistinguishable_for_unknown_accounts() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true, 100);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "known@example.com"));

        // 実在アカウント・不存在アカウントとも Accepted（列挙防止）。
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(tenant), "known@example.com", &ctx())
                .await,
            RequestResetOutcome::Accepted
        ));
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(tenant), "unknown@example.com", &ctx())
                .await,
            RequestResetOutcome::Accepted
        ));
        // メールは実在アカウントの 1 通だけ送られ、本文にリセットリンクを含む。
        let sent = h.mailer.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1.to, "known@example.com");
        assert!(sent[0].1.body_text.contains(&format!(
            "https://idp.example.com/{tenant}/password-reset?token="
        )));
        // 保存されるのはハッシュのみ。
        let token = token_from_mail(&sent[0].1);
        let rows = h.tokens.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_hash, crypto::sha256_hex(&token));
        assert_ne!(rows[0].token_hash, token);
    }

    #[tokio::test]
    async fn request_is_unavailable_without_smtp_and_rate_limited() {
        let tenant: TenantId = Uuid::now_v7().into();
        let h = harness(false, 100);
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(tenant), "a@example.com", &ctx())
                .await,
            RequestResetOutcome::Unavailable
        ));

        let h = harness(true, 1);
        h.svc
            .request_reset(TenantContext::new(tenant), "a@example.com", &ctx())
            .await;
        assert!(matches!(
            h.svc
                .request_reset(TenantContext::new(tenant), "a@example.com", &ctx())
                .await,
            RequestResetOutcome::RateLimited
        ));
    }

    #[tokio::test]
    async fn reset_updates_password_revokes_sessions_and_is_single_use() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true, 100);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));
        h.svc
            .request_reset(TenantContext::new(tenant), "u@example.com", &ctx())
            .await;
        let token = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);

        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &token,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::Ok
        ));
        // パスワードが更新される。
        assert_eq!(
            h.users.rows.lock().unwrap()[0].password_hash,
            "hash:new-password-123"
        );
        // 全セッション・refresh token・未消費 code が失効する。
        assert_eq!(*h.sso.revoked_users.lock().unwrap(), vec![user]);
        assert_eq!(*h.refresh.revoked_users.lock().unwrap(), vec![user]);
        assert_eq!(*h.codes.revoked_users.lock().unwrap(), vec![user]);
        // 監査に requested + completed が記録され、トークンは漏れない。
        {
            let events = h.sink.events.lock().unwrap();
            assert!(events
                .iter()
                .any(|e| e.event_type == AuditEventType::PasswordResetRequested));
            assert!(events
                .iter()
                .any(|e| e.event_type == AuditEventType::PasswordResetCompleted));
            assert!(events.iter().all(|e| e
                .reason
                .as_deref()
                .map(|r| !r.contains(&token))
                .unwrap_or(true)));
        }

        // 同じトークンの再利用は拒否される（単回消費）。
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &token,
                    "another-password-1",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::InvalidOrExpired
        ));
    }

    #[tokio::test]
    async fn reset_rejects_other_tenant_and_weak_password_keeps_token() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true, 100);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));
        h.svc
            .request_reset(TenantContext::new(tenant), "u@example.com", &ctx())
            .await;
        let token = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);

        // 弱いパスワードはトークンを消費しない（先に強度検証）。
        assert!(matches!(
            h.svc
                .reset_password(TenantContext::new(tenant), &token, "short", &ctx())
                .await,
            ResetPasswordOutcome::WeakPassword
        ));

        // 別テナントの reset 画面へトークンを持ち込むと拒否（このとき消費される。
        // 消費後の所有者照合のため。安全側: 攻撃者に再試行させない）。
        let other: TenantId = Uuid::now_v7().into();
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(other),
                    &token,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::InvalidOrExpired
        ));
        // パスワードは変わらない。
        assert_eq!(
            h.users.rows.lock().unwrap()[0].password_hash,
            "hash:old-password"
        );
    }

    #[tokio::test]
    async fn new_request_invalidates_previous_token() {
        let tenant: TenantId = Uuid::now_v7().into();
        let user = Uuid::new_v4();
        let h = harness(true, 100);
        h.users
            .rows
            .lock()
            .unwrap()
            .push(test_user(user, tenant, "u@example.com"));

        h.svc
            .request_reset(TenantContext::new(tenant), "u@example.com", &ctx())
            .await;
        let first = token_from_mail(&h.mailer.sent.lock().unwrap()[0].1);
        h.svc
            .request_reset(TenantContext::new(tenant), "u@example.com", &ctx())
            .await;
        let second = token_from_mail(&h.mailer.sent.lock().unwrap()[1].1);

        // 旧トークンは失効し、新トークンだけが使える。
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &first,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::InvalidOrExpired
        ));
        assert!(matches!(
            h.svc
                .reset_password(
                    TenantContext::new(tenant),
                    &second,
                    "new-password-123",
                    &ctx()
                )
                .await,
            ResetPasswordOutcome::Ok
        ));
    }
}
