//! Step-up 認証のユースケース（AP5。ユーザー認証・認証ポリシー仕様書 §15）。
//!
//! 重要操作（パスワード変更・認証器の追加削除・外部 IdP の紐付け・セッション失効）の直前に
//! 「今この操作をしてよいと確認できているか」を判定し、足りなければ本人確認をやり直させる。
//!
//! 判定（[`crate::domain::step_up::evaluate_step_up`]）はドメインの純粋関数で、本サービスは
//! SSO セッションと利用者の認証器の有無を集めて渡す係と、確認が通ったときに SSO セッションへ
//! 記録する係を担う。
//!
//! # 検証の順序
//!
//! パスワードは必ず検証する（step-up の起点は常に「本人しか知らないもの」）。第二要素は
//! 要件が多要素のときだけ追加で検証する。パスワードを飛ばして TOTP だけで通せる作りにすると、
//! 端末を拾った攻撃者が本人確認を通せてしまう。
//!
//! # 総当たり対策
//!
//! step-up はログイン画面と同じく資格情報を受け取る入口なので、ログインと同じ IP レート制限器を
//! 共有する（別枠にすると、ログインで締め出された攻撃者が step-up 経由で試行を続けられる）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::application::totp_registration::verify_totp_code;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::PasswordHasher;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{SsoSessionRepository, TotpSecretRepository, UserRepository};
use crate::domain::step_up::{
    evaluate_step_up, SensitiveOperation, StepUpDecision, StepUpRequirement,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::{AuthenticationMethod, AuthenticationStrength};
use std::sync::Arc;

/// 「この操作を今してよいか」の判定結果（画面が次にどう振る舞うかを決める）。
pub enum StepUpCheckOutcome {
    /// 要件を満たしている。操作を続けてよい。
    Satisfied,
    /// 本人確認をやり直す必要がある。`second_factor_required` が真なら TOTP まで求める。
    ChallengeRequired {
        second_factor_required: bool,
    },
    /// SSO セッションが無い・期限切れ・利用者が無効。
    SessionExpired,
    Internal(String),
}

pub struct StepUpVerifyCommand {
    /// SSO セッション Cookie の生値。
    pub sso_session_id: String,
    /// 対象の重要操作（要件の決定と監査に使う）。
    pub operation: SensitiveOperation,
    pub password: String,
    /// TOTP コード（第二要素を求められている場合のみ必須）。
    pub totp_code: Option<String>,
}

pub enum StepUpVerifyOutcome {
    /// 確認できた。SSO セッションへ記録済みで、続けて操作してよい。
    Ok,
    /// パスワードまたは TOTP が不一致（どちらが違うかは返さない）。
    InvalidCredentials,
    /// 第二要素が要るのにコードが提示されていない。画面は TOTP 入力欄を出す。
    SecondFactorRequired,
    /// IP 単位のレート制限超過。
    RateLimited,
    SessionExpired,
    Internal(String),
}

pub struct StepUpService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
    /// 直近の本人確認からこの秒数を超えたら再確認を求める（設定注入）。
    max_age_secs: u64,
}

impl StepUpService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
        max_age_secs: u64,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            totp_secrets,
            hasher,
            rate_limiter,
            audit,
            clock,
            key_encryption_key,
            max_age_secs,
        }
    }

    /// 重要操作の直前に呼び、step-up が要るかを判定する。
    pub async fn check(
        &self,
        sso_session_id: &str,
        operation: SensitiveOperation,
    ) -> StepUpCheckOutcome {
        let now = self.clock.now();
        let session_hash = crypto::sha256_hex(sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return StepUpCheckOutcome::SessionExpired,
            Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
        };
        match self.users.find_by_id(session.user_id).await {
            Ok(Some(u)) if u.is_active() => {}
            Ok(_) => return StepUpCheckOutcome::SessionExpired,
            Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
        }

        let has_second_factor =
            match user_has_confirmed_totp(self.totp_secrets.as_ref(), session.user_id).await {
                Ok(v) => v,
                Err(e) => return StepUpCheckOutcome::Internal(e.to_string()),
            };
        let requirement =
            StepUpRequirement::for_operation(operation, self.max_age_secs, has_second_factor);

        match evaluate_step_up(&session, session.step_up_at, requirement, now) {
            StepUpDecision::Satisfied => StepUpCheckOutcome::Satisfied,
            StepUpDecision::ReauthenticationRequired => StepUpCheckOutcome::ChallengeRequired {
                second_factor_required: requirement.required_strength
                    == AuthenticationStrength::MultiFactor,
            },
            StepUpDecision::SecondFactorRequired => StepUpCheckOutcome::ChallengeRequired {
                second_factor_required: true,
            },
        }
    }

    /// 本人確認をやり直し、通ったら SSO セッションへ記録する。
    pub async fn verify(
        &self,
        tenant: TenantContext,
        cmd: StepUpVerifyCommand,
        ctx: &RequestContext,
    ) -> StepUpVerifyOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. IP 単位のレート制限（ログインと同じ枠を消費する）。
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                return StepUpVerifyOutcome::RateLimited;
            }
        }

        // 2. セッションから本人を解決する。
        let session_hash = crypto::sha256_hex(&cmd.sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return StepUpVerifyOutcome::SessionExpired,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };
        let user = match self.users.find_by_id(session.user_id).await {
            Ok(Some(u)) if u.is_active() && !u.is_locked_at(now) => u,
            Ok(_) => return StepUpVerifyOutcome::SessionExpired,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };

        // 3. パスワード検証（step-up の起点は常にこれ）。
        let password_ok = match self.hasher.verify(&cmd.password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
        };
        if !password_ok {
            self.record_failure(tenant, cmd.operation, user.id, "invalid_password", ctx)
                .await;
            return StepUpVerifyOutcome::InvalidCredentials;
        }

        // 4. 要件に応じて第二要素も検証する。
        let has_second_factor =
            match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
                Ok(v) => v,
                Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
            };
        let requirement =
            StepUpRequirement::for_operation(cmd.operation, self.max_age_secs, has_second_factor);
        let mut methods = vec![AuthenticationMethod::Password];

        if requirement.required_strength == AuthenticationStrength::MultiFactor {
            let Some(code) = cmd.totp_code.as_deref().filter(|c| !c.is_empty()) else {
                return StepUpVerifyOutcome::SecondFactorRequired;
            };
            let record = match self.totp_secrets.find_by_user_id(user.id).await {
                Ok(Some(r)) if r.is_confirmed() => r,
                // 要件が多要素なのに認証器が消えている（並行して削除された）ときは通さない。
                Ok(_) => return StepUpVerifyOutcome::SecondFactorRequired,
                Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
            };
            let secret = match crypto::decrypt(&record.secret_encrypted, &self.key_encryption_key) {
                Ok(b) => b,
                Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
            };
            let code_ok = match verify_totp_code(&secret, code) {
                Ok(v) => v,
                Err(e) => return StepUpVerifyOutcome::Internal(e.to_string()),
            };
            if !code_ok {
                self.record_failure(tenant, cmd.operation, user.id, "invalid_totp", ctx)
                    .await;
                return StepUpVerifyOutcome::InvalidCredentials;
            }
            methods.push(AuthenticationMethod::Totp);
        }

        // 5. 記録する。単一要素の再確認では強度・MFA の鮮度は動かさない（実装は repository 側）。
        if let Err(e) = self
            .sso_sessions
            .record_step_up(&session_hash, &methods, now)
            .await
        {
            return StepUpVerifyOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::StepUpSucceeded,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                Some(&format!("operation={}", cmd.operation.as_str())),
                ctx,
            )
            .await;
        StepUpVerifyOutcome::Ok
    }

    async fn record_failure(
        &self,
        tenant: TenantContext,
        operation: SensitiveOperation,
        user_id: uuid::Uuid,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::StepUpFailed,
                AuditResult::Failure,
                Some(tenant.tenant_id()),
                Some(user_id),
                None,
                Some(&format!("operation={} reason={reason}", operation.as_str())),
                ctx,
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::sso_session::SsoSession;
    use crate::domain::tenant::TenantId;
    use crate::domain::totp_secret::TotpSecret;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use std::sync::Mutex;
    use uuid::Uuid;

    const COOKIE: &str = "sso-cookie";
    const KEY: [u8; 32] = [3u8; 32];

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
    }

    fn tenant() -> TenantContext {
        TenantContext::new(TenantId::from(Uuid::from_u128(9)))
    }

    struct FixedClock;
    impl Clock for FixedClock {
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

    struct AllowAll;
    impl LoginRateLimiter for AllowAll {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct DiscardingSink;
    #[async_trait]
    impl AuditLogSink for DiscardingSink {
        async fn record(&self, _e: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
            Ok(())
        }
    }

    struct FakeSessions {
        row: Mutex<SsoSession>,
        step_ups: Mutex<Vec<Vec<AuthenticationMethod>>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, hash: &str) -> DomainResult<Option<SsoSession>> {
            let row = self.row.lock().unwrap();
            Ok((row.session_hash == hash).then(|| row.clone()))
        }
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn record_step_up(
            &self,
            _h: &str,
            methods: &[AuthenticationMethod],
            verified_at: DateTime<Utc>,
        ) -> DomainResult<()> {
            self.step_ups.lock().unwrap().push(methods.to_vec());
            let mut row = self.row.lock().unwrap();
            row.step_up_at = Some(verified_at);
            if AuthenticationStrength::from_methods(methods) == AuthenticationStrength::MultiFactor
            {
                row.mfa_completed_at = Some(verified_at);
            }
            Ok(())
        }
        async fn delete(&self, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct FakeUsers;
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// このテストはログイン失敗経路を通らない（SEC13 の検証は login / mfa_login にある）。
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(Some(User {
                id,
                tenant_id: TenantId::from(Uuid::from_u128(9)),
                sub: Uuid::from_u128(3),
                email: "u@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("u".to_string()),
                name: None,
                language: None,
                password_hash: "hash:correct".to_string(),
                must_change_password: false,
                password_changed_at: None,
                status: UserStatus::Active,
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
        async fn update_password(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn reset_password_forced(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
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

    struct FakeTotp {
        confirmed: bool,
    }
    #[async_trait]
    impl TotpSecretRepository for FakeTotp {
        async fn upsert(&self, _s: &TotpSecret) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_user_id(&self, user_id: Uuid) -> DomainResult<Option<TotpSecret>> {
            Ok(self.confirmed.then(|| TotpSecret {
                user_id,
                secret_encrypted: crypto::encrypt(b"12345678901234567890", &KEY).expect("encrypt"),
                confirmed_at: Some(now()),
                created_at: now(),
                updated_at: now(),
            }))
        }
        async fn confirm(&self, _u: Uuid, _c: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn service(session: SsoSession, has_totp: bool) -> (StepUpService, Arc<FakeSessions>) {
        let sessions = Arc::new(FakeSessions {
            row: Mutex::new(session),
            step_ups: Mutex::new(Vec::new()),
        });
        let clock: Arc<dyn Clock> = Arc::new(FixedClock);
        let service = StepUpService::new(
            sessions.clone(),
            Arc::new(FakeUsers),
            Arc::new(FakeTotp {
                confirmed: has_totp,
            }),
            Arc::new(PlainHasher),
            Arc::new(AllowAll),
            Arc::new(AuditService::new(Arc::new(DiscardingSink), clock.clone())),
            clock,
            KEY,
            300,
        );
        (service, sessions)
    }

    fn session(methods: Vec<AuthenticationMethod>, age: Duration) -> SsoSession {
        let mut s = SsoSession::establish(
            crypto::sha256_hex(COOKIE),
            Uuid::from_u128(1),
            now() - age,
            Duration::hours(1),
            Duration::hours(8),
            methods,
            None,
            None,
        );
        s.idle_expires_at = now() + Duration::hours(1);
        s.absolute_expires_at = now() + Duration::hours(8);
        s
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "t".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    /// ログイン直後は step-up 済み。すぐに再入力を求めない。
    #[tokio::test]
    async fn a_fresh_session_satisfies_a_password_level_operation() {
        let (svc, _) = service(
            session(vec![AuthenticationMethod::Password], Duration::zero()),
            false,
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::Satisfied
        ));
    }

    /// 認証器を持つ利用者の「認証器管理」は、単一要素のセッションでは通さない。
    #[tokio::test]
    async fn managing_authenticators_needs_the_second_factor() {
        let (svc, _) = service(
            session(vec![AuthenticationMethod::Password], Duration::zero()),
            true,
        );
        let StepUpCheckOutcome::ChallengeRequired {
            second_factor_required,
        } = svc
            .check(COOKIE, SensitiveOperation::ManageAuthenticators)
            .await
        else {
            panic!("expected a challenge");
        };
        assert!(second_factor_required);
    }

    /// 認証器を持たない利用者には第二要素を求めない（求めても通せないため）。
    #[tokio::test]
    async fn managing_authenticators_without_an_enrolled_one_stays_single_factor() {
        let (svc, _) = service(
            session(vec![AuthenticationMethod::Password], Duration::zero()),
            false,
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ManageAuthenticators)
                .await,
            StepUpCheckOutcome::Satisfied
        ));
    }

    /// 古いセッションは再確認を求める。パスワードが通れば `step_up_at` が進み、以後は満たす。
    #[tokio::test]
    async fn a_stale_session_is_refreshed_by_a_password_step_up() {
        let (svc, sessions) = service(
            session(vec![AuthenticationMethod::Password], Duration::hours(4)),
            false,
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::ChallengeRequired {
                second_factor_required: false
            }
        ));

        let outcome = svc
            .verify(
                tenant(),
                StepUpVerifyCommand {
                    sso_session_id: COOKIE.to_string(),
                    operation: SensitiveOperation::ChangePassword,
                    password: "correct".to_string(),
                    totp_code: None,
                },
                &ctx(),
            )
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::Ok));
        assert_eq!(
            *sessions.step_ups.lock().unwrap(),
            vec![vec![AuthenticationMethod::Password]]
        );
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::Satisfied
        ));
    }

    #[tokio::test]
    async fn a_wrong_password_does_not_refresh_the_session() {
        let (svc, sessions) = service(
            session(vec![AuthenticationMethod::Password], Duration::hours(4)),
            false,
        );
        let outcome = svc
            .verify(
                tenant(),
                StepUpVerifyCommand {
                    sso_session_id: COOKIE.to_string(),
                    operation: SensitiveOperation::ChangePassword,
                    password: "wrong".to_string(),
                    totp_code: None,
                },
                &ctx(),
            )
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::InvalidCredentials));
        assert!(sessions.step_ups.lock().unwrap().is_empty());
    }

    /// 第二要素が要る操作で TOTP を省いた要求は、パスワードが正しくても通さない。
    #[tokio::test]
    async fn a_multi_factor_operation_rejects_a_password_only_step_up() {
        let (svc, sessions) = service(
            session(vec![AuthenticationMethod::Password], Duration::zero()),
            true,
        );
        let outcome = svc
            .verify(
                tenant(),
                StepUpVerifyCommand {
                    sso_session_id: COOKIE.to_string(),
                    operation: SensitiveOperation::ManageAuthenticators,
                    password: "correct".to_string(),
                    totp_code: None,
                },
                &ctx(),
            )
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::SecondFactorRequired));
        assert!(sessions.step_ups.lock().unwrap().is_empty());
    }

    /// セッションが切れていれば、正しいパスワードでも通さない。
    #[tokio::test]
    async fn an_expired_session_cannot_step_up() {
        let mut expired = session(vec![AuthenticationMethod::Password], Duration::hours(4));
        expired.idle_expires_at = now() - Duration::minutes(1);
        let (svc, _) = service(expired, false);
        assert!(matches!(
            svc.check(COOKIE, SensitiveOperation::ChangePassword).await,
            StepUpCheckOutcome::SessionExpired
        ));
        let outcome = svc
            .verify(
                tenant(),
                StepUpVerifyCommand {
                    sso_session_id: COOKIE.to_string(),
                    operation: SensitiveOperation::ChangePassword,
                    password: "correct".to_string(),
                    totp_code: None,
                },
                &ctx(),
            )
            .await;
        assert!(matches!(outcome, StepUpVerifyOutcome::SessionExpired));
    }
}
