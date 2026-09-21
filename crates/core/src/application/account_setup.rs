//! アカウント設定のワンタイムリンク（ADR-0062）。
//!
//! 管理者が利用者を作った直後・パスワードを再発行した直後に渡す「1 回だけ開けるリンク」の、
//! **発行**と**消費**をここに閉じる。渡し方は管理者の手（画面に出たリンクを共有する）で、
//! メールは前提にしない —— 送信が整っていない環境でも、作ったその場で渡せる必要がある。
//!
//! リンク先でできることは 2 つ。**どちらか一方で完了**し、その時点でリンクは死ぬ。
//!
//! 1. **パスキーを登録する**（主）。以後その利用者はパスワードを知らないまま入れる
//!    （パスキーのログイン経路は `must_change_password` を見ない）。
//! 2. **パスワードを設定する**。実体は忘失時の再設定と同じ経路
//!    （[`crate::application::password_reset::PasswordResetService::reset_password`]）で、
//!    トークンの表が同じなのでそのまま通る。
//!
//! ⚠ **開いただけでは消費しない。** チャットに貼ったリンクは、相手より先にプレビューの bot が
//! 取りに来る（過去にワンタイムリンクを 1 本食われた）。消費するのは実際に資格情報を決める
//! 操作だけで、[`AccountSetupService::describe`] は読むだけである。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::passkey_registration::{
    PasskeyRegistrationError, PasskeyRegistrationService,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::password_reset::{PasswordResetToken, ResetPurpose};
use crate::domain::repositories::{PasswordResetTokenRepository, UserRepository};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// リンクのトークンのバイト長（base64url で 43 文字程度。再設定リンクと同じ）。
const SETUP_TOKEN_BYTES: usize = 32;

/// 発行したリンク。`token` は平文で、**この一度だけ**返す（保存はハッシュのみ）。
#[derive(Debug, Clone)]
pub struct SetupLink {
    pub token: String,
    /// 本人へ渡す絶対 URL。**リンクの形を決めるのはここ 1 か所**にする（画面も機械も同じ値を配る）。
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

/// リンクを開いた画面が出す中身（消費しない）。
#[derive(Debug, Clone)]
pub struct SetupLinkView {
    pub user_id: Uuid,
    /// 誰のリンクかを画面に出す。リンクの持ち主にしか見えない（トークンが鍵）。
    pub email: String,
    pub purpose: ResetPurpose,
    pub expires_at: DateTime<Utc>,
}

impl SetupLinkView {
    /// この画面でパスキーを登録してよいか（用途で決まる）。
    pub fn allows_passkey_registration(&self) -> bool {
        self.purpose.allows_passkey_registration()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountSetupError {
    /// 不存在・期限切れ・使用済み・テナント違い・利用者が ACTIVE でない。**言い分けない**
    /// （どれなのかを返すと、リンクを拾った相手に当たりを与える）。
    #[error("invalid or expired setup link")]
    InvalidOrExpired,
    /// この用途のリンクでは許していない操作（`reset` のリンクでパスキーを登録しようとした等）。
    #[error("not allowed for this link")]
    NotAllowed,
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<PasskeyRegistrationError> for AccountSetupError {
    fn from(e: PasskeyRegistrationError) -> Self {
        match e {
            PasskeyRegistrationError::ChallengeNotFound => AccountSetupError::InvalidOrExpired,
            PasskeyRegistrationError::InvalidCredential(m)
            | PasskeyRegistrationError::Internal(m) => AccountSetupError::InvalidCredential(m),
            PasskeyRegistrationError::DuplicateCredential => {
                AccountSetupError::InvalidCredential("duplicate credential".to_string())
            }
            PasskeyRegistrationError::SessionExpired | PasskeyRegistrationError::NotFound => {
                AccountSetupError::InvalidOrExpired
            }
        }
    }
}

/// リンクを**出す**側（管理者の操作の一部として呼ばれる）。
///
/// 出すのに要るのはトークンの表と寿命だけで、パスキーも利用者の読み出しも要らない。
/// ⚠ **消費する側と型を分ける**のは、出すだけの利用者作成に WebAuthn 一式を引きずらせないため。
pub struct AccountSetupLinkIssuer {
    tokens: Arc<dyn PasswordResetTokenRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    clock: Arc<dyn Clock>,
    /// リンクの土台となる公開ベース URL（web 画面。末尾スラッシュ無し）。
    console_base_url: String,
}

/// リンクを**使う**側（本人が開いた画面から呼ばれる）。
/// このユースケースが要るのは「本人性を確かめた利用者へパスキーを 1 本足す」ことだけである。
///
/// WebAuthn 一式（`PasskeyRegistrationService`）をそのまま抱えると、リンクを読むだけの試験まで
/// 認証器・チャレンジ・SSO セッションのフェイクを要求することになる。要るところだけを
/// トレイトで受ける（CLAUDE.md の DIP）。
#[async_trait::async_trait]
pub trait PasskeyEnrollment: Send + Sync {
    async fn begin(
        &self,
        user_id: Uuid,
        user_name: &str,
    ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError>;
    async fn complete(
        &self,
        user_id: Uuid,
        challenge_id: Uuid,
        name: &str,
        credential: serde_json::Value,
    ) -> Result<(), PasskeyRegistrationError>;
}

#[async_trait::async_trait]
impl PasskeyEnrollment for PasskeyRegistrationService {
    async fn begin(
        &self,
        user_id: Uuid,
        user_name: &str,
    ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError> {
        self.begin_for_user(user_id, user_name).await
    }

    async fn complete(
        &self,
        user_id: Uuid,
        challenge_id: Uuid,
        name: &str,
        credential: serde_json::Value,
    ) -> Result<(), PasskeyRegistrationError> {
        self.complete_for_user(user_id, challenge_id, name, credential)
            .await?;
        Ok(())
    }
}

pub struct AccountSetupService {
    users: Arc<dyn UserRepository>,
    tokens: Arc<dyn PasswordResetTokenRepository>,
    passkeys: Arc<dyn PasskeyEnrollment>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountSetupLinkIssuer {
    pub fn new(
        tokens: Arc<dyn PasswordResetTokenRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        clock: Arc<dyn Clock>,
        console_base_url: String,
    ) -> Self {
        Self {
            tokens,
            settings,
            clock,
            console_base_url: console_base_url.trim_end_matches('/').to_string(),
        }
    }

    /// 設定リンクを発行する（管理者の操作の一部として呼ばれる）。
    ///
    /// **その利用者の未使用リンクは、発行のたびに失効させる。** 生きたリンクが同時に 2 本ある
    /// と、どれを渡したかが分からなくなり、渡し間違いを止める手段も無くなる（再設定と同じ規則）。
    pub async fn issue(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
    ) -> Result<SetupLink, AccountSetupError> {
        let now = self.clock.now();
        let ttl = self
            .settings
            .account_setup_ttl(tenant_id)
            .await
            .map_err(|e| AccountSetupError::Internal(e.to_string()))?;

        self.tokens
            .invalidate_all_for_user(user_id, now)
            .await
            .map_err(|e| AccountSetupError::Internal(e.to_string()))?;

        let token = crypto::random_token(SETUP_TOKEN_BYTES);
        let expires_at = now + ttl;
        let record = PasswordResetToken {
            token_hash: crypto::sha256_hex(&token),
            user_id,
            purpose: ResetPurpose::Setup,
            expires_at,
            used_at: None,
            created_at: now,
        };
        self.tokens
            .create(&record)
            .await
            .map_err(|e| AccountSetupError::Internal(e.to_string()))?;

        let url = format!(
            "{}/{}/account-setup?token={}",
            self.console_base_url, tenant_id, token
        );
        Ok(SetupLink {
            token,
            url,
            expires_at,
        })
    }
}

impl AccountSetupService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        tokens: Arc<dyn PasswordResetTokenRepository>,
        passkeys: Arc<dyn PasskeyEnrollment>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            tokens,
            passkeys,
            audit,
            clock,
        }
    }

    /// リンクの中身を読む（**消費しない**）。
    pub async fn describe(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<SetupLinkView, AccountSetupError> {
        let (record, user) = self.resolve(tenant, token).await?;
        Ok(SetupLinkView {
            user_id: user.id,
            email: user.email,
            purpose: record.purpose,
            expires_at: record.expires_at,
        })
    }

    /// パスキー登録の開始。⚠ **ここではまだトークンを消費しない**（登録が終わらなかった相手を
    /// リンクごと締め出さないため。消費は [`Self::complete_passkey`] で行う）。
    pub async fn begin_passkey(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<(Uuid, serde_json::Value), AccountSetupError> {
        let (record, user) = self.resolve(tenant, token).await?;
        if !record.purpose.allows_passkey_registration() {
            return Err(AccountSetupError::NotAllowed);
        }
        // 認証器に出す名前は、本人が自分のアカウントだと分かる値にする（メールアドレス）。
        let options = self.passkeys.begin(user.id, &user.email).await?;
        Ok(options)
    }

    /// パスキー登録の完了。成功したらリンクを消費する（1 本のリンクで登録できるのは 1 つ）。
    pub async fn complete_passkey(
        &self,
        tenant: TenantContext,
        token: &str,
        challenge_id: Uuid,
        name: &str,
        credential: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<(), AccountSetupError> {
        let (record, user) = self.resolve(tenant, token).await?;
        if !record.purpose.allows_passkey_registration() {
            return Err(AccountSetupError::NotAllowed);
        }

        self.passkeys
            .complete(user.id, challenge_id, name, credential)
            .await?;

        // ⚠ **登録が通ってから消費する。** 先に消費すると、認証器の側で断られた相手が
        // リンクも失って手詰まりになる（管理者に出し直してもらうしかなくなる）。
        let now = self.clock.now();
        if let Err(e) = self.tokens.consume(&crypto::sha256_hex(token), now).await {
            // 登録は済んでいる。消費に失敗してもリンクは期限で切れるので、ここでは落とさない。
            tracing::warn!(error = %e, "failed to consume the setup link after registering a passkey");
        }

        self.audit
            .record(
                AuditEventType::AccountSetupCompleted,
                AuditResult::Success,
                Some(user.tenant_id),
                Some(user.id),
                None,
                Some("method=passkey"),
                ctx,
            )
            .await;
        Ok(())
    }

    /// トークンから「未使用・期限内・テナントが一致・ACTIVE な利用者」を解決する。
    ///
    /// ⚠ 断る理由を分けない（[`AccountSetupError::InvalidOrExpired`] のコメント参照）。
    async fn resolve(
        &self,
        tenant: TenantContext,
        token: &str,
    ) -> Result<(PasswordResetToken, User), AccountSetupError> {
        if token.is_empty() {
            return Err(AccountSetupError::InvalidOrExpired);
        }
        let now = self.clock.now();
        let record = self
            .tokens
            .find_active(&crypto::sha256_hex(token), now)
            .await
            .map_err(|e| AccountSetupError::Internal(e.to_string()))?
            .ok_or(AccountSetupError::InvalidOrExpired)?;

        // リンクの経路（テナント）と所属元が一致すること。他テナントの画面へ持ち込ませない。
        match self.users.find_by_id(record.user_id).await {
            Ok(Some(user)) if user.is_active() && user.tenant_id == tenant.tenant_id() => {
                Ok((record, user))
            }
            Ok(_) => Err(AccountSetupError::InvalidOrExpired),
            Err(e) => Err(AccountSetupError::Internal(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{link_issuer, FakeSetupTokens};
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use chrono::TimeZone;
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 21, 9, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[derive(Default)]
    struct SilentSink;
    #[async_trait::async_trait]
    impl AuditLogSink for SilentSink {
        async fn record(&self, _event: &AuditEvent) -> DomainResult<()> {
            Ok(())
        }
    }

    /// 呼ばれた回数だけ覚える（本物の WebAuthn は要らない。トレイトで切ってある）。
    #[derive(Default)]
    struct FakePasskeys {
        completed: Mutex<Vec<Uuid>>,
    }
    #[async_trait::async_trait]
    impl PasskeyEnrollment for FakePasskeys {
        async fn begin(
            &self,
            _user_id: Uuid,
            _user_name: &str,
        ) -> Result<(Uuid, serde_json::Value), PasskeyRegistrationError> {
            Ok((Uuid::new_v4(), serde_json::json!({ "publicKey": {} })))
        }
        async fn complete(
            &self,
            user_id: Uuid,
            _challenge_id: Uuid,
            _name: &str,
            _credential: serde_json::Value,
        ) -> Result<(), PasskeyRegistrationError> {
            self.completed.lock().unwrap().push(user_id);
            Ok(())
        }
    }

    struct FakeUsers(Mutex<Vec<User>>);
    #[async_trait::async_trait]
    impl UserRepository for FakeUsers {
        async fn create(&self, _user: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self.0.lock().unwrap().iter().find(|u| u.id == id).cloned())
        }
        async fn find_by_sub(&self, _sub: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(
            &self,
            _tenant_id: TenantId,
            _email: &str,
        ) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(
            &self,
            _tenant_id: TenantId,
            _username: &str,
        ) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: DateTime<Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
        // この試験が通らない口（資格情報の書き換えはリンクの経路の外）。
        async fn update_login_state(
            &self,
            _id: Uuid,
            _failed_login_count: i32,
            _locked_until: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_password(
            &self,
            _id: Uuid,
            _expected_current_hash: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected_current_hash: &str,
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
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn user(tenant: TenantId) -> User {
        User {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            sub: Uuid::new_v4(),
            email: "newbie@example.com".to_string(),
            email_verified: false,
            preferred_username: None,
            name: None,
            language: None,
            theme: None,
            password_hash: "nobody-knows".to_string(),
            must_change_password: true,
            password_changed_at: None,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        }
    }

    struct Fixture {
        service: AccountSetupService,
        tokens: Arc<FakeSetupTokens>,
        passkeys: Arc<FakePasskeys>,
        tenant: TenantId,
        user_id: Uuid,
    }

    async fn fixture() -> (Fixture, String) {
        let tenant: TenantId = Uuid::now_v7().into();
        let person = user(tenant);
        let user_id = person.id;
        let tokens = Arc::new(FakeSetupTokens::default());
        let passkeys = Arc::new(FakePasskeys::default());
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(now()));
        let link = link_issuer(tokens.clone(), clock.clone())
            .issue(tenant, user_id)
            .await
            .expect("link issued");
        let service = AccountSetupService::new(
            Arc::new(FakeUsers(Mutex::new(vec![person]))),
            tokens.clone(),
            passkeys.clone(),
            Arc::new(AuditService::new(Arc::new(SilentSink), clock.clone())),
            clock,
        );
        (
            Fixture {
                service,
                tokens,
                passkeys,
                tenant,
                user_id,
            },
            link.token,
        )
    }

    /// リンクを開くと、誰のものかとできることが分かる。
    #[tokio::test]
    async fn a_setup_link_tells_who_it_belongs_to() {
        let (f, token) = fixture().await;
        let view = f
            .service
            .describe(TenantContext::new(f.tenant), &token)
            .await
            .expect("described");
        assert_eq!(view.email, "newbie@example.com");
        assert!(view.allows_passkey_registration());
    }

    /// ⚠ **開いただけでは消費しない。** チャットのプレビュー bot が先に取りに来ても、本人が
    /// 開いたときリンクは生きている（過去に 1 本食われた）。
    #[tokio::test]
    async fn opening_the_link_does_not_consume_it() {
        let (f, token) = fixture().await;
        for _ in 0..3 {
            f.service
                .describe(TenantContext::new(f.tenant), &token)
                .await
                .expect("still open");
        }
        assert!(f.tokens.rows.lock().unwrap()[0].used_at.is_none());
    }

    /// パスキーを登録し終えるとリンクは死ぬ（1 本のリンクで登録できるのは 1 つ）。
    #[tokio::test]
    async fn finishing_a_passkey_consumes_the_link() {
        let (f, token) = fixture().await;
        let ctx = RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        };
        f.service
            .complete_passkey(
                TenantContext::new(f.tenant),
                &token,
                Uuid::new_v4(),
                "This device",
                serde_json::json!({}),
                &ctx,
            )
            .await
            .expect("registered");
        assert_eq!(f.passkeys.completed.lock().unwrap().as_slice(), [f.user_id]);

        assert!(matches!(
            f.service
                .describe(TenantContext::new(f.tenant), &token)
                .await,
            Err(AccountSetupError::InvalidOrExpired)
        ));
    }

    /// 別テナントの画面へ持ち込んでも通らない。
    #[tokio::test]
    async fn a_link_does_not_work_on_another_tenants_screen() {
        let (f, token) = fixture().await;
        let other: TenantId = Uuid::now_v7().into();
        assert!(matches!(
            f.service.describe(TenantContext::new(other), &token).await,
            Err(AccountSetupError::InvalidOrExpired)
        ));
    }

    /// ⚠ **忘失時の再設定リンクではパスキーを登録させない**（ADR-0062 の決定 2）。
    #[tokio::test]
    async fn a_password_reset_link_may_not_add_a_passkey() {
        let (f, _) = fixture().await;
        // 同じ利用者に「再設定」用途のトークンを 1 本置く。
        let token = "reset-token-plain";
        f.tokens
            .create(&PasswordResetToken {
                token_hash: crypto::sha256_hex(token),
                user_id: f.user_id,
                purpose: ResetPurpose::Reset,
                expires_at: now() + chrono::Duration::hours(1),
                used_at: None,
                created_at: now(),
            })
            .await
            .unwrap();

        assert!(matches!(
            f.service
                .begin_passkey(TenantContext::new(f.tenant), token)
                .await,
            Err(AccountSetupError::NotAllowed)
        ));
    }
}

/// 試験用の組み立て。
///
/// リンクを**出す**側は、利用者作成・パスワード再発行のユースケースが抱えている。それらの
/// 試験にトークンの表のフェイクを毎回書かせないよう、ここに 1 つ置く。
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::domain::error::Result as DomainResult;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// 発行したトークンを覚えておくだけのフェイク（消費・失効も素直に写す）。
    #[derive(Default)]
    pub struct FakeSetupTokens {
        pub rows: Mutex<Vec<PasswordResetToken>>,
    }

    #[async_trait]
    impl PasswordResetTokenRepository for FakeSetupTokens {
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
            let Some(row) = rows.iter_mut().find(|r| {
                r.token_hash == token_hash && r.used_at.is_none() && r.expires_at > used_at
            }) else {
                return Ok(None);
            };
            row.used_at = Some(used_at);
            Ok(Some(row.clone()))
        }

        async fn find_active(
            &self,
            token_hash: &str,
            now: DateTime<Utc>,
        ) -> DomainResult<Option<PasswordResetToken>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.token_hash == token_hash && r.used_at.is_none() && r.expires_at > now)
                .cloned())
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

    /// 既定の寿命で動く発行側（`https://idp.example.com` のリンクを作る）。
    pub fn link_issuer(
        tokens: Arc<FakeSetupTokens>,
        clock: Arc<dyn Clock>,
    ) -> Arc<AccountSetupLinkIssuer> {
        Arc::new(AccountSetupLinkIssuer::new(
            tokens,
            crate::application::tenant_settings::testing::tenant_settings_with_global(&[(
                "ACCOUNT_SETUP_TTL_SECS",
                "86400",
            )]),
            clock,
            "https://idp.example.com".to_string(),
        ))
    }
}
