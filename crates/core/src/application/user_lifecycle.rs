//! 管理者による利用者ライフサイクル操作（無効化・有効化・削除・パスワード再発行。ADR-0009 §5）。
//!
//! 操作対象は**所属元（HOME）が要求テナントの利用者のみ**（`users.tenant_id` 照合。ゲストの
//! `users` レコードは所属元テナントの管理者だけが操作できる。§3）。自分自身への操作は禁止する
//! （誤操作によるロックアウト防止。パスワード変更はセルフサービスを使う）。
//!
//! パスワード再発行は作成時と同じ方針（[`crate::application::user_management`]）: 32 文字以上の
//! ランダムパスワードを自動生成し、`must_change_password = true` を設定する。生成パスワードは
//! **その応答でのみ**平文で返し、ログ・監査には出さない。再発行・無効化時は当該利用者の
//! SSO セッション・refresh token・未消費 authorization code を全失効させる。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::{
    AuthorizationCodeRepository, RefreshTokenRepository, SsoSessionRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::values::UserStatus;
use std::sync::Arc;
use uuid::Uuid;

/// 自動生成パスワードのバイト長（base64url で 43 文字。ADR-0009 §5 の「32 文字以上」を満たす）。
const GENERATED_PASSWORD_BYTES: usize = 32;

/// パスワード再発行の結果。`generated_password` は**この一度だけ**平文で返す。
pub struct ResetUserPassword {
    pub user_id: Uuid,
    pub generated_password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UserLifecycleError {
    #[error("user not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("internal error: {0}")]
    Internal(String),
}

fn internal(e: crate::domain::error::DomainError) -> UserLifecycleError {
    UserLifecycleError::Internal(e.to_string())
}

pub struct UserLifecycleService {
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl UserLifecycleService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            users,
            sso_sessions,
            refresh_tokens,
            codes,
            hasher,
            audit,
            clock,
        }
    }

    /// 利用者のパスワードを再発行する（内部 ID 指定）。生成パスワードを一度だけ返す。
    pub async fn reset_password(
        &self,
        tenant: TenantContext,
        target: Uuid,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<ResetUserPassword, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        self.ensure_not_self(user.id, actor)?;
        self.reset_password_for(tenant, &user, actor, ctx).await
    }

    /// 利用者のパスワードを再発行する（メールアドレス指定。テナント管理コンソールが子テナントの
    /// 管理者を対象に使う）。`tenant` は**対象利用者の所属元テナント**を渡す。
    pub async fn reset_password_by_email(
        &self,
        tenant: TenantContext,
        email: &str,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<ResetUserPassword, UserLifecycleError> {
        let email = email.trim();
        if email.is_empty() {
            return Err(UserLifecycleError::Validation("email is required".into()));
        }
        let user = self
            .users
            .find_by_email(tenant.tenant_id(), email)
            .await
            .map_err(internal)?
            .ok_or(UserLifecycleError::NotFound)?;
        self.ensure_not_self(user.id, actor)?;
        self.reset_password_for(tenant, &user, actor, ctx).await
    }

    /// 利用者の状態を変更する（有効化・無効化）。`LOCKED` はログイン失敗ロック専用のため
    /// 管理操作では設定できない。無効化時は全セッション・トークンを失効させる。
    pub async fn set_status(
        &self,
        tenant: TenantContext,
        target: Uuid,
        status: UserStatus,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), UserLifecycleError> {
        if status == UserStatus::Locked {
            return Err(UserLifecycleError::Validation(
                "LOCKED cannot be set by administrators".into(),
            ));
        }
        let user = self.find_home_user(tenant, target).await?;
        self.ensure_not_self(user.id, actor)?;
        self.users
            .update_status(user.id, status)
            .await
            .map_err(internal)?;
        if status == UserStatus::Disabled {
            self.revoke_credentials(user.id).await;
        }
        self.audit
            .record(
                AuditEventType::UserStatusChanged,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(actor),
                None,
                Some(&format!("user={} status={}", user.id, status.as_str())),
                ctx,
            )
            .await;
        Ok(())
    }

    /// 利用者を削除する。関連行（メンバーシップ・権限・セッション・トークン・MFA 資格情報）は
    /// DB の FK CASCADE / SET NULL で後始末される。
    pub async fn delete_user(
        &self,
        tenant: TenantContext,
        target: Uuid,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        self.ensure_not_self(user.id, actor)?;
        self.users.delete(user.id).await.map_err(internal)?;
        self.audit
            .record(
                AuditEventType::UserDeleted,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(actor),
                None,
                Some(&format!("user={}", user.id)),
                ctx,
            )
            .await;
        Ok(())
    }

    async fn reset_password_for(
        &self,
        tenant: TenantContext,
        user: &User,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<ResetUserPassword, UserLifecycleError> {
        let generated_password = crypto::random_token(GENERATED_PASSWORD_BYTES);
        let password_hash = self.hasher.hash(&generated_password).map_err(internal)?;
        self.users
            .reset_password_forced(user.id, &password_hash)
            .await
            .map_err(internal)?;
        // 旧資格情報で発行済みのセッション・トークンを失効させる（fail-open にしない: 失敗はログのみ。
        // パスワードは既に更新済みで、旧パスワードでのログインはできない）。
        self.revoke_credentials(user.id).await;
        // 監査には内部 ID のみ記録する（生成パスワードは出さない。§5）。
        self.audit
            .record(
                AuditEventType::UserPasswordReset,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(actor),
                None,
                Some(&format!("user={}", user.id)),
                ctx,
            )
            .await;
        Ok(ResetUserPassword {
            user_id: user.id,
            generated_password,
        })
    }

    /// 所属元（HOME）が要求テナントの利用者を解決する。不存在・テナント越しは一律 `NotFound`
    /// （存在推測を防ぐ）。
    async fn find_home_user(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<User, UserLifecycleError> {
        match self.users.find_by_id(target).await.map_err(internal)? {
            Some(user) if user.tenant_id == tenant.tenant_id() => Ok(user),
            _ => Err(UserLifecycleError::NotFound),
        }
    }

    fn ensure_not_self(&self, target: Uuid, actor: Uuid) -> Result<(), UserLifecycleError> {
        if target == actor {
            return Err(UserLifecycleError::Forbidden(
                "cannot operate on your own account".into(),
            ));
        }
        Ok(())
    }

    async fn revoke_credentials(&self, user_id: Uuid) {
        let now = self.clock.now();
        if let Err(e) = self.sso_sessions.delete_all_for_user(user_id).await {
            tracing::warn!(error = %e, "failed to revoke SSO sessions in user lifecycle operation");
        }
        if let Err(e) = self.refresh_tokens.revoke_all_for_user(user_id, now).await {
            tracing::warn!(error = %e, "failed to revoke refresh tokens in user lifecycle operation");
        }
        if let Err(e) = self.codes.revoke_all_active_for_user(user_id, now).await {
            tracing::warn!(error = %e, "failed to revoke authorization codes in user lifecycle operation");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::authorization_code::AuthorizationCode;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::password::PasswordHasher as PasswordHasherTrait;
    use crate::domain::refresh_token::RefreshToken;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::sso_session::SsoSession;
    use crate::domain::tenant::TenantId;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 11, 12, 0, 0).unwrap()
    }

    struct FixedClock(DateTime<Utc>);
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    struct PlainHasher;
    impl PasswordHasherTrait for PlainHasher {
        fn hash(&self, password: &str) -> DomainResult<String> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> DomainResult<bool> {
            Ok(hash == format!("hash:{password}"))
        }
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &AuditEvent) -> DomainResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeUsers {
        rows: Mutex<Vec<User>>,
        forced_resets: Mutex<Vec<Uuid>>,
        deleted: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn create(&self, u: &User) -> DomainResult<()> {
            self.rows.lock().unwrap().push(u.clone());
            Ok(())
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
        async fn update_password(&self, _id: Uuid, _password_hash: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn reset_password_forced(&self, id: Uuid, password_hash: &str) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            let user = rows
                .iter_mut()
                .find(|u| u.id == id)
                .ok_or_else(|| DomainError::Repository("not found".into()))?;
            user.password_hash = password_hash.to_string();
            user.must_change_password = true;
            self.forced_resets.lock().unwrap().push(id);
            Ok(())
        }
        async fn update_status(&self, id: Uuid, status: UserStatus) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            let user = rows
                .iter_mut()
                .find(|u| u.id == id)
                .ok_or_else(|| DomainError::Repository("not found".into()))?;
            user.status = status;
            Ok(())
        }
        async fn delete(&self, id: Uuid) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|u| u.id != id);
            self.deleted.lock().unwrap().push(id);
            Ok(())
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
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
        async fn extend_idle(&self, _h: &str, _i: DateTime<Utc>) -> DomainResult<()> {
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
        async fn find_by_hash(
            &self,
            _tenant: TenantId,
            _h: &str,
        ) -> DomainResult<Option<RefreshToken>> {
            unreachable!()
        }
        async fn revoke(&self, _h: &str, _now: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn exists_by_parent_hash(&self, _p: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn revoke_all_for_user(
            &self,
            user_id: Uuid,
            _now: DateTime<Utc>,
        ) -> DomainResult<()> {
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
            _tenant: TenantId,
            _code_hash: &str,
            _now: DateTime<Utc>,
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

    fn user(id: Uuid, tenant: TenantId) -> User {
        User {
            id,
            tenant_id: tenant,
            sub: Uuid::new_v4(),
            email: format!("{id}@example.com"),
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            password_hash: "hash:old".to_string(),
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

    struct Fixture {
        users: Arc<FakeUsers>,
        sso: Arc<FakeSsoSessions>,
        refresh: Arc<FakeRefreshTokens>,
        codes: Arc<FakeCodes>,
        sink: Arc<CapturingSink>,
        svc: UserLifecycleService,
    }

    fn fixture() -> Fixture {
        let users = Arc::new(FakeUsers::default());
        let sso = Arc::new(FakeSsoSessions::default());
        let refresh = Arc::new(FakeRefreshTokens::default());
        let codes = Arc::new(FakeCodes::default());
        let sink = Arc::new(CapturingSink::default());
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock(now()))));
        let svc = UserLifecycleService::new(
            users.clone(),
            sso.clone(),
            refresh.clone(),
            codes.clone(),
            Arc::new(PlainHasher),
            audit,
            Arc::new(FixedClock(now())),
        );
        Fixture {
            users,
            sso,
            refresh,
            codes,
            sink,
            svc,
        }
    }

    #[tokio::test]
    async fn resets_password_with_forced_change_and_revokes_credentials() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let reset = f
            .svc
            .reset_password(TenantContext::new(tenant), target, Uuid::now_v7(), &ctx())
            .await
            .expect("reset");

        assert!(reset.generated_password.len() >= 32);
        let stored = f.users.rows.lock().unwrap()[0].clone();
        assert_eq!(
            stored.password_hash,
            format!("hash:{}", reset.generated_password)
        );
        assert!(stored.must_change_password);
        assert_eq!(*f.sso.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.refresh.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.codes.revoked_users.lock().unwrap(), vec![target]);
        // 監査に生成パスワードが漏れていない。
        let events = f.sink.events.lock().unwrap();
        assert_eq!(events[0].event_type, AuditEventType::UserPasswordReset);
        assert!(events.iter().all(|e| e
            .reason
            .as_deref()
            .map(|r| !r.contains(&reset.generated_password))
            .unwrap_or(true)));
    }

    #[tokio::test]
    async fn resets_password_by_email_within_tenant() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let reset = f
            .svc
            .reset_password_by_email(
                TenantContext::new(tenant),
                &format!("{target}@example.com"),
                Uuid::now_v7(),
                &ctx(),
            )
            .await
            .expect("reset");
        assert_eq!(reset.user_id, target);
    }

    #[tokio::test]
    async fn rejects_cross_tenant_and_self_operations() {
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, other)).await.unwrap();

        // テナント越し: 不存在と同じ NotFound。
        assert!(matches!(
            f.svc
                .reset_password(TenantContext::new(tenant), target, Uuid::now_v7(), &ctx())
                .await,
            Err(UserLifecycleError::NotFound)
        ));

        // 自分自身: Forbidden。
        let own = Uuid::now_v7();
        f.users.create(&user(own, tenant)).await.unwrap();
        assert!(matches!(
            f.svc
                .delete_user(TenantContext::new(tenant), own, own, &ctx())
                .await,
            Err(UserLifecycleError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn disables_user_and_revokes_credentials() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        f.svc
            .set_status(
                TenantContext::new(tenant),
                target,
                UserStatus::Disabled,
                Uuid::now_v7(),
                &ctx(),
            )
            .await
            .expect("disable");
        assert_eq!(f.users.rows.lock().unwrap()[0].status, UserStatus::Disabled);
        assert_eq!(*f.sso.revoked_users.lock().unwrap(), vec![target]);

        // 再有効化はセッション失効を伴わない。
        f.svc
            .set_status(
                TenantContext::new(tenant),
                target,
                UserStatus::Active,
                Uuid::now_v7(),
                &ctx(),
            )
            .await
            .expect("enable");
        assert_eq!(f.users.rows.lock().unwrap()[0].status, UserStatus::Active);
        assert_eq!(f.sso.revoked_users.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rejects_locked_status_from_administrators() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();
        assert!(matches!(
            f.svc
                .set_status(
                    TenantContext::new(tenant),
                    target,
                    UserStatus::Locked,
                    Uuid::now_v7(),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn deletes_user() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        f.svc
            .delete_user(TenantContext::new(tenant), target, Uuid::now_v7(), &ctx())
            .await
            .expect("delete");
        assert!(f.users.rows.lock().unwrap().is_empty());
        assert_eq!(*f.users.deleted.lock().unwrap(), vec![target]);
        assert_eq!(
            f.sink.events.lock().unwrap()[0].event_type,
            AuditEventType::UserDeleted
        );
    }
}
