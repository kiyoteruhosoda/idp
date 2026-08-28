//! 利用者セルフサービスのセキュリティ画面（G10）。
//!
//! 一般的な IdP が持つのに本 IdP に無かった 2 つを扱う:
//!
//! - **ログイン中セッションの一覧・失効**。端末を紛失した利用者が、管理者を介さずに他端末の
//!   セッションを切れるようにする（これまでは今のセッションをログアウトすることしかできなかった）。
//! - **連携済みアプリ（consent）の確認・取り消し**。一度同意すると利用者側から解除できず、
//!   `ClientConsentRepository::revoke` / `list_for_user` は実装済みなのに呼び出し元が無かった。
//!
//! # セッションの指し方
//!
//! `sso_sessions` の主キーは Cookie 値の SHA-256 で、これを画面へそのまま出す必要はない。
//! ドメイン分離した非可逆の表示用 ID（[`crate::domain::sso_session::SsoSession::display_id`]）を
//! 提示し、失効要求はその値と**当人のセッション集合**を突き合わせて解決する。値から
//! `session_hash` を復元する経路は作らないので、表示用 ID が漏れても他人のセッションは切れない。
//!
//! # 同意の取り消しで何を消すか
//!
//! 同意行を消すだけでは、その同意で発行済みのトークンが生き残る（利用者から見れば「解除したのに
//! まだ繋がっている」）。取り消し時は当該クライアントの refresh token も失効させる。access token は
//! 自己完結型 JWT のため、その寿命（既定 15 分）が切れるまでは有効なまま — これは設計上の受容点で、
//! 即時性が要るなら `revoked_access_tokens` へ載せる仕組み（F5）を使う。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{
    ClientConsentRepository, ClientRepository, RefreshTokenRepository, SsoSessionRepository,
    UserRepository,
};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationStrength;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// 画面に出すログインセッション 1 件。
#[derive(Debug, Clone)]
pub struct SessionSummary {
    /// 失効要求で指すための表示用 ID（`session_hash` の非可逆な導出値）。
    pub id: String,
    /// このセッションが「今使っているブラウザのセッション」か。
    pub current: bool,
    pub auth_time: DateTime<Utc>,
    /// 第二要素まで完了しているか（AP4 の記録。利用者が「この端末は MFA 済み」を確認できる）。
    pub multi_factor: bool,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

/// 画面に出す連携済みアプリ 1 件。
#[derive(Debug, Clone)]
pub struct ConnectedAppSummary {
    pub client_id: String,
    /// 表示名（クライアントが削除済みなら `client_id` にフォールバックする）。
    pub app_name: String,
    /// 同意済み scope（`openid` を含む保存値そのまま）。
    pub scopes: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// セキュリティ画面の表示内容。
pub struct SecurityOverview {
    pub sessions: Vec<SessionSummary>,
    pub connected_apps: Vec<ConnectedAppSummary>,
}

pub enum SecurityOverviewOutcome {
    Ok(Box<SecurityOverview>),
    /// SSO セッションが無い・期限切れ・利用者が無効。
    SessionExpired,
    Internal(String),
}

pub enum RevokeSessionOutcome {
    /// 失効した（冪等: 既に消えていた場合も含む）。
    Ok,
    /// 指定 ID が当人のセッションに無い（他人のセッション・古い画面からの再送）。
    NotFound,
    /// 今使っているセッション自身は、この画面からは切らせない（ログアウト導線を使わせる）。
    CurrentSession,
    SessionExpired,
    Internal(String),
}

pub enum RevokeConsentOutcome {
    /// 取り消した（冪等: 同意が無かった場合も含む）。
    Ok,
    SessionExpired,
    Internal(String),
}

pub struct AccountSecurityService {
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    consents: Arc<dyn ClientConsentRepository>,
    clients: Arc<dyn ClientRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl AccountSecurityService {
    pub fn new(
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        consents: Arc<dyn ClientConsentRepository>,
        clients: Arc<dyn ClientRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            sso_sessions,
            users,
            consents,
            clients,
            refresh_tokens,
            audit,
            clock,
        }
    }

    /// セキュリティ画面の表示内容（有効なセッション一覧＋連携済みアプリ一覧）を返す。
    pub async fn overview(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
    ) -> SecurityOverviewOutcome {
        let now = self.clock.now();
        let current_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.resolve_active_user_id(&current_hash, now).await {
            Ok(Some(id)) => id,
            Ok(None) => return SecurityOverviewOutcome::SessionExpired,
            Err(e) => return SecurityOverviewOutcome::Internal(e),
        };

        let sessions = match self.sso_sessions.list_for_user(user_id).await {
            Ok(rows) => rows,
            Err(e) => return SecurityOverviewOutcome::Internal(e.to_string()),
        };
        // 期限切れの行は GC を待たずに画面から落とす（利用者に「まだ生きている」と誤解させない）。
        let sessions: Vec<SessionSummary> = sessions
            .into_iter()
            .filter(|s| s.is_valid_at(now))
            .map(|s| SessionSummary {
                id: s.display_id(),
                current: s.session_hash == current_hash,
                auth_time: s.auth_time,
                multi_factor: s.authentication_strength == AuthenticationStrength::MultiFactor,
                user_agent: s.user_agent.clone(),
                ip_address: s.ip_address.clone(),
                created_at: s.created_at,
                idle_expires_at: s.idle_expires_at,
                absolute_expires_at: s.absolute_expires_at,
            })
            .collect();

        let tenant_id = tenant.tenant_id();
        let consents = match self.consents.list_for_user(tenant_id, user_id).await {
            Ok(rows) => rows,
            Err(e) => return SecurityOverviewOutcome::Internal(e.to_string()),
        };
        // 表示名はクライアント一覧から引く（1 件ずつ引くと同意数ぶん往復するため 1 回で済ませる）。
        let clients = match self.clients.list(tenant_id).await {
            Ok(rows) => rows,
            Err(e) => return SecurityOverviewOutcome::Internal(e.to_string()),
        };
        let connected_apps: Vec<ConnectedAppSummary> = consents
            .into_iter()
            .map(|c| {
                let app_name = clients
                    .iter()
                    .find(|client| client.client_id == c.client_id)
                    .map(|client| client.app_name.clone())
                    .unwrap_or_else(|| c.client_id.clone());
                ConnectedAppSummary {
                    client_id: c.client_id,
                    app_name,
                    scopes: c.scopes,
                    granted_at: c.granted_at,
                    updated_at: c.updated_at,
                }
            })
            .collect();

        SecurityOverviewOutcome::Ok(Box::new(SecurityOverview {
            sessions,
            connected_apps,
        }))
    }

    /// 指定セッションを失効させる（当人のセッションに限る）。
    pub async fn revoke_session(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        target_display_id: &str,
        ctx: &RequestContext,
    ) -> RevokeSessionOutcome {
        let now = self.clock.now();
        let current_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.resolve_active_user_id(&current_hash, now).await {
            Ok(Some(id)) => id,
            Ok(None) => return RevokeSessionOutcome::SessionExpired,
            Err(e) => return RevokeSessionOutcome::Internal(e),
        };

        let sessions = match self.sso_sessions.list_for_user(user_id).await {
            Ok(rows) => rows,
            Err(e) => return RevokeSessionOutcome::Internal(e.to_string()),
        };
        // 当人のセッション集合の中だけで表示用 ID を突き合わせる。他人のセッションはそもそも
        // この集合に入らないため、ID を推測できても切れない。
        let Some(target) = sessions
            .iter()
            .find(|s| s.display_id() == target_display_id)
        else {
            return RevokeSessionOutcome::NotFound;
        };
        if target.session_hash == current_hash {
            // 今のセッションを切ると Cookie だけが残って挙動が読みづらくなる。ログアウト導線へ回す。
            return RevokeSessionOutcome::CurrentSession;
        }

        if let Err(e) = self.sso_sessions.delete(&target.session_hash).await {
            return RevokeSessionOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::SsoSessionTerminated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(user_id),
                None,
                Some("self_service_revoke"),
                ctx,
            )
            .await;
        RevokeSessionOutcome::Ok
    }

    /// 連携済みアプリの同意を取り消し、そのクライアント向けの refresh token も失効させる。
    pub async fn revoke_consent(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        client_id: &str,
        ctx: &RequestContext,
    ) -> RevokeConsentOutcome {
        let now = self.clock.now();
        let current_hash = crypto::sha256_hex(sso_session_id);
        let user_id = match self.resolve_active_user_id(&current_hash, now).await {
            Ok(Some(id)) => id,
            Ok(None) => return RevokeConsentOutcome::SessionExpired,
            Err(e) => return RevokeConsentOutcome::Internal(e),
        };
        let tenant_id = tenant.tenant_id();

        if let Err(e) = self.consents.revoke(tenant_id, user_id, client_id).await {
            return RevokeConsentOutcome::Internal(e.to_string());
        }
        // 同意行だけ消しても発行済みトークンは生きている。利用者から見た「解除」を成立させるため、
        // **解除したクライアントへ**発行済みの refresh token を失効させる。テナント単位で消すと、
        // 1 つのアプリを外しただけで同じテナントの他のアプリからも締め出される。
        if let Err(e) = self
            .refresh_tokens
            .revoke_all_for_user_and_client(tenant_id, user_id, client_id, now)
            .await
        {
            // 同意の取り消し自体は成立している。トークンが残る点は運用ログで追えるようにする。
            tracing::error!(
                error = %e,
                "failed to revoke refresh tokens after a self-service consent revocation"
            );
        }

        self.audit
            .record(
                AuditEventType::ConsentRevoked,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
                Some(client_id),
                Some("self_service"),
                ctx,
            )
            .await;
        RevokeConsentOutcome::Ok
    }

    /// SSO セッションから本人を解決する。セッション無効・ユーザー不在・無効化済みは `Ok(None)`
    /// （他のセルフサービス経路と同じ判定。`AccountProfileService::resolve_active_user` に倣う）。
    async fn resolve_active_user_id(
        &self,
        session_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Uuid>, String> {
        let user_id = match self.sso_sessions.find_by_hash(session_hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s.user_id,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        match self.users.find_by_id(user_id).await {
            Ok(Some(user)) if user.is_active() => Ok(Some(user_id)),
            Ok(_) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// テナント境界の型付けだけを担う補助（Presentation から `TenantId` を渡すため）。
impl AccountSecurityService {
    pub fn tenant_context(tenant_id: TenantId) -> TenantContext {
        TenantContext::new(tenant_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::consent::ClientConsent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::refresh_token::RefreshToken;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::sso_session::SsoSession;
    use crate::domain::user::User;
    use crate::domain::values::{AuthenticationMethod, UserStatus};
    use async_trait::async_trait;
    use chrono::{Duration, TimeZone};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap()
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

    fn session(raw_cookie: &str, methods: Vec<AuthenticationMethod>, valid: bool) -> SsoSession {
        let mut s = SsoSession::establish(
            crypto::sha256_hex(raw_cookie),
            user_id(),
            now(),
            Duration::hours(1),
            Duration::hours(8),
            methods,
            Some("Mozilla/5.0".to_string()),
            Some("203.0.113.10".to_string()),
        );
        if !valid {
            s.idle_expires_at = now() - Duration::minutes(1);
        }
        s
    }

    #[derive(Default)]
    struct FakeSsoSessions {
        rows: Mutex<Vec<SsoSession>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
            unreachable!()
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
        async fn list_for_user(&self, uid: Uuid) -> DomainResult<Vec<SsoSession>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.user_id == uid)
                .cloned()
                .collect())
        }
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, hash: &str) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|s| s.session_hash != hash);
            Ok(())
        }
        async fn delete_all_for_user(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct FakeUsers {
        active: bool,
    }
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
                tenant_id: tenant_id(),
                sub: Uuid::from_u128(7),
                email: "user@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("user".to_string()),
                name: None,
                language: None,
                theme: None,
                password_hash: String::new(),
                must_change_password: false,
                password_changed_at: None,
                status: if self.active {
                    UserStatus::Active
                } else {
                    UserStatus::Disabled
                },
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
    struct FakeConsents {
        rows: Mutex<Vec<ClientConsent>>,
    }
    #[async_trait]
    impl ClientConsentRepository for FakeConsents {
        async fn find(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
        ) -> DomainResult<Option<ClientConsent>> {
            unreachable!()
        }
        async fn upsert(&self, _c: &ClientConsent) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke(&self, _t: TenantId, _u: Uuid, client_id: &str) -> DomainResult<()> {
            self.rows
                .lock()
                .unwrap()
                .retain(|c| c.client_id != client_id);
            Ok(())
        }
        async fn list_for_user(&self, _t: TenantId, _u: Uuid) -> DomainResult<Vec<ClientConsent>> {
            Ok(self.rows.lock().unwrap().clone())
        }
    }

    #[derive(Default)]
    struct FakeClients;
    #[async_trait]
    impl ClientRepository for FakeClients {
        async fn find_by_client_id(
            &self,
            _t: TenantId,
            _c: &str,
        ) -> DomainResult<Option<crate::domain::client::Client>> {
            unreachable!()
        }
        async fn create(&self, _c: &crate::domain::client::Client) -> DomainResult<()> {
            unreachable!()
        }
        async fn list(&self, _t: TenantId) -> DomainResult<Vec<crate::domain::client::Client>> {
            // 表示名が引けないケース（削除済みクライアント）を再現する。
            Ok(Vec::new())
        }
        async fn update(&self, _c: &crate::domain::client::Client) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeRefreshTokens {
        /// 失効を要求された `(テナント, 利用者, クライアント)`。連携解除がクライアント単位に
        /// 絞られているかを見るため、クライアントまで記録する。
        revoked: Mutex<Vec<(TenantId, Uuid, String)>>,
    }
    #[async_trait]
    impl RefreshTokenRepository for FakeRefreshTokens {
        async fn revoke_family(
            &self,
            _t: TenantId,
            _family: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            unreachable!()
        }
        async fn create(&self, _t: &RefreshToken) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_hash(&self, _t: TenantId, _h: &str) -> DomainResult<Option<RefreshToken>> {
            unreachable!()
        }
        async fn revoke(&self, _h: &str, _at: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
        async fn exists_by_parent_hash(&self, _h: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn revoke_all_for_user(&self, _u: Uuid, _at: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke_all_for_user_in_tenant(
            &self,
            _t: TenantId,
            _u: Uuid,
            _at: DateTime<Utc>,
        ) -> DomainResult<()> {
            // 連携解除ではテナント単位の全失効を呼んではいけない（他のアプリを巻き込む）。
            unreachable!("consent revocation must not revoke every client in the tenant")
        }
        async fn revoke_all_for_user_and_client(
            &self,
            t: TenantId,
            u: Uuid,
            c: &str,
            _at: DateTime<Utc>,
        ) -> DomainResult<()> {
            self.revoked.lock().unwrap().push((t, u, c.to_string()));
            Ok(())
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

    struct Harness {
        service: AccountSecurityService,
        sessions: Arc<FakeSsoSessions>,
        consents: Arc<FakeConsents>,
        refresh_tokens: Arc<FakeRefreshTokens>,
    }

    fn harness(active_user: bool) -> Harness {
        let sessions = Arc::new(FakeSsoSessions::default());
        let consents = Arc::new(FakeConsents::default());
        let refresh_tokens = Arc::new(FakeRefreshTokens::default());
        let clock: Arc<dyn Clock> = Arc::new(FixedClock);
        let service = AccountSecurityService::new(
            sessions.clone(),
            Arc::new(FakeUsers {
                active: active_user,
            }),
            consents.clone(),
            Arc::new(FakeClients),
            refresh_tokens.clone(),
            Arc::new(AuditService::new(Arc::new(DiscardingSink), clock.clone())),
            clock,
        );
        Harness {
            service,
            sessions,
            consents,
            refresh_tokens,
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "test".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn overview_lists_valid_sessions_and_marks_the_current_one() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().extend([
            session("current-cookie", vec![AuthenticationMethod::Password], true),
            session(
                "other-cookie",
                vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
                true,
            ),
            session(
                "expired-cookie",
                vec![AuthenticationMethod::Password],
                false,
            ),
        ]);
        h.consents.rows.lock().unwrap().push(ClientConsent {
            user_id: user_id(),
            tenant_id: tenant_id(),
            client_id: "deleted-app".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            granted_at: now(),
            updated_at: now(),
        });

        let SecurityOverviewOutcome::Ok(overview) = h
            .service
            .overview(TenantContext::new(tenant_id()), "current-cookie")
            .await
        else {
            panic!("expected an overview");
        };

        // 期限切れは出さない。
        assert_eq!(overview.sessions.len(), 2);
        let current = overview.sessions.iter().find(|s| s.current).unwrap();
        assert!(!current.multi_factor);
        let other = overview.sessions.iter().find(|s| !s.current).unwrap();
        assert!(other.multi_factor, "MFA 済みセッションはそう見える");
        // 表示用 ID は session_hash そのものではない。
        assert_ne!(current.id, crypto::sha256_hex("current-cookie"));

        // クライアントが引けない場合は client_id を表示名に使う。
        assert_eq!(overview.connected_apps.len(), 1);
        assert_eq!(overview.connected_apps[0].app_name, "deleted-app");
    }

    #[tokio::test]
    async fn revoking_another_session_deletes_only_that_row() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().extend([
            session("current-cookie", vec![AuthenticationMethod::Password], true),
            session("other-cookie", vec![AuthenticationMethod::Password], true),
        ]);
        let other_id =
            session("other-cookie", vec![AuthenticationMethod::Password], true).display_id();

        assert!(matches!(
            h.service
                .revoke_session(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    &other_id,
                    &ctx()
                )
                .await,
            RevokeSessionOutcome::Ok
        ));
        let rows = h.sessions.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].session_hash, crypto::sha256_hex("current-cookie"));
    }

    /// 今使っているセッションはこの画面からは切らせない（ログアウト導線へ回す）。
    #[tokio::test]
    async fn revoking_the_current_session_is_refused() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));
        let current_id =
            session("current-cookie", vec![AuthenticationMethod::Password], true).display_id();

        assert!(matches!(
            h.service
                .revoke_session(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    &current_id,
                    &ctx()
                )
                .await,
            RevokeSessionOutcome::CurrentSession
        ));
        assert_eq!(h.sessions.rows.lock().unwrap().len(), 1);
    }

    /// 他人のセッションの表示用 ID を持ち込んでも切れない（当人の集合としか突き合わせない）。
    #[tokio::test]
    async fn a_session_id_that_is_not_ours_is_not_found() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));
        let foreign =
            crate::domain::sso_session::display_id_of(&crypto::sha256_hex("someone-else"));

        assert!(matches!(
            h.service
                .revoke_session(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    &foreign,
                    &ctx()
                )
                .await,
            RevokeSessionOutcome::NotFound
        ));
        assert_eq!(h.sessions.rows.lock().unwrap().len(), 1);
    }

    /// 同意の取り消しは、同意行の削除に加えて当該テナントの refresh token も失効させる。
    #[tokio::test]
    async fn revoking_a_consent_also_revokes_refresh_tokens_in_that_tenant() {
        let h = harness(true);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));
        h.consents.rows.lock().unwrap().push(ClientConsent {
            user_id: user_id(),
            tenant_id: tenant_id(),
            client_id: "app-a".to_string(),
            scopes: vec!["openid".to_string()],
            granted_at: now(),
            updated_at: now(),
        });

        assert!(matches!(
            h.service
                .revoke_consent(
                    TenantContext::new(tenant_id()),
                    "current-cookie",
                    "app-a",
                    &ctx()
                )
                .await,
            RevokeConsentOutcome::Ok
        ));
        assert!(h.consents.rows.lock().unwrap().is_empty());
        // 解除したクライアントのトークンだけを失効させる（同じテナントの他アプリは残る）。
        assert_eq!(
            *h.refresh_tokens.revoked.lock().unwrap(),
            vec![(tenant_id(), user_id(), "app-a".to_string())]
        );
    }

    /// 無効化された利用者のセッションが残っていても操作させない（他のセルフサービス経路と同じ）。
    #[tokio::test]
    async fn a_disabled_user_cannot_use_the_screen() {
        let h = harness(false);
        h.sessions.rows.lock().unwrap().push(session(
            "current-cookie",
            vec![AuthenticationMethod::Password],
            true,
        ));
        assert!(matches!(
            h.service
                .overview(TenantContext::new(tenant_id()), "current-cookie")
                .await,
            SecurityOverviewOutcome::SessionExpired
        ));
    }
}
