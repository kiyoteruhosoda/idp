//! 利用者が自分で登録する SSH の公開鍵と、配る機械への一覧（task #885。ADR-0072）。
//!
//! # 流れ
//!
//! 1. **登録**: 利用者が「アカウントのセキュリティ」の「SSH の鍵」で [`SshKeyRegistryService::register`]。
//!    **パスキーで本人を確かめてから 5 分以内**だけ通す（端末の登録と同じ確かめ方。ADR-0071）。
//!    受け付けるのは sk 型だけ（[`SshPublicKey::parse`]）。
//! 2. **取り消し**: [`SshKeyRegistryService::revoke`]。これもパスキーで 5 分以内だけ。
//! 3. **配る**: `idp.ssh-keys:read` を持つ**機械クライアント**が [`SshKeyRegistryService::distributable`]
//!    で組織の有効な鍵の一覧を読み、各機器の authorized_keys へ書く（deploy-repo の host/sshkeys）。
//!
//! どれも組織の設定 `SSH_KEYS_ENABLED`（既定 false）が有効なときだけ働く。無効の組織では画面に出さず、
//! 配る一覧は空にする（登録済みの行は消さない。有効へ戻すと元の鍵がそのまま配られる）。
//!
//! 登録・取り消しは監査ログに必ず残し、セキュリティの知らせ（[`SecurityAlertSink`]）へ送る。
//! 機能を有効にした組織だけが鍵を登録できるので、知らせに別の有効・無効は持たない。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::effective_tenant_settings::EffectiveTenantSettings;
use crate::domain::error::DomainError;
use crate::domain::repositories::{SsoSessionRepository, UserRepository, UserSshKeyRepository};
use crate::domain::security_alert::{SecurityAlert, SecurityAlertKind, SecurityAlertSink};
use crate::domain::ssh_key::{
    normalize_ssh_key_name, DistributedSshKey, SshKeyRejection, SshPublicKey, UserSshKey,
    MAX_SSH_KEYS_PER_USER,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::user_device::passkey_verified_recently;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// 「SSH の鍵」の欄に出すもの。
#[derive(Debug, Clone)]
pub struct SshKeyOverview {
    /// この組織で SSH の鍵を使うか（無効なら画面に欄を出さない）。
    pub enabled: bool,
    /// パスキーでの本人確認がまだ有効か（有効なら登録・取り消しはそのまま通る）。
    pub passkey_fresh: bool,
    pub keys: Vec<UserSshKey>,
}

#[derive(Debug)]
pub enum SshKeyOverviewOutcome {
    Ok(Box<SshKeyOverview>),
    SessionExpired,
    Internal(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterSshKeyOutcome {
    Registered {
        fingerprint: String,
    },
    /// この組織では SSH の鍵を使っていない。
    Disabled,
    /// パスキーで本人を確かめてから 5 分を過ぎている（またはパスキーで確かめていない）。
    PasskeyRequired,
    /// 名前が空・長すぎ・制御文字入り。
    InvalidName,
    /// 公開鍵を断った（秘密鍵らしきもの・sk 型でない・壊れている）。
    Rejected(SshKeyRejection),
    /// 同じ鍵がこの組織に登録済み。
    AlreadyRegistered,
    /// 1 人が登録できる数を超える。
    TooMany,
    SessionExpired,
    Internal(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeSshKeyOutcome {
    Revoked,
    PasskeyRequired,
    NotFound,
    SessionExpired,
    Internal(String),
}

/// 配る一覧を読めなかった理由。
#[derive(Debug, PartialEq, Eq)]
pub enum SshKeyDistributionError {
    /// 呼び出し元が機械クライアントではない（人の管理トークン）。
    NotAMachine,
    Internal(String),
}

pub struct SshKeyRegistryService {
    keys: Arc<dyn UserSshKeyRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    users: Arc<dyn UserRepository>,
    settings: Arc<dyn EffectiveTenantSettings>,
    alerts: Arc<dyn SecurityAlertSink>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

/// 認証済みの今のセッションと利用者。
struct ActiveSession {
    session: SsoSession,
    user: User,
}

impl SshKeyRegistryService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keys: Arc<dyn UserSshKeyRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        users: Arc<dyn UserRepository>,
        settings: Arc<dyn EffectiveTenantSettings>,
        alerts: Arc<dyn SecurityAlertSink>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            keys,
            sso_sessions,
            users,
            settings,
            alerts,
            audit,
            clock,
        }
    }

    /// 「SSH の鍵」の欄の中身。
    pub async fn overview(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
    ) -> SshKeyOverviewOutcome {
        let now = self.clock.now();
        let active = match self.active_session(sso_session_id, now).await {
            Ok(Some(active)) => active,
            Ok(None) => return SshKeyOverviewOutcome::SessionExpired,
            Err(e) => return SshKeyOverviewOutcome::Internal(e),
        };
        let enabled = match self.settings.ssh_keys_enabled(tenant.tenant_id()).await {
            Ok(enabled) => enabled,
            Err(e) => return SshKeyOverviewOutcome::Internal(e.to_string()),
        };
        if !enabled {
            return SshKeyOverviewOutcome::Ok(Box::new(SshKeyOverview {
                enabled: false,
                passkey_fresh: false,
                keys: Vec::new(),
            }));
        }
        let keys = match self
            .keys
            .list_for_user(tenant.tenant_id(), active.user.id)
            .await
        {
            Ok(keys) => keys,
            Err(e) => return SshKeyOverviewOutcome::Internal(e.to_string()),
        };
        let passkey_fresh = match self.passkey_is_fresh(&active.session, now).await {
            Ok(fresh) => fresh,
            Err(e) => return SshKeyOverviewOutcome::Internal(e.to_string()),
        };
        SshKeyOverviewOutcome::Ok(Box::new(SshKeyOverview {
            enabled: true,
            passkey_fresh,
            keys,
        }))
    }

    /// SSH の公開鍵を登録する。
    pub async fn register(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        public_key: &str,
        name: &str,
        ctx: &RequestContext,
    ) -> RegisterSshKeyOutcome {
        let now = self.clock.now();
        let active = match self.active_session(sso_session_id, now).await {
            Ok(Some(active)) => active,
            Ok(None) => return RegisterSshKeyOutcome::SessionExpired,
            Err(e) => return RegisterSshKeyOutcome::Internal(e),
        };
        match self.settings.ssh_keys_enabled(tenant.tenant_id()).await {
            Ok(true) => {}
            Ok(false) => return RegisterSshKeyOutcome::Disabled,
            Err(e) => return RegisterSshKeyOutcome::Internal(e.to_string()),
        }
        // 鍵の形は本人確認より先に見る（貼り間違いのたびにパスキーへ回さない）。秘密鍵は
        // ここで断り、どこにも残さない。
        let key = match SshPublicKey::parse(public_key) {
            Ok(key) => key,
            Err(rejection) => return RegisterSshKeyOutcome::Rejected(rejection),
        };
        let Some(name) = normalize_ssh_key_name(name) else {
            return RegisterSshKeyOutcome::InvalidName;
        };
        match self.passkey_is_fresh(&active.session, now).await {
            Ok(true) => {}
            Ok(false) => return RegisterSshKeyOutcome::PasskeyRequired,
            Err(e) => return RegisterSshKeyOutcome::Internal(e.to_string()),
        }
        match self
            .keys
            .list_for_user(tenant.tenant_id(), active.user.id)
            .await
        {
            Ok(existing) if existing.len() >= MAX_SSH_KEYS_PER_USER => {
                return RegisterSshKeyOutcome::TooMany;
            }
            Ok(_) => {}
            Err(e) => return RegisterSshKeyOutcome::Internal(e.to_string()),
        }
        let registered = UserSshKey {
            id: Uuid::now_v7(),
            tenant_id: tenant.tenant_id(),
            user_id: active.user.id,
            name: name.clone(),
            key,
            created_at: now,
        };
        match self.keys.insert(&registered).await {
            Ok(()) => {}
            Err(DomainError::Conflict(_)) => return RegisterSshKeyOutcome::AlreadyRegistered,
            Err(e) => return RegisterSshKeyOutcome::Internal(e.to_string()),
        }
        let fingerprint = registered.key.fingerprint().to_string();
        self.audit
            .record(
                AuditEventType::SshKeyRegistered,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(active.user.id),
                None,
                Some(&format!(
                    "ssh_key_id={} fingerprint={fingerprint}",
                    registered.id
                )),
                ctx,
            )
            .await;
        self.alert(
            &active.user,
            &tenant,
            SecurityAlertKind::SshKeyRegistered {
                key_name: name,
                fingerprint: fingerprint.clone(),
            },
            &fingerprint,
            now,
            ctx,
        )
        .await;
        RegisterSshKeyOutcome::Registered { fingerprint }
    }

    /// SSH の公開鍵を取り消す。
    pub async fn revoke(
        &self,
        tenant: TenantContext,
        sso_session_id: &str,
        key_id: Uuid,
        ctx: &RequestContext,
    ) -> RevokeSshKeyOutcome {
        let now = self.clock.now();
        let active = match self.active_session(sso_session_id, now).await {
            Ok(Some(active)) => active,
            Ok(None) => return RevokeSshKeyOutcome::SessionExpired,
            Err(e) => return RevokeSshKeyOutcome::Internal(e),
        };
        match self.passkey_is_fresh(&active.session, now).await {
            Ok(true) => {}
            Ok(false) => return RevokeSshKeyOutcome::PasskeyRequired,
            Err(e) => return RevokeSshKeyOutcome::Internal(e.to_string()),
        }
        let removed = match self
            .keys
            .delete(tenant.tenant_id(), active.user.id, key_id)
            .await
        {
            Ok(Some(key)) => key,
            Ok(None) => return RevokeSshKeyOutcome::NotFound,
            Err(e) => return RevokeSshKeyOutcome::Internal(e.to_string()),
        };
        let fingerprint = removed.key.fingerprint().to_string();
        self.audit
            .record(
                AuditEventType::SshKeyRevoked,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(active.user.id),
                None,
                Some(&format!(
                    "ssh_key_id={} fingerprint={fingerprint}",
                    removed.id
                )),
                ctx,
            )
            .await;
        self.alert(
            &active.user,
            &tenant,
            SecurityAlertKind::SshKeyRevoked {
                key_name: removed.name.clone(),
                fingerprint: fingerprint.clone(),
            },
            &fingerprint,
            now,
            ctx,
        )
        .await;
        RevokeSshKeyOutcome::Revoked
    }

    /// 配る機械へ渡す、組織の有効な鍵の一覧。
    ///
    /// ⚠ **機械クライアントだけ**に返す。人の管理トークンは `idp.ssh-keys:read` を含意していても
    /// 断る（テナント管理者のブラウザが乗っ取られても、ここから「誰のどの鍵が通るか」を集めさせない
    /// ——一覧そのものは公開鍵だが、どの機器のどの利用者に通るかの地図になる）。
    pub async fn distributable(
        &self,
        tenant: TenantContext,
        caller: &AdminActor,
    ) -> Result<Vec<DistributedSshKey>, SshKeyDistributionError> {
        if !caller.is_client() {
            return Err(SshKeyDistributionError::NotAMachine);
        }
        let enabled = self
            .settings
            .ssh_keys_enabled(tenant.tenant_id())
            .await
            .map_err(|e| SshKeyDistributionError::Internal(e.to_string()))?;
        if !enabled {
            return Ok(Vec::new());
        }
        self.keys
            .list_distributable(tenant.tenant_id())
            .await
            .map_err(|e| SshKeyDistributionError::Internal(e.to_string()))
    }

    /// パスキーで本人を確かめてから 5 分以内か（端末の登録と同じ判定。ADR-0071）。
    async fn passkey_is_fresh(
        &self,
        session: &SsoSession,
        now: DateTime<Utc>,
    ) -> Result<bool, DomainError> {
        let verified_at = self
            .sso_sessions
            .passkey_verified_at(&session.session_hash)
            .await?;
        Ok(passkey_verified_recently(session, verified_at, now))
    }

    async fn active_session(
        &self,
        sso_session_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ActiveSession>, String> {
        let hash = crypto::sha256_hex(sso_session_id);
        let session = match self.sso_sessions.find_by_hash(&hash).await {
            Ok(Some(s)) if s.is_valid_at(now) => s,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        match self.users.find_by_id(session.user_id).await {
            Ok(Some(user)) if user.is_active() => Ok(Some(ActiveSession { session, user })),
            Ok(_) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn alert(
        &self,
        user: &User,
        tenant: &TenantContext,
        kind: SecurityAlertKind,
        fingerprint: &str,
        now: DateTime<Utc>,
        ctx: &RequestContext,
    ) {
        let username = user
            .preferred_username
            .clone()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| format!("利用者 {}", &user.sub.simple().to_string()[..8]));
        self.alerts
            .send(SecurityAlert {
                kind,
                tenant_id: tenant.tenant_id(),
                user_id: user.id,
                username,
                occurred_at: now,
                country: None,
                ip_address: ctx.ip_address.clone(),
                user_agent: ctx.user_agent.clone(),
                // 同じ鍵の知らせを束ねる（指紋の頭。指紋は公開鍵から誰でも計算できる値）。
                group_key: crypto::sha256_hex(fingerprint)[..16].to_string(),
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::tenant_settings::testing::{audit, tenant_settings, CapturingSink};
    use crate::domain::error::Result as DomainResult;
    use crate::domain::ssh_key::testing::{ecdsa_sk_line, ed25519_file_line, ed25519_sk_line};
    use crate::domain::tenant::TenantId;
    use crate::domain::values::{AuthenticationMethod, UserStatus};
    use async_trait::async_trait;
    use chrono::{Duration, TimeZone};
    use std::sync::Mutex;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 4, 12, 0, 0).unwrap()
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

    fn other_tenant_id() -> TenantId {
        TenantId::from(Uuid::from_u128(0x0197_0000_0000_7000_8000_0000_0000_0002))
    }

    fn user_id() -> Uuid {
        Uuid::from_u128(42)
    }

    const COOKIE: &str = "sso-cookie";

    #[derive(Default)]
    struct FakeSessions {
        rows: Mutex<Vec<SsoSession>>,
        passkey_at: Mutex<Option<DateTime<Utc>>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSessions {
        async fn create(&self, s: &SsoSession) -> DomainResult<()> {
            self.rows.lock().unwrap().push(s.clone());
            Ok(())
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
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn passkey_verified_at(&self, _h: &str) -> DomainResult<Option<DateTime<Utc>>> {
            Ok(*self.passkey_at.lock().unwrap())
        }
        async fn delete(&self, hash: &str) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|s| s.session_hash != hash);
            Ok(())
        }
        async fn delete_all_for_user(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeKeys {
        rows: Mutex<Vec<UserSshKey>>,
    }
    #[async_trait]
    impl UserSshKeyRepository for FakeKeys {
        async fn list_for_user(&self, t: TenantId, u: Uuid) -> DomainResult<Vec<UserSshKey>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|k| k.tenant_id == t && k.user_id == u)
                .cloned()
                .collect())
        }
        async fn insert(&self, key: &UserSshKey) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if rows.iter().any(|k| {
                k.tenant_id == key.tenant_id && k.key.fingerprint() == key.key.fingerprint()
            }) {
                return Err(DomainError::Conflict("dup".into()));
            }
            rows.push(key.clone());
            Ok(())
        }
        async fn delete(&self, t: TenantId, u: Uuid, id: Uuid) -> DomainResult<Option<UserSshKey>> {
            let mut rows = self.rows.lock().unwrap();
            let found = rows
                .iter()
                .position(|k| k.tenant_id == t && k.user_id == u && k.id == id);
            Ok(found.map(|i| rows.remove(i)))
        }
        async fn list_distributable(&self, t: TenantId) -> DomainResult<Vec<DistributedSshKey>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|k| k.tenant_id == t)
                .map(|k| DistributedSshKey {
                    username: "kyon".to_string(),
                    name: k.name.clone(),
                    key: k.key.clone(),
                    created_at: k.created_at,
                })
                .collect())
        }
    }

    struct FakeUsers;
    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: DateTime<Utc>,
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
                preferred_username: Some("kyon".to_string()),
                name: None,
                language: None,
                theme: None,
                password_hash: String::new(),
                must_change_password: false,
                password_changed_at: None,
                status: UserStatus::Active,
                pending_setup: false,
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
        async fn update_password(&self, _id: Uuid, _e: &str, _p: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(&self, _id: Uuid, _e: &str, _p: &str) -> DomainResult<bool> {
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
    struct CapturingAlerts {
        sent: Mutex<Vec<SecurityAlert>>,
    }
    #[async_trait]
    impl SecurityAlertSink for CapturingAlerts {
        async fn send(&self, alert: SecurityAlert) {
            self.sent.lock().unwrap().push(alert);
        }
    }

    struct Harness {
        service: SshKeyRegistryService,
        sessions: Arc<FakeSessions>,
        keys: Arc<FakeKeys>,
        alerts: Arc<CapturingAlerts>,
        audit_events: Arc<CapturingSink>,
    }

    /// `enabled`: その組織で SSH の鍵を使うか。`methods`・`auth_age`: ログインの入り方と経過時間。
    fn harness(enabled: bool, methods: Vec<AuthenticationMethod>, auth_age: Duration) -> Harness {
        let settings = tenant_settings();
        if enabled {
            settings.set_tenant(tenant_id(), "SSH_KEYS_ENABLED", "true");
        }
        let sessions = Arc::new(FakeSessions::default());
        sessions.rows.lock().unwrap().push(SsoSession::establish(
            crypto::sha256_hex(COOKIE),
            user_id(),
            now() - auth_age,
            Duration::hours(8),
            Duration::hours(24),
            methods,
            None,
            None,
        ));
        let keys = Arc::new(FakeKeys::default());
        let alerts = Arc::new(CapturingAlerts::default());
        let audit_events = Arc::new(CapturingSink::default());
        let service = SshKeyRegistryService::new(
            keys.clone(),
            sessions.clone(),
            Arc::new(FakeUsers),
            settings.service.clone(),
            alerts.clone(),
            audit(audit_events.clone()),
            Arc::new(FixedClock),
        );
        Harness {
            service,
            sessions,
            keys,
            alerts,
            audit_events,
        }
    }

    fn passkey_just_now() -> Harness {
        harness(
            true,
            vec![AuthenticationMethod::WebAuthn],
            Duration::seconds(30),
        )
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "c".to_string(),
            ip_address: Some("203.0.113.10".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::new(tenant_id())
    }

    fn events(h: &Harness) -> Vec<(AuditEventType, Option<String>)> {
        h.audit_events
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.event_type, e.reason.clone()))
            .collect()
    }

    async fn register(h: &Harness, line: &str) -> RegisterSshKeyOutcome {
        h.service
            .register(tenant(), COOKIE, line, "kyon-pc", &ctx())
            .await
    }

    fn machine() -> AdminActor {
        AdminActor::Client {
            id: Uuid::from_u128(9),
            client_id: "host-sshkeys".to_string(),
        }
    }

    #[tokio::test]
    async fn a_security_key_is_registered_right_after_a_passkey_sign_in() {
        let h = passkey_just_now();
        let RegisterSshKeyOutcome::Registered { fingerprint } =
            register(&h, &ed25519_sk_line(1)).await
        else {
            panic!("not registered");
        };
        assert!(fingerprint.starts_with("SHA256:"));
        let rows = h.keys.rows.lock().unwrap().clone();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "kyon-pc");
        assert!(!rows[0].key.authorized_key().contains("kyon@kyon-pc"));

        let recorded = events(&h);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, AuditEventType::SshKeyRegistered);
        assert!(recorded[0]
            .1
            .as_deref()
            .unwrap()
            .contains(&format!("fingerprint={fingerprint}")));

        let sent = h.alerts.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].kind,
            SecurityAlertKind::SshKeyRegistered {
                key_name: "kyon-pc".to_string(),
                fingerprint
            }
        );
        assert_eq!(sent[0].username, "kyon");
    }

    #[tokio::test]
    async fn a_password_sign_in_is_sent_to_the_passkey_check() {
        let h = harness(
            true,
            vec![AuthenticationMethod::Password, AuthenticationMethod::Totp],
            Duration::seconds(30),
        );
        assert_eq!(
            register(&h, &ed25519_sk_line(1)).await,
            RegisterSshKeyOutcome::PasskeyRequired
        );
        assert!(h.keys.rows.lock().unwrap().is_empty());
        assert!(h.alerts.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_passkey_sign_in_older_than_five_minutes_is_not_enough() {
        let h = harness(
            true,
            vec![AuthenticationMethod::WebAuthn],
            Duration::seconds(301),
        );
        assert_eq!(
            register(&h, &ed25519_sk_line(1)).await,
            RegisterSshKeyOutcome::PasskeyRequired
        );
        // 後からパスキーで確かめれば通る（step-up）。
        *h.sessions.passkey_at.lock().unwrap() = Some(now() - Duration::seconds(10));
        assert!(matches!(
            register(&h, &ed25519_sk_line(1)).await,
            RegisterSshKeyOutcome::Registered { .. }
        ));
    }

    #[tokio::test]
    async fn only_security_key_types_are_accepted() {
        let h = passkey_just_now();
        assert_eq!(
            register(&h, &ed25519_file_line()).await,
            RegisterSshKeyOutcome::Rejected(SshKeyRejection::NotSecurityKeyType)
        );
        assert_eq!(
            register(&h, "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n").await,
            RegisterSshKeyOutcome::Rejected(SshKeyRejection::LooksLikePrivateKey)
        );
        assert_eq!(
            register(&h, "sk-ssh-ed25519@openssh.com AAAA").await,
            RegisterSshKeyOutcome::Rejected(SshKeyRejection::Malformed)
        );
        assert!(matches!(
            register(&h, &ecdsa_sk_line(2)).await,
            RegisterSshKeyOutcome::Registered { .. }
        ));
        assert_eq!(h.keys.rows.lock().unwrap().len(), 1);
        // 断ったものは監査にも知らせにも出ない（秘密鍵の中身をどこにも残さない）。
        assert_eq!(events(&h).len(), 1);
    }

    #[tokio::test]
    async fn the_same_key_cannot_be_registered_twice() {
        let h = passkey_just_now();
        assert!(matches!(
            register(&h, &ed25519_sk_line(1)).await,
            RegisterSshKeyOutcome::Registered { .. }
        ));
        // コメントだけ違う同じ鍵も同じ鍵。
        let same_key = ed25519_sk_line(1).replace("kyon@kyon-pc", "other-comment");
        assert_eq!(
            register(&h, &same_key).await,
            RegisterSshKeyOutcome::AlreadyRegistered
        );
    }

    #[tokio::test]
    async fn a_disabled_tenant_neither_registers_nor_distributes() {
        let h = harness(
            false,
            vec![AuthenticationMethod::WebAuthn],
            Duration::seconds(30),
        );
        assert_eq!(
            register(&h, &ed25519_sk_line(1)).await,
            RegisterSshKeyOutcome::Disabled
        );
        let SshKeyOverviewOutcome::Ok(view) = h.service.overview(tenant(), COOKIE).await else {
            panic!("overview failed");
        };
        assert!(!view.enabled);
        // 行が残っていても、無効の組織では配らない。
        h.keys.rows.lock().unwrap().push(UserSshKey {
            id: Uuid::now_v7(),
            tenant_id: tenant_id(),
            user_id: user_id(),
            name: "old".to_string(),
            key: SshPublicKey::parse(&ed25519_sk_line(3)).unwrap(),
            created_at: now(),
        });
        assert_eq!(
            h.service.distributable(tenant(), &machine()).await,
            Ok(Vec::new())
        );
    }

    #[tokio::test]
    async fn revocation_needs_a_fresh_passkey_and_removes_the_key_from_distribution() {
        let h = passkey_just_now();
        register(&h, &ed25519_sk_line(1)).await;
        register(&h, &ecdsa_sk_line(2)).await;
        let listed = h.service.distributable(tenant(), &machine()).await.unwrap();
        assert_eq!(listed.len(), 2);
        let target = h.keys.rows.lock().unwrap()[0].clone();

        // 5 分を過ぎたら取り消しも断る。
        let stale = harness(
            true,
            vec![AuthenticationMethod::WebAuthn],
            Duration::minutes(10),
        );
        stale.keys.rows.lock().unwrap().push(target.clone());
        assert_eq!(
            stale
                .service
                .revoke(tenant(), COOKIE, target.id, &ctx())
                .await,
            RevokeSshKeyOutcome::PasskeyRequired
        );
        assert_eq!(stale.keys.rows.lock().unwrap().len(), 1);

        assert_eq!(
            h.service.revoke(tenant(), COOKIE, target.id, &ctx()).await,
            RevokeSshKeyOutcome::Revoked
        );
        let listed = h.service.distributable(tenant(), &machine()).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_ne!(listed[0].key.fingerprint(), target.key.fingerprint());
        assert_eq!(events(&h).last().unwrap().0, AuditEventType::SshKeyRevoked);
        assert!(matches!(
            h.alerts.sent.lock().unwrap().last().unwrap().kind,
            SecurityAlertKind::SshKeyRevoked { .. }
        ));
        // 2 度目・別の組織の id は見つからない。
        assert_eq!(
            h.service.revoke(tenant(), COOKIE, target.id, &ctx()).await,
            RevokeSshKeyOutcome::NotFound
        );
        let other = listed[0].clone();
        let other_id = h.keys.rows.lock().unwrap()[0].id;
        assert_eq!(
            h.service
                .revoke(
                    TenantContext::new(other_tenant_id()),
                    COOKIE,
                    other_id,
                    &ctx()
                )
                .await,
            RevokeSshKeyOutcome::NotFound
        );
        assert_eq!(other.username, "kyon");
    }

    #[tokio::test]
    async fn people_cannot_read_the_distribution_list() {
        let h = passkey_just_now();
        register(&h, &ed25519_sk_line(1)).await;
        assert_eq!(
            h.service
                .distributable(tenant(), &AdminActor::User(Uuid::from_u128(1)))
                .await,
            Err(SshKeyDistributionError::NotAMachine)
        );
    }

    #[tokio::test]
    async fn a_user_has_a_limit_on_keys() {
        let h = passkey_just_now();
        for seed in 0..MAX_SSH_KEYS_PER_USER as u8 {
            assert!(matches!(
                register(&h, &ed25519_sk_line(seed + 10)).await,
                RegisterSshKeyOutcome::Registered { .. }
            ));
        }
        assert_eq!(
            register(&h, &ed25519_sk_line(200)).await,
            RegisterSshKeyOutcome::TooMany
        );
    }
}
