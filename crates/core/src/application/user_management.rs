//! 管理者による利用者作成ユースケース（ADR-0009 §5・§6）。
//!
//! テナント管理者（`idp.tenant.admin`）が、所属元が当該テナントの利用者を作成する
//! （`POST /{tenant_id}/admin/users`）。セルフ登録（[`crate::application::register`]）と異なり、
//! **パスワードを自動生成**し（32 文字以上のランダム文字列）、`must_change_password = true` を付与する。
//! 生成パスワードは**この一度だけ**平文でレスポンスに返し（管理者が本人へ別途通知する）、ログ・監査には
//! 出さない（設定リンク・招待トークンと同じパターン。ADR-0009 §5・ADR-0062）。
//!
//! テナント作成フロー（[`crate::application::tenant_management`]）が生成する初期管理者ユーザーも
//! 本サービスを通す（作成ロジックの単一の出所）。判定・検証は本 Application 層で完結し、Presentation
//! には結果のみ返す（`CLAUDE.md`「権限管理」）。

use crate::application::account_setup::{AccountSetupLinkIssuer, SetupLink};
use crate::application::audit::{AuditService, RequestContext};
use crate::domain::admin_actor::AdminActor;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::member_note::normalize_member_note;
use crate::domain::message::MessageKey;
use crate::domain::password::PasswordHasher;
use crate::domain::repositories::{
    MemberNoteRepository, TenantMembershipRepository, UserRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::tenant_membership::TenantMembership;
use crate::domain::user::User;
use crate::domain::values::{
    validate_email as domain_validate_email,
    validate_preferred_username as domain_validate_preferred_username, UserStatus,
};
use std::sync::Arc;
use uuid::Uuid;

/// 自動生成パスワードのバイト長。base64url（パディング無し）で 43 文字となり、ADR-0009 §5 の
/// 「32 文字以上」を満たす。
const GENERATED_PASSWORD_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct CreateUserCommand {
    pub email: String,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    /// 管理者メモ（任意。ADR-0063）。作った利用者の HOME メンバーシップに付く。
    pub note: Option<String>,
}

/// 作成結果。`generated_password` は**この一度だけ**平文で返す（保存はハッシュのみ、ログ・監査には出さない）。
pub struct CreatedUser {
    pub user_id: Uuid,
    pub sub: Uuid,
    /// 本人へ渡す**アカウント設定リンク**（ADR-0062）。この一度だけ返す。
    ///
    /// ⚠ **生成パスワードは返さない。** 作った利用者のハッシュは誰も知らない値で埋めてあり、
    /// 本人はこのリンクでパスキーかパスワードを決めて初めて入れる。管理者が本人の資格情報を
    /// 一度でも手にする形をやめるための変更である。
    pub setup_link: SetupLink,
}

/// 構築済み（未永続化）の利用者。検証・自動生成パスワードのハッシュ化まで済んでおり、永続化だけが
/// 残っている状態。テナント開通（REF2）が、テナント行と同一トランザクションで管理者を永続化する
/// ために使う。`generated_password` の扱いは [`CreatedUser`] と同じ（一度だけ平文、ログに出さない）。
pub struct PreparedUser {
    pub user: User,
    pub generated_password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UserManagementError {
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

pub struct UserManagementService {
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    hasher: Arc<dyn PasswordHasher>,
    /// 作った直後に本人へ渡すリンクを出す（ADR-0062）。作成とリンクの発行は 1 つの操作なので、
    /// 画面やハンドラで 2 回呼ぶ形にしない（片方だけ成功した利用者を作らないため）。
    account_setup: Arc<AccountSetupLinkIssuer>,
    /// 作成と同時に書く管理者メモ（ADR-0063）。
    notes: Arc<dyn MemberNoteRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl UserManagementService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        hasher: Arc<dyn PasswordHasher>,
        account_setup: Arc<AccountSetupLinkIssuer>,
        notes: Arc<dyn MemberNoteRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            users,
            memberships,
            account_setup,
            notes,
            hasher,
            audit,
            clock,
            ids,
        }
    }

    /// 所属元が `tenant` の利用者を**構築だけ**する（永続化しない）。入力検証・一意性の事前チェック・
    /// パスワード自動生成とハッシュ化まで行う。永続化とセットで使う（`create_user`、またはテナント
    /// 開通トランザクション）。
    pub async fn prepare_user(
        &self,
        tenant: TenantContext,
        cmd: CreateUserCommand,
    ) -> Result<PreparedUser, UserManagementError> {
        let email = cmd.email.trim().to_string();
        validate_email(&email)?;
        // ログイン識別子は preferred_username。未指定なら email を既定値として採用する（ADR-0009 §8）。
        let preferred_username =
            normalize_optional(cmd.preferred_username).unwrap_or_else(|| email.clone());
        // カラム長（VARCHAR(255)）超過を永続化前に弾く（email は VARCHAR(320) のため既定値化で超え得る）。
        domain_validate_preferred_username(&preferred_username)
            .map_err(UserManagementError::Validation)?;
        let name = normalize_optional(cmd.name);
        let tenant_id = tenant.tenant_id();

        // 一意性の事前チェック（利用者向けの分かりやすいエラー）。最終的な一意性は DB の
        // `(tenant_id, email)` / `(tenant_id, preferred_username)` UNIQUE 制約と、ログイン識別子の
        // 登録簿の一意制約（AP8）が保証する。識別子側は**解決経路と同じ引き方**で見る
        // （`users` だけを見ると、別名として登録済みの値を素通しにしてしまう）。
        if self
            .users
            .find_by_email(tenant_id, &email)
            .await
            .map_err(internal)?
            .is_some()
        {
            return Err(UserManagementError::Conflict(MessageKey::new(
                "api-user-email-conflict",
            )));
        }
        if self
            .users
            .find_by_login_identifier(tenant_id, &preferred_username)
            .await
            .map_err(internal)?
            .is_taken()
        {
            return Err(UserManagementError::Conflict(MessageKey::new(
                "api-user-username-conflict",
            )));
        }

        let generated_password = crypto::random_token(GENERATED_PASSWORD_BYTES);
        let password_hash = self.hasher.hash(&generated_password).map_err(internal)?;
        let now = self.clock.now();
        let user = User {
            id: self.ids.new_id(),
            tenant_id,
            sub: self.ids.new_id(),
            email,
            // 管理者が作成するユーザーは管理者がメール所有を保証する扱いとし、検証済みで作る（SEC6b）。
            // これにより自己登録（未検証）のみがログイン時のメール検証ゲートに掛かる。テナント作成時の
            // 初期管理者（本サービス経由）もログイン可能なまま。
            email_verified: true,
            preferred_username: Some(preferred_username),
            name,
            language: None,
            theme: None,
            password_hash,
            must_change_password: true,
            password_changed_at: Some(now),
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        };

        Ok(PreparedUser {
            user,
            generated_password,
        })
    }

    /// 所属元が `tenant` の利用者を、自動生成パスワード付きで作成する。HOME メンバーシップを同時に
    /// 生成し、`must_change_password = true` を付与する。生成パスワードを一度だけ返す。
    pub async fn create_user(
        &self,
        tenant: TenantContext,
        cmd: CreateUserCommand,
        actor: &AdminActor,
        ctx: &RequestContext,
    ) -> Result<CreatedUser, UserManagementError> {
        let tenant_id = tenant.tenant_id();
        // ⚠ メモは**何も書く前に**確かめる。利用者を作ったあとで長すぎると分かっても、作成は
        //   取り消せない（「作れたのにエラー」になる）。
        let note = normalize_member_note(cmd.note.as_deref().unwrap_or(""))
            .map_err(UserManagementError::Validation)?;
        let prepared = self.prepare_user(tenant, cmd).await?;
        let user = prepared.user;

        self.users.create(&user).await.map_err(|e| match e {
            // DB の一意制約違反は (tenant_id, email) / (tenant_id, preferred_username) のいずれか。
            // 事前チェックとの競合（同時登録）でのみ到達するため、どちらかを特定せず一括で伝える。
            DomainError::Conflict(_) => {
                UserManagementError::Conflict(MessageKey::new("api-user-identity-conflict"))
            }
            other => UserManagementError::Internal(other.to_string()),
        })?;

        // HOME メンバーシップ（所属元の単一の出所は users.tenant_id。この行はフロー判定用の投影。§3）。
        self.memberships
            .create(&TenantMembership::new_home(
                tenant_id,
                user.id,
                user.created_at,
            ))
            .await
            .map_err(internal)?;

        // 監査には内部 ID のみ記録する（生成パスワードは出さない。§5）。
        self.audit
            .record(
                AuditEventType::UserCreated,
                AuditResult::Success,
                Some(tenant_id),
                actor.user_id(),
                actor.client_id(),
                Some(&format!("user={}", user.id)),
                ctx,
            )
            .await;

        // 管理者メモ（ADR-0063）。メンバーの画面から書くのと同じ行・同じ監査の形にする
        // （中身は監査に残さない）。
        if let Some(text) = note.as_deref() {
            self.notes
                .save(tenant_id, user.id, text, actor.user_id(), self.clock.now())
                .await
                .map_err(internal)?;
            self.audit
                .record(
                    AuditEventType::TenantMemberNoteUpdated,
                    AuditResult::Success,
                    Some(tenant_id),
                    actor.user_id(),
                    actor.client_id(),
                    Some(&format!("member={}", user.id)),
                    ctx,
                )
                .await;
        }

        // 本人へ渡すリンクを出す。⚠ **ここで失敗したら作成ごと失敗させる** —— リンクの無い
        // 利用者は、誰も知らないパスワードだけを持つ「入れないアカウント」になる。
        let setup_link = self
            .account_setup
            .issue(tenant_id, user.id)
            .await
            .map_err(|e| UserManagementError::Internal(e.to_string()))?;

        Ok(CreatedUser {
            user_id: user.id,
            sub: user.sub,
            setup_link,
        })
    }
}

fn validate_email(email: &str) -> Result<(), UserManagementError> {
    domain_validate_email(email).map_err(UserManagementError::Validation)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn internal(e: DomainError) -> UserManagementError {
    UserManagementError::Internal(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::password::PasswordHasher as PasswordHasherTrait;
    use crate::domain::repositories::AuditLogSink;
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

    struct FixedIds(Mutex<u128>);
    impl IdGenerator for FixedIds {
        fn new_id(&self) -> Uuid {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            Uuid::from_u128(*n)
        }
    }

    struct PlainHasher;
    impl PasswordHasherTrait for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
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
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        /// 本番の sqlx 実装は 1 文の UPDATE で加算する（SEC13）。フェイクは単一スレッドの
        /// テストでしか動かないので、同じ結果になる素朴な加算で足りる。
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
        async fn find_by_username(&self, t: TenantId, name: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.tenant_id == t && u.preferred_username.as_deref() == Some(name))
                .cloned())
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
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_language(&self, _id: Uuid, _language: Option<&str>) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeMemberships {
        rows: Mutex<Vec<TenantMembership>>,
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn update_status(
            &self,
            _t: TenantId,
            _u: Uuid,
            _s: crate::domain::values::MembershipStatus,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn create(&self, m: &TenantMembership) -> DomainResult<()> {
            self.rows.lock().unwrap().push(m.clone());
            Ok(())
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, _t: TenantId, _u: Uuid) -> DomainResult<bool> {
            unreachable!()
        }
        async fn find_by_invitation_token_hash(
            &self,
            _h: &str,
        ) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn activate(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn ctx() -> RequestContext {
        RequestContext {
            correlation_id: "corr-1".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    /// 書かれたメモを記録するだけのフェイク（ADR-0063）。
    #[derive(Default)]
    struct FakeNotes {
        saved: Mutex<Vec<(TenantId, Uuid, String)>>,
    }
    #[async_trait]
    impl MemberNoteRepository for FakeNotes {
        async fn save(
            &self,
            tenant_id: TenantId,
            user_id: Uuid,
            text: &str,
            _updated_by: Option<Uuid>,
            _now: DateTime<Utc>,
        ) -> DomainResult<()> {
            self.saved
                .lock()
                .unwrap()
                .push((tenant_id, user_id, text.to_string()));
            Ok(())
        }
        async fn clear(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!("作成でメモを消すことはない")
        }
    }

    fn service(
        users: Arc<FakeUsers>,
        memberships: Arc<FakeMemberships>,
        sink: Arc<CapturingSink>,
    ) -> UserManagementService {
        service_with_notes(users, memberships, sink, Arc::new(FakeNotes::default()))
    }

    fn service_with_notes(
        users: Arc<FakeUsers>,
        memberships: Arc<FakeMemberships>,
        sink: Arc<CapturingSink>,
        notes: Arc<FakeNotes>,
    ) -> UserManagementService {
        let audit = Arc::new(AuditService::new(sink, Arc::new(FixedClock(now()))));
        UserManagementService::new(
            users,
            memberships,
            Arc::new(PlainHasher),
            crate::application::account_setup::testing::link_issuer(
                Arc::new(crate::application::account_setup::testing::FakeSetupTokens::default()),
                Arc::new(FixedClock(now())),
            ),
            notes,
            audit,
            Arc::new(FixedClock(now())),
            Arc::new(FixedIds(Mutex::new(0))),
        )
    }

    #[tokio::test]
    async fn creates_user_with_generated_password_and_home_membership() {
        let tenant: TenantId = Uuid::now_v7().into();
        let users = Arc::new(FakeUsers::default());
        let memberships = Arc::new(FakeMemberships::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(users.clone(), memberships.clone(), sink.clone());

        let created = svc
            .create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "  new@example.com ".to_string(),
                    preferred_username: Some("newbie".to_string()),
                    name: None,
                    note: None,
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("created");

        // 本人へ渡すリンクが出る（ADR-0062）。⚠ **生成パスワードは返らない。**
        assert!(created.setup_link.token.len() >= 32);
        assert!(
            created
                .setup_link
                .url
                .starts_with("https://idp.example.com/"),
            "the link points at the web console: {}",
            created.setup_link.url
        );
        assert!(created.setup_link.url.contains(&created.setup_link.token));
        let stored = users.rows.lock().unwrap()[0].clone();
        // ⚠ **誰も知らないパスワードで埋まっている**（管理者も本人も入れない。リンクで決める）。
        assert!(stored.password_hash.starts_with("hash:"));
        assert!(stored.must_change_password);
        assert_eq!(stored.email, "new@example.com");
        assert_eq!(stored.tenant_id, tenant);
        // HOME メンバーシップが作られる。
        let m = memberships.rows.lock().unwrap()[0].clone();
        assert!(m.is_home());
        assert_eq!(m.tenant_id, tenant);
        // 監査にリンクのトークンが漏れていない。
        assert!(sink.events.lock().unwrap().iter().all(|e| e
            .reason
            .as_deref()
            .map(|r| !r.contains(&created.setup_link.token))
            .unwrap_or(true)));
        assert_eq!(
            sink.events.lock().unwrap()[0].event_type,
            AuditEventType::UserCreated
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_email() {
        let tenant: TenantId = Uuid::now_v7().into();
        let users = Arc::new(FakeUsers::default());
        let svc = service(
            users.clone(),
            Arc::new(FakeMemberships::default()),
            Arc::new(CapturingSink::default()),
        );
        let cmd = || CreateUserCommand {
            email: "dup@example.com".to_string(),
            preferred_username: None,
            name: None,
            note: None,
        };
        svc.create_user(
            TenantContext::new(tenant),
            cmd(),
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("first ok");
        assert!(matches!(
            svc.create_user(
                TenantContext::new(tenant),
                cmd(),
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(UserManagementError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_email() {
        let tenant: TenantId = Uuid::now_v7().into();
        let svc = service(
            Arc::new(FakeUsers::default()),
            Arc::new(FakeMemberships::default()),
            Arc::new(CapturingSink::default()),
        );
        assert!(matches!(
            svc.create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "not-an-email".to_string(),
                    preferred_username: None,
                    name: None,
                    note: None,
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx()
            )
            .await,
            Err(UserManagementError::Validation(_))
        ));
    }

    /// ADR-0063: 作成と同時に書いたメモは、作った利用者の HOME メンバーシップに付く。
    /// 監査は「作った」と「メモを書いた」の 2 件で、⚠ メモの中身は残らない。
    #[tokio::test]
    async fn a_note_given_at_creation_goes_on_the_home_membership() {
        let tenant: TenantId = Uuid::now_v7().into();
        let sink = Arc::new(CapturingSink::default());
        let notes = Arc::new(FakeNotes::default());
        let svc = service_with_notes(
            Arc::new(FakeUsers::default()),
            Arc::new(FakeMemberships::default()),
            sink.clone(),
            notes.clone(),
        );
        let created = svc
            .create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "family@example.com".to_string(),
                    preferred_username: None,
                    name: None,
                    note: Some("\r\n 家族として作成\r\n".to_string()),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await
            .expect("created");

        let saved = notes.saved.lock().unwrap().clone();
        assert_eq!(
            saved,
            vec![(tenant, created.user_id, "家族として作成".to_string())]
        );
        let events = sink.events.lock().unwrap();
        let kinds: Vec<_> = events.iter().map(|e| e.event_type).collect();
        assert_eq!(
            kinds,
            vec![
                AuditEventType::UserCreated,
                AuditEventType::TenantMemberNoteUpdated
            ]
        );
        assert!(events
            .iter()
            .all(|e| !e.reason.as_deref().unwrap_or("").contains("家族")));
    }

    /// 空のメモは「メモ無し」。行も監査も増えない。
    #[tokio::test]
    async fn a_blank_note_at_creation_writes_nothing() {
        let tenant: TenantId = Uuid::now_v7().into();
        let sink = Arc::new(CapturingSink::default());
        let notes = Arc::new(FakeNotes::default());
        let svc = service_with_notes(
            Arc::new(FakeUsers::default()),
            Arc::new(FakeMemberships::default()),
            sink.clone(),
            notes.clone(),
        );
        svc.create_user(
            TenantContext::new(tenant),
            CreateUserCommand {
                email: "blank@example.com".to_string(),
                preferred_username: None,
                name: None,
                note: Some("  \n ".to_string()),
            },
            &AdminActor::User(Uuid::new_v4()),
            &ctx(),
        )
        .await
        .expect("created");
        assert!(notes.saved.lock().unwrap().is_empty());
        assert_eq!(sink.events.lock().unwrap().len(), 1);
    }

    /// ⚠ 長すぎるメモは**利用者を作る前に**断る（作ったあとで断ると「作れたのにエラー」になる）。
    #[tokio::test]
    async fn a_too_long_note_is_rejected_before_anything_is_created() {
        let tenant: TenantId = Uuid::now_v7().into();
        let users = Arc::new(FakeUsers::default());
        let memberships = Arc::new(FakeMemberships::default());
        let sink = Arc::new(CapturingSink::default());
        let svc = service(users.clone(), memberships.clone(), sink.clone());
        let result = svc
            .create_user(
                TenantContext::new(tenant),
                CreateUserCommand {
                    email: "long@example.com".to_string(),
                    preferred_username: None,
                    name: None,
                    note: Some("あ".repeat(crate::domain::member_note::MEMBER_NOTE_MAX_LEN + 1)),
                },
                &AdminActor::User(Uuid::new_v4()),
                &ctx(),
            )
            .await;
        assert!(matches!(result, Err(UserManagementError::Validation(_))));
        assert!(users.rows.lock().unwrap().is_empty());
        assert!(memberships.rows.lock().unwrap().is_empty());
        assert!(sink.events.lock().unwrap().is_empty());
    }
}
