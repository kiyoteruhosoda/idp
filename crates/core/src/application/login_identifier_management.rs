//! ログイン識別子の管理ユースケース（AP8。仕様 §4）。
//!
//! テナント管理者（`idp.tenant.admin`）が、利用者に**複数のログイン識別子**を割り当てる。
//! 電話番号・社員番号のように組織がすでに配っている値でログインさせたり、旧いユーザー名を
//! 残したまま新しい名前を配ったりするための操作である。
//!
//! # 一意性の判定は「解決してみる」で行う
//!
//! 追加する値が使えるかは、DB の一意制約（登録簿の中の重複）だけでは決まらない。
//! 主たるログイン識別子は expand フェーズの間 `users.preferred_username` 側にもあり、
//! そちらと衝突した識別子は「登録はできたが、ログインすると別人が返る（あるいは返らない）」
//! という壊れ方をする。そこで**実際の解決経路と同じ引き方**
//! （[`UserRepository::find_by_login_identifier`]）を通し、他人に解決される値を拒否する。
//! 判定と本番の経路が同じである限り、両者がずれることはない。
//!
//! メールアドレスを識別子にする場合、その所有確認（検証メール）は行わない。管理者が割り当てる
//! 操作であり、管理者によるメール変更（MT25）が検証済みを維持するのと同じ扱いにする。
//! 利用者本人が自分で足せる導線は用意しない。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::error::DomainError;
use crate::domain::id_generator::IdGenerator;
use crate::domain::login_identifier::{LoginIdentifierType, UserLoginIdentifier};
use crate::domain::message::MessageKey;
use crate::domain::repositories::{UserLoginIdentifierRepository, UserRepository};
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use std::sync::Arc;
use uuid::Uuid;

/// 主たるログイン識別子（`users.preferred_username`）と登録簿の写しを一致させる係（AP8）。
///
/// expand フェーズでは同じ値が 2 か所にある。解決は登録簿を先に見るため、`users` 側だけを
/// 変えると**変更前のユーザー名でログインできてしまう**。利用者の作成・プロフィール編集の
/// どちらからも同じ 1 メソッドを通し、「同期の作法」がユースケースごとに分かれないようにする。
///
/// 写しの撤去（`preferred_username` 列そのものを登録簿へ移す contract フェーズ）まで生きる
/// 一時的な部品であり、そのときこの型ごと消える。
pub struct PrimaryLoginIdentifierSync {
    identifiers: Arc<dyn UserLoginIdentifierRepository>,
    ids: Arc<dyn IdGenerator>,
}

impl PrimaryLoginIdentifierSync {
    pub fn new(
        identifiers: Arc<dyn UserLoginIdentifierRepository>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self { identifiers, ids }
    }

    /// 登録簿の `username` 種別の行を、現在の `preferred_username` に合わせる。
    /// `None`（識別子の解除）なら行を消す。
    pub async fn sync_username(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        preferred_username: Option<&str>,
    ) -> Result<(), DomainError> {
        self.identifiers
            .sync_derived(
                tenant_id,
                user_id,
                LoginIdentifierType::Username,
                preferred_username,
                self.ids.new_id(),
            )
            .await
    }
}

#[derive(Debug, Clone)]
pub struct AddLoginIdentifierCommand {
    pub identifier_type: LoginIdentifierType,
    /// 利用者が入力するままの値（正規化前）。
    pub value: String,
    /// 追加直後に有効にするか（既定 true）。
    pub is_active: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum LoginIdentifierManagementError {
    #[error("not found")]
    NotFound,
    #[error("validation error: {0}")]
    Validation(MessageKey),
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

fn internal(e: DomainError) -> LoginIdentifierManagementError {
    LoginIdentifierManagementError::Internal(e.to_string())
}

pub struct LoginIdentifierManagementService {
    identifiers: Arc<dyn UserLoginIdentifierRepository>,
    users: Arc<dyn UserRepository>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
}

impl LoginIdentifierManagementService {
    pub fn new(
        identifiers: Arc<dyn UserLoginIdentifierRepository>,
        users: Arc<dyn UserRepository>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            identifiers,
            users,
            audit,
            clock,
            ids,
        }
    }

    /// 利用者のログイン識別子を一覧する（無効な行も含む）。
    pub async fn list(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<Vec<UserLoginIdentifier>, LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        self.identifiers
            .list_for_user(user.id)
            .await
            .map_err(internal)
    }

    /// ログイン識別子を追加する。
    pub async fn add(
        &self,
        tenant: TenantContext,
        target: Uuid,
        cmd: AddLoginIdentifierCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<UserLoginIdentifier, LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let tenant_id = tenant.tenant_id();
        let raw = cmd.value.trim().to_string();
        let normalized = cmd
            .identifier_type
            .normalize_checked(&raw)
            .map_err(LoginIdentifierManagementError::Validation)?;

        self.ensure_available(tenant_id, &user, cmd.identifier_type, &raw)
            .await?;

        let now = self.clock.now();
        let identifier = UserLoginIdentifier {
            id: self.ids.new_id(),
            tenant_id,
            user_id: user.id,
            identifier_type: cmd.identifier_type,
            display_value: raw,
            normalized_value: normalized,
            is_active: cmd.is_active,
            created_at: now,
            updated_at: now,
        };
        self.identifiers
            .create(&identifier)
            .await
            .map_err(|e| match e {
                DomainError::Conflict(_) => LoginIdentifierManagementError::Conflict(
                    MessageKey::new("api-login-identifier-conflict"),
                ),
                other => internal(other),
            })?;

        self.record(
            AuditEventType::UserLoginIdentifierAdded,
            tenant_id,
            actor,
            &format!("type={}", cmd.identifier_type.as_str()),
            ctx,
        )
        .await;
        Ok(identifier)
    }

    /// 識別子単位の有効/無効を切り替える（仕様 §4）。
    ///
    /// 行を消さずに止められることが要点で、止めた値は他の利用者が登録できないままになる
    /// （登録簿の一意制約は `is_active` を見ない）。止めた識別子の宛先が黙って別人に移るのを防ぐ。
    pub async fn set_active(
        &self,
        tenant: TenantContext,
        target: Uuid,
        identifier_id: Uuid,
        is_active: bool,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<UserLoginIdentifier, LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let identifier = self.find_owned(user.id, identifier_id).await?;
        if !self
            .identifiers
            .set_active(identifier.id, user.id, is_active)
            .await
            .map_err(internal)?
        {
            return Err(LoginIdentifierManagementError::NotFound);
        }
        self.record(
            AuditEventType::UserLoginIdentifierUpdated,
            tenant.tenant_id(),
            actor,
            &format!(
                "type={} active={}",
                identifier.identifier_type.as_str(),
                is_active
            ),
            ctx,
        )
        .await;
        Ok(UserLoginIdentifier {
            is_active,
            updated_at: self.clock.now(),
            ..identifier
        })
    }

    /// 識別子を削除する。
    ///
    /// `users.preferred_username` の写し（`username` 種別）は削除させない。消しても
    /// `users` 側が残っているためログインは通り続け、「消したのに使える」という食い違いだけが
    /// 残る。ログイン識別子そのものを変えたいならプロフィール編集（MT25）を使う。
    pub async fn remove(
        &self,
        tenant: TenantContext,
        target: Uuid,
        identifier_id: Uuid,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<(), LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let identifier = self.find_owned(user.id, identifier_id).await?;
        if identifier.identifier_type == LoginIdentifierType::Username
            && user
                .preferred_username
                .as_deref()
                .map(|v| LoginIdentifierType::Username.normalize(v))
                .as_deref()
                == Some(identifier.normalized_value.as_str())
        {
            return Err(LoginIdentifierManagementError::Validation(MessageKey::new(
                "api-login-identifier-primary-immutable",
            )));
        }
        if !self
            .identifiers
            .delete(identifier.id, user.id)
            .await
            .map_err(internal)?
        {
            return Err(LoginIdentifierManagementError::NotFound);
        }
        self.record(
            AuditEventType::UserLoginIdentifierRemoved,
            tenant.tenant_id(),
            actor,
            &format!("type={}", identifier.identifier_type.as_str()),
            ctx,
        )
        .await;
        Ok(())
    }

    /// 追加しようとしている値が、この利用者以外に解決されないことを確かめる。
    async fn ensure_available(
        &self,
        tenant_id: TenantId,
        user: &User,
        identifier_type: LoginIdentifierType,
        raw: &str,
    ) -> Result<(), LoginIdentifierManagementError> {
        // 1. 実際のログイン経路と同じ引き方。登録簿にも `users.preferred_username` にも当たる。
        if let Some(found) = self
            .users
            .find_by_login_identifier(tenant_id, raw)
            .await
            .map_err(internal)?
        {
            if found.id != user.id {
                return Err(LoginIdentifierManagementError::Conflict(MessageKey::new(
                    "api-login-identifier-conflict",
                )));
            }
        }
        // 2. `users.email` は現状ログインの入り口ではないため 1 では当たらない。しかし他人の
        //    メールアドレスを自分のログイン識別子にできると、その人の連絡先で本人になりすませる。
        //    メール種別のときだけ、利用者表の側も見る。
        if identifier_type == LoginIdentifierType::Email {
            if let Some(found) = self
                .users
                .find_by_email(tenant_id, raw)
                .await
                .map_err(internal)?
            {
                if found.id != user.id {
                    return Err(LoginIdentifierManagementError::Conflict(MessageKey::new(
                        "api-login-identifier-conflict",
                    )));
                }
            }
        }
        Ok(())
    }

    async fn find_owned(
        &self,
        user_id: Uuid,
        identifier_id: Uuid,
    ) -> Result<UserLoginIdentifier, LoginIdentifierManagementError> {
        match self
            .identifiers
            .find_by_id(identifier_id)
            .await
            .map_err(internal)?
        {
            Some(identifier) if identifier.user_id == user_id => Ok(identifier),
            _ => Err(LoginIdentifierManagementError::NotFound),
        }
    }

    async fn find_home_user(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<User, LoginIdentifierManagementError> {
        match self.users.find_by_id(target).await.map_err(internal)? {
            Some(user) if user.tenant_id == tenant.tenant_id() => Ok(user),
            _ => Err(LoginIdentifierManagementError::NotFound),
        }
    }

    /// 監査記録。**識別子の値は残さない**（電話番号・メールは PII。`CLAUDE.md`「ログ」）。
    async fn record(
        &self,
        event_type: AuditEventType,
        tenant_id: TenantId,
        actor: Uuid,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                event_type,
                AuditResult::Success,
                Some(tenant_id),
                Some(actor),
                None,
                Some(reason),
                ctx,
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::audit::AuditEvent;
    use crate::domain::clock::Clock;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

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

    struct DiscardingSink;
    #[async_trait]
    impl AuditLogSink for DiscardingSink {
        async fn record(&self, _event: &AuditEvent) -> DomainResult<()> {
            Ok(())
        }
    }

    struct Users {
        rows: Vec<User>,
    }

    #[async_trait]
    impl UserRepository for Users {
        async fn create(&self, _user: &User) -> DomainResult<()> {
            Ok(())
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self.rows.iter().find(|u| u.id == id).cloned())
        }
        async fn find_by_sub(&self, _sub: Uuid) -> DomainResult<Option<User>> {
            Ok(None)
        }
        async fn find_by_email(&self, t: TenantId, e: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .iter()
                .find(|u| u.tenant_id == t && u.email.eq_ignore_ascii_case(e))
                .cloned())
        }
        async fn find_by_username(&self, t: TenantId, n: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .iter()
                .find(|u| {
                    u.tenant_id == t
                        && u.preferred_username
                            .as_deref()
                            .is_some_and(|v| v.eq_ignore_ascii_case(n))
                })
                .cloned())
        }
        async fn update_login_state(
            &self,
            _id: Uuid,
            _c: i32,
            _l: Option<chrono::DateTime<Utc>>,
        ) -> DomainResult<()> {
            Ok(())
        }
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: chrono::DateTime<Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
        async fn update_password(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
            Ok(())
        }
        async fn reset_password_forced(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
            Ok(())
        }
        async fn update_status(&self, _id: Uuid, _s: UserStatus) -> DomainResult<()> {
            Ok(())
        }
        async fn delete(&self, _id: Uuid) -> DomainResult<()> {
            Ok(())
        }
        async fn mark_email_verified(&self, _id: Uuid) -> DomainResult<()> {
            Ok(())
        }
        async fn update_language(&self, _id: Uuid, _l: Option<&str>) -> DomainResult<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Identifiers {
        rows: Mutex<Vec<UserLoginIdentifier>>,
    }

    #[async_trait]
    impl UserLoginIdentifierRepository for Identifiers {
        async fn create(&self, identifier: &UserLoginIdentifier) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if rows.iter().any(|r| {
                r.tenant_id == identifier.tenant_id
                    && r.identifier_type == identifier.identifier_type
                    && r.normalized_value == identifier.normalized_value
            }) {
                return Err(DomainError::Conflict("duplicate".to_string()));
            }
            rows.push(identifier.clone());
            Ok(())
        }
        async fn list_for_user(&self, user_id: Uuid) -> DomainResult<Vec<UserLoginIdentifier>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.user_id == user_id)
                .cloned()
                .collect())
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<UserLoginIdentifier>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.id == id)
                .cloned())
        }
        async fn set_active(&self, id: Uuid, user_id: Uuid, is_active: bool) -> DomainResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            match rows.iter_mut().find(|r| r.id == id && r.user_id == user_id) {
                Some(row) => {
                    row.is_active = is_active;
                    Ok(true)
                }
                None => Ok(false),
            }
        }
        async fn delete(&self, id: Uuid, user_id: Uuid) -> DomainResult<bool> {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|r| !(r.id == id && r.user_id == user_id));
            Ok(rows.len() != before)
        }
    }

    fn tenant() -> TenantContext {
        TenantContext::new(TenantId::from(Uuid::from_u128(1)))
    }

    fn user(id: u128, username: &str, email: &str) -> User {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        User {
            id: Uuid::from_u128(id),
            tenant_id: TenantId::from(Uuid::from_u128(1)),
            sub: Uuid::from_u128(id + 100),
            email: email.to_string(),
            email_verified: true,
            preferred_username: Some(username.to_string()),
            name: None,
            language: None,
            password_hash: String::new(),
            must_change_password: false,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn service(users: Vec<User>) -> (LoginIdentifierManagementService, Arc<Identifiers>) {
        let clock = Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap(),
        ));
        let identifiers = Arc::new(Identifiers::default());
        let audit = Arc::new(AuditService::new(Arc::new(DiscardingSink), clock.clone()));
        let service = LoginIdentifierManagementService::new(
            identifiers.clone(),
            Arc::new(Users { rows: users }),
            audit,
            clock,
            Arc::new(FixedIds(Mutex::new(1000))),
        );
        (service, identifiers)
    }

    fn ctx() -> RequestContext {
        RequestContext {
            ip_address: None,
            user_agent: None,
            correlation_id: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn adds_a_phone_identifier_and_normalizes_it() {
        let (service, _) = service(vec![user(2, "alice", "alice@example.com")]);
        let added = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::PhoneNumber,
                    value: "090-1234-5678".to_string(),
                    is_active: true,
                },
                Uuid::from_u128(9),
                &ctx(),
            )
            .await
            .unwrap();
        // 表示は登録どおり、照合は正規化した値。
        assert_eq!(added.display_value, "090-1234-5678");
        assert_eq!(added.normalized_value, "09012345678");
    }

    #[tokio::test]
    async fn rejects_a_value_that_resolves_to_another_user() {
        // bob の `preferred_username` を alice の識別子にはできない（ログイン時に別人が返る）。
        let (service, _) = service(vec![
            user(2, "alice", "alice@example.com"),
            user(3, "bob", "bob@example.com"),
        ]);
        let err = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::Username,
                    value: "BOB".to_string(),
                    is_active: true,
                },
                Uuid::from_u128(9),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::Conflict(_)));
    }

    #[tokio::test]
    async fn rejects_another_users_email_even_though_email_is_not_a_login_route() {
        let (service, _) = service(vec![
            user(2, "alice", "alice@example.com"),
            user(3, "bob", "bob@example.com"),
        ]);
        let err = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::Email,
                    value: "Bob@Example.com".to_string(),
                    is_active: true,
                },
                Uuid::from_u128(9),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::Conflict(_)));
    }

    #[tokio::test]
    async fn deactivating_keeps_the_row_so_nobody_else_can_claim_it() {
        let (service, repo) = service(vec![user(2, "alice", "alice@example.com")]);
        let added = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::EmployeeNumber,
                    value: "E-1001".to_string(),
                    is_active: true,
                },
                Uuid::from_u128(9),
                &ctx(),
            )
            .await
            .unwrap();
        let updated = service
            .set_active(
                tenant(),
                Uuid::from_u128(2),
                added.id,
                false,
                Uuid::from_u128(9),
                &ctx(),
            )
            .await
            .unwrap();
        assert!(!updated.is_active);
        assert_eq!(repo.rows.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refuses_to_remove_the_copy_of_the_primary_username() {
        let (service, repo) = service(vec![user(2, "alice", "alice@example.com")]);
        // migration 0029 の backfill が作る行に相当する。
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        repo.rows.lock().unwrap().push(UserLoginIdentifier {
            id: Uuid::from_u128(50),
            tenant_id: TenantId::from(Uuid::from_u128(1)),
            user_id: Uuid::from_u128(2),
            identifier_type: LoginIdentifierType::Username,
            display_value: "alice".to_string(),
            normalized_value: "alice".to_string(),
            is_active: true,
            created_at: now,
            updated_at: now,
        });
        let err = service
            .remove(
                tenant(),
                Uuid::from_u128(2),
                Uuid::from_u128(50),
                Uuid::from_u128(9),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::Validation(_)));
    }

    #[tokio::test]
    async fn does_not_touch_users_from_another_tenant() {
        let mut outsider = user(3, "carol", "carol@example.com");
        outsider.tenant_id = TenantId::from(Uuid::from_u128(2));
        let (service, _) = service(vec![outsider]);
        let err = service
            .list(tenant(), Uuid::from_u128(3))
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::NotFound));
    }
}
