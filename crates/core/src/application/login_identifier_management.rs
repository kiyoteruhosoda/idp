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

#[derive(Debug, Clone)]
pub struct AddLoginIdentifierCommand {
    pub identifier_type: LoginIdentifierType,
    /// 利用者が入力するままの値（正規化前）。
    pub value: String,
    /// 追加直後に有効にするか（既定 true）。
    pub is_active: bool,
}

/// 一覧の 1 件。
///
/// `id` は `Option` のままにしてある。AP15b で主識別子も登録簿の行になり、合成行は無くなった
/// ので現状は常に `Some` だが、**契約（API の応答）としては `null` を返し得る形**を保つ。
/// 型を狭めると api・web・その先の利用者に同時配布を強いる変更になり、得られるのは
/// 「`None` を書けない」だけである。
#[derive(Debug, Clone)]
pub struct LoginIdentifierEntry {
    pub id: Option<Uuid>,
    pub identifier_type: LoginIdentifierType,
    pub display_value: String,
    pub normalized_value: String,
    pub is_active: bool,
    /// 主たるログイン識別子か（登録簿の `primary_of_user` 行）。主識別子は識別子単位の
    /// 有効/無効・削除の対象にならない（変えるならプロフィール編集、止めるならアカウントの無効化）。
    pub is_primary: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserLoginIdentifier> for LoginIdentifierEntry {
    fn from(v: UserLoginIdentifier) -> Self {
        Self {
            id: Some(v.id),
            identifier_type: v.identifier_type,
            display_value: v.display_value,
            normalized_value: v.normalized_value,
            is_active: v.is_active,
            is_primary: v.is_primary,
            created_at: v.created_at,
            updated_at: v.updated_at,
        }
    }
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
    ///
    /// **登録簿の行がすべてである**（AP15b）。主識別子も行として在るので、expand フェーズで
    /// 足していた「`users.preferred_username` から読み出し時に合成する行」は無くなった。
    /// ここに出る値と、ログイン欄で実際に解決される値が、同じ 1 つの表から来る。
    pub async fn list(
        &self,
        tenant: TenantContext,
        target: Uuid,
    ) -> Result<Vec<LoginIdentifierEntry>, LoginIdentifierManagementError> {
        let user = self.find_home_user(tenant, target).await?;
        let stored = self
            .identifiers
            .list_for_user(user.id)
            .await
            .map_err(internal)?;
        let mut entries: Vec<LoginIdentifierEntry> =
            stored.into_iter().map(LoginIdentifierEntry::from).collect();
        // 主識別子を先頭に固定する（登録簿の行は追加順に並ぶため、格上げされた行は途中に来る）。
        entries.sort_by_key(|e| !e.is_primary);
        Ok(entries)
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

        self.ensure_available(tenant_id, user.id, cmd.identifier_type, &raw)
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
            // 管理画面から足すのは**追加の**識別子（主識別子はプロフィール編集が持つ）。
            is_primary: false,
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
    /// 主たるログイン識別子（`users.preferred_username`）は登録簿に無いため対象にならない
    /// （一覧では `id` が `null` の合成行として出る）。変えたいならプロフィール編集（MT25）を使う。
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

    /// 追加しようとしている値が、まだ誰のログインにも使われていないことを確かめる。
    ///
    /// **自分自身に解決される値も拒む。** 他人に解決される値が危ないのは自明だが、自分の
    /// `users.preferred_username` と同じ値を登録簿にも足せてしまうと、その行を無効化しても
    /// `preferred_username` へのフォールバックで認証が通る ——「止めたのに使える」識別子が
    /// できる。重複させないことがその状態を作らせない一番簡単な方法である。
    async fn ensure_available(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        identifier_type: LoginIdentifierType,
        raw: &str,
    ) -> Result<(), LoginIdentifierManagementError> {
        // 1. 実際のログイン経路と同じ引き方。登録簿にも `users.preferred_username` にも当たる。
        if self
            .users
            .find_by_login_identifier(tenant_id, raw)
            .await
            .map_err(internal)?
            .is_taken()
        {
            return Err(LoginIdentifierManagementError::Conflict(MessageKey::new(
                "api-login-identifier-conflict",
            )));
        }
        // 2. `users.email` は現状ログインの入り口ではないため 1 では当たらない。しかし他人の
        //    メールアドレスを自分のログイン識別子にできると、その人の連絡先で本人になりすませる。
        //    メール種別のときだけ、利用者表の側も見る。
        // 本人のメールアドレスを本人の識別子にするのは正当な使い方（「メールでログインしたい」）
        // なので、他人のものだけを拒む。
        if identifier_type == LoginIdentifierType::Email {
            if let Some(found) = self
                .users
                .find_by_email(tenant_id, raw)
                .await
                .map_err(internal)?
            {
                if found.id != user_id {
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
        async fn update_password(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            Ok(true)
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            Ok(true)
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
            // DB の一意キーと同じ判定にする（migration 0041 で**種別を含めない**形になった。
            // 種別は正規化のしかたを決めるためのもので、値の持ち主を決めるものではない）。
            // 値の比較も大小を無視する —— 列の照合順序が `utf8mb4_unicode_ci` であり、種別ごとに
            // 正規化の向きが違う（ユーザー名は小文字化、社員番号は大文字化）ため、`==` で見ると
            // `alice` と `ALICE` の衝突を DB は弾くのにフェイクは通してしまう。
            if rows.iter().any(|r| {
                r.tenant_id == identifier.tenant_id
                    && r.normalized_value
                        .eq_ignore_ascii_case(&identifier.normalized_value)
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
            password_changed_at: None,
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
    async fn rejects_a_value_that_already_resolves_to_the_user_themselves() {
        // 自分の `preferred_username` を登録簿にも足せてしまうと、その行を無効化しても
        // `users` へのフォールバックで認証が通る（「止めたのに使える」識別子）。
        let (service, _) = service(vec![user(2, "alice", "alice@example.com")]);
        let err = service
            .add(
                tenant(),
                Uuid::from_u128(2),
                AddLoginIdentifierCommand {
                    identifier_type: LoginIdentifierType::Username,
                    value: "Alice".to_string(),
                    is_active: true,
                },
                Uuid::from_u128(9),
                &ctx(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LoginIdentifierManagementError::Conflict(_)));
    }

    /// 一覧は登録簿の行だけを出す（AP15b で合成行は無くなった）。主識別子は先頭に来る。
    #[tokio::test]
    async fn the_list_shows_registry_rows_with_the_primary_first() {
        let (service, identifiers) = service(vec![user(2, "alice", "alice@example.com")]);
        // 主識別子は登録簿の行として在る（`UserRepository` が作る。ここでは直接置く）。
        let now = chrono::Utc::now();
        identifiers
            .create(&UserLoginIdentifier {
                id: Uuid::from_u128(100),
                tenant_id: tenant().tenant_id(),
                user_id: Uuid::from_u128(2),
                identifier_type: LoginIdentifierType::Username,
                display_value: "alice".to_string(),
                normalized_value: "alice".to_string(),
                is_active: true,
                is_primary: true,
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        service
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

        let entries = service.list(tenant(), Uuid::from_u128(2)).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_primary);
        assert_eq!(entries[0].normalized_value, "alice");
        // 主識別子も保存された行なので id を持つ。識別子単位で操作できないのは
        // リポジトリ側が弾くからであって、宛先が無いからではない。
        assert!(entries[0].id.is_some());
        assert!(!entries[1].is_primary);
        assert!(entries[1].id.is_some());
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
