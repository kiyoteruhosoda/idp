//! 管理者による利用者ライフサイクル操作（無効化・有効化・削除・パスワード再発行・MFA 解除・
//! プロフィール編集。ADR-0009 §5・MT21・MT25）。
//!
//! 操作対象は**所属元（HOME）が要求テナントの利用者のみ**（`users.tenant_id` 照合。ゲストの
//! `users` レコードは所属元テナントの管理者だけが操作できる。§3）。自分自身への操作は禁止する
//! （誤操作によるロックアウト防止。パスワード変更・MFA 解除はセルフサービスを使う）。ただし
//! プロフィール編集（[`UserLifecycleService::update_profile`]）はロックアウトを招かないため自分自身も
//! 対象にできる。
//!
//! パスワード再発行は作成時と同じ方針（[`crate::application::user_management`]）: 32 文字以上の
//! ランダムパスワードを自動生成し、`must_change_password = true` を設定する。生成パスワードは
//! **その応答でのみ**平文で返し、ログ・監査には出さない。再発行・無効化・MFA 解除時は当該利用者の
//! SSO セッション・refresh token・未消費 authorization code を全失効させる。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::message::MessageKey;
use crate::domain::password::PasswordHasher;
use crate::domain::user_authenticator::AuthenticatorType;
use crate::domain::repositories::{
    AuthorizationCodeRepository, RefreshTokenRepository, SsoSessionRepository,
    TotpSecretRepository, UserAuthenticatorRepository, UserRepository,
    WebAuthnCredentialRepository,
};
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::values::{
    validate_display_name, validate_email, validate_preferred_username, UserStatus,
};
use std::sync::Arc;
use uuid::Uuid;

/// 自動生成パスワードのバイト長（base64url で 43 文字。ADR-0009 §5 の「32 文字以上」を満たす）。
const GENERATED_PASSWORD_BYTES: usize = 32;

/// パスワード再発行の結果。`generated_password` は**この一度だけ**平文で返す。
pub struct ResetUserPassword {
    pub user_id: Uuid,
    pub generated_password: String,
}

/// MFA 解除の結果（MT21）。何を外したかを管理者へ返す（監査にも同じ粒度で記録する）。
/// シークレット・クレデンシャルそのものは含めない（`Debug` に載る値も同様）。
#[derive(Debug)]
pub struct MfaReset {
    pub user_id: Uuid,
    /// TOTP 設定が存在して削除されたか（未設定なら `false`）。
    pub totp_removed: bool,
    /// 削除した Passkey（WebAuthn クレデンシャル）の件数。
    pub passkeys_removed: u64,
}

/// プロフィール編集の指示（MT25）。`None` のフィールドは変更しない（部分更新）。
/// `preferred_username` / `name` に空文字を渡すと「解除（`NULL`）」を意味する。
#[derive(Debug, Default, Clone)]
pub struct UpdateUserProfileCommand {
    pub email: Option<String>,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum UserLifecycleError {
    #[error("user not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(MessageKey),
    #[error("validation error: {0}")]
    Validation(MessageKey),
    /// email / preferred_username がテナント内で既に使われている（MT25）。
    #[error("conflict: {0}")]
    Conflict(MessageKey),
    #[error("internal error: {0}")]
    Internal(String),
}

fn internal(e: crate::domain::error::DomainError) -> UserLifecycleError {
    UserLifecycleError::Internal(e.to_string())
}

pub struct UserLifecycleService {
    /// 認証器の登録簿（AP9）。MFA 解除で登録簿側も失効させる。要るのは失効だけなので、
    /// 管理ユースケース全体ではなくリポジトリを直接受ける。
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    refresh_tokens: Arc<dyn RefreshTokenRepository>,
    codes: Arc<dyn AuthorizationCodeRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl UserLifecycleService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        refresh_tokens: Arc<dyn RefreshTokenRepository>,
        codes: Arc<dyn AuthorizationCodeRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            authenticators,
            users,
            sso_sessions,
            refresh_tokens,
            codes,
            totp_secrets,
            webauthn_credentials,
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
            return Err(UserLifecycleError::Validation(MessageKey::new(
                "api-email-required",
            )));
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
            return Err(UserLifecycleError::Validation(MessageKey::new(
                "api-user-status-locked-forbidden",
            )));
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

    /// 利用者のプロフィール（メール・ログイン識別子・表示名）を編集する（MT25）。
    ///
    /// 対象は他のライフサイクル操作と同じく**所属元（HOME）が要求テナントの利用者のみ**。ただし
    /// **自分自身も編集できる**（他操作の自己禁止はロックアウト防止が目的で、表示名やメールの変更は
    /// ロックアウトを招かない。管理者が自分のメールを直せないと運用が詰まる）。
    ///
    /// 変更後の email は**管理者がメール所有を保証する扱い**とし、検証済み（`email_verified`）を
    /// 維持する（管理者作成ユーザーと同じ方針。ADR-0009 §5・SEC6b）。これによりメール変更直後に
    /// 本人がログイン不能になることを避ける。
    ///
    /// `preferred_username` はログイン識別子（ADR-0009 §8）であり、変更するとその利用者の**ログイン
    /// 名が変わる**。空文字は解除を意味するが、解除するとパスワードログインできなくなるため
    /// `Validation` で拒否する。
    pub async fn update_profile(
        &self,
        tenant: TenantContext,
        target: Uuid,
        cmd: UpdateUserProfileCommand,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<User, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        let tenant_id = tenant.tenant_id();
        let mut changed: Vec<&'static str> = Vec::new();

        let email = match cmd.email.as_deref().map(str::trim) {
            Some(email) if email != user.email => {
                validate_email(email).map_err(UserLifecycleError::Validation)?;
                // 一意性の事前チェック（分かりやすいエラー）。最終的な保証は DB の UNIQUE 制約。
                if self
                    .users
                    .find_by_email(tenant_id, email)
                    .await
                    .map_err(internal)?
                    .is_some()
                {
                    return Err(UserLifecycleError::Conflict(MessageKey::new(
                        "api-user-email-conflict",
                    )));
                }
                changed.push("email");
                email.to_string()
            }
            _ => user.email.clone(),
        };

        let preferred_username = match cmd.preferred_username.as_deref().map(str::trim) {
            Some(value) if Some(value) != user.preferred_username.as_deref() => {
                if value.is_empty() {
                    return Err(UserLifecycleError::Validation(MessageKey::new(
                        "api-username-required",
                    )));
                }
                validate_preferred_username(value).map_err(UserLifecycleError::Validation)?;
                if self
                    .users
                    .find_by_username(tenant_id, value)
                    .await
                    .map_err(internal)?
                    .is_some()
                {
                    return Err(UserLifecycleError::Conflict(MessageKey::new(
                        "api-user-username-conflict",
                    )));
                }
                changed.push("preferred_username");
                Some(value.to_string())
            }
            _ => user.preferred_username.clone(),
        };

        let name = match cmd.name.as_deref().map(str::trim) {
            Some(value) => {
                validate_display_name(value).map_err(UserLifecycleError::Validation)?;
                // 空文字は表示名の解除（`NULL`）。
                let next = (!value.is_empty()).then(|| value.to_string());
                if next != user.name {
                    changed.push("name");
                }
                next
            }
            None => user.name.clone(),
        };

        if changed.is_empty() {
            // 変更が無いなら書き込みも監査もしない（監査ログを無内容な行で埋めない）。
            return Ok(user);
        }

        self.users
            .update_profile(
                user.id,
                &email,
                preferred_username.as_deref(),
                name.as_deref(),
            )
            .await
            .map_err(|e| match e {
                // 事前チェックとの競合（同時更新）のみ。どちらの一意キーかは DB からは特定できない。
                crate::domain::error::DomainError::Conflict(_) => {
                    UserLifecycleError::Conflict(MessageKey::new("api-user-identity-conflict"))
                }
                other => internal(other),
            })?;

        // 監査には対象と「変更した項目名」のみ記録する（メール・表示名そのものは PII のため出さない）。
        self.audit
            .record(
                AuditEventType::UserProfileUpdated,
                AuditResult::Success,
                Some(tenant_id),
                Some(actor),
                None,
                Some(&format!("user={} fields={}", user.id, changed.join(","))),
                ctx,
            )
            .await;

        Ok(User {
            email,
            preferred_username,
            name,
            ..user
        })
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

    /// 利用者の MFA（TOTP・Passkey）を解除する（MT21）。本人が端末を失って自分では解除できない
    /// 状態からの復旧手段。
    ///
    /// TOTP と Passkey を**両方まとめて**外す。片方だけ残ると本人はログインできないままで、
    /// 復旧手段として成立しないため。すでに未設定でもエラーにせず、何を外したかを結果で返す
    /// （管理者が「効いたのか」を確認できるようにする）。
    ///
    /// 併せて当該利用者の SSO セッション・refresh token・未消費 code を失効させる。この操作の
    /// 契機は「端末の紛失・盗難」であり、その端末が生きたセッションを保持している可能性がある
    /// ためである（MFA を外すだけでは、紛失した端末のログイン状態はそのまま残る）。
    ///
    /// **失効に失敗したらこの操作全体を失敗させる**（他のライフサイクル操作と違い fail-open に
    /// しない）。パスワード再発行や無効化では、失効が漏れても資格情報そのものが変わっている／
    /// アカウントが無効になっているという別の防御線が残る。MFA 解除では失効が唯一の防御線で、
    /// 「盗まれた端末のセッションは切れた」と管理者へ伝えたのに実際は生きている、という取り違えを
    /// 生む。MFA の削除は済んでいるが、再実行は冪等なので失効だけをやり直せる。
    pub async fn reset_mfa(
        &self,
        tenant: TenantContext,
        target: Uuid,
        actor: Uuid,
        ctx: &RequestContext,
    ) -> Result<MfaReset, UserLifecycleError> {
        let user = self.find_home_user(tenant, target).await?;
        self.ensure_not_self(user.id, actor)?;

        // 「外した件数」を返すため、削除の前に TOTP の有無を確認する（delete は冪等で件数を返さない）。
        let totp_removed = self
            .totp_secrets
            .find_by_user_id(user.id)
            .await
            .map_err(internal)?
            .is_some();
        if totp_removed {
            self.totp_secrets.delete(user.id).await.map_err(internal)?;
        }
        let passkeys_removed = self
            .webauthn_credentials
            .delete_all_for_user(user.id)
            .await
            .map_err(internal)?;

        // 認証器の登録簿（AP9）も同じ操作で失効させる。ここが漏れると、解除したはずの認証器が
        // 一覧に残り、リカバリーコードの古い束も生き続ける（＝古い紙で入れてしまう）。
        let now = self.clock.now();
        for authenticator_type in [
            AuthenticatorType::Totp,
            AuthenticatorType::WebAuthn,
            AuthenticatorType::RecoveryCode,
            AuthenticatorType::EmailOtp,
        ] {
            self.authenticators
                .revoke_all_of_type(user.id, authenticator_type, now)
                .await
                .map_err(internal)?;
        }

        // 失効できなければ成功を返さない（紛失端末のセッションが生き残る）。監査も記録しない。
        self.revoke_credentials_strict(user.id).await?;

        // 監査には対象と外した要素の粒度のみ記録する（シークレット・クレデンシャルは出さない）。
        self.audit
            .record(
                AuditEventType::UserMfaReset,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                Some(actor),
                None,
                Some(&format!(
                    "user={} totp={} passkeys={}",
                    user.id,
                    if totp_removed { "removed" } else { "absent" },
                    passkeys_removed
                )),
                ctx,
            )
            .await;

        Ok(MfaReset {
            user_id: user.id,
            totp_removed,
            passkeys_removed,
        })
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
            return Err(UserLifecycleError::Forbidden(MessageKey::new(
                "api-user-self-operation-forbidden",
            )));
        }
        Ok(())
    }

    /// 資格情報を失効させ、**失敗はログに留めて先へ進む**（fail-open）。
    ///
    /// パスワード再発行・無効化から使う。これらは失効が漏れても「パスワードが変わっている」
    /// 「アカウントが無効」という別の防御線が残るため、一過性の DB エラーで操作全体を失敗させる
    /// 方が運用上の害が大きい。失効が唯一の防御線になる MFA 解除では
    /// [`revoke_credentials_strict`](Self::revoke_credentials_strict) を使う。
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

    /// 資格情報を失効させ、**1 つでも失敗したら呼び出し元へ伝える**（fail-closed）。
    ///
    /// 途中で失敗しても残りは試みる（部分的にでも失効させた方が安全側）。返すのは最初のエラー。
    async fn revoke_credentials_strict(&self, user_id: Uuid) -> Result<(), UserLifecycleError> {
        let now = self.clock.now();
        let mut first_error = None;
        let mut remember = |label: &str, result: crate::domain::error::Result<()>| {
            if let Err(e) = result {
                tracing::error!(error = %e, credential = label, "failed to revoke credentials");
                first_error.get_or_insert_with(|| internal(e));
            }
        };
        remember(
            "sso_session",
            self.sso_sessions.delete_all_for_user(user_id).await,
        );
        remember(
            "refresh_token",
            self.refresh_tokens.revoke_all_for_user(user_id, now).await,
        );
        remember(
            "authorization_code",
            self.codes.revoke_all_active_for_user(user_id, now).await,
        );
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
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
    use crate::domain::totp_secret::TotpSecret;
    use crate::domain::webauthn_credential::WebAuthnCredential;
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
        async fn find_by_username(&self, t: TenantId, n: &str) -> DomainResult<Option<User>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.tenant_id == t && u.preferred_username.as_deref() == Some(n))
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
        async fn update_profile(
            &self,
            id: Uuid,
            email: &str,
            preferred_username: Option<&str>,
            name: Option<&str>,
        ) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            let user = rows
                .iter_mut()
                .find(|u| u.id == id)
                .ok_or_else(|| DomainError::Repository("not found".into()))?;
            user.email = email.to_string();
            user.preferred_username = preferred_username.map(str::to_string);
            user.name = name.map(str::to_string);
            Ok(())
        }
    }

    /// 認証器の登録簿のフェイク。MFA 解除で「どの種別を失効させたか」だけ記録する
    /// （他のメソッドはトレイトの既定実装 ＝ 見つからない、で足りる）。
    #[derive(Default)]
    struct FakeAuthenticators {
        revoked_types: Mutex<Vec<AuthenticatorType>>,
    }
    #[async_trait]
    impl UserAuthenticatorRepository for FakeAuthenticators {
        async fn create(
            &self,
            _a: &crate::domain::user_authenticator::UserAuthenticator,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke_all_of_type(
            &self,
            _u: Uuid,
            authenticator_type: AuthenticatorType,
            _at: DateTime<Utc>,
        ) -> DomainResult<u64> {
            self.revoked_types.lock().unwrap().push(authenticator_type);
            Ok(0)
        }
    }

    #[derive(Default)]
    struct FakeSsoSessions {
        revoked_users: Mutex<Vec<Uuid>>,
        /// `true` のとき失効が DB エラーで失敗する（fail-closed の検証用）。
        fail_revoke: Mutex<bool>,
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
            if *self.fail_revoke.lock().unwrap() {
                return Err(DomainError::Repository("connection lost".into()));
            }
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
        async fn revoke_all_for_user_in_tenant(
            &self,
            _tenant: TenantId,
            _user_id: Uuid,
            _now: DateTime<Utc>,
        ) -> DomainResult<()> {
            // ライフサイクル操作はユーザー単位で全失効させる（テナント単位の失効はゲストの
            // 一時停止（MT24）専用）。
            unreachable!()
        }
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

    #[derive(Default)]
    struct FakeTotpSecrets {
        rows: Mutex<Vec<TotpSecret>>,
        deleted: Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl TotpSecretRepository for FakeTotpSecrets {
        async fn upsert(&self, secret: &TotpSecret) -> DomainResult<()> {
            self.rows.lock().unwrap().push(secret.clone());
            Ok(())
        }
        async fn find_by_user_id(&self, user_id: Uuid) -> DomainResult<Option<TotpSecret>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.user_id == user_id)
                .cloned())
        }
        async fn confirm(&self, _id: Uuid, _at: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, user_id: Uuid) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|s| s.user_id != user_id);
            self.deleted.lock().unwrap().push(user_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeWebAuthnCredentials {
        rows: Mutex<Vec<(Uuid, Uuid)>>,
    }
    #[async_trait]
    impl WebAuthnCredentialRepository for FakeWebAuthnCredentials {
        async fn create(&self, _c: &WebAuthnCredential) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, _id: Uuid) -> DomainResult<Option<WebAuthnCredential>> {
            unreachable!()
        }
        async fn find_by_credential_id(
            &self,
            _credential_id: &str,
        ) -> DomainResult<Option<WebAuthnCredential>> {
            unreachable!()
        }
        async fn list_by_user_id(&self, _user_id: Uuid) -> DomainResult<Vec<WebAuthnCredential>> {
            unreachable!()
        }
        async fn update_passkey(
            &self,
            _id: Uuid,
            _passkey_json: &str,
            _last_used_at: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid, _user_id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, user_id: Uuid) -> DomainResult<u64> {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|(_, owner)| *owner != user_id);
            Ok((before - rows.len()) as u64)
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

    fn totp_secret(user_id: Uuid) -> TotpSecret {
        TotpSecret {
            user_id,
            secret_encrypted: "ciphertext".to_string(),
            confirmed_at: Some(now()),
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
        totp: Arc<FakeTotpSecrets>,
        passkeys: Arc<FakeWebAuthnCredentials>,
        sink: Arc<CapturingSink>,
        svc: UserLifecycleService,
    }

    fn fixture() -> Fixture {
        let users = Arc::new(FakeUsers::default());
        let sso = Arc::new(FakeSsoSessions::default());
        let refresh = Arc::new(FakeRefreshTokens::default());
        let codes = Arc::new(FakeCodes::default());
        let totp = Arc::new(FakeTotpSecrets::default());
        let passkeys = Arc::new(FakeWebAuthnCredentials::default());
        let sink = Arc::new(CapturingSink::default());
        let audit = Arc::new(AuditService::new(sink.clone(), Arc::new(FixedClock(now()))));
        let svc = UserLifecycleService::new(
            Arc::new(FakeAuthenticators::default()),
            users.clone(),
            sso.clone(),
            refresh.clone(),
            codes.clone(),
            totp.clone(),
            passkeys.clone(),
            Arc::new(PlainHasher),
            audit,
            Arc::new(FixedClock(now())),
        );
        Fixture {
            users,
            sso,
            refresh,
            codes,
            totp,
            passkeys,
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

    /// MT21: TOTP と Passkey を両方外し、紛失端末が握っているセッション・トークンも失効させる。
    #[tokio::test]
    async fn resets_both_mfa_factors_and_revokes_credentials() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let other = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();
        f.totp.upsert(&totp_secret(target)).await.unwrap();
        // 他人の分・対象の分を混在させ、対象の分だけが消えることを見る。
        f.passkeys.rows.lock().unwrap().extend([
            (Uuid::now_v7(), target),
            (Uuid::now_v7(), target),
            (Uuid::now_v7(), other),
        ]);

        let reset = f
            .svc
            .reset_mfa(TenantContext::new(tenant), target, Uuid::now_v7(), &ctx())
            .await
            .expect("reset mfa");

        assert!(reset.totp_removed);
        assert_eq!(reset.passkeys_removed, 2);
        assert!(f.totp.rows.lock().unwrap().is_empty());
        assert_eq!(
            f.passkeys
                .rows
                .lock()
                .unwrap()
                .iter()
                .map(|(_, owner)| *owner)
                .collect::<Vec<_>>(),
            vec![other],
            "other users' passkeys must survive"
        );
        // 紛失した端末の生きたセッションを残さない。
        assert_eq!(*f.sso.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.refresh.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.codes.revoked_users.lock().unwrap(), vec![target]);

        let events = f.sink.events.lock().unwrap();
        assert_eq!(events[0].event_type, AuditEventType::UserMfaReset);
        let reason = events[0].reason.clone().unwrap_or_default();
        assert!(reason.contains("totp=removed"), "{reason}");
        assert!(reason.contains("passkeys=2"), "{reason}");
        // 監査にシークレットを出さない。
        assert!(!reason.contains("secret"), "{reason}");
    }

    /// MFA 未設定の利用者でも失敗させない（管理者は設定の有無を知らずに操作する）。
    #[tokio::test]
    async fn resetting_mfa_is_idempotent_when_nothing_is_configured() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let reset = f
            .svc
            .reset_mfa(TenantContext::new(tenant), target, Uuid::now_v7(), &ctx())
            .await
            .expect("reset mfa");
        assert!(!reset.totp_removed);
        assert_eq!(reset.passkeys_removed, 0);
        assert!(f.totp.deleted.lock().unwrap().is_empty());
    }

    /// MT21: 失効に失敗したら MFA 解除は成功を返さない（fail-closed）。
    ///
    /// 「盗まれた端末のセッションは切れた」と管理者へ伝えたのに実際は生きている、という取り違えを
    /// 防ぐ。ここが fail-open に戻ると、監査には成功が残り応答も 200 になってしまう。
    #[tokio::test]
    async fn mfa_reset_fails_when_credentials_cannot_be_revoked() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();
        f.totp.upsert(&totp_secret(target)).await.unwrap();
        *f.sso.fail_revoke.lock().unwrap() = true;

        let err = f
            .svc
            .reset_mfa(TenantContext::new(tenant), target, Uuid::now_v7(), &ctx())
            .await
            .expect_err("revocation failure must fail the reset");
        assert!(matches!(err, UserLifecycleError::Internal(_)), "{err:?}");
        // 失敗したときは監査へ成功を残さない。
        assert!(f.sink.events.lock().unwrap().is_empty());
        // 失効できなかった側があっても、残りは試みる（部分的にでも失効させる）。
        assert_eq!(*f.refresh.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(*f.codes.revoked_users.lock().unwrap(), vec![target]);

        // 再実行は冪等: 失効が回復すれば成功する（MFA は既に外れているので totp_removed = false）。
        *f.sso.fail_revoke.lock().unwrap() = false;
        let reset = f
            .svc
            .reset_mfa(TenantContext::new(tenant), target, Uuid::now_v7(), &ctx())
            .await
            .expect("retry succeeds");
        assert!(!reset.totp_removed);
        assert_eq!(*f.sso.revoked_users.lock().unwrap(), vec![target]);
        assert_eq!(
            f.sink.events.lock().unwrap()[0].event_type,
            AuditEventType::UserMfaReset
        );
    }

    /// 他テナントの利用者・自分自身は他のライフサイクル操作と同じ扱い。
    #[tokio::test]
    async fn resetting_mfa_rejects_cross_tenant_and_self() {
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let foreign = Uuid::now_v7();
        f.users.create(&user(foreign, other)).await.unwrap();
        assert!(matches!(
            f.svc
                .reset_mfa(TenantContext::new(tenant), foreign, Uuid::now_v7(), &ctx())
                .await,
            Err(UserLifecycleError::NotFound)
        ));

        let own = Uuid::now_v7();
        f.users.create(&user(own, tenant)).await.unwrap();
        assert!(matches!(
            f.svc
                .reset_mfa(TenantContext::new(tenant), own, own, &ctx())
                .await,
            Err(UserLifecycleError::Forbidden(_))
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

    // ── プロフィール編集（MT25）────────────────────────────────────────────────

    #[tokio::test]
    async fn updates_profile_and_audits_only_the_changed_field_names() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();

        let updated = f
            .svc
            .update_profile(
                TenantContext::new(tenant),
                target,
                UpdateUserProfileCommand {
                    email: Some("  renamed@example.com  ".into()),
                    preferred_username: Some("renamed".into()),
                    name: Some("Renamed User".into()),
                },
                Uuid::now_v7(),
                &ctx(),
            )
            .await
            .expect("updated");

        assert_eq!(updated.email, "renamed@example.com");
        assert_eq!(updated.preferred_username.as_deref(), Some("renamed"));
        assert_eq!(updated.name.as_deref(), Some("Renamed User"));
        // 管理者が所有を保証する扱いのため検証済みを維持する（メール変更でログイン不能にしない）。
        assert!(updated.email_verified);

        let stored = f.users.rows.lock().unwrap()[0].clone();
        assert_eq!(stored.email, "renamed@example.com");

        let events = f.sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::UserProfileUpdated);
        let reason = events[0].reason.clone().expect("reason");
        assert!(
            reason.contains("fields=email,preferred_username,name"),
            "{reason}"
        );
        // 値そのもの（PII）は監査に出さない。
        assert!(!reason.contains("renamed@example.com"), "{reason}");
        assert!(!reason.contains("Renamed User"), "{reason}");
    }

    #[tokio::test]
    async fn updates_profile_partially_and_clears_the_display_name_with_an_empty_value() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let mut existing = user(target, tenant);
        existing.name = Some("Old Name".into());
        existing.preferred_username = Some("keep-me".into());
        f.users.create(&existing).await.unwrap();

        // name のみ空文字 = 表示名の解除。email / preferred_username は未指定なので現状維持。
        let updated = f
            .svc
            .update_profile(
                TenantContext::new(tenant),
                target,
                UpdateUserProfileCommand {
                    name: Some("   ".into()),
                    ..Default::default()
                },
                Uuid::now_v7(),
                &ctx(),
            )
            .await
            .expect("updated");
        assert_eq!(updated.name, None);
        assert_eq!(updated.email, existing.email);
        assert_eq!(updated.preferred_username.as_deref(), Some("keep-me"));

        let reason = f.sink.events.lock().unwrap()[0]
            .reason
            .clone()
            .expect("reason");
        assert!(reason.contains("fields=name"), "{reason}");
    }

    #[tokio::test]
    async fn updating_profile_with_no_change_does_not_write_or_audit() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let existing = user(target, tenant);
        f.users.create(&existing).await.unwrap();

        f.svc
            .update_profile(
                TenantContext::new(tenant),
                target,
                UpdateUserProfileCommand {
                    email: Some(existing.email.clone()),
                    ..Default::default()
                },
                Uuid::now_v7(),
                &ctx(),
            )
            .await
            .expect("no-op update");
        assert!(f.sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn updating_profile_rejects_duplicates_within_the_tenant() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        f.users.create(&user(target, tenant)).await.unwrap();
        let mut other = user(Uuid::now_v7(), tenant);
        other.email = "taken@example.com".into();
        other.preferred_username = Some("taken".into());
        f.users.create(&other).await.unwrap();

        assert!(matches!(
            f.svc
                .update_profile(
                    TenantContext::new(tenant),
                    target,
                    UpdateUserProfileCommand {
                        email: Some("taken@example.com".into()),
                        ..Default::default()
                    },
                    Uuid::now_v7(),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::Conflict(_))
        ));
        assert!(matches!(
            f.svc
                .update_profile(
                    TenantContext::new(tenant),
                    target,
                    UpdateUserProfileCommand {
                        preferred_username: Some("taken".into()),
                        ..Default::default()
                    },
                    Uuid::now_v7(),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn updating_profile_rejects_invalid_input_and_clearing_the_login_identifier() {
        let tenant: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let target = Uuid::now_v7();
        let mut existing = user(target, tenant);
        existing.preferred_username = Some("alice".into());
        f.users.create(&existing).await.unwrap();

        let invalid = |cmd| {
            let svc = &f.svc;
            async move {
                svc.update_profile(
                    TenantContext::new(tenant),
                    target,
                    cmd,
                    Uuid::now_v7(),
                    &ctx(),
                )
                .await
            }
        };

        assert!(matches!(
            invalid(UpdateUserProfileCommand {
                email: Some("not-an-email".into()),
                ..Default::default()
            })
            .await,
            Err(UserLifecycleError::Validation(_))
        ));
        // ログイン識別子の解除はパスワードログイン不能を招くため拒否する。
        assert!(matches!(
            invalid(UpdateUserProfileCommand {
                preferred_username: Some("".into()),
                ..Default::default()
            })
            .await,
            Err(UserLifecycleError::Validation(_))
        ));
        // カラム長超過は永続化前に入力エラーとして返す。
        assert!(matches!(
            invalid(UpdateUserProfileCommand {
                name: Some("x".repeat(256)),
                ..Default::default()
            })
            .await,
            Err(UserLifecycleError::Validation(_))
        ));
    }

    /// プロフィール編集は他のライフサイクル操作と違い自分自身も対象にできる（ロックアウトを招かない）。
    /// 一方、テナント越し（所属元が他テナント）は他操作と同じく `NotFound`。
    #[tokio::test]
    async fn updating_own_profile_is_allowed_but_cross_tenant_is_not() {
        let tenant: TenantId = Uuid::now_v7().into();
        let other: TenantId = Uuid::now_v7().into();
        let f = fixture();
        let me = Uuid::now_v7();
        f.users.create(&user(me, tenant)).await.unwrap();

        f.svc
            .update_profile(
                TenantContext::new(tenant),
                me,
                UpdateUserProfileCommand {
                    name: Some("My Name".into()),
                    ..Default::default()
                },
                me,
                &ctx(),
            )
            .await
            .expect("self edit is allowed");

        assert!(matches!(
            f.svc
                .update_profile(
                    TenantContext::new(other),
                    me,
                    UpdateUserProfileCommand {
                        name: Some("Hijack".into()),
                        ..Default::default()
                    },
                    Uuid::now_v7(),
                    &ctx(),
                )
                .await,
            Err(UserLifecycleError::NotFound)
        ));
    }
}
