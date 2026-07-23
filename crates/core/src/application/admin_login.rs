//! 管理コンソール（A2）へのログインのユースケース（ADR-0006 §6）。
//!
//! 通常の OIDC ログイン（[`crate::application::login`]）は `/authorize` が発行する `auth_session_id` に
//! 結合し、成功後は authorization code を発行して RP の `redirect_uri` へ戻す。管理コンソールは
//! OIDC の RP ではなく IdP 自身の画面であり、初回デプロイ時はクライアントが 1 件も存在しないため、
//! その導線は使えない（クライアント登録のためにコンソールへ入りたいのにログインにクライアントが要る、
//! という鶏卵問題）。
//!
//! そこで本ユースケースは資格情報を検証し、テナント admin 権限（`idp.tenant.admin`／`idp.system.admin`）の保有を確認したうえで **SSO セッションを
//! 直接発行する**（code 発行・redirect は行わない）。ロックアウト（設計仕様 §4.3）と IP レート制限は
//! 通常ログインと同じ方針で適用する。発行された SSO セッションは通常ログインのものと同一機構
//! （`sso_session_id` Cookie ＝ 平文、DB は SHA-256）であり、`RequirePerms<IdpAdmin>` がそのまま検証する。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::permission;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{SsoSessionRepository, UserPermissionRepository, UserRepository};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use chrono::Duration;
use std::sync::Arc;

/// username 単位のロック閾値（連続失敗回数）。通常ログイン（`login.rs`）と揃える。
const MAX_FAILED_LOGINS: i32 = 10;
/// ロック時間（分）。
const LOCK_DURATION_MINUTES: i64 = 15;

// 管理ログインフォームの CSRF 同期トークン導出（`admin_csrf_token`）は、ADR-0007 で管理コンソールを
// web crate へ移設したのに伴い web 側（`idp-web` の `csrf` モジュール）へ移った。api（core）は保持しない。

#[derive(Debug)]
pub struct AdminLoginCommand {
    /// ログイン識別子（メールアドレス。ADR-0009 §8）。
    pub email: String,
    pub password: String,
}

/// 強制パスワード変更を伴う管理ログイン（ADR-0009 §5）のコマンド。管理コンソールのログインは
/// `auth_session_id` のような一時状態を持たないため、現行パスワードを含め毎回フルに再検証する。
#[derive(Debug)]
pub struct AdminChangePasswordCommand {
    /// ログイン識別子（メールアドレス。ADR-0009 §8）。
    pub email: String,
    pub current_password: String,
    pub new_password: String,
}

/// 管理ログインの結果。Presentation は画面（HTML）に写す。
pub enum AdminLoginOutcome {
    /// 認証成功かつ `idp.tenant.admin` 保有。SSO Cookie を発行して管理コンソールへ 302 する。
    Success {
        sso_session_id: String,
    },
    /// 認証成功・管理権限保有だが `must_change_password`（ADR-0009 §5）。パスワード変更画面へ誘導する。
    /// SSO はまだ発行しない（変更完了までは他の操作を許可しない）。
    PasswordChangeRequired {
        email: String,
    },
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正（ユーザー不存在・パスワード不一致・無効アカウントを区別しない）。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    /// 資格情報は正しいが テナント admin 権限を保有しない。
    Forbidden,
    /// 新パスワードが強度要件を満たさない（`change_password` のみ）。
    WeakPassword,
    Internal(String),
}

pub struct AdminLoginService {
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
}

impl AdminLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
    ) -> Self {
        Self {
            users,
            sso_sessions,
            permissions,
            hasher,
            rate_limiter,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
        }
    }

    pub async fn login(
        &self,
        tenant: TenantContext,
        cmd: AdminLoginCommand,
        ctx: &RequestContext,
    ) -> AdminLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. IP 単位のレート制限（CSRF 検証後・資格情報検証前。通常ログインと同順）。
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        None,
                        Some("ip_rate_limited"),
                        ctx,
                    )
                    .await;
                return AdminLoginOutcome::RateLimited;
            }
        }

        // 2. ユーザー検索（ログイン識別子はメールアドレスに統一）。
        //    認証は所属元テナント限定（ADR-0009 §8）。
        let user = match self.users.find_by_email(tenant_id, &cmd.email).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        None,
                        Some("unknown_user"),
                        ctx,
                    )
                    .await;
                return AdminLoginOutcome::InvalidCredentials;
            }
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };

        // 3. ロック状態の確認。
        if user.is_locked_at(now) {
            self.audit
                .record(
                    AuditEventType::LoginLocked,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    None,
                    Some("account_locked"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::Locked;
        }

        // 4. アカウント状態の確認（存在の露呈を避けるため資格情報エラーと同じ応答にする）。
        if !user.is_active() {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    None,
                    Some("account_not_active"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::InvalidCredentials;
        }

        // 5. パスワード検証。
        let verified = match self.hasher.verify(&cmd.password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if !verified {
            return self.handle_password_failure(tenant_id, &user, ctx).await;
        }

        // 6. 権限確認（資格情報は正しいが管理権限を持たない利用者を締め出す）。
        //    ログインしたテナントを scope に持つ admin 権限の完全一致で判定する（ADR-0009 §4。
        //    idp.system.admin は root scope のみ存在し root 自身の管理を含むため代替として許可）。
        //    パスワードは正しいので失敗カウンタは増やさない（ロックの対象にしない）。
        let has_admin = match self
            .permissions
            .has_any_permission(
                tenant_id,
                user.id,
                &[permission::TENANT_ADMIN, permission::SYSTEM_ADMIN],
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if !has_admin {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    None,
                    Some("missing_admin_permission"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::Forbidden;
        }

        // 6.5. 強制パスワード変更（ADR-0009 §5）。SSO はまだ発行せず変更画面へ誘導する。
        if user.must_change_password {
            return AdminLoginOutcome::PasswordChangeRequired { email: cmd.email };
        }

        // 7. 成功: 失敗カウンタとロックをリセットする。
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return AdminLoginOutcome::Internal(e.to_string());
            }
        }

        // 8. SSO セッション発行（Cookie には session_id、DB には SHA-256 ハッシュ。login.rs と同一機構）。
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession {
            session_hash: crypto::sha256_hex(&sso_session_id),
            user_id: user.id,
            auth_time: now,
            idle_expires_at: now + self.sso_idle_ttl,
            absolute_expires_at: now + self.sso_absolute_ttl,
            user_agent: ctx.user_agent.clone(),
            ip_address: ctx.ip_address.clone(),
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.sso_sessions.create(&sso).await {
            return AdminLoginOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::LoginSucceeded,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;

        AdminLoginOutcome::Success { sso_session_id }
    }

    /// 強制パスワード変更（ADR-0009 §5）。管理ログインを現行パスワードを含めフルに再検証し、成功時に
    /// 新パスワードを保存して SSO セッションを発行する（`login` と同じ検証を毎回やり直す。管理ログインは
    /// `auth_session_id` のような一時状態を持たないため）。
    pub async fn change_password(
        &self,
        tenant: TenantContext,
        cmd: AdminChangePasswordCommand,
        ctx: &RequestContext,
    ) -> AdminLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                return AdminLoginOutcome::RateLimited;
            }
        }

        let user = match self.users.find_by_email(tenant_id, &cmd.email).await {
            Ok(Some(u)) => u,
            Ok(None) => return AdminLoginOutcome::InvalidCredentials,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };

        if user.is_locked_at(now) {
            return AdminLoginOutcome::Locked;
        }
        if !user.is_active() {
            return AdminLoginOutcome::InvalidCredentials;
        }
        if !user.must_change_password {
            // 変更不要な状態でこのエンドポイントに来るのは想定外（多重送信等）。fail-closed。
            return AdminLoginOutcome::InvalidCredentials;
        }

        let verified = match self
            .hasher
            .verify(&cmd.current_password, &user.password_hash)
        {
            Ok(v) => v,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if !verified {
            return self.handle_password_failure(tenant_id, &user, ctx).await;
        }

        let has_admin = match self
            .permissions
            .has_any_permission(
                tenant_id,
                user.id,
                &[permission::TENANT_ADMIN, permission::SYSTEM_ADMIN],
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if !has_admin {
            return AdminLoginOutcome::Forbidden;
        }

        if validate_password_strength(&cmd.new_password).is_err() {
            return AdminLoginOutcome::WeakPassword;
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };
        if let Err(e) = self.users.update_password(user.id, &new_hash).await {
            return AdminLoginOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::PasswordChanged,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;

        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return AdminLoginOutcome::Internal(e.to_string());
            }
        }

        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession {
            session_hash: crypto::sha256_hex(&sso_session_id),
            user_id: user.id,
            auth_time: now,
            idle_expires_at: now + self.sso_idle_ttl,
            absolute_expires_at: now + self.sso_absolute_ttl,
            user_agent: ctx.user_agent.clone(),
            ip_address: ctx.ip_address.clone(),
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = self.sso_sessions.create(&sso).await {
            return AdminLoginOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;
        self.audit
            .record(
                AuditEventType::LoginSucceeded,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                None,
                None,
                ctx,
            )
            .await;

        AdminLoginOutcome::Success { sso_session_id }
    }

    /// 管理コンソールからのログアウト。SSO セッションを DB から削除して監査へ記録する。
    /// Cookie の失効は Presentation（ハンドラ）が行う。不明・不正なセッションは何もしない（冪等）。
    pub async fn logout(&self, tenant: TenantContext, sso_session_id: &str, ctx: &RequestContext) {
        if sso_session_id.is_empty() {
            return;
        }
        let session_hash = crypto::sha256_hex(sso_session_id);
        // 監査に user_id を残すため、削除前にセッションを引く（best-effort）。
        let user_id = match self.sso_sessions.find_by_hash(&session_hash).await {
            Ok(Some(session)) => Some(session.user_id),
            _ => None,
        };
        if let Err(e) = self.sso_sessions.delete(&session_hash).await {
            tracing::warn!(error = %e, "failed to delete sso session on admin logout");
            return;
        }
        self.audit
            .record(
                AuditEventType::SsoSessionTerminated,
                AuditResult::Success,
                Some(tenant.tenant_id()),
                user_id,
                None,
                Some("admin_logout"),
                ctx,
            )
            .await;
    }

    /// パスワード不一致時の失敗カウント更新とロック判定（login.rs と同ポリシー）。
    async fn handle_password_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        ctx: &RequestContext,
    ) -> AdminLoginOutcome {
        let now = self.clock.now();
        let failed = user.failed_login_count + 1;
        let locked_until = if failed >= MAX_FAILED_LOGINS {
            Some(now + Duration::minutes(LOCK_DURATION_MINUTES))
        } else {
            None
        };

        if let Err(e) = self
            .users
            .update_login_state(user.id, failed, locked_until)
            .await
        {
            return AdminLoginOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                Some(user.id),
                None,
                Some("invalid_password"),
                ctx,
            )
            .await;

        if locked_until.is_some() {
            self.audit
                .record(
                    AuditEventType::LoginLocked,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    None,
                    Some("too_many_failures"),
                    ctx,
                )
                .await;
            return AdminLoginOutcome::Locked;
        }
        AdminLoginOutcome::InvalidCredentials
    }
}
