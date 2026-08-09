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
//! 通常ログインと同じ方針で適用する。
//!
//! 認証ポリシー（AP2。ユーザー認証・認証ポリシー仕様書 §7〜§9）も OIDC ログインと同じ規則で適用する。
//! 管理コンソールはクライアント文脈を持たないため評価コンテキストの `client_id` は `None`（`client_ids`
//! 条件を持つポリシーは一致しない）。管理コンソールこそ `deny` / `require_mfa` の対象から外せない
//! （最も強い権限を持つ利用者が入る画面であり、ここが素通りするとポリシーは実質無効になる）。発行された SSO セッションは通常ログインのものと同一機構
//! （`sso_session_id` Cookie ＝ 平文、DB は SHA-256）であり、`RequirePerms<IdpAdmin>` がそのまま検証する。

use crate::application::audit::{AuditService, RequestContext};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, DefaultPolicyEffect, PolicyDecision,
};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::permission;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{
    AuthenticationPolicyRepository, SsoSessionRepository, TotpSecretRepository,
    UserPermissionRepository, UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::values::AuthenticationMethod;
use chrono::Duration;
use std::sync::Arc;

// 管理ログインフォームの CSRF 同期トークン導出（`admin_csrf_token`）は、ADR-0007 で管理コンソールを
// web crate へ移設したのに伴い web 側（`idp-web` の `csrf` モジュール）へ移った。api（core）は保持しない。

#[derive(Debug)]
pub struct AdminLoginCommand {
    /// ログイン識別子（ユーザー名 = `preferred_username`。ADR-0009 §8）。
    pub username: String,
    pub password: String,
}

/// 強制パスワード変更を伴う管理ログイン（ADR-0009 §5）のコマンド。管理コンソールのログインは
/// `auth_session_id` のような一時状態を持たないため、現行パスワードを含め毎回フルに再検証する。
#[derive(Debug)]
pub struct AdminChangePasswordCommand {
    /// ログイン識別子（ユーザー名 = `preferred_username`。ADR-0009 §8）。
    pub username: String,
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
        username: String,
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
    /// 認証ポリシーにより拒否（AP2。仕様 §7.4 `deny`）。
    PolicyDenied,
    /// 認証ポリシーが MFA を必須としたが、使用可能な認証器（確認済み TOTP）が無い（AP2）。
    /// 管理コンソールは TOTP 入力ステップを持たないため、MFA 必須の管理者はポータル経由で
    /// 認証器を登録するか、ポータルログインで第二要素を通す必要がある。
    MfaEnrollmentRequired,
    /// 認証ポリシーが MFA を必須とし、利用者は認証器を持っている（AP2）。管理コンソールのログインは
    /// 第二要素の入力ステップを持たないため、ポータルログイン（`/{tenant_id}/login`）で MFA まで
    /// 通してから管理コンソールへ入るよう案内する。
    MfaRequired,
    Internal(String),
}

pub struct AdminLoginService {
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    permissions: Arc<dyn UserPermissionRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    /// アカウントロックのポリシー（設定注入。通常ログイン `login.rs` と同じ値を使う）。
    lockout: crate::domain::authentication_policy::LockoutPolicy,
    /// 一致するポリシーが無い場合の既定動作（AP2。`login.rs` と同じ設定値を使う）。
    policy_default_effect: DefaultPolicyEffect,
}

impl AdminLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        permissions: Arc<dyn UserPermissionRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
        lockout: crate::domain::authentication_policy::LockoutPolicy,
        policy_default_effect: DefaultPolicyEffect,
    ) -> Self {
        Self {
            users,
            sso_sessions,
            permissions,
            totp_secrets,
            authentication_policies,
            hasher,
            rate_limiter,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
            lockout,
            policy_default_effect,
        }
    }

    /// 認証ポリシーを評価し、SSO を発行してよいかを判定する（AP2）。
    ///
    /// `Ok(())` なら発行可。`Err(outcome)` はそのまま呼び出し側の戻り値になる。管理コンソールは
    /// 第二要素の入力ステップを持たないため、`require_mfa` は認証器の有無で案内を出し分けて
    /// **いずれにせよ SSO を発行しない**（単一要素で管理コンソールに入れてしまわないため）。
    async fn check_policy(
        &self,
        tenant_id: TenantId,
        user_id: uuid::Uuid,
        ctx: &RequestContext,
    ) -> Result<(), AdminLoginOutcome> {
        let policies = match self
            .authentication_policies
            .list_enabled_for_tenant(tenant_id)
            .await
        {
            Ok(p) => p,
            Err(e) => return Err(AdminLoginOutcome::Internal(e.to_string())),
        };
        let decision = evaluate_policies(
            &policies,
            &AuthenticationContext {
                client_id: None,
                user_id,
                ip_address: ctx.ip_address.as_deref(),
                now: self.clock.now(),
                // 管理コンソールのログインは OIDC 認可要求ではないため `acr_values` は無い。
                requested_acr: &[],
            },
            self.policy_default_effect,
        );
        match decision {
            PolicyDecision::Allow { .. } => Ok(()),
            PolicyDecision::Deny { policy_code } => {
                self.record_policy_denied(
                    tenant_id,
                    user_id,
                    &format!("policy={policy_code}"),
                    ctx,
                )
                .await;
                Err(AdminLoginOutcome::PolicyDenied)
            }
            PolicyDecision::RequireMfa { policy_code } => {
                let has_totp = match crate::application::mfa_login::user_has_confirmed_totp(
                    self.totp_secrets.as_ref(),
                    user_id,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => return Err(AdminLoginOutcome::Internal(e.to_string())),
                };
                let reason = if has_totp {
                    format!("policy={policy_code} reason=mfa_step_not_available")
                } else {
                    format!("policy={policy_code} reason=mfa_not_enrolled")
                };
                self.record_policy_denied(tenant_id, user_id, &reason, ctx)
                    .await;
                Err(if has_totp {
                    AdminLoginOutcome::MfaRequired
                } else {
                    AdminLoginOutcome::MfaEnrollmentRequired
                })
            }
            // `require_specific_method`（AP3）。管理コンソールのログインはパスワード（+ TOTP）
            // しか通らないため、それで満たせない要求は拒否する。
            PolicyDecision::RequireMethods {
                policy_code,
                requirement,
            } => {
                if requirement.satisfied_by(&[AuthenticationMethod::Password], false) {
                    return Ok(());
                }
                self.record_policy_denied(
                    tenant_id,
                    user_id,
                    &format!(
                        "policy={policy_code} reason=method_required required={}",
                        requirement.describe()
                    ),
                    ctx,
                )
                .await;
                Err(AdminLoginOutcome::PolicyDenied)
            }
        }
    }

    /// ポリシー拒否を監査へ記録する（AP2。OIDC ログインと同じイベント種別・理由形式）。
    async fn record_policy_denied(
        &self,
        tenant_id: TenantId,
        user_id: uuid::Uuid,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::LoginPolicyDenied,
                AuditResult::Failure,
                Some(tenant_id),
                Some(user_id),
                None,
                Some(reason),
                ctx,
            )
            .await;
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

        // 2. ユーザー検索（ログイン識別子は preferred_username）。
        //    認証は所属元テナント限定（ADR-0009 §8）。
        let user = match self.users.find_by_username(tenant_id, &cmd.username).await {
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
            return self
                .handle_password_failure(tenant_id, &user, "invalid_password", ctx)
                .await;
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

        // 6.4. 認証ポリシー評価（AP2）。資格情報・権限の確認後、SSO 発行前にゲートする。
        if let Err(outcome) = self.check_policy(tenant_id, user.id, ctx).await {
            return outcome;
        }

        // 6.5. 強制パスワード変更（ADR-0009 §5）。SSO はまだ発行せず変更画面へ誘導する。
        if user.must_change_password {
            return AdminLoginOutcome::PasswordChangeRequired {
                username: cmd.username,
            };
        }

        // 7. 成功: 失敗カウンタとロックをリセットする。
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return AdminLoginOutcome::Internal(e.to_string());
            }
        }

        // 8. SSO セッション発行（Cookie には session_id、DB には SHA-256 ハッシュ。login.rs と同一機構）。
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession::establish(
            crypto::sha256_hex(&sso_session_id),
            user.id,
            now,
            self.sso_idle_ttl,
            self.sso_absolute_ttl,
            vec![AuthenticationMethod::Password],
            ctx.user_agent.clone(),
            ctx.ip_address.clone(),
        );
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

        let user = match self.users.find_by_username(tenant_id, &cmd.username).await {
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
        // 多重送信の検出（冪等化）: 直前の送信で変更が成功して `must_change_password` が下りた直後の
        // 再送では、旧 current_password が新ハッシュに一致せず「現在のパスワードが違う」と誤表示される。
        // `new_password` が現行ハッシュに一致する場合は同じ変更の再送とみなし、保存をスキップして
        // 成功時と同じ後続（admin 権限確認 → SSO 発行）へ進める（照合は現行パスワードの完全な検証で、
        // 認証強度は通常ログインと等価）。
        let duplicate_submit = if user.must_change_password {
            false
        } else {
            match self.hasher.verify(&cmd.new_password, &user.password_hash) {
                Ok(v) => v,
                Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
            }
        };
        if !user.must_change_password && !duplicate_submit {
            // 変更不要な状態でこのエンドポイントに来るのは想定外。fail-closed
            //（利用者列挙を避けるため資格情報エラーと同じ応答にする）。上の `new_password` 照合が
            // パスワードの正誤オラクルになるため、通常ログインと同じ失敗カウント・ロック判定に載せて
            // 本経路がロックアウトを迂回する推測口にならないようにする。
            return self
                .handle_password_failure(tenant_id, &user, "password_change_not_required", ctx)
                .await;
        }

        if !duplicate_submit {
            let verified = match self
                .hasher
                .verify(&cmd.current_password, &user.password_hash)
            {
                Ok(v) => v,
                Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
            };
            if !verified {
                return self
                    .handle_password_failure(tenant_id, &user, "invalid_password", ctx)
                    .await;
            }
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

        // 認証ポリシー評価（AP2）。本経路も SSO を発行する側なので `login` と同じ規則を適用する。
        if let Err(outcome) = self.check_policy(tenant_id, user.id, ctx).await {
            return outcome;
        }

        // 多重送信（変更適用済み）の場合は保存・監査をスキップし、成功時と同じ後続へ進める。
        if !duplicate_submit {
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
        }

        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return AdminLoginOutcome::Internal(e.to_string());
            }
        }

        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession::establish(
            crypto::sha256_hex(&sso_session_id),
            user.id,
            now,
            self.sso_idle_ttl,
            self.sso_absolute_ttl,
            vec![AuthenticationMethod::Password],
            ctx.user_agent.clone(),
            ctx.ip_address.clone(),
        );
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
        reason: &str,
        ctx: &RequestContext,
    ) -> AdminLoginOutcome {
        let now = self.clock.now();
        // 加算とロック判定は 1 文の UPDATE に閉じる（SEC13）。
        let failure = match self
            .users
            .record_login_failure(user.id, self.lockout, now)
            .await
        {
            Ok(f) => f,
            Err(e) => return AdminLoginOutcome::Internal(e.to_string()),
        };

        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                Some(user.id),
                None,
                Some(reason),
                ctx,
            )
            .await;

        if failure.is_locked() {
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
