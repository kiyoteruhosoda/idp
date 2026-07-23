//! エンドユーザー・ポータルへのログインのユースケース。
//!
//! 通常の OIDC ログイン（[`crate::application::login`]）は `/authorize` が発行する `auth_session_id` に
//! 結合し、成功後は authorization code を発行して RP の `redirect_uri` へ戻す。対して本ユースケースは
//! IdP 自身のアカウント画面（`/{tenant_id}/settings`）へ入るための **クライアント非依存の直接ログイン**で、
//! 管理コンソールのログイン（[`crate::application::admin_login`]）と同じく **SSO セッションを直接発行する**
//! （code 発行・redirect は行わない）。
//!
//! 管理ログインとの違いは 2 点:
//! 1. admin 権限を要求しない（有効な利用者なら誰でも入れる）。
//! 2. **TOTP（MFA）を尊重する**。TOTP 設定済みの利用者はパスワード認証だけでは SSO を発行せず、署名付きの
//!    短命チケット（`mfa_ticket`）を返して TOTP 入力ステップへ誘導する。これにより、ポータルログインが
//!    OIDC ログインの MFA を迂回して SSO を得る抜け道になることを防ぐ。
//!
//! ロックアウト（設計仕様 §4.3）と IP レート制限・メール検証ゲート（SEC6b）・強制パスワード変更
//! （ADR-0009 §5）は通常ログインと同じ方針で適用する。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::application::totp_registration::verify_totp_code;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{SsoSessionRepository, TotpSecretRepository, UserRepository};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// username 単位のロック閾値（連続失敗回数）。通常ログイン（`login.rs`）と揃える。
const MAX_FAILED_LOGINS: i32 = 10;
/// ロック時間（分）。
const LOCK_DURATION_MINUTES: i64 = 15;
/// MFA チケットの有効期間（秒）。TOTP 入力までの猶予。
const MFA_TICKET_TTL_SECS: i64 = 300;

#[derive(Debug)]
pub struct PortalLoginCommand {
    /// ログイン識別子（ユーザー名 = `preferred_username`。ADR-0009 §8）。
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct PortalMfaCommand {
    pub mfa_ticket: String,
    pub totp_code: String,
}

/// ポータルの強制パスワード変更（ADR-0009 §5）のコマンド。ポータルログインは `auth_session_id` の
/// ような一時状態を持たないため、管理コンソールと同じく現行パスワードを含め毎回フルに再検証する。
#[derive(Debug)]
pub struct PortalChangePasswordCommand {
    /// ログイン識別子（ユーザー名 = `preferred_username`）。
    pub username: String,
    pub current_password: String,
    pub new_password: String,
}

/// ポータルログインの結果。Presentation は画面（HTML）に写す。
pub enum PortalLoginOutcome {
    /// 認証成功（TOTP 未設定）。SSO Cookie を発行してアカウント画面へ 302 する。
    Success {
        sso_session_id: String,
        user_language: Option<String>,
    },
    /// パスワード認証成功だが TOTP が必要。`mfa_ticket` を Cookie 化して TOTP 入力画面へ誘導する。
    MfaRequired {
        mfa_ticket: String,
    },
    /// 自己登録アカウントのメール未検証（SEC6b）。
    EmailVerificationRequired,
    /// 強制パスワード変更が必要（ADR-0009 §5）。web は強制パスワード変更フォームへ誘導する
    /// （管理コンソールと同方式。`username` は入力値をフォーム再表示用に返す）。
    PasswordChangeRequired {
        username: String,
    },
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正（ユーザー不存在・パスワード不一致・無効アカウントを区別しない）。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    Internal(String),
}

/// ポータルの強制パスワード変更の結果。
pub enum PortalChangePasswordOutcome {
    /// 変更成功（TOTP 未設定）。SSO Cookie を発行してアカウント画面へ 302 する。
    Success {
        sso_session_id: String,
        user_language: Option<String>,
    },
    /// パスワード変更は成功したが TOTP が必要（`login()` と同じ MFA ゲート）。`mfa_ticket` を Cookie 化して
    /// TOTP 入力画面へ誘導する。SSO はまだ発行しない（所持のみでの MFA バイパスを防ぐ）。
    MfaRequired {
        mfa_ticket: String,
    },
    /// 自己登録アカウントのメール未検証（SEC6b）。ステートレスな本経路は `login()` のメール検証ゲートを
    /// 経ていないため、ここで再判定する（管理者が未検証ユーザーをリセットした場合の抜け道を塞ぐ）。
    EmailVerificationRequired,
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正（利用者不存在・現行パスワード不一致・無効アカウントを区別しない）。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    /// 新パスワードが強度要件を満たさない。
    WeakPassword,
    Internal(String),
}

/// ポータル TOTP 検証の結果。
pub enum PortalMfaOutcome {
    Success {
        sso_session_id: String,
        user_language: Option<String>,
    },
    /// TOTP コード不正（チケットが有効なら再試行できる）。
    InvalidCode,
    /// チケットが無効・期限切れ（ログインからやり直し）。
    TicketExpired,
    RateLimited,
    Internal(String),
}

pub struct PortalLoginService {
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
    /// `mfa_ticket` の署名鍵。CSRF 秘密鍵を流用する（用途はプレフィクスで名前空間分離）。
    ticket_secret: [u8; 32],
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
}

impl PortalLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
        ticket_secret: [u8; 32],
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
    ) -> Self {
        Self {
            users,
            sso_sessions,
            totp_secrets,
            hasher,
            rate_limiter,
            audit,
            clock,
            key_encryption_key,
            ticket_secret,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
        }
    }

    pub async fn login(
        &self,
        tenant: TenantContext,
        cmd: PortalLoginCommand,
        ctx: &RequestContext,
    ) -> PortalLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. IP 単位のレート制限（資格情報検証前。通常ログインと同順）。
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.record_failure(tenant_id, None, "ip_rate_limited", ctx)
                    .await;
                return PortalLoginOutcome::RateLimited;
            }
        }

        // 2. ユーザー検索（ログイン識別子は preferred_username）。認証は所属元テナント限定（ADR-0009 §8）。
        let user = match self.users.find_by_username(tenant_id, &cmd.username).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                self.record_failure(tenant_id, None, "unknown_user", ctx)
                    .await;
                return PortalLoginOutcome::InvalidCredentials;
            }
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
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
            return PortalLoginOutcome::Locked;
        }

        // 4. アカウント状態の確認（存在の露呈を避けるため資格情報エラーと同じ応答にする）。
        if !user.is_active() {
            self.record_failure(tenant_id, Some(user.id), "account_not_active", ctx)
                .await;
            return PortalLoginOutcome::InvalidCredentials;
        }

        // 5. パスワード検証。
        let verified = match self.hasher.verify(&cmd.password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };
        if !verified {
            return self.handle_password_failure(tenant_id, &user, ctx).await;
        }

        // 6. 成功: 失敗カウンタとロックをリセットする。
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return PortalLoginOutcome::Internal(e.to_string());
            }
        }

        // 7. メール検証ゲート（SEC6b）。パスワード検証成功後に判定して列挙を防ぐ。
        if !user.email_verified {
            self.record_failure(tenant_id, Some(user.id), "email_not_verified", ctx)
                .await;
            return PortalLoginOutcome::EmailVerificationRequired;
        }

        // 8. 強制パスワード変更（ADR-0009 §5）。SSO はまだ発行せず、強制変更フォームへ誘導する
        //    （管理コンソールと同方式。`change_password` で現行パスワードを含め再検証する）。
        if user.must_change_password {
            return PortalLoginOutcome::PasswordChangeRequired {
                username: cmd.username,
            };
        }

        // 9. TOTP（MFA）が設定済みなら SSO を発行せず TOTP 入力ステップへ誘導する。
        let has_totp = match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
            Ok(v) => v,
            Err(e) => return PortalLoginOutcome::Internal(e.to_string()),
        };
        if has_totp {
            let ticket = self.issue_ticket(tenant_id, user.id, now);
            return PortalLoginOutcome::MfaRequired { mfa_ticket: ticket };
        }

        // 10. TOTP 未設定: SSO セッションを発行する。
        let sso_session_id = match self.issue_sso(tenant_id, &user, ctx, now).await {
            Ok(id) => id,
            Err(e) => return PortalLoginOutcome::Internal(e),
        };
        PortalLoginOutcome::Success {
            sso_session_id,
            user_language: user.language.clone(),
        }
    }

    /// 強制パスワード変更（ADR-0009 §5）。ポータルログインを現行パスワードを含めフルに再検証し、
    /// 成功時に新パスワードを保存して SSO セッションを発行する（管理コンソールの `change_password` と
    /// 同方式。ポータルは admin 権限を要求しない点だけが異なる）。この状態のユーザーは自己登録 MFA を
    /// 設定できないため（SSO が必要）、変更後に改めて TOTP 判定へ進む必要はない。
    pub async fn change_password(
        &self,
        tenant: TenantContext,
        cmd: PortalChangePasswordCommand,
        ctx: &RequestContext,
    ) -> PortalChangePasswordOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.record_failure(tenant_id, None, "ip_rate_limited", ctx)
                    .await;
                return PortalChangePasswordOutcome::RateLimited;
            }
        }

        let user = match self.users.find_by_username(tenant_id, &cmd.username).await {
            Ok(Some(u)) => u,
            Ok(None) => return PortalChangePasswordOutcome::InvalidCredentials,
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };

        if user.is_locked_at(now) {
            return PortalChangePasswordOutcome::Locked;
        }
        if !user.is_active() {
            return PortalChangePasswordOutcome::InvalidCredentials;
        }
        if !user.must_change_password {
            // 変更不要な状態でこのエンドポイントに来るのは想定外（多重送信等）。fail-closed。
            return PortalChangePasswordOutcome::InvalidCredentials;
        }

        let verified = match self
            .hasher
            .verify(&cmd.current_password, &user.password_hash)
        {
            Ok(v) => v,
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };
        if !verified {
            // 現行パスワード不一致は通常ログインと同じ失敗カウント・ロック判定に載せる。
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
                return PortalChangePasswordOutcome::Internal(e.to_string());
            }
            self.record_failure(tenant_id, Some(user.id), "invalid_password", ctx)
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
                return PortalChangePasswordOutcome::Locked;
            }
            return PortalChangePasswordOutcome::InvalidCredentials;
        }

        // メール検証ゲート（SEC6b）。`login()` はメール検証を強制変更より先に判定するが、本経路は
        // ステートレスで直接呼べるため、その前提に依存できない。現行パスワード検証後に判定して列挙を防ぐ。
        if !user.email_verified {
            self.record_failure(tenant_id, Some(user.id), "email_not_verified", ctx)
                .await;
            return PortalChangePasswordOutcome::EmailVerificationRequired;
        }

        if validate_password_strength(&cmd.new_password).is_err() {
            return PortalChangePasswordOutcome::WeakPassword;
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };
        if let Err(e) = self.users.update_password(user.id, &new_hash).await {
            return PortalChangePasswordOutcome::Internal(e.to_string());
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
                return PortalChangePasswordOutcome::Internal(e.to_string());
            }
        }

        // TOTP（MFA）が設定済みなら SSO を発行せず TOTP 入力ステップへ誘導する（`login()` と同じ MFA ゲート）。
        // 管理者が既存 TOTP 利用者のパスワードをリセットした場合でも、生成パスワードの所持だけでは
        // 第二要素を迂回できないようにする。
        let has_totp = match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
            Ok(v) => v,
            Err(e) => return PortalChangePasswordOutcome::Internal(e.to_string()),
        };
        if has_totp {
            let ticket = self.issue_ticket(tenant_id, user.id, now);
            return PortalChangePasswordOutcome::MfaRequired { mfa_ticket: ticket };
        }

        let sso_session_id = match self.issue_sso(tenant_id, &user, ctx, now).await {
            Ok(id) => id,
            Err(e) => return PortalChangePasswordOutcome::Internal(e),
        };
        PortalChangePasswordOutcome::Success {
            sso_session_id,
            user_language: user.language.clone(),
        }
    }

    /// TOTP 検証（パスワード認証済みの `mfa_ticket` を提示して行う 2 段階目）。
    pub async fn verify_mfa(
        &self,
        tenant: TenantContext,
        cmd: PortalMfaCommand,
        ctx: &RequestContext,
    ) -> PortalMfaOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. IP 単位のレート制限。
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                return PortalMfaOutcome::RateLimited;
            }
        }

        // 2. チケット検証（署名・テナント・期限）。
        let Some(user_id) = self.verify_ticket(tenant_id, &cmd.mfa_ticket, now) else {
            return PortalMfaOutcome::TicketExpired;
        };

        // 3. ユーザーを取得して有効確認する。
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return PortalMfaOutcome::TicketExpired,
            Err(e) => return PortalMfaOutcome::Internal(e.to_string()),
        };
        if user.is_locked_at(now) || !user.is_active() {
            return PortalMfaOutcome::TicketExpired;
        }

        // 4. TOTP シークレットを取得して検証する。
        let totp_record = match self.totp_secrets.find_by_user_id(user_id).await {
            Ok(Some(r)) if r.is_confirmed() => r,
            Ok(_) => return PortalMfaOutcome::TicketExpired,
            Err(e) => return PortalMfaOutcome::Internal(e.to_string()),
        };
        let secret_bytes =
            match crypto::decrypt(&totp_record.secret_encrypted, &self.key_encryption_key) {
                Ok(b) => b,
                Err(e) => return PortalMfaOutcome::Internal(e.to_string()),
            };
        let valid = match verify_totp_code(&secret_bytes, &cmd.totp_code) {
            Ok(v) => v,
            Err(e) => return PortalMfaOutcome::Internal(e.to_string()),
        };
        if !valid {
            self.record_failure(tenant_id, Some(user_id), "invalid_totp", ctx)
                .await;
            return PortalMfaOutcome::InvalidCode;
        }

        // 5. SSO セッションを発行する。
        let sso_session_id = match self.issue_sso(tenant_id, &user, ctx, now).await {
            Ok(id) => id,
            Err(e) => return PortalMfaOutcome::Internal(e),
        };
        PortalMfaOutcome::Success {
            sso_session_id,
            user_language: user.language.clone(),
        }
    }

    /// SSO セッションを発行し、監査へ記録する（`login.rs` / `admin_login.rs` と同一機構）。
    async fn issue_sso(
        &self,
        tenant_id: TenantId,
        user: &User,
        ctx: &RequestContext,
        now: DateTime<Utc>,
    ) -> Result<String, String> {
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
            return Err(e.to_string());
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
        Ok(sso_session_id)
    }

    /// 署名付き `mfa_ticket` を発行する。
    fn issue_ticket(&self, tenant_id: TenantId, user_id: Uuid, now: DateTime<Utc>) -> String {
        let exp = now.timestamp() + MFA_TICKET_TTL_SECS;
        sign_ticket(&self.ticket_secret, tenant_id.as_uuid(), user_id, exp)
    }

    /// `mfa_ticket` を検証し、有効なら `user_id` を返す（テナント一致・署名一致・未期限）。
    fn verify_ticket(&self, tenant_id: TenantId, ticket: &str, now: DateTime<Utc>) -> Option<Uuid> {
        verify_ticket(
            &self.ticket_secret,
            tenant_id.as_uuid(),
            ticket,
            now.timestamp(),
        )
    }

    /// パスワード不一致時の失敗カウント更新とロック判定（login.rs / admin_login.rs と同ポリシー）。
    async fn handle_password_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        ctx: &RequestContext,
    ) -> PortalLoginOutcome {
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
            return PortalLoginOutcome::Internal(e.to_string());
        }
        self.record_failure(tenant_id, Some(user.id), "invalid_password", ctx)
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
            return PortalLoginOutcome::Locked;
        }
        PortalLoginOutcome::InvalidCredentials
    }

    async fn record_failure(
        &self,
        tenant_id: TenantId,
        user_id: Option<Uuid>,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                user_id,
                None,
                Some(reason),
                ctx,
            )
            .await;
    }
}

/// 署名付き `mfa_ticket` を作る。形式: `{tenant}.{user}.{exp}.{hmac_hex}`。
/// HMAC は `portal-mfa:{tenant}:{user}:{exp}` に対して計算し、テナント越え・改竄・使い回しを防ぐ。
fn sign_ticket(secret: &[u8; 32], tenant: Uuid, user: Uuid, exp: i64) -> String {
    let sig = ticket_signature(secret, &tenant.to_string(), &user.to_string(), exp);
    format!("{tenant}.{user}.{exp}.{sig}")
}

/// `mfa_ticket` を検証し、有効なら `user_id` を返す（テナント一致・署名一致・未期限）。
fn verify_ticket(secret: &[u8; 32], tenant: Uuid, ticket: &str, now_ts: i64) -> Option<Uuid> {
    let mut parts = ticket.splitn(4, '.');
    let tenant_str = parts.next()?;
    let user_str = parts.next()?;
    let exp_str = parts.next()?;
    let sig = parts.next()?;

    // テナント一致（チケットの使い回し防止）。
    if tenant_str != tenant.to_string() {
        return None;
    }
    let exp: i64 = exp_str.parse().ok()?;
    if now_ts > exp {
        return None;
    }
    // HMAC の定数時間検証（`verify_slice`）で署名照合する。
    let sig_bytes = hex::decode(sig).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("portal-mfa:{tenant_str}:{user_str}:{exp}").as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;
    Uuid::parse_str(user_str).ok()
}

fn ticket_signature(secret: &[u8; 32], tenant: &str, user: &str, exp: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(format!("portal-mfa:{tenant}:{user}:{exp}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];

    #[test]
    fn ticket_round_trips_within_ttl() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 1_000 + MFA_TICKET_TTL_SECS);
        assert_eq!(verify_ticket(&SECRET, tenant, &ticket, 1_000), Some(user));
    }

    #[test]
    fn ticket_rejected_after_expiry() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 1_000);
        // now (1_001) を exp (1_000) が下回る = 期限切れ。
        assert_eq!(verify_ticket(&SECRET, tenant, &ticket, 1_001), None);
    }

    #[test]
    fn ticket_rejected_for_other_tenant() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 5_000);
        let other = Uuid::from_u128(99);
        assert_eq!(verify_ticket(&SECRET, other, &ticket, 1_000), None);
    }

    #[test]
    fn ticket_rejected_with_tampered_signature() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 5_000);
        // 署名を 1 文字書き換える。
        let mut bytes = ticket.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'a' { b'b' } else { b'a' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert_eq!(verify_ticket(&SECRET, tenant, &tampered, 1_000), None);
    }

    #[test]
    fn ticket_rejected_with_wrong_secret() {
        let tenant = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let ticket = sign_ticket(&SECRET, tenant, user, 5_000);
        let other_secret = [9u8; 32];
        assert_eq!(verify_ticket(&other_secret, tenant, &ticket, 1_000), None);
    }
}
