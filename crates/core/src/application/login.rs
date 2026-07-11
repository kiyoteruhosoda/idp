//! ログインのユースケース（設計仕様 §4.3）。
//!
//! AuthSession（Cookie）→ CSRF → レート制限 → 資格情報 → アカウント状態・ロックの順に検証し、
//! 成功時は SSO セッション発行 → 同意チェック → 同意済みなら code 発行（`code_issuance` 共通モジュール）
//! → AuthSession 削除。同意未完なら `/consent` へ誘導する（F3）。
//!
//! ロックポリシー: username 単位で連続 10 回失敗 → 15 分ロック。IP 単位のレート制限。
//! 成功時に `failed_login_count = 0` / `locked_until = NULL` へリセットする。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::password::PasswordHasher;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, SsoSessionRepository, TotpSecretRepository,
    UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::infrastructure::crypto;
use chrono::Duration;
use std::sync::Arc;

/// username 単位のロック閾値（連続失敗回数）。
const MAX_FAILED_LOGINS: i32 = 10;
/// ロック時間（分）。
const LOCK_DURATION_MINUTES: i64 = 15;

/// `auth_session_id` に紐づく CSRF トークンを導出する。
///
/// 導出は web（フォーム描画）と api（検証）で一致させる必要があるため `idp-contracts` に一元化する
/// （ADR-0007 §6。同期トークン方式。サーバ側の追加保存は不要）。
pub fn csrf_token(auth_session_id: &str) -> String {
    idp_contracts::csrf::login_csrf_token(auth_session_id)
}

#[derive(Debug)]
pub struct LoginCommand {
    /// `auth_session_id` Cookie の値。
    pub auth_session_id: Option<String>,
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

pub enum LoginOutcome {
    /// 認証成功かつ同意済み。`redirect_uri?code=...&state=...` へ 302 し、SSO Cookie を発行する。
    Success {
        location: String,
        sso_session_id: String,
    },
    /// 認証成功だが未同意 scope あり。同意画面へリダイレクトする。
    /// SSO Cookie は発行済み（`sso_session_id`）。AuthSession は認証済み状態で残す。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
    },
    /// パスワード認証成功だが MFA（TOTP）が設定済み。TOTP 入力画面へ誘導する。
    /// `auth_session_id` Cookie はそのまま維持し、SSO Cookie はまだ発行しない。
    MfaRequired {
        auth_session_id: String,
    },
    /// パスワード認証成功だが `must_change_password`（ADR-0009 §5）。パスワード変更画面へ誘導する。
    /// `auth_session_id` Cookie はそのまま維持し、SSO Cookie はまだ発行しない。認可フローは
    /// 変更完了まで完了させない（[`crate::application::change_password::ChangePasswordService`]）。
    PasswordChangeRequired {
        auth_session_id: String,
    },
    /// AuthSession が無い・期限切れ（`/authorize` からやり直し）。
    SessionExpired,
    /// CSRF トークン不一致。
    CsrfMismatch,
    /// IP 単位のレート制限超過。
    RateLimited,
    /// 資格情報不正（ユーザー不存在・パスワード不一致・無効アカウントを区別しない）。
    InvalidCredentials,
    /// アカウントロック中。
    Locked,
    Internal(String),
}

pub struct LoginService {
    users: Arc<dyn UserRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
}

impl LoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
    ) -> Self {
        Self {
            users,
            auth_sessions,
            sso_sessions,
            client_consents,
            totp_secrets,
            code_issuance,
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
        cmd: LoginCommand,
        ctx: &RequestContext,
    ) -> LoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. Cookie の auth_session_id から AuthSession を取得する（フローのテナントに限る）。
        let Some(session_id) = cmd.auth_session_id.as_deref().filter(|s| !s.is_empty()) else {
            return LoginOutcome::SessionExpired;
        };
        let session = match self.auth_sessions.find_by_id(tenant_id, session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return LoginOutcome::SessionExpired,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return LoginOutcome::SessionExpired;
        }

        // 2. CSRF トークン検証。
        if csrf_token(&session.id) != cmd.csrf_token {
            return LoginOutcome::CsrfMismatch;
        }

        let client_id = session.client_id.clone();

        // 3. IP 単位のレート制限。
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        Some(&client_id),
                        Some("ip_rate_limited"),
                        ctx,
                    )
                    .await;
                return LoginOutcome::RateLimited;
            }
        }

        // 4. ユーザー検索（username → 見つからなければ email として検索）。
        //    認証は所属元テナント限定 = このテナントを所属元とするユーザーのみが対象（ADR-0009 §8）。
        let user = match self.find_user(tenant_id, &cmd.username).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                self.audit
                    .record(
                        AuditEventType::LoginFailed,
                        AuditResult::Failure,
                        Some(tenant_id),
                        None,
                        Some(&client_id),
                        Some("unknown_user"),
                        ctx,
                    )
                    .await;
                return LoginOutcome::InvalidCredentials;
            }
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };

        // 5. ロック状態の確認。
        if user.is_locked_at(now) {
            self.audit
                .record(
                    AuditEventType::LoginLocked,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some("account_locked"),
                    ctx,
                )
                .await;
            return LoginOutcome::Locked;
        }

        // 6. アカウント状態の確認（存在の露呈を避けるため資格情報エラーと同じ応答にする）。
        if !user.is_active() {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some("account_not_active"),
                    ctx,
                )
                .await;
            return LoginOutcome::InvalidCredentials;
        }

        // 7. パスワード検証。
        let verified = match self.hasher.verify(&cmd.password, &user.password_hash) {
            Ok(v) => v,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if !verified {
            return self
                .handle_password_failure(tenant_id, &user, &client_id, ctx)
                .await;
        }

        // 8. 成功: 失敗カウンタとロックをリセットする。
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return LoginOutcome::Internal(e.to_string());
            }
        }

        // 8.5. 強制パスワード変更（ADR-0009 §5）。自動生成パスワードで作成された利用者は、MFA・同意より
        //      先にパスワード変更画面へ誘導する（変更完了までは他の操作を許可しない）。この状態のユーザーは
        //      自己登録 MFA を設定できないため（SSO が必要）、変更後に改めて MFA 判定へ進む必要はない。
        if user.must_change_password {
            if let Err(e) = self
                .auth_sessions
                .set_password_verified(&session.id, user.id, now)
                .await
            {
                return LoginOutcome::Internal(e.to_string());
            }
            return LoginOutcome::PasswordChangeRequired {
                auth_session_id: session.id,
            };
        }

        // 9. MFA（TOTP）が設定済みか確認する。設定済みなら TOTP 入力ステップへ誘導する。
        let has_totp = match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
            Ok(v) => v,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if has_totp {
            // パスワード検証成功を AuthSession に記録（MFA pending 状態）。
            if let Err(e) = self
                .auth_sessions
                .set_password_verified(&session.id, user.id, now)
                .await
            {
                return LoginOutcome::Internal(e.to_string());
            }
            return LoginOutcome::MfaRequired {
                auth_session_id: session.id,
            };
        }

        // 10. SSO セッション発行（Cookie には session_id、DB には SHA-256 ハッシュ）。
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
            return LoginOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                Some(&client_id),
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
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 10. AuthSession に認証結果を記録する。
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(&session.id, user.id, now)
            .await
        {
            return LoginOutcome::Internal(e.to_string());
        }

        // 11. 同意チェック（`openid` は暗黙同意）。
        let scopes_needing_consent: Vec<String> = session
            .scope
            .iter()
            .filter(|s| s.as_str() != "openid")
            .cloned()
            .collect();
        let consented = if scopes_needing_consent.is_empty() {
            true
        } else {
            match self
                .client_consents
                .find(tenant_id, user.id, &client_id)
                .await
            {
                Ok(Some(consent)) => consent.covers(&scopes_needing_consent),
                Ok(None) => false,
                Err(e) => return LoginOutcome::Internal(e.to_string()),
            }
        };

        if !consented {
            // 同意未完: AuthSession は認証済み状態のまま残す。同意画面へ。
            return LoginOutcome::ConsentRequired {
                auth_session_id: session.id,
                sso_session_id,
            };
        }

        // 12. 同意済み: code を発行する（§4.2 と共通モジュール）。
        let code = match self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    user_id: user.id,
                    client_id: client_id.clone(),
                    redirect_uri: session.redirect_uri.clone(),
                    scope: session.scope.clone(),
                    nonce: session.nonce.clone(),
                    auth_time: now,
                    code_challenge: session.code_challenge.clone(),
                    code_challenge_method: session.code_challenge_method,
                },
                ctx,
            )
            .await
        {
            Ok(code) => code,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };

        // 13. AuthSession を削除する（Cookie 失効はハンドラが行う）。
        if let Err(e) = self.auth_sessions.delete(&session.id).await {
            tracing::warn!(error = %e, "failed to delete auth session after code issuance");
        }

        LoginOutcome::Success {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
            sso_session_id,
        }
    }

    async fn find_user(
        &self,
        tenant_id: TenantId,
        username: &str,
    ) -> Result<Option<User>, crate::domain::error::DomainError> {
        if let Some(user) = self.users.find_by_username(tenant_id, username).await? {
            return Ok(Some(user));
        }
        if username.contains('@') {
            return self.users.find_by_email(tenant_id, username).await;
        }
        Ok(None)
    }

    /// パスワード不一致時の失敗カウント更新とロック判定。
    async fn handle_password_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        client_id: &str,
        ctx: &RequestContext,
    ) -> LoginOutcome {
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
            return LoginOutcome::Internal(e.to_string());
        }

        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                Some(user.id),
                Some(client_id),
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
                    Some(client_id),
                    Some("too_many_failures"),
                    ctx,
                )
                .await;
            return LoginOutcome::Locked;
        }
        LoginOutcome::InvalidCredentials
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_token_is_deterministic_and_session_bound() {
        let a = csrf_token("session-a");
        assert_eq!(a, csrf_token("session-a"));
        assert_ne!(a, csrf_token("session-b"));
        // SHA-256 hex（64 文字）でフォームに埋め込める安全な文字のみ。
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
