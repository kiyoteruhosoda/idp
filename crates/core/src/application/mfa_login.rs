//! MFA ログイン検証ユースケース。
//!
//! パスワード認証は `LoginService` で完了済み（`auth_sessions.password_verified_at` が設定されている）。
//! 本サービスは TOTP コードを検証し、成功時に SSO セッション発行 → 同意チェック → code 発行を行う。
//! フロー後半は `LoginService` と共通（`CodeIssuanceService` を再利用）。
//!
//! 総当たり対策は `LoginService` と同じ二段構え（SEC3）:
//!
//! * IP 単位のスライディングウィンドウ（`LoginRateLimiter`。パスワード認証と同じ枠を消費する）
//! * ユーザー単位の失敗カウント・期限付きロック（`LockoutPolicy`。`users.failed_login_count` /
//!   `locked_until` をパスワード認証と共有する）
//!
//! 6 桁 TOTP は探索空間が 10^6 しかなく、auth_session の生存中（既定 600 秒）に無制限の試行を
//! 許すとパスワード窃取済みの攻撃者が MFA を突破できるため、どちらも省略できない。
//!
//! 失敗カウンタのリセットは **TOTP 成功時にここで**行う。`LoginService` はパスワード成功だけでは
//! リセットしない（そこで消すと、再ログインを挟むだけでロックを回避できる）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::application::totp_registration::verify_totp_code;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::authentication_policy::LockoutPolicy;
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::application::authenticator_management::consume_single_use_code;
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, SsoSessionRepository, TotpSecretRepository,
    UserAuthenticatorRepository, UserRepository,
};
use crate::domain::user_authenticator::AuthenticatorType;
use crate::domain::sso_session::SsoSession;
use crate::domain::values::AuthenticationMethod;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use chrono::Duration;
use std::sync::Arc;
use uuid::Uuid;

pub enum MfaLoginOutcome {
    /// TOTP 検証成功かつ同意済み。code 付き redirect_to へ 302 する。
    Success {
        location: String,
        sso_session_id: String,
        /// ユーザーの表示言語設定（MT20）。web は `lang` Cookie をこの値で上書きする。
        user_language: Option<String>,
    },
    /// TOTP 検証成功だが同意が必要。同意画面へ誘導する。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
    },
    /// AuthSession が無い・期限切れ・MFA pending 状態でない（`/authorize` からやり直し）。
    SessionExpired,
    /// CSRF トークン不一致。
    CsrfMismatch,
    /// TOTP コードが不正。
    InvalidCode,
    /// IP 単位のレート制限に掛かった（SEC3）。
    RateLimited,
    /// アカウントがロック中（連続失敗、または他経路の失敗でロック済み。SEC3）。
    Locked,
    /// 内部エラー。
    Internal(String),
}

pub struct MfaLoginCommand {
    pub auth_session_id: Option<String>,
    pub totp_code: String,
    pub csrf_token: String,
}

pub struct MfaLoginService {
    /// 認証器の登録簿（AP9）。リカバリーコード・email OTP の消費に使う。要るのは消費だけなので、
    /// 管理ユースケース全体ではなくリポジトリを直接受ける（正規化は共有関数に閉じている）。
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    key_encryption_key: [u8; 32],
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    lockout: LockoutPolicy,
    csrf_secret: [u8; 32],
}

impl MfaLoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        key_encryption_key: [u8; 32],
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
        lockout: LockoutPolicy,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            authenticators,
            auth_sessions,
            totp_secrets,
            users,
            sso_sessions,
            client_consents,
            code_issuance,
            rate_limiter,
            audit,
            clock,
            key_encryption_key,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
            lockout,
            csrf_secret,
        }
    }

    pub async fn verify(
        &self,
        tenant: TenantContext,
        cmd: MfaLoginCommand,
        ctx: &RequestContext,
    ) -> MfaLoginOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. auth_session_id から AuthSession を取得する（フローのテナントに限る）。
        let Some(session_id) = cmd.auth_session_id.as_deref().filter(|s| !s.is_empty()) else {
            return MfaLoginOutcome::SessionExpired;
        };
        let session = match self.auth_sessions.find_by_id(tenant_id, session_id).await {
            Ok(Some(s)) => s,
            Ok(None) => return MfaLoginOutcome::SessionExpired,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return MfaLoginOutcome::SessionExpired;
        }

        // 2. MFA pending 状態か確認する（password_verified_at が設定されている必要がある）。
        let Some(user_id) = session.authenticated_user_id else {
            return MfaLoginOutcome::SessionExpired;
        };
        if session.password_verified_at.is_none() {
            return MfaLoginOutcome::SessionExpired;
        }

        // 3. CSRF トークン検証（login_csrf_token と同じ導出を使う）。
        if idp_contracts::csrf::login_csrf_token(session_id, &self.csrf_secret) != cmd.csrf_token {
            return MfaLoginOutcome::CsrfMismatch;
        }

        let client_id = session.client_id.clone();

        // 4. IP 単位のレート制限（SEC3）。パスワード認証と同じ枠を消費するため、窃取済み資格情報で
        //    ログインしてから TOTP を叩き続ける経路にも同じ上限が掛かる。
        if let Some(ip) = &ctx.ip_address {
            if !self.rate_limiter.check_and_record(ip, now) {
                self.record_failure(tenant_id, None, &client_id, "ip_rate_limited", ctx)
                    .await;
                return MfaLoginOutcome::RateLimited;
            }
        }

        // 5. ユーザーを取得して有効確認する。
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return MfaLoginOutcome::SessionExpired,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };
        // 5.1. ロック状態の確認（SEC3）。パスワード認証と同じ `locked_until` を見るため、
        //      パスワード側の連続失敗でロックされたアカウントもこの経路で弾かれる。
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
            return MfaLoginOutcome::Locked;
        }
        if !user.is_active() {
            return MfaLoginOutcome::Internal("user not active".to_string());
        }

        // 6. 第二要素を検証する。入力欄は 1 つで、TOTP・リカバリーコード・email OTP のどれでも
        //    受ける（AP9）。認証器を失った利用者に別の入力画面へ移らせると、その画面へ辿り着く
        //    ことが復旧の前提になってしまう。値の形式で分岐せず、順に照合する（いずれも保存済み
        //    シークレットとの照合なので、取り違えは起こらない）。
        let second_factor = match self
            .verify_second_factor(tenant_id, user_id, &cmd.totp_code, ctx)
            .await
        {
            Ok(Some(method)) => method,
            Ok(None) => {
                return self
                    .handle_totp_failure(tenant_id, &user, &client_id, now, ctx)
                    .await;
            }
            Err(e) => return MfaLoginOutcome::Internal(e),
        };

        // 7. 成功: 失敗カウンタとロックをリセットする（パスワード認証の成功時と同じ扱い）。
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return MfaLoginOutcome::Internal(e.to_string());
            }
        }

        // 8. SSO セッションを組み立てる（`sid` を auth_session へ預けるため、永続化より先に作る）。
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession::establish(
            crypto::sha256_hex(&sso_session_id),
            user_id,
            now,
            self.sso_idle_ttl,
            self.sso_absolute_ttl,
            vec![AuthenticationMethod::Password, second_factor],
            ctx.user_agent.clone(),
            ctx.ip_address.clone(),
        );

        // 9. auth_time と `sid` を設定する（MFA 完了時刻を認証時刻とする）。
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(&session.id, user_id, now, Some(&sso.sid()))
            .await
        {
            return MfaLoginOutcome::Internal(e.to_string());
        }

        if let Err(e) = self.sso_sessions.create(&sso).await {
            return MfaLoginOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::SsoSessionCreated,
                AuditResult::Success,
                Some(tenant_id),
                Some(user_id),
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
                Some(user_id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 10. 同意チェック（`openid` は暗黙同意）。
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
                .find(tenant_id, user_id, &client_id)
                .await
            {
                Ok(Some(consent)) => consent.covers(&scopes_needing_consent),
                Ok(None) => false,
                Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
            }
        };

        if !consented {
            return MfaLoginOutcome::ConsentRequired {
                auth_session_id: session.id,
                sso_session_id,
            };
        }

        // 11. code 発行。
        let code = match self
            .code_issuance
            .issue(
                IssueCodeCommand {
                    tenant,
                    user_id,
                    client_id: client_id.clone(),
                    redirect_uri: session.redirect_uri.clone(),
                    scope: session.scope.clone(),
                    nonce: session.nonce.clone(),
                    auth_time: now,
                    sid: Some(sso.sid()),
                    code_challenge: session.code_challenge.clone(),
                    code_challenge_method: session.code_challenge_method,
                },
                ctx,
            )
            .await
        {
            Ok(c) => c,
            Err(e) => return MfaLoginOutcome::Internal(e.to_string()),
        };

        // 12. AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(&session.id).await {
            tracing::warn!(error = %e, "failed to delete auth session after MFA code issuance");
        }

        MfaLoginOutcome::Success {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
            sso_session_id,
            user_language: user.language.clone(),
        }
    }

    /// TOTP 不一致時の失敗カウント更新とロック判定（SEC3）。
    ///
    /// `auth_session_id` から MFA 待ちの利用者を解決する（AP9。email OTP の送信先を決めるために
    /// 使う）。パスワード検証済み（`password_verified_at` 非 NULL）でなければ `None` を返す
    /// —— 未認証のリクエストでメール送信を誘発させないため。
    pub async fn pending_mfa_user(
        &self,
        tenant: TenantContext,
        auth_session_id: &str,
    ) -> Option<Uuid> {
        let now = self.clock.now();
        let session = self
            .auth_sessions
            .find_by_id(tenant.tenant_id(), auth_session_id)
            .await
            .ok()
            .flatten()?;
        if session.is_expired_at(now) || session.password_verified_at.is_none() {
            return None;
        }
        session.authenticated_user_id
    }

    /// 第二要素を検証する（AP9）。通ったら、記録すべき認証方式を返す。どれにも一致しなければ
    /// `Ok(None)`（呼び出し側が失敗として扱う）。
    ///
    /// 照合の順序は TOTP → リカバリーコード → email OTP。TOTP を先に見るのは、日常的に使われる
    /// 経路を最短にするため（後ろ 2 つは DB アクセスを伴う）。
    async fn verify_second_factor(
        &self,
        tenant_id: TenantId,
        user_id: Uuid,
        code: &str,
        ctx: &RequestContext,
    ) -> Result<Option<AuthenticationMethod>, String> {
        // TOTP。未設定なら次へ倒す（TOTP を持たずリカバリーコードだけの利用者があり得る）。
        match self.totp_secrets.find_by_user_id(user_id).await {
            Ok(Some(record)) if record.is_confirmed() => {
                let secret = crypto::decrypt(&record.secret_encrypted, &self.key_encryption_key)
                    .map_err(|e| e.to_string())?;
                if verify_totp_code(&secret, code).map_err(|e| e.to_string())? {
                    return Ok(Some(AuthenticationMethod::Totp));
                }
            }
            Ok(_) => {}
            Err(e) => return Err(e.to_string()),
        }

        // リカバリーコード・email OTP（いずれも 1 回きり）。消費できたら第二要素として通す。
        let now = self.clock.now();
        for (authenticator_type, method) in [
            (
                AuthenticatorType::RecoveryCode,
                AuthenticationMethod::RecoveryCode,
            ),
            (AuthenticatorType::EmailOtp, AuthenticationMethod::EmailOtp),
        ] {
            if consume_single_use_code(
                self.authenticators.as_ref(),
                user_id,
                authenticator_type,
                code,
                now,
            )
            .await
            .map_err(|e| e.to_string())?
            {
                self.audit
                    .record(
                        AuditEventType::RecoveryCodeUsed,
                        AuditResult::Success,
                        Some(tenant_id),
                        Some(user_id),
                        None,
                        Some(&format!("type={authenticator_type}")),
                        ctx,
                    )
                    .await;
                return Ok(Some(method));
            }
        }

        Ok(None)
    }

    /// カウンタはパスワード認証（`LoginService::handle_password_failure`）と同じ
    /// `users.failed_login_count` を進める。MFA だけを別カウンタにすると、パスワードで N-1 回、
    /// TOTP で N-1 回という配分でロックを免れる余地が残るため共有する。
    async fn handle_totp_failure(
        &self,
        tenant_id: TenantId,
        user: &User,
        client_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        ctx: &RequestContext,
    ) -> MfaLoginOutcome {
        let failed = user.failed_login_count + 1;
        let locked_until = self.lockout.locked_until_after_failure(failed, now);

        if let Err(e) = self
            .users
            .update_login_state(user.id, failed, locked_until)
            .await
        {
            return MfaLoginOutcome::Internal(e.to_string());
        }

        self.record_failure(tenant_id, Some(user.id), client_id, "invalid_totp", ctx)
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
            return MfaLoginOutcome::Locked;
        }
        MfaLoginOutcome::InvalidCode
    }

    async fn record_failure(
        &self,
        tenant_id: TenantId,
        user_id: Option<Uuid>,
        client_id: &str,
        reason: &str,
        ctx: &RequestContext,
    ) {
        self.audit
            .record(
                AuditEventType::LoginFailed,
                AuditResult::Failure,
                Some(tenant_id),
                user_id,
                Some(client_id),
                Some(reason),
                ctx,
            )
            .await;
    }

    /// 認証不要なユーザー（TOTP 未設定）が MFA エンドポイントへ来た場合の user_id 取得補助。
    /// `auth_session_id` が MFA pending 状態かを確認するだけ。
    pub async fn has_mfa_pending(&self, tenant: TenantContext, auth_session_id: &str) -> bool {
        let Ok(Some(session)) = self
            .auth_sessions
            .find_by_id(tenant.tenant_id(), auth_session_id)
            .await
        else {
            return false;
        };
        session.password_verified_at.is_some() && session.authenticated_user_id.is_some()
    }
}

/// `user_id` のユーザーが確認済み TOTP を持つか（他サービスからの問い合わせ用）。
pub async fn user_has_confirmed_totp(
    totp_secrets: &dyn TotpSecretRepository,
    user_id: Uuid,
) -> Result<bool, crate::domain::error::DomainError> {
    Ok(totp_secrets
        .find_by_user_id(user_id)
        .await?
        .map(|s| s.is_confirmed())
        .unwrap_or(false))
}

#[cfg(test)]
mod tests {
    //! SEC3（TOTP 総当たり対策）の回帰テスト。
    //!
    //! `verify_totp_code` は実時刻に依存する（`totp-rs` の `check_current`）ため、成功パスの
    //! テストだけは同じパラメータで現在のコードを生成して渡す。失敗パスは固定の不正コードで足りる。

    use super::*;
    use crate::domain::auth_session::AuthSession;
    use crate::domain::authorization_code::AuthorizationCode;
    use crate::domain::clock::Clock as ClockTrait;
    use crate::domain::consent::ClientConsent;
    use crate::domain::error::Result as DomainResult;
    use crate::domain::repositories::AuditLogSink;
    use crate::domain::totp_secret::TotpSecret;
    use crate::domain::values::{CodeChallengeMethod, UserStatus};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;

    const TEST_KEY: [u8; 32] = *b"unit-test-key-0123456789abcdef!!";
    const CSRF_SECRET: [u8; 32] = *b"unit-test-csrf-0123456789abcdef!";
    const SESSION_ID: &str = "auth-session-id";
    const CLIENT_ID: &str = "client-a";
    /// TOTP シークレット（20 バイト = SHA-1 の推奨長）。
    const TOTP_SECRET: &[u8] = b"12345678901234567890";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl ClockTrait for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    /// 実時刻で有効な TOTP コードを生成する（`verify_totp_code` と同じパラメータ）。
    fn current_totp_code() -> String {
        use totp_rs::{Algorithm, TOTP};
        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            TOTP_SECRET.to_vec(),
            None,
            String::new(),
        )
        .expect("build TOTP")
        .generate_current()
        .expect("generate TOTP code")
    }

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<crate::domain::audit::AuditEvent>>,
    }
    #[async_trait]
    impl AuditLogSink for CapturingSink {
        async fn record(&self, event: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    struct FakeAuthSessions {
        rows: Mutex<Vec<AuthSession>>,
    }
    #[async_trait]
    impl AuthSessionRepository for FakeAuthSessions {
        async fn create(&self, _s: &AuthSession) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, t: TenantId, id: &str) -> DomainResult<Option<AuthSession>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.tenant_id == t && s.id == id)
                .cloned())
        }
        async fn find_by_handle(
            &self,
            _t: TenantId,
            _h: &str,
        ) -> DomainResult<Option<AuthSession>> {
            unreachable!()
        }
        async fn consume_handle(&self, _id: &str, _h: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn set_authenticated_user(
            &self,
            id: &str,
            user_id: Uuid,
            auth_time: DateTime<Utc>,
            sso_sid: Option<&str>,
        ) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|s| s.id == id) {
                row.authenticated_user_id = Some(user_id);
                row.auth_time = Some(auth_time);
                row.sso_sid = sso_sid.map(str::to_string);
            }
            Ok(())
        }
        async fn set_password_verified(
            &self,
            _id: &str,
            _u: Uuid,
            _v: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, id: &str) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|s| s.id != id);
            Ok(())
        }
    }

    /// 認証器の登録簿のフェイク。既定実装（見つからない）に任せるので、`create` だけ塞ぐ。
    /// リカバリーコード・email OTP を持たない利用者の経路を再現する。
    struct FakeAuthenticators;
    #[async_trait]
    impl UserAuthenticatorRepository for FakeAuthenticators {
        async fn create(
            &self,
            _a: &crate::domain::user_authenticator::UserAuthenticator,
        ) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeUsers {
        rows: Mutex<Vec<User>>,
    }
    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
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
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_username(&self, _t: TenantId, _n: &str) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn update_login_state(
            &self,
            id: Uuid,
            count: i32,
            locked_until: Option<DateTime<Utc>>,
        ) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|u| u.id == id) {
                row.failed_login_count = count;
                row.locked_until = locked_until;
            }
            Ok(())
        }
        async fn update_password(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn reset_password_forced(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
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

    /// TOTP 参照の有無で「レート制限・ロックが検証より前に効いたか」を判定できるようにする。
    #[derive(Default)]
    struct FakeTotpSecrets {
        row: Mutex<Option<TotpSecret>>,
        lookups: Mutex<usize>,
    }
    #[async_trait]
    impl TotpSecretRepository for FakeTotpSecrets {
        async fn upsert(&self, _s: &TotpSecret) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_user_id(&self, _user_id: Uuid) -> DomainResult<Option<TotpSecret>> {
            *self.lookups.lock().unwrap() += 1;
            Ok(self.row.lock().unwrap().clone())
        }
        async fn confirm(&self, _u: Uuid, _c: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeSsoSessions {
        created: Mutex<Vec<SsoSession>>,
    }
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, s: &SsoSession) -> DomainResult<()> {
            self.created.lock().unwrap().push(s.clone());
            Ok(())
        }
        async fn find_by_hash(&self, _h: &str) -> DomainResult<Option<SsoSession>> {
            unreachable!()
        }
        async fn extend_idle(&self, _h: &str, _t: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeConsents;
    #[async_trait]
    impl ClientConsentRepository for FakeConsents {
        async fn find(
            &self,
            _t: TenantId,
            _u: Uuid,
            _c: &str,
        ) -> DomainResult<Option<ClientConsent>> {
            Ok(None)
        }
        async fn upsert(&self, _c: &ClientConsent) -> DomainResult<()> {
            unreachable!()
        }
        async fn revoke(&self, _t: TenantId, _u: Uuid, _c: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn list_for_user(&self, _t: TenantId, _u: Uuid) -> DomainResult<Vec<ClientConsent>> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeCodes {
        created: Mutex<Vec<AuthorizationCode>>,
    }
    #[async_trait]
    impl crate::domain::repositories::AuthorizationCodeRepository for FakeCodes {
        async fn create(&self, c: &AuthorizationCode) -> DomainResult<()> {
            self.created.lock().unwrap().push(c.clone());
            Ok(())
        }
        async fn consume(
            &self,
            _t: TenantId,
            _h: &str,
            _u: DateTime<Utc>,
        ) -> DomainResult<Option<AuthorizationCode>> {
            unreachable!()
        }
        async fn revoke_all_active_for_user(
            &self,
            _u: Uuid,
            _n: DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
    }

    /// `allowed` 回だけ通し、以降は拒否する limiter。
    struct CountingLimiter {
        allowed: usize,
        calls: Mutex<usize>,
    }
    impl LoginRateLimiter for CountingLimiter {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            *calls <= self.allowed
        }
    }

    struct Harness {
        service: MfaLoginService,
        users: Arc<FakeUsers>,
        totp_secrets: Arc<FakeTotpSecrets>,
        sso_sessions: Arc<FakeSsoSessions>,
        sink: Arc<CapturingSink>,
        tenant: TenantContext,
        user_id: Uuid,
    }

    impl Harness {
        fn new(rate_limit_allowed: usize, max_failed_attempts: i32) -> Self {
            let tenant_id: TenantId = Uuid::now_v7().into();
            let tenant = TenantContext::new(tenant_id);
            let user_id = Uuid::now_v7();

            let users = Arc::new(FakeUsers::default());
            users.rows.lock().unwrap().push(User {
                id: user_id,
                tenant_id,
                sub: Uuid::now_v7(),
                email: "user@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("user".to_string()),
                name: None,
                language: None,
                password_hash: "hash".to_string(),
                must_change_password: false,
                status: UserStatus::Active,
                failed_login_count: 0,
                locked_until: None,
                created_at: now(),
                updated_at: now(),
            });

            let auth_sessions = Arc::new(FakeAuthSessions {
                rows: Mutex::new(vec![AuthSession {
                    id: SESSION_ID.to_string(),
                    tenant_id,
                    client_id: CLIENT_ID.to_string(),
                    redirect_uri: "https://rp.example.com/cb".to_string(),
                    scope: vec!["openid".to_string()],
                    state: "state-1".to_string(),
                    nonce: "nonce-1".to_string(),
                    code_challenge: "challenge".to_string(),
                    code_challenge_method: CodeChallengeMethod::S256,
                    prompt: None,
                    max_age: None,
                    handle_hash: None,
                    handle_expires_at: None,
                    authenticated_user_id: Some(user_id),
                    auth_time: None,
                    password_verified_at: Some(now()),
                    sso_sid: None,
                    expires_at: now() + Duration::seconds(600),
                    created_at: now(),
                    updated_at: now(),
                }]),
            });

            let totp_secrets = Arc::new(FakeTotpSecrets::default());
            *totp_secrets.row.lock().unwrap() = Some(TotpSecret {
                user_id,
                secret_encrypted: crypto::encrypt(TOTP_SECRET, &TEST_KEY).expect("encrypt secret"),
                confirmed_at: Some(now()),
                created_at: now(),
                updated_at: now(),
            });

            let sink = Arc::new(CapturingSink::default());
            let clock: Arc<dyn ClockTrait> = Arc::new(FixedClock);
            let audit = Arc::new(AuditService::new(sink.clone(), clock.clone()));
            let sso_sessions = Arc::new(FakeSsoSessions::default());
            let code_issuance = Arc::new(CodeIssuanceService::new(
                Arc::new(FakeCodes::default()),
                audit.clone(),
                clock.clone(),
                std::time::Duration::from_secs(60),
            ));

            let service = MfaLoginService::new(
                Arc::new(FakeAuthenticators),
                auth_sessions,
                totp_secrets.clone(),
                users.clone(),
                sso_sessions.clone(),
                Arc::new(FakeConsents),
                code_issuance,
                Arc::new(CountingLimiter {
                    allowed: rate_limit_allowed,
                    calls: Mutex::new(0),
                }),
                audit,
                clock,
                TEST_KEY,
                std::time::Duration::from_secs(3600),
                std::time::Duration::from_secs(28800),
                LockoutPolicy {
                    max_failed_attempts,
                    lock_duration_secs: 900,
                },
                CSRF_SECRET,
            );

            Self {
                service,
                users,
                totp_secrets,
                sso_sessions,
                sink,
                tenant,
                user_id,
            }
        }

        async fn verify(&self, code: &str) -> MfaLoginOutcome {
            let ctx = RequestContext {
                correlation_id: "test-correlation".to_string(),
                ip_address: Some("203.0.113.10".to_string()),
                user_agent: None,
            };
            self.service
                .verify(
                    self.tenant,
                    MfaLoginCommand {
                        auth_session_id: Some(SESSION_ID.to_string()),
                        totp_code: code.to_string(),
                        csrf_token: idp_contracts::csrf::login_csrf_token(SESSION_ID, &CSRF_SECRET),
                    },
                    &ctx,
                )
                .await
        }

        fn user(&self) -> User {
            self.users.rows.lock().unwrap()[0].clone()
        }

        fn totp_lookups(&self) -> usize {
            *self.totp_secrets.lookups.lock().unwrap()
        }

        fn audit_reasons(&self) -> Vec<String> {
            self.sink
                .events
                .lock()
                .unwrap()
                .iter()
                .filter_map(|e| e.reason.clone())
                .collect()
        }
    }

    #[tokio::test]
    async fn rate_limited_before_totp_is_checked() {
        // 1 回だけ通す limiter。2 回目は TOTP を照合する前に打ち切られる。
        let h = Harness::new(1, 10);
        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::InvalidCode
        ));
        assert_eq!(h.totp_lookups(), 1);

        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::RateLimited
        ));
        // TOTP は参照されない（Argon2 のような重い処理は無いが、判定は検証前に行う）。
        assert_eq!(h.totp_lookups(), 1);
        // 失敗カウンタもレート制限では進めない（IP 由来の攻撃で他人をロックできないようにする）。
        assert_eq!(h.user().failed_login_count, 1);
        assert!(h.audit_reasons().contains(&"ip_rate_limited".to_string()));
    }

    #[tokio::test]
    async fn invalid_code_increments_failed_count_and_locks_at_threshold() {
        let h = Harness::new(100, 3);

        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::InvalidCode
        ));
        assert_eq!(h.user().failed_login_count, 1);
        assert!(h.user().locked_until.is_none());

        assert!(matches!(
            h.verify("000000").await,
            MfaLoginOutcome::InvalidCode
        ));
        assert_eq!(h.user().failed_login_count, 2);
        assert!(h.user().locked_until.is_none());

        // 3 回目でロック。
        assert!(matches!(h.verify("000000").await, MfaLoginOutcome::Locked));
        assert_eq!(h.user().failed_login_count, 3);
        assert_eq!(h.user().locked_until, Some(now() + Duration::seconds(900)));

        let reasons = h.audit_reasons();
        assert_eq!(
            reasons.iter().filter(|r| *r == "invalid_totp").count(),
            3,
            "each failure is audited"
        );
        assert!(reasons.contains(&"too_many_failures".to_string()));
    }

    #[tokio::test]
    async fn locked_account_is_rejected_before_totp_is_checked() {
        let h = Harness::new(100, 10);
        h.users.rows.lock().unwrap()[0].locked_until = Some(now() + Duration::seconds(60));

        // 正しいコードでもロック中は通さない。
        assert!(matches!(
            h.verify(&current_totp_code()).await,
            MfaLoginOutcome::Locked
        ));
        assert_eq!(h.totp_lookups(), 0);
        assert!(h.audit_reasons().contains(&"account_locked".to_string()));
    }

    #[tokio::test]
    async fn successful_verification_resets_failed_count() {
        let h = Harness::new(100, 10);
        {
            let mut rows = h.users.rows.lock().unwrap();
            rows[0].failed_login_count = 2;
        }

        let outcome = h.verify(&current_totp_code()).await;
        assert!(
            matches!(outcome, MfaLoginOutcome::Success { .. }),
            "valid TOTP must complete the flow"
        );
        assert_eq!(h.user().failed_login_count, 0);
        assert!(h.user().locked_until.is_none());
        assert_eq!(h.sso_sessions.created.lock().unwrap().len(), 1);
        assert_eq!(h.user_id, h.sso_sessions.created.lock().unwrap()[0].user_id);
    }
}
