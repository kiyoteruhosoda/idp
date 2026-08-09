//! ログインのユースケース（設計仕様 §4.3）。
//!
//! AuthSession（Cookie）→ CSRF → レート制限 → 資格情報 → アカウント状態・ロックの順に検証し、
//! 成功時は SSO セッション発行 → 同意チェック → 同意済みなら code 発行（`code_issuance` 共通モジュール）
//! → AuthSession 削除。同意未完なら `/consent` へ誘導する（F3）。
//!
//! ロックポリシー: username 単位で連続 `LOGIN_MAX_FAILED_ATTEMPTS` 回失敗 →
//! `LOGIN_LOCK_DURATION_SECS` 秒ロック（設定注入。既定 10 回 / 15 分）。IP 単位のレート制限。
//! 失敗カウンタのリセット（`failed_login_count = 0` / `locked_until = NULL`）は、**認証が最後まで
//! 通った時点**でのみ行う。MFA 待ちで返す経路ではリセットせず、TOTP 成功時に
//! [`crate::application::mfa_login::MfaLoginService`] が行う（SEC3。パスワード成功のたびに消すと、
//! パスワードを知る攻撃者が TOTP のロックを永久に回避できる）。
//!
//! 認証ポリシー（ユーザー認証・認証ポリシー仕様書 §7〜§9）: パスワード検証成功後に
//! テナントの有効ポリシーを評価し、`deny` は拒否（`PolicyDenied`）、`require_mfa` は
//! TOTP 未設定なら拒否（`MfaEnrollmentRequired`）・設定済みなら既存の MFA ステップへ倒す。
//! パスワード検証後に評価することで、資格情報を知らない攻撃者からはポリシーの存在を観測できない。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session;
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, DefaultPolicyEffect, LockoutPolicy, PolicyDecision,
};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::PasswordHasher;
use crate::domain::rate_limit::LoginRateLimiter;
use crate::domain::repositories::{
    AuthSessionRepository, AuthenticationPolicyRepository, ClientConsentRepository,
    SsoSessionRepository, TotpSecretRepository, UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user::User;
use crate::domain::values::AuthenticationMethod;
use chrono::Duration;
use std::sync::Arc;

/// `auth_session_id` に紐づく CSRF トークンを導出する。
///
/// 導出は web（フォーム描画）と api（検証）で一致させる必要があるため `idp-contracts` に一元化する
/// （ADR-0007 §6。同期トークン方式。サーバ側の追加保存は不要）。
pub fn csrf_token(auth_session_id: &str, key: &[u8]) -> String {
    idp_contracts::csrf::login_csrf_token(auth_session_id, key)
}

#[derive(Debug)]
pub struct LoginCommand {
    /// `auth_session_id` Cookie の値。
    pub auth_session_id: Option<String>,
    /// ログイン識別子（ユーザー名 = `preferred_username`。ADR-0009 §8）。
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

pub enum LoginOutcome {
    /// 認証成功かつ同意済み。`redirect_uri?code=...&state=...` へ 302 し、SSO Cookie を発行する。
    Success {
        location: String,
        sso_session_id: String,
        /// ユーザーの表示言語設定（MT20）。web は `lang` Cookie をこの値で上書きする。
        user_language: Option<String>,
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
    /// パスワード認証成功だが自己登録アカウントのメール未検証（SEC6b）。確認リンクを踏むまでは
    /// ログインを許可しない。SSO Cookie は発行しない。パスワード検証後に判定するため、資格情報を
    /// 知らない攻撃者からはメール検証状態を観測できない（列挙防止）。
    EmailVerificationRequired,
    /// 認証ポリシーにより拒否（仕様 §7.4 `deny`）。資格情報の成否は既に確認済みのため、
    /// 資格情報エラーとは別の文言で「組織のポリシーで拒否された」ことを表示してよい。
    PolicyDenied,
    /// 認証ポリシーが MFA を必須としたが、ユーザーに使用可能な認証器（確認済み TOTP）が無い。
    /// ポータルから MFA を設定するよう案内する。SSO Cookie は発行しない。
    MfaEnrollmentRequired,
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
    authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn LoginRateLimiter>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    lockout: LockoutPolicy,
    policy_default_effect: DefaultPolicyEffect,
    csrf_secret: [u8; 32],
}

impl LoginService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn LoginRateLimiter>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
        lockout: LockoutPolicy,
        policy_default_effect: DefaultPolicyEffect,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            users,
            auth_sessions,
            sso_sessions,
            client_consents,
            totp_secrets,
            authentication_policies,
            code_issuance,
            hasher,
            rate_limiter,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
            lockout,
            policy_default_effect,
            csrf_secret,
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
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "login rejected: auth_session_id cookie missing"
            );
            return LoginOutcome::SessionExpired;
        };
        // 認証成功時に id を再生成する（SEC7）ため mut。以降 `session.id_hash` は常に「今この
        // ブラウザが持つべき値」のハッシュを指す。
        let mut session = match self
            .auth_sessions
            .find_by_id_hash(tenant_id, &auth_session::id_hash(session_id))
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => {
                tracing::warn!(
                    correlation_id = %ctx.correlation_id,
                    "login rejected: auth session not found (already consumed or wrong tenant)"
                );
                return LoginOutcome::SessionExpired;
            }
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id_hash).await;
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "login rejected: auth session expired"
            );
            return LoginOutcome::SessionExpired;
        }

        // 2. CSRF トークン検証。不一致は攻撃だけでなく「別タブでの新フローによる Cookie 差し替え」等の
        //    正規操作でも起こるため、監査に記録して web 側でフォーム再表示（PRG）に載せる。
        if !idp_contracts::csrf::verify(&csrf_token(session_id, &self.csrf_secret), &cmd.csrf_token)
        {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    None,
                    Some(&session.client_id),
                    Some("csrf_mismatch"),
                    ctx,
                )
                .await;
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

        // 4. ユーザー検索（ログイン識別子は preferred_username）。メールアドレスでの照合は行わない。
        //    認証は所属元テナント限定 = このテナントを所属元とするユーザーのみが対象（ADR-0009 §8）。
        let user = match self.users.find_by_username(tenant_id, &cmd.username).await {
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

        // 8. パスワード検証成功。**ここでは失敗カウンタをリセットしない**（SEC3）。
        //    リセットは「認証が最後まで通った時点」（10. の直前、または MFA 成功時に
        //    `MfaLoginService`）で行う。ここで消すと、パスワードを知っている攻撃者が
        //    「TOTP を上限手前まで失敗 → 正しいパスワードで再ログインしてカウンタを 0 に戻す」を
        //    繰り返してロックを永久に回避できる。
        //
        // 8.1. メール検証ゲート（SEC6b）。自己登録アカウントは `email_verified` が立つまでログイン不可。
        //      管理者作成・招待ユーザーは検証済みで作られるため掛からない。パスワード検証成功後に判定する
        //      ことで、資格情報を知らない攻撃者からは検証状態を観測できない（列挙防止）。
        if !user.email_verified {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some("email_not_verified"),
                    ctx,
                )
                .await;
            return LoginOutcome::EmailVerificationRequired;
        }

        // 8.2. 認証ポリシー評価（ユーザー認証・認証ポリシー仕様書 §9）。パスワード検証成功後に
        //      評価する（資格情報を知らない攻撃者にポリシーの存在・内容を観測させない）。
        //      `deny` は即拒否。`require_mfa` は後段の MFA 判定（9.）で強制する。
        // 認可要求の `acr_values`（AP3 の `requested_acr` 条件が参照する）。
        let requested_acr = session.requested_acr();
        let policy_decision = match self
            .authentication_policies
            .list_enabled_for_tenant(tenant_id)
            .await
        {
            Ok(policies) => evaluate_policies(
                &policies,
                &AuthenticationContext {
                    client_id: Some(&client_id),
                    user_id: user.id,
                    ip_address: ctx.ip_address.as_deref(),
                    now,
                    requested_acr: &requested_acr,
                },
                self.policy_default_effect,
            ),
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if let PolicyDecision::Deny { policy_code } = &policy_decision {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some(&format!("policy={policy_code}")),
                    ctx,
                )
                .await;
            return LoginOutcome::PolicyDenied;
        }

        // 8.5. 強制パスワード変更（ADR-0009 §5）。自動生成パスワードで作成・再発行された利用者は、
        //      MFA・同意より先にパスワード変更画面へ誘導する（変更完了までは他の操作を許可しない）。
        //      TOTP の検証・ポリシーの MFA 要件は変更完了時に `ChangePasswordService` が適用する
        //      （`must_change_password` は管理者による既存ユーザーのパスワード再発行でも立つため、
        //      「この状態のユーザーに MFA 判定は不要」とは限らない）。
        if user.must_change_password {
            let rotated_id = crypto::random_hex(32);
            if let Err(e) = self
                .auth_sessions
                .set_password_verified(
                    &session.id_hash,
                    &auth_session::id_hash(&rotated_id),
                    user.id,
                    now,
                )
                .await
            {
                return LoginOutcome::Internal(e.to_string());
            }
            return LoginOutcome::PasswordChangeRequired {
                auth_session_id: rotated_id,
            };
        }

        // 9. MFA（TOTP）が設定済みか確認する。設定済みなら TOTP 入力ステップへ誘導する。
        //    認証ポリシーが MFA 必須（`require_mfa`）なのに使用可能な認証器が無い場合は、
        //    単一要素での成立を許さず拒否する（仕様 §24.4「MFA 必須ユーザーが単一要素のみでは
        //    認証完了しないこと」）。
        let has_totp = match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
            Ok(v) => v,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };
        if has_totp {
            // パスワード検証成功を AuthSession に記録（MFA pending 状態）。id も再生成する（SEC7）。
            let rotated_id = crypto::random_hex(32);
            if let Err(e) = self
                .auth_sessions
                .set_password_verified(
                    &session.id_hash,
                    &auth_session::id_hash(&rotated_id),
                    user.id,
                    now,
                )
                .await
            {
                return LoginOutcome::Internal(e.to_string());
            }
            return LoginOutcome::MfaRequired {
                auth_session_id: rotated_id,
            };
        }
        if let PolicyDecision::RequireMfa { policy_code } = &policy_decision {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some(&format!("policy={policy_code} reason=mfa_not_enrolled")),
                    ctx,
                )
                .await;
            return LoginOutcome::MfaEnrollmentRequired;
        }
        // 9.1. `require_specific_method`（AP3。仕様 §12.2）。ここへ来た時点で使った方式は
        //      パスワードだけなので、方式指定を満たしていなければ成立させない。TOTP を要求する
        //      ポリシーは上の MFA ステップ（`has_totp`）で満たされる経路へ入っており、そこで
        //      `MfaLoginService` が最終的な方式集合に対して再評価する。パスキーを要求する
        //      ポリシーはログイン画面のパスキーボタン（`PasskeyAuthenticationService`）が満たす。
        if let Some(unmet) =
            policy_decision.unmet_method_requirement(&[AuthenticationMethod::Password], false)
        {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some(&format!(
                        "policy={} reason=method_required required={}",
                        unmet.policy_code,
                        unmet.requirement.describe()
                    )),
                    ctx,
                )
                .await;
            return LoginOutcome::PolicyDenied;
        }

        // 9.5. ここまで来た＝単一要素で認証が成立した（MFA 待ちではない）。失敗カウンタと
        //      ロックをリセットする（SEC3。MFA 待ちの経路では `MfaLoginService` が TOTP 成功時に行う）。
        if user.failed_login_count > 0 || user.locked_until.is_some() {
            if let Err(e) = self.users.update_login_state(user.id, 0, None).await {
                return LoginOutcome::Internal(e.to_string());
            }
        }

        // 10. SSO セッション発行（Cookie には session_id、DB には SHA-256 ハッシュ）。
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

        // 10. AuthSession に認証結果を記録する（id も再生成する。SEC7）。
        let rotated_id = crypto::random_hex(32);
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(
                &session.id_hash,
                &auth_session::id_hash(&rotated_id),
                user.id,
                now,
                Some(&sso.sid()),
            )
            .await
        {
            return LoginOutcome::Internal(e.to_string());
        }
        session.id_hash = auth_session::id_hash(&rotated_id);

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
                auth_session_id: rotated_id,
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
                    sid: Some(sso.sid()),
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
        if let Err(e) = self.auth_sessions.delete(&session.id_hash).await {
            tracing::warn!(error = %e, "failed to delete auth session after code issuance");
        }

        LoginOutcome::Success {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
            sso_session_id,
            user_language: user.language.clone(),
        }
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
        // 加算とロック判定は 1 文の UPDATE に閉じる（SEC13）。
        let failure = match self
            .users
            .record_login_failure(user.id, self.lockout, now)
            .await
        {
            Ok(f) => f,
            Err(e) => return LoginOutcome::Internal(e.to_string()),
        };

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

        if failure.is_locked() {
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
        let key = *b"test-key-for-csrf-32-bytes-xxxxx";
        let a = csrf_token("session-a", &key);
        assert_eq!(a, csrf_token("session-a", &key));
        assert_ne!(a, csrf_token("session-b", &key));
        // HMAC-SHA256 hex（64 文字）でフォームに埋め込める安全な文字のみ。
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    // ── SEC3: MFA 待ちのパスワード成功では失敗カウンタを消さない ──────────────

    use crate::domain::auth_session::AuthSession;
    use crate::domain::authentication_policy::AuthenticationPolicy;
    use crate::domain::authorization_code::AuthorizationCode;
    use crate::domain::consent::ClientConsent;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::repositories::{AuditLogSink, AuthorizationCodeRepository};
    use crate::domain::totp_secret::TotpSecret;
    use crate::domain::values::{CodeChallengeMethod, UserStatus};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::sync::Mutex;
    use uuid::Uuid;

    const CSRF_KEY: [u8; 32] = *b"unit-test-csrf-0123456789abcdef!";
    const SESSION_ID: &str = "auth-session-id";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap()
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            now()
        }
    }

    struct PlainHasher;
    impl PasswordHasher for PlainHasher {
        fn hash(&self, password: &str) -> Result<String, DomainError> {
            Ok(format!("hash:{password}"))
        }
        fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError> {
            Ok(hash == format!("hash:{password}"))
        }
    }

    struct AllowAll;
    impl LoginRateLimiter for AllowAll {
        fn check_and_record(&self, _key: &str, _now: DateTime<Utc>) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct DiscardingSink;
    #[async_trait]
    impl AuditLogSink for DiscardingSink {
        async fn record(&self, _event: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
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
        async fn find_by_id_hash(
            &self,
            t: TenantId,
            id_hash: &str,
        ) -> DomainResult<Option<AuthSession>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.tenant_id == t && s.id_hash == id_hash)
                .cloned())
        }
        async fn find_by_handle(
            &self,
            _t: TenantId,
            _h: &str,
        ) -> DomainResult<Option<AuthSession>> {
            unreachable!()
        }
        async fn consume_handle(&self, _id: &str, _h: &str, _n: &str) -> DomainResult<bool> {
            unreachable!()
        }
        async fn set_authenticated_user(
            &self,
            id_hash: &str,
            new_id_hash: &str,
            user_id: Uuid,
            auth_time: DateTime<Utc>,
            sso_sid: Option<&str>,
        ) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|s| s.id_hash == id_hash) {
                row.id_hash = new_id_hash.to_string();
                row.authenticated_user_id = Some(user_id);
                row.auth_time = Some(auth_time);
                row.sso_sid = sso_sid.map(str::to_string);
            }
            Ok(())
        }
        async fn set_password_verified(
            &self,
            id_hash: &str,
            new_id_hash: &str,
            user_id: Uuid,
            verified_at: DateTime<Utc>,
        ) -> DomainResult<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter_mut().find(|s| s.id_hash == id_hash) {
                row.id_hash = new_id_hash.to_string();
                row.authenticated_user_id = Some(user_id);
                row.password_verified_at = Some(verified_at);
            }
            Ok(())
        }
        async fn delete(&self, id_hash: &str) -> DomainResult<()> {
            self.rows.lock().unwrap().retain(|s| s.id_hash != id_hash);
            Ok(())
        }
        async fn delete_expired(&self, _now: DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
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
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, _id: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_sub(&self, _s: Uuid) -> DomainResult<Option<User>> {
            unreachable!()
        }
        async fn find_by_email(&self, _t: TenantId, _e: &str) -> DomainResult<Option<User>> {
            unreachable!()
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

    /// TOTP 設定済み／未設定を切り替えるだけのフェイク。
    struct FakeTotpSecrets {
        confirmed: bool,
    }
    #[async_trait]
    impl TotpSecretRepository for FakeTotpSecrets {
        async fn upsert(&self, _s: &TotpSecret) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_user_id(&self, user_id: Uuid) -> DomainResult<Option<TotpSecret>> {
            Ok(self.confirmed.then(|| TotpSecret {
                user_id,
                secret_encrypted: String::new(),
                confirmed_at: Some(now()),
                created_at: now(),
                updated_at: now(),
            }))
        }
        async fn confirm(&self, _u: Uuid, _c: DateTime<Utc>) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeSsoSessions;
    #[async_trait]
    impl SsoSessionRepository for FakeSsoSessions {
        async fn create(&self, _s: &SsoSession) -> DomainResult<()> {
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
    struct FakePolicies;
    #[async_trait]
    impl AuthenticationPolicyRepository for FakePolicies {
        async fn create(&self, _p: &AuthenticationPolicy) -> DomainResult<()> {
            unreachable!()
        }
        async fn list_for_tenant(&self, _t: TenantId) -> DomainResult<Vec<AuthenticationPolicy>> {
            unreachable!()
        }
        async fn list_enabled_for_tenant(
            &self,
            _t: TenantId,
        ) -> DomainResult<Vec<AuthenticationPolicy>> {
            Ok(Vec::new())
        }
        async fn find_by_id(
            &self,
            _t: TenantId,
            _id: Uuid,
        ) -> DomainResult<Option<AuthenticationPolicy>> {
            unreachable!()
        }
        async fn update(&self, _p: &AuthenticationPolicy) -> DomainResult<bool> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _id: Uuid) -> DomainResult<bool> {
            unreachable!()
        }
    }

    #[derive(Default)]
    struct FakeCodes;
    #[async_trait]
    impl AuthorizationCodeRepository for FakeCodes {
        async fn find_used(
            &self,
            _t: TenantId,
            _h: &str,
        ) -> DomainResult<Option<AuthorizationCode>> {
            unreachable!()
        }
        async fn create(&self, _c: &AuthorizationCode) -> DomainResult<()> {
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

    struct Harness {
        service: LoginService,
        users: Arc<FakeUsers>,
        auth_sessions: Arc<FakeAuthSessions>,
        tenant: TenantContext,
        user_id: Uuid,
    }

    /// `failed_login_count` を `initial_failures` にした利用者で 1 回ログインする土台。
    fn harness(has_totp: bool, initial_failures: i32) -> Harness {
        let tenant_id: TenantId = Uuid::now_v7().into();
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
            password_hash: "hash:correct-password".to_string(),
            must_change_password: false,
            status: UserStatus::Active,
            failed_login_count: initial_failures,
            locked_until: None,
            created_at: now(),
            updated_at: now(),
        });

        let auth_sessions = Arc::new(FakeAuthSessions {
            rows: Mutex::new(vec![AuthSession {
                id_hash: auth_session::id_hash(SESSION_ID),
                acr_values: None,
                login_hint: None,
                ui_locales: None,
                tenant_id,
                client_id: "client-a".to_string(),
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
                authenticated_user_id: None,
                auth_time: None,
                password_verified_at: None,
                sso_sid: None,
                expires_at: now() + Duration::seconds(600),
                created_at: now(),
                updated_at: now(),
            }]),
        });

        let clock: Arc<dyn Clock> = Arc::new(FixedClock);
        let audit = Arc::new(AuditService::new(Arc::new(DiscardingSink), clock.clone()));
        let code_issuance = Arc::new(CodeIssuanceService::new(
            Arc::new(FakeCodes),
            audit.clone(),
            clock.clone(),
            std::time::Duration::from_secs(60),
        ));

        let service = LoginService::new(
            users.clone(),
            auth_sessions.clone(),
            Arc::new(FakeSsoSessions),
            Arc::new(FakeConsents),
            Arc::new(FakeTotpSecrets {
                confirmed: has_totp,
            }),
            Arc::new(FakePolicies),
            code_issuance,
            Arc::new(PlainHasher),
            Arc::new(AllowAll),
            audit,
            clock,
            std::time::Duration::from_secs(3600),
            std::time::Duration::from_secs(28800),
            LockoutPolicy {
                max_failed_attempts: 10,
                lock_duration_secs: 900,
            },
            DefaultPolicyEffect::Allow,
            CSRF_KEY,
        );

        Harness {
            service,
            users,
            auth_sessions,
            tenant: TenantContext::new(tenant_id),
            user_id,
        }
    }

    impl Harness {
        async fn login(&self) -> LoginOutcome {
            let ctx = RequestContext {
                correlation_id: "test-correlation".to_string(),
                ip_address: Some("203.0.113.10".to_string()),
                user_agent: None,
            };
            self.service
                .login(
                    self.tenant,
                    LoginCommand {
                        auth_session_id: Some(SESSION_ID.to_string()),
                        username: "user".to_string(),
                        password: "correct-password".to_string(),
                        csrf_token: csrf_token(SESSION_ID, &CSRF_KEY),
                    },
                    &ctx,
                )
                .await
        }

        fn failed_count(&self) -> i32 {
            self.users.rows.lock().unwrap()[0].failed_login_count
        }

        /// 保存されている auth_session の現在の id_hash。
        fn stored_session_id_hash(&self) -> String {
            self.auth_sessions.rows.lock().unwrap()[0].id_hash.clone()
        }
    }

    /// SEC3 の要: MFA 待ちで止まる経路では失敗カウンタを消さない。消してしまうと、パスワードを
    /// 知っている攻撃者が「TOTP を上限手前まで失敗 → 再ログインでカウンタを 0 に戻す」を
    /// 繰り返してロックを永久に回避できる。
    #[tokio::test]
    async fn mfa_pending_login_keeps_the_failure_counter() {
        let h = harness(true, 4);
        assert!(matches!(h.login().await, LoginOutcome::MfaRequired { .. }));
        assert_eq!(h.failed_count(), 4, "MFA 待ちではリセットしない");
    }

    /// SEC7: パスワード検証を通した時点で `auth_session_id` を再生成する。認証前に発行した
    /// Cookie 値をそのまま使い回すと、事前に値を仕込めた攻撃者が MFA 待ちの認可セッションへ
    /// 相乗りできる（`sso_session_id` はログインのたびに再生成しており、非対称にしない）。
    #[tokio::test]
    async fn mfa_pending_login_rotates_the_auth_session_id() {
        let h = harness(true, 0);
        let LoginOutcome::MfaRequired { auth_session_id } = h.login().await else {
            panic!("expected MfaRequired");
        };
        assert_ne!(auth_session_id, SESSION_ID, "認証前の値を使い回さない");
        assert_eq!(
            h.stored_session_id_hash(),
            auth_session::id_hash(&auth_session_id),
            "DB 側も新しい id のハッシュに置き換わり、旧 id では引けない"
        );
        assert_ne!(
            h.stored_session_id_hash(),
            auth_session_id,
            "DB には平文を置かない（SEC6）"
        );
    }

    /// SEC7: 認証成立まで進む経路でも再生成する。ここは code 発行後に auth_session を削除する
    /// ため id を直接は観測できないが、**行が消えている**ことが再生成後の id で削除できた証拠になる
    /// （記録と削除で id がずれていれば行が残る）。
    #[tokio::test]
    async fn completed_login_deletes_the_session_through_the_rotated_id() {
        let h = harness(false, 0);
        assert!(matches!(h.login().await, LoginOutcome::Success { .. }));
        assert!(
            h.auth_sessions.rows.lock().unwrap().is_empty(),
            "code 発行後に auth_session が残っている = 再生成した id で削除できていない"
        );
    }

    /// 単一要素で認証が成立する経路（TOTP 未設定）は従来どおりリセットする。
    #[tokio::test]
    async fn completed_single_factor_login_resets_the_failure_counter() {
        let h = harness(false, 4);
        let outcome = h.login().await;
        assert!(
            matches!(outcome, LoginOutcome::Success { .. }),
            "TOTP 未設定なら単一要素で成立する"
        );
        assert_eq!(h.failed_count(), 0);
        let _ = h.user_id;
    }
}
