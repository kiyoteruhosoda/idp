//! パスワード変更ユースケース（ADR-0009 §5）。
//!
//! `LoginService` が検出した `must_change_password`（`LoginOutcome::PasswordChangeRequired`）を受けて、
//! ログイン中の `auth_session_id`（パスワード検証済み状態）を用いて新パスワードを設定する。
//! 「ログイン済みユーザーが現行パスワードで認証したうえで新パスワードを設定する」フローに限定する
//! （ADR-0009 §5）ため、現行パスワードの再入力を要求する。
//!
//! 成功後の SSO 発行 → 同意チェック → code 発行は `LoginService`／`MfaLoginService` と共通のフロー
//! （`CodeIssuanceService` を再利用）。
//!
//! 本サービスは SSO セッション・code を**発行する側**のため、発行前に認証ポリシー
//! （ユーザー認証・認証ポリシー仕様書 §9）を再評価する。`must_change_password` は自動生成
//! パスワードでの新規作成だけでなく**管理者による既存ユーザーのパスワード再発行**でも立つため、
//! 「変更後に MFA 判定は不要」とは限らない。`require_mfa` 一致時は TOTP 設定済みなら MFA ステップへ
//! 誘導し、未設定なら単一要素での成立を拒否する（LoginService と同じ規則。仕様 §24.4）。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session;
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, DefaultPolicyEffect, PolicyDecision,
};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::password::{validate_password_strength, PasswordHasher};
use crate::domain::repositories::{
    AuthSessionRepository, AuthenticationPolicyRepository, ClientConsentRepository,
    SsoSessionRepository, TotpSecretRepository, UserRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use chrono::Duration;
use std::sync::Arc;

pub struct ChangePasswordCommand {
    pub auth_session_id: Option<String>,
    pub current_password: String,
    pub new_password: String,
    pub csrf_token: String,
}

pub enum ChangePasswordOutcome {
    /// 変更成功かつ同意済み。code 付き redirect_to へ 302 する。
    Success {
        location: String,
        sso_session_id: String,
    },
    /// 変更成功だが同意が必要。同意画面へ誘導する。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
    },
    /// 変更成功だが認証ポリシーが MFA を必須とし、TOTP 設定済み。TOTP 入力画面へ誘導する
    /// （`auth_session_id` Cookie は維持。SSO はまだ発行しない）。
    MfaRequired {
        auth_session_id: String,
    },
    /// 変更は成功したが認証ポリシーによりログインを拒否（仕様 §7.4 `deny`）。SSO は発行しない。
    PolicyDenied,
    /// 変更は成功したが認証ポリシーが MFA を必須とし、使用可能な認証器（確認済み TOTP）が無い。
    /// ポータルから MFA を設定するよう案内する。SSO は発行しない。
    MfaEnrollmentRequired,
    /// AuthSession が無い・期限切れ・パスワード変更待ち状態でない（`/authorize` からやり直し）。
    SessionExpired,
    /// CSRF トークン不一致。
    CsrfMismatch,
    /// 現行パスワードが不一致。
    InvalidCurrentPassword,
    /// 新パスワードが強度要件を満たさない。
    WeakPassword,
    Internal(String),
}

pub struct ChangePasswordService {
    auth_sessions: Arc<dyn AuthSessionRepository>,
    users: Arc<dyn UserRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    policy_default_effect: DefaultPolicyEffect,
    csrf_secret: [u8; 32],
}

impl ChangePasswordService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth_sessions: Arc<dyn AuthSessionRepository>,
        users: Arc<dyn UserRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        hasher: Arc<dyn PasswordHasher>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: std::time::Duration,
        sso_absolute_ttl: std::time::Duration,
        policy_default_effect: DefaultPolicyEffect,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            auth_sessions,
            users,
            sso_sessions,
            client_consents,
            totp_secrets,
            authentication_policies,
            code_issuance,
            hasher,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
            policy_default_effect,
            csrf_secret,
        }
    }

    pub async fn change(
        &self,
        tenant: TenantContext,
        cmd: ChangePasswordCommand,
        ctx: &RequestContext,
    ) -> ChangePasswordOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. auth_session_id から AuthSession を取得する（フローのテナントに限る）。
        let Some(session_id) = cmd.auth_session_id.as_deref().filter(|s| !s.is_empty()) else {
            return ChangePasswordOutcome::SessionExpired;
        };
        let session = match self
            .auth_sessions
            .find_by_id_hash(tenant_id, &auth_session::id_hash(session_id))
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return ChangePasswordOutcome::SessionExpired,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id_hash).await;
            return ChangePasswordOutcome::SessionExpired;
        }

        // 2. パスワード変更待ち状態か確認する（password_verified_at が設定されている必要がある）。
        let Some(user_id) = session.authenticated_user_id else {
            return ChangePasswordOutcome::SessionExpired;
        };
        if session.password_verified_at.is_none() {
            return ChangePasswordOutcome::SessionExpired;
        }

        // 3. CSRF トークン検証（login_csrf_token と同じ導出を使う）。
        if !idp_contracts::csrf::verify(
            &idp_contracts::csrf::login_csrf_token(session_id, &self.csrf_secret),
            &cmd.csrf_token,
        ) {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    Some(&session.client_id),
                    Some("password_change_csrf_mismatch"),
                    ctx,
                )
                .await;
            return ChangePasswordOutcome::CsrfMismatch;
        }

        let client_id = session.client_id.clone();

        // 4. ユーザーを取得して有効・変更待ちであることを確認する。
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return ChangePasswordOutcome::SessionExpired,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if !user.is_active() || !user.must_change_password {
            // 変更不要な状態でこのエンドポイントに来るのは想定外（多重送信等）。fail-closed。
            tracing::warn!(
                correlation_id = %ctx.correlation_id,
                "password change rejected: user not in must-change state (duplicate submit?)"
            );
            return ChangePasswordOutcome::SessionExpired;
        }

        // 5. 現行パスワードを検証する。
        let verified = match self
            .hasher
            .verify(&cmd.current_password, &user.password_hash)
        {
            Ok(v) => v,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if !verified {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user.id),
                    Some(&client_id),
                    Some("invalid_current_password"),
                    ctx,
                )
                .await;
            return ChangePasswordOutcome::InvalidCurrentPassword;
        }

        // 6. 新パスワードの強度を検証し、ハッシュ化して保存する。
        if validate_password_strength(&cmd.new_password).is_err() {
            return ChangePasswordOutcome::WeakPassword;
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if let Err(e) = self.users.update_password(user.id, &new_hash).await {
            return ChangePasswordOutcome::Internal(e.to_string());
        }
        self.audit
            .record(
                AuditEventType::PasswordChanged,
                AuditResult::Success,
                Some(tenant_id),
                Some(user.id),
                Some(&client_id),
                None,
                ctx,
            )
            .await;

        // 6.5. 認証ポリシー評価（仕様 §9）。本サービスは SSO・code を発行する側のため、発行前に
        //      LoginService と同じ規則を適用する（`must_change_password` は管理者による既存ユーザーの
        //      パスワード再発行でも立つため、TOTP 設定済みユーザーもこの経路を通り得る）。
        //      パスワード変更自体は本人のセルフサービスとして完了させ、セッション発行のみをゲートする。
        // 認可要求の `acr_values`（AP3 の `requested_acr` 条件が参照する）。
        let requested_acr = session.requested_acr();
        let decision = match self
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
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        match &decision {
            PolicyDecision::Deny { policy_code } => {
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
                return ChangePasswordOutcome::PolicyDenied;
            }
            PolicyDecision::RequireMfa { policy_code } => {
                let has_totp =
                    match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
                        Ok(v) => v,
                        Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
                    };
                if has_totp {
                    // AuthSession は `authenticated_user_id` と `password_verified_at` が設定済み
                    //（MFA pending 相当）のため、そのまま TOTP 検証ステップへ引き継げる。
                    return ChangePasswordOutcome::MfaRequired {
                        auth_session_id: session_id.to_string(),
                    };
                }
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
                return ChangePasswordOutcome::MfaEnrollmentRequired;
            }
            // `require_specific_method`（AP3）。この経路が完了した時点で使った方式はパスワードだけ。
            PolicyDecision::RequireMethods {
                policy_code,
                requirement,
            } => {
                if !requirement.satisfied_by(&[AuthenticationMethod::Password], false) {
                    self.audit
                        .record(
                            AuditEventType::LoginPolicyDenied,
                            AuditResult::Failure,
                            Some(tenant_id),
                            Some(user.id),
                            Some(&client_id),
                            Some(&format!(
                                "policy={policy_code} reason=method_required required={}",
                                requirement.describe()
                            )),
                            ctx,
                        )
                        .await;
                    return ChangePasswordOutcome::PolicyDenied;
                }
            }
            PolicyDecision::Allow { .. } => {}
        }

        // 7. SSO セッションを組み立てる（`sid` を auth_session へ預けるため、永続化より先に作る）。
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

        // 8. auth_time と `sid` を設定する（パスワード変更完了時刻を認証時刻とする）。
        //    id も再生成する（SEC7）。
        let rotated_id = crypto::random_hex(32);
        let rotated_id_hash = auth_session::id_hash(&rotated_id);
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(
                &session.id_hash,
                &rotated_id_hash,
                user.id,
                now,
                Some(&sso.sid()),
            )
            .await
        {
            return ChangePasswordOutcome::Internal(e.to_string());
        }

        if let Err(e) = self.sso_sessions.create(&sso).await {
            return ChangePasswordOutcome::Internal(e.to_string());
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

        // 9. 同意チェック（`openid` は暗黙同意）。
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
                Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
            }
        };

        if !consented {
            return ChangePasswordOutcome::ConsentRequired {
                auth_session_id: rotated_id,
                sso_session_id,
            };
        }

        // 10. code 発行。
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
            Ok(c) => c,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };

        // 11. AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(&rotated_id_hash).await {
            tracing::warn!(error = %e, "failed to delete auth session after password change");
        }

        ChangePasswordOutcome::Success {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
            sso_session_id,
        }
    }
}
