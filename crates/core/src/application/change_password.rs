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
use crate::application::authentication_policy_gate::{
    AuthenticationPolicyGate, PolicyAudience, PolicyQuery,
};
use crate::application::mfa_login::user_has_confirmed_totp;
use crate::application::password_policy::PasswordPolicyService;
use crate::application::sign_in_completion::{AuthorizationContinuation, SignIn, SignInCompletion};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session::AuthSessionIdHash;
use crate::domain::authentication_policy::PolicyDecision;
use crate::domain::clock::Clock;
use crate::domain::password::PasswordHasher;
use crate::domain::password_policy::{password_change_required, PasswordRejection};
use crate::domain::repositories::{AuthSessionRepository, TotpSecretRepository, UserRepository};
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
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
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        form_post: Option<Vec<(String, String)>>,
        sso_session_id: String,
        /// SSO Cookie の `Max-Age`（確立したセッションの絶対期限までの秒数。ADR-0058）。
        sso_absolute_ttl_secs: u64,
    },
    /// 変更成功だが同意が必要。同意画面へ誘導する。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
        /// SSO Cookie の `Max-Age`（確立したセッションの絶対期限までの秒数。ADR-0058）。
        sso_absolute_ttl_secs: u64,
    },
    /// 変更成功だが認証ポリシーが MFA を必須とし、TOTP 設定済み。TOTP 入力画面へ誘導する
    /// （`auth_session_id` Cookie は維持。SSO はまだ発行しない）。
    MfaRequired {
        auth_session_id: String,
    },
    /// 変更は成功したが認証ポリシーによりログインを拒否（仕様 §7.4 `deny`）。SSO は発行しない。
    /// 認証は通ったが、このアプリの利用が許可されていない（ADR-0054）。⚠ **RP へ戻さない。**
    /// SSO セッションは発行する（assay には入れている）ので、他のアプリへはそのまま進める。
    ApplicationNotPermitted {
        /// 画面に出すアプリ名。どのアプリで断られたかが分からないと、次に誰へ頼めばよいかを
        /// 利用者が決められない。
        application_name: String,
        sso_session_id: String,
        /// SSO Cookie の `Max-Age`（確立したセッションの絶対期限までの秒数。ADR-0058）。
        sso_absolute_ttl_secs: u64,
    },
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
    /// 新パスワードがポリシーを満たさない（長さ・漏えい済み・再利用。AP7）。
    WeakPassword(PasswordRejection),
    Internal(String),
}

pub struct ChangePasswordService {
    auth_sessions: Arc<dyn AuthSessionRepository>,
    users: Arc<dyn UserRepository>,
    totp_secrets: Arc<dyn TotpSecretRepository>,
    /// 認証ポリシーの評価（材料の引き当てと評価。`authentication_policy_gate`）。
    policy_gate: Arc<AuthenticationPolicyGate>,
    /// 認証が成立した後の共通の後段（SSO の確立・認可フローの続き）。
    sign_in: Arc<SignInCompletion>,
    hasher: Arc<dyn PasswordHasher>,
    password_policy: Arc<PasswordPolicyService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    csrf_secret: [u8; 32],
}

impl ChangePasswordService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth_sessions: Arc<dyn AuthSessionRepository>,
        users: Arc<dyn UserRepository>,
        totp_secrets: Arc<dyn TotpSecretRepository>,
        policy_gate: Arc<AuthenticationPolicyGate>,
        sign_in: Arc<SignInCompletion>,
        hasher: Arc<dyn PasswordHasher>,
        password_policy: Arc<PasswordPolicyService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        csrf_secret: [u8; 32],
    ) -> Self {
        Self {
            auth_sessions,
            users,
            totp_secrets,
            policy_gate,
            sign_in,
            hasher,
            password_policy,
            audit,
            clock,
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
        let mut session = match self
            .auth_sessions
            .find(tenant_id, &AuthSessionIdHash::of_plain(session_id))
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return ChangePasswordOutcome::SessionExpired,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(session.id_hash()).await;
            return ChangePasswordOutcome::SessionExpired;
        }

        // 2. パスワード変更待ち状態か確認する（password_verified_at が設定されている必要がある）。
        let Some(user_id) = session.password_verified_user() else {
            return ChangePasswordOutcome::SessionExpired;
        };

        // 3. CSRF トークン検証（login_csrf_token と同じ導出を使う）。
        if !assay_contracts::csrf::verify(
            &assay_contracts::csrf::login_csrf_token(session_id, &self.csrf_secret),
            &cmd.csrf_token,
        ) {
            self.audit
                .record(
                    AuditEventType::LoginFailed,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    Some(session.client_id()),
                    Some("password_change_csrf_mismatch"),
                    ctx,
                )
                .await;
            return ChangePasswordOutcome::CsrfMismatch;
        }

        let client_id = session.client_id().to_string();

        // 4. ユーザーを取得して有効・変更待ちであることを確認する。
        let user = match self.users.find_by_id(user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => return ChangePasswordOutcome::SessionExpired,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        // 変更を要求されている状態か（強制フラグ、または有効期限切れ。AP7）。有効期限は利用者の
        // 所属元テナントのポリシーで測る（ADR-0058）。
        let password_policy = match self.password_policy.policy(user.tenant_id).await {
            Ok(policy) => policy,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        if !user.is_active() || !password_change_required(&user, &password_policy, now) {
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

        // 6. 新パスワードがポリシーを満たすか検証し（長さ・漏えい済み・再利用。AP7）、
        //    ハッシュ化して保存する。
        match self
            .password_policy
            .validate(
                user.tenant_id,
                Some(user.id),
                Some(&user.password_hash),
                &cmd.new_password,
            )
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(rejection)) => return ChangePasswordOutcome::WeakPassword(rejection),
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        }
        let new_hash = match self.hasher.hash(&cmd.new_password) {
            Ok(h) => h,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        // 現行ハッシュを条件にした置き換え（AP7。`account_password` と同じ理由）。
        match self
            .users
            .update_password(user.id, &user.password_hash, &new_hash)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    correlation_id = %ctx.correlation_id,
                    "forced password change lost a concurrent update; asking to retry"
                );
                return ChangePasswordOutcome::InvalidCurrentPassword;
            }
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        }
        self.password_policy
            .record_change(user.tenant_id, user.id, &user.password_hash)
            .await;
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
        let requested_acr = session.request().requested_acr();
        let decision = match self
            .policy_gate
            .decide(PolicyQuery {
                tenant_id,
                audience: PolicyAudience::OidcClient(&client_id),
                user_id: user.id,
                ip_address: ctx.ip_address.as_deref(),
                requested_acr: &requested_acr,
                now,
            })
            .await
        {
            Ok(decision) => decision,
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
            PolicyDecision::RequireMethods { .. } => {
                let used = [AuthenticationMethod::Password];
                if let Some(unmet) = decision.unmet_method_requirement(&used, false) {
                    // 第二要素を足せば満たせる利用者は MFA ステップへ送る（`require_mfa` と同じ扱い）。
                    // AuthSession は `authenticated_user_id` と `password_verified_at` が設定済み
                    // （MFA pending 相当）なので、そのまま `MfaLoginService` へ引き継げる。そちらが
                    // 最終的な方式集合で判定し直すため、満たせない第二要素で通ることはない。
                    let has_totp =
                        match user_has_confirmed_totp(self.totp_secrets.as_ref(), user.id).await {
                            Ok(v) => v,
                            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
                        };
                    if has_totp
                        && decision.satisfied_by_adding(&used, AuthenticationMethod::Totp, false)
                    {
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
                            Some(&format!(
                                "policy={} reason=method_required required={}",
                                unmet.policy_code,
                                unmet.requirement.describe()
                            )),
                            ctx,
                        )
                        .await;
                    return ChangePasswordOutcome::PolicyDenied;
                }
            }
            PolicyDecision::Allow { .. } => {}
        }

        // 7. SSO セッションを確立し、認可フローを続ける（同意の確認 → code 発行）。
        let sso = match self
            .sign_in
            .establish_sso(
                SignIn {
                    tenant_id,
                    user_id: user.id,
                    home_tenant_id: user.tenant_id,
                    methods: vec![AuthenticationMethod::Password],
                    client_id: Some(&client_id),
                    success_event: AuditEventType::LoginSucceeded,
                    success_detail: None,
                },
                ctx,
                now,
            )
            .await
        {
            Ok(sso) => sso,
            Err(e) => return ChangePasswordOutcome::Internal(e.to_string()),
        };
        let sso_session_id = sso.session_id().to_string();
        let sso_absolute_ttl_secs = sso.absolute_ttl_secs();
        match self
            .sign_in
            .continue_authorization(tenant, &mut session, &sso, now, ctx)
            .await
        {
            Ok(AuthorizationContinuation::ConsentRequired { auth_session_id }) => {
                ChangePasswordOutcome::ConsentRequired {
                    auth_session_id,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::ApplicationNotPermitted { application_name }) => {
                ChangePasswordOutcome::ApplicationNotPermitted {
                    application_name,
                    sso_session_id,
                    sso_absolute_ttl_secs,
                }
            }
            Ok(AuthorizationContinuation::Authorized(dispatch)) => ChangePasswordOutcome::Success {
                location: dispatch.location,
                form_post: dispatch.form_post,
                sso_session_id,
                sso_absolute_ttl_secs,
            },
            Err(e) => ChangePasswordOutcome::Internal(e.to_string()),
        }
    }
}
