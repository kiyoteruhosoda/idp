//! Passkey（WebAuthn discoverable credentials）による **OIDC 認可フローのログイン**ユースケース。
//!
//! パスワード入力なしで Passkey だけでログインする。認証フロー:
//! 1. `begin()` — discoverable チャレンジを生成して options JSON を返す。
//! 2. `complete()` — ブラウザからのクレデンシャルを検証し、SSO セッション発行 → code 発行。
//!
//! セレモニーそのもの（チャレンジの発行・消費、アサーション検証、認証器登録簿の判定、テナント境界）は
//! [`crate::application::passkey_assertion`] が持つ。本モジュールはその上に **`auth_session` の継続と
//! authorization code の発行**を載せる層である。認可フロー外の直接ログインは
//! [`crate::application::admin_login`]・[`crate::application::portal_login`] が同じセレモニーの上に
//! それぞれの続きを載せる。
//!
//! 認証ポリシー（ユーザー認証・認証ポリシー仕様書 §7〜§9）: `deny` ポリシーはこの経路でも
//! 拒否する（パスワード経路だけ塞いでも迂回できてしまうため）。`require_mfa` は WebAuthn が
//! 所有＋生体/知識（User Verification）の複数要素・フィッシング耐性認証であるため満たすものと扱う。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_dispatch;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::application::passkey_assertion::{
    PasskeyAssertionError, PasskeyAssertionService, PasskeyFlow,
};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session;
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, DefaultPolicyEffect, PolicyDecision,
};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::repositories::{
    AuthSessionRepository, AuthenticationPolicyRepository, ClientConsentRepository,
    SsoSessionRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant_context::TenantContext;
use crate::domain::values::AuthenticationMethod;
use chrono::Duration;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use uuid::Uuid;

#[derive(Debug)]
pub enum PasskeyAuthOutcome {
    /// 認証成功かつ同意済み。code 付き redirect_to へ 302 する。
    Success {
        location: String,
        /// `form_post` のとき POST する hidden フィールド（G12）。`None` は `query`。
        form_post: Option<Vec<(String, String)>>,
        sso_session_id: String,
    },
    /// 認証成功だが同意が必要。同意画面へ誘導する。
    ConsentRequired {
        auth_session_id: String,
        sso_session_id: String,
    },
    /// チャレンジが見つからない・期限切れ。
    ChallengeNotFound,
    /// AuthSession が無い・期限切れ（OIDC フローをやり直し）。
    SessionExpired,
    /// クレデンシャルが無効。
    InvalidCredential,
    /// 認証ポリシーにより拒否（仕様 §7.4 `deny`）。
    PolicyDenied,
    /// 内部エラー。
    Internal(String),
}

pub struct PasskeyAuthenticationService {
    /// WebAuthn セレモニー（チャレンジ発行・アサーション検証）。3 つのログイン経路で共有する。
    assertion: Arc<PasskeyAssertionService>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    policy_default_effect: DefaultPolicyEffect,
}

impl PasskeyAuthenticationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        assertion: Arc<PasskeyAssertionService>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: StdDuration,
        sso_absolute_ttl: StdDuration,
        policy_default_effect: DefaultPolicyEffect,
    ) -> Self {
        Self {
            assertion,
            auth_sessions,
            sso_sessions,
            client_consents,
            authentication_policies,
            code_issuance,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
            policy_default_effect,
        }
    }

    /// 認証開始。`auth_session_id` は OIDC フローを継続するために必要。
    ///
    /// 返り値: `(challenge_id, options_json)`
    pub async fn begin(
        &self,
        auth_session_id: Option<&str>,
    ) -> Result<(Uuid, serde_json::Value), String> {
        self.assertion.begin(auth_session_id).await
    }

    /// 認証完了。
    pub async fn complete(
        &self,
        tenant: TenantContext,
        challenge_id: Uuid,
        credential_value: serde_json::Value,
        ctx: &RequestContext,
    ) -> PasskeyAuthOutcome {
        let now = self.clock.now();
        let tenant_id = tenant.tenant_id();

        // 1. WebAuthn セレモニーの検証（チャレンジ消費・登録簿の一時停止判定・署名カウンタ更新・
        //    テナント境界）は `PasskeyAssertionService` が持つ。ここから下は OIDC フロー固有の続き。
        let verified = match self
            .assertion
            .verify(
                tenant_id,
                challenge_id,
                credential_value,
                PasskeyFlow::Oidc,
                ctx,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return e.into(),
        };
        let user_id = verified.user_id;

        // 2. AuthSession を取得して OIDC フローを継続する。
        let Some(auth_session_id_hash) = verified.auth_session_id_hash.as_deref() else {
            // `PasskeyFlow::Oidc` の検証を通った＝結合は必ずある。
            return PasskeyAuthOutcome::Internal("no auth_session_id in challenge".to_string());
        };
        let session = match self
            .auth_sessions
            .find_by_id_hash(tenant_id, auth_session_id_hash)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return PasskeyAuthOutcome::SessionExpired,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id_hash).await;
            return PasskeyAuthOutcome::SessionExpired;
        }

        let client_id = session.client_id.clone();

        // 3. 認証ポリシー評価（仕様 §9）。`deny` はパスキー経路でも拒否する。
        //    `require_mfa` は WebAuthn（所有要素 + User Verification）が満たすため通過する。
        let decision = match self
            .authentication_policies
            .list_enabled_for_tenant(tenant_id)
            .await
        {
            Ok(policies) => evaluate_policies(
                &policies,
                &AuthenticationContext {
                    client_id: Some(&client_id),
                    user_id,
                    ip_address: ctx.ip_address.as_deref(),
                    now,
                    requested_acr: &session.requested_acr(),
                },
                self.policy_default_effect,
            ),
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if let PolicyDecision::Deny { policy_code } = &decision {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    Some(&client_id),
                    Some(&format!("policy={policy_code}")),
                    ctx,
                )
                .await;
            return PasskeyAuthOutcome::PolicyDenied;
        }
        // `require_specific_method`（AP3）。パスキー認証は WebAuthn かつ User Verification 済み
        // （`webauthn-rs` の検証を通っている）なので §12.2 の「WebAuthn 必須」「UV 必須」を満たす。
        // 満たさないのは「TOTP でなければ駄目」のような別方式の指定に当たった場合。
        if let Some(unmet) =
            decision.unmet_method_requirement(&[AuthenticationMethod::WebAuthn], true)
        {
            self.audit
                .record(
                    AuditEventType::LoginPolicyDenied,
                    AuditResult::Failure,
                    Some(tenant_id),
                    Some(user_id),
                    Some(&client_id),
                    Some(&format!(
                        "policy={} reason=method_required required={}",
                        unmet.policy_code,
                        unmet.requirement.describe()
                    )),
                    ctx,
                )
                .await;
            return PasskeyAuthOutcome::PolicyDenied;
        }

        // 4. SSO セッションを組み立てる（`sid` を auth_session へ預けるため、永続化より先に作る）。
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession::establish(
            crypto::sha256_hex(&sso_session_id),
            user_id,
            now,
            self.sso_idle_ttl,
            self.sso_absolute_ttl,
            vec![AuthenticationMethod::WebAuthn],
            ctx.user_agent.clone(),
            ctx.ip_address.clone(),
        );

        // 5. auth_time と `sid` を設定する（id も再生成する。SEC7）。
        let rotated_id = crypto::random_hex(32);
        let rotated_id_hash = auth_session::id_hash(&rotated_id);
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(
                &session.id_hash,
                &rotated_id_hash,
                user_id,
                now,
                Some(&sso.sid()),
            )
            .await
        {
            return PasskeyAuthOutcome::Internal(e.to_string());
        }

        if let Err(e) = self.sso_sessions.create(&sso).await {
            return PasskeyAuthOutcome::Internal(e.to_string());
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

        // 6. 同意チェック（`openid` は暗黙同意）。
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
                Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
            }
        };

        if !consented {
            return PasskeyAuthOutcome::ConsentRequired {
                auth_session_id: rotated_id,
                sso_session_id,
            };
        }

        // 7. code 発行。
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
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };

        // 8. AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(&rotated_id_hash).await {
            tracing::warn!(error = %e, "failed to delete auth session after passkey auth");
        }

        let dispatch = code_dispatch(&session, &code);
        PasskeyAuthOutcome::Success {
            location: dispatch.location,
            form_post: dispatch.form_post,
            sso_session_id,
        }
    }
}

impl From<PasskeyAssertionError> for PasskeyAuthOutcome {
    fn from(e: PasskeyAssertionError) -> Self {
        match e {
            // 用途違いのチャレンジ（直接ログイン用を認可フローで完了しようとした）は、利用者から見れば
            // 「やり直してください」でしかないため、期限切れと同じ扱いにする。
            PasskeyAssertionError::ChallengeNotFound | PasskeyAssertionError::WrongFlow => {
                PasskeyAuthOutcome::ChallengeNotFound
            }
            PasskeyAssertionError::InvalidCredential => PasskeyAuthOutcome::InvalidCredential,
            PasskeyAssertionError::Internal(msg) => PasskeyAuthOutcome::Internal(msg),
        }
    }
}
