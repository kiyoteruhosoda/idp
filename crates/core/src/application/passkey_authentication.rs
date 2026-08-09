//! Passkey（WebAuthn discoverable credentials）認証ユースケース。
//!
//! パスワード入力なしで Passkey だけでログインする。認証フロー:
//! 1. `begin()` — discoverable チャレンジを生成して options JSON を返す。
//! 2. `complete()` — ブラウザからのクレデンシャルを検証し、SSO セッション発行 → code 発行。
//!
//! 認証ポリシー（ユーザー認証・認証ポリシー仕様書 §7〜§9）: `deny` ポリシーはこの経路でも
//! 拒否する（パスワード経路だけ塞いでも迂回できてしまうため）。`require_mfa` は WebAuthn が
//! 所有＋生体/知識（User Verification）の複数要素・フィッシング耐性認証であるため満たすものと扱う。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authenticator_management::is_blocked_in_registry;
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session;
use crate::domain::authentication_policy::{
    evaluate_policies, AuthenticationContext, DefaultPolicyEffect, PolicyDecision,
};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use crate::domain::repositories::{
    AuthSessionRepository, AuthenticationPolicyRepository, ClientConsentRepository,
    PasskeyChallengeRepository, SsoSessionRepository, TenantMembershipRepository,
    UserAuthenticatorRepository, UserRepository, WebAuthnCredentialRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
use crate::domain::user_authenticator::AuthenticatorType;
use crate::domain::values::AuthenticationMethod;
use crate::domain::webauthn_port::WebAuthnPort;
use chrono::Duration;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PublicKeyCredential,
};

/// チャレンジの有効期限（5 分）。
const CHALLENGE_TTL: StdDuration = StdDuration::from_secs(300);

#[derive(Debug)]
pub enum PasskeyAuthOutcome {
    /// 認証成功かつ同意済み。code 付き redirect_to へ 302 する。
    Success {
        location: String,
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
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    /// 認証器の登録簿（AP9）。一時停止・失効はここにしか無いため、認証時に必ず見る。
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    webauthn: Arc<dyn WebAuthnPort>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
    policy_default_effect: DefaultPolicyEffect,
}

impl PasskeyAuthenticationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        authentication_policies: Arc<dyn AuthenticationPolicyRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        webauthn: Arc<dyn WebAuthnPort>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: StdDuration,
        sso_absolute_ttl: StdDuration,
        policy_default_effect: DefaultPolicyEffect,
    ) -> Self {
        Self {
            webauthn_credentials,
            authenticators,
            passkey_challenges,
            auth_sessions,
            users,
            memberships,
            sso_sessions,
            client_consents,
            authentication_policies,
            code_issuance,
            webauthn,
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
        let now = self.clock.now();

        let (crc, state) = self
            .webauthn
            .begin_authentication()
            .map_err(|e| format!("begin_authentication failed: {e}"))?;

        let state_json =
            serde_json::to_string(&state).map_err(|e| format!("serialize state: {e}"))?;

        let challenge_id = Uuid::new_v4();
        let challenge = PasskeyChallenge {
            id: challenge_id,
            user_id: None,
            challenge_type: PasskeyChallengeType::Authenticate,
            state_json,
            auth_session_id_hash: auth_session_id.map(auth_session::id_hash),
            expires_at: now + Duration::from_std(CHALLENGE_TTL).unwrap(),
            created_at: now,
        };
        self.passkey_challenges
            .create(&challenge)
            .await
            .map_err(|e| e.to_string())?;

        let options_json =
            serde_json::to_value(&crc).map_err(|e| format!("serialize options: {e}"))?;

        Ok((challenge_id, options_json))
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

        // 1. チャレンジを取得して消費する。
        let challenge = match self.passkey_challenges.find_by_id(challenge_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return PasskeyAuthOutcome::ChallengeNotFound,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if challenge.expires_at <= now {
            let _ = self.passkey_challenges.delete(challenge_id).await;
            return PasskeyAuthOutcome::ChallengeNotFound;
        }
        // チャレンジを先に削除（リプレイ防止）。
        if let Err(e) = self.passkey_challenges.delete(challenge_id).await {
            return PasskeyAuthOutcome::Internal(e.to_string());
        }

        // 2. DiscoverableAuthentication 状態を復元する。
        let auth_state: DiscoverableAuthentication =
            match serde_json::from_str(&challenge.state_json) {
                Ok(s) => s,
                Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
            };

        // 3. ブラウザからのクレデンシャルをデシリアライズする。
        let public_key_credential: PublicKeyCredential =
            match serde_json::from_value(credential_value) {
                Ok(c) => c,
                Err(_) => return PasskeyAuthOutcome::InvalidCredential,
            };

        // 4. credential_id から登録済みクレデンシャルを引く。
        let stored_cred = match self
            .webauthn_credentials
            .find_by_credential_id(public_key_credential.id.as_str())
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => return PasskeyAuthOutcome::InvalidCredential,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };

        let passkey: Passkey = match serde_json::from_str(&stored_cred.passkey_json) {
            Ok(p) => p,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };

        let user_id = stored_cred.user_id;
        let cred_row_id = stored_cred.id;

        // 登録簿でこの 1 本が止められていないかを見る（AP9）。公開鍵は
        // `user_webauthn_credentials` に残ったままなので、ここで見ないと一時停止・失効が
        // 効かない。パスキーは 1 利用者に複数あるため、止めた 1 本だけを塞ぐ。
        match is_blocked_in_registry(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::WebAuthn,
            Some(cred_row_id),
        )
        .await
        {
            Ok(true) => return PasskeyAuthOutcome::InvalidCredential,
            Ok(false) => {}
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        }

        // 5. WebAuthn 検証。
        let dk = DiscoverableKey::from(&passkey);
        let auth_result =
            match self
                .webauthn
                .finish_authentication(&public_key_credential, auth_state, &[dk])
            {
                Ok(r) => r,
                Err(_) => {
                    self.audit
                        .record(
                            AuditEventType::LoginFailed,
                            AuditResult::Failure,
                            Some(tenant_id),
                            Some(user_id),
                            None,
                            Some("invalid_passkey"),
                            ctx,
                        )
                        .await;
                    return PasskeyAuthOutcome::InvalidCredential;
                }
            };

        // 6. sign_count を更新して passkey_json を保存する（更新があれば DB に反映する）。
        let mut updated_passkey = passkey;
        if updated_passkey
            .update_credential(&auth_result)
            .unwrap_or(false)
        {
            let new_json = match serde_json::to_string(&updated_passkey) {
                Ok(j) => j,
                Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
            };
            if let Err(e) = self
                .webauthn_credentials
                .update_passkey(cred_row_id, &new_json, now)
                .await
            {
                return PasskeyAuthOutcome::Internal(e.to_string());
            }
        }

        // 7. ユーザーの有効性と、フローのテナントへの ACTIVE メンバーシップ（HOME または GUEST）を
        //    確認する。WebAuthn クレデンシャルはテナント列を持たずホスト単位で解決されるため、テナント
        //    境界はこのアプリ層の紐付けで強制する（ADR-0009 §8。`authorize` の SSO 復元と同じ判定）。
        //    非メンバー・無効・不明はいずれも `InvalidCredential` に倒す（列挙防止のため理由を分けない）。
        if let Err(outcome) = ensure_active_member(
            self.users.as_ref(),
            self.memberships.as_ref(),
            tenant_id,
            user_id,
        )
        .await
        {
            return outcome;
        }

        // 8. AuthSession を取得して OIDC フローを継続する。
        let Some(auth_session_id_hash) = challenge.auth_session_id_hash.as_deref() else {
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

        // 8.5. 認証ポリシー評価（仕様 §9）。`deny` はパスキー経路でも拒否する。
        //      `require_mfa` は WebAuthn（所有要素 + User Verification）が満たすため通過する。
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

        // 9. SSO セッションを組み立てる（`sid` を auth_session へ預けるため、永続化より先に作る）。
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

        // 10. auth_time と `sid` を設定する（id も再生成する。SEC7）。
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

        // 12. code 発行。
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

        // 13. AuthSession を削除する。
        if let Err(e) = self.auth_sessions.delete(&rotated_id_hash).await {
            tracing::warn!(error = %e, "failed to delete auth session after passkey auth");
        }

        PasskeyAuthOutcome::Success {
            location: code_redirect(&session.redirect_uri, &code, &session.state),
            sso_session_id,
        }
    }
}

/// クレデンシャルの所有者がフローのテナントの ACTIVE メンバー（HOME または GUEST）で、かつ有効な
/// アカウントであることを検証する。所属外・無効・不明・障害はいずれも `InvalidCredential`／`Internal`
/// に倒す（テナント境界の強制。ADR-0009 §8）。サービス本体から切り出してユニットテスト可能にする。
async fn ensure_active_member(
    users: &dyn UserRepository,
    memberships: &dyn TenantMembershipRepository,
    tenant_id: TenantId,
    user_id: Uuid,
) -> Result<(), PasskeyAuthOutcome> {
    match users.find_by_id(user_id).await {
        Ok(Some(u)) if u.is_active() => {}
        Ok(_) => return Err(PasskeyAuthOutcome::InvalidCredential),
        Err(e) => return Err(PasskeyAuthOutcome::Internal(e.to_string())),
    }
    match memberships.is_active_member(tenant_id, user_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(PasskeyAuthOutcome::InvalidCredential),
        Err(e) => Err(PasskeyAuthOutcome::Internal(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::{DomainError, Result as DomainResult};
    use crate::domain::tenant_membership::TenantMembership;
    use crate::domain::user::User;
    use crate::domain::values::UserStatus;
    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};

    fn active_user(id: Uuid, tenant_id: TenantId) -> User {
        let t = Utc.with_ymd_and_hms(2026, 7, 17, 0, 0, 0).unwrap();
        User {
            id,
            tenant_id,
            sub: Uuid::new_v4(),
            email: "u@example.com".to_string(),
            email_verified: true,
            preferred_username: None,
            name: None,
            language: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            status: UserStatus::Active,
            failed_login_count: 0,
            locked_until: None,
            created_at: t,
            updated_at: t,
        }
    }

    /// 単一ユーザーを返すフェイク（`None` で不存在を表す）。
    struct FakeUsers(Option<User>);
    #[async_trait]
    impl UserRepository for FakeUsers {
        async fn create(&self, _u: &User) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<User>> {
            Ok(self.0.clone().filter(|u| u.id == id))
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
            _id: Uuid,
            _c: i32,
            _l: Option<chrono::DateTime<Utc>>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_password(&self, _id: Uuid, _h: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn reset_password_forced(&self, _id: Uuid, _password_hash: &str) -> DomainResult<()> {
            unreachable!()
        }
        async fn update_status(&self, _id: Uuid, _status: UserStatus) -> DomainResult<()> {
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

    /// 指定テナントに対する `is_active_member` の戻り値を固定するフェイク。
    struct FakeMemberships {
        tenant_id: TenantId,
        is_member: DomainResult<bool>,
    }
    #[async_trait]
    impl TenantMembershipRepository for FakeMemberships {
        async fn update_status(
            &self,
            _t: TenantId,
            _u: Uuid,
            _s: crate::domain::values::MembershipStatus,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn create(&self, _m: &TenantMembership) -> DomainResult<()> {
            unreachable!()
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn is_active_member(&self, t: TenantId, _u: Uuid) -> DomainResult<bool> {
            assert_eq!(
                t, self.tenant_id,
                "membership check must use the flow tenant"
            );
            match &self.is_member {
                Ok(v) => Ok(*v),
                Err(e) => Err(DomainError::Repository(e.to_string())),
            }
        }
        async fn find_by_invitation_token_hash(
            &self,
            _h: &str,
        ) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn activate(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _t: TenantId, _u: Uuid) -> DomainResult<()> {
            unreachable!()
        }
    }

    fn ids() -> (Uuid, TenantId) {
        (Uuid::new_v4(), Uuid::now_v7().into())
    }

    #[tokio::test]
    async fn active_member_is_authorized() {
        let (uid, tid) = ids();
        let users = FakeUsers(Some(active_user(uid, tid)));
        let memberships = FakeMemberships {
            tenant_id: tid,
            is_member: Ok(true),
        };
        assert!(ensure_active_member(&users, &memberships, tid, uid)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn non_member_is_rejected_as_invalid_credential() {
        // 別テナントのフローでパスキーを提示しても、当該テナントの ACTIVE メンバーでなければ拒否する
        // （テナント分離。ADR-0009 §8）。
        let (uid, home) = ids();
        let other_tenant: TenantId = Uuid::now_v7().into();
        let users = FakeUsers(Some(active_user(uid, home)));
        let memberships = FakeMemberships {
            tenant_id: other_tenant,
            is_member: Ok(false),
        };
        let outcome = ensure_active_member(&users, &memberships, other_tenant, uid)
            .await
            .expect_err("non-member must be rejected");
        assert!(matches!(outcome, PasskeyAuthOutcome::InvalidCredential));
    }

    #[tokio::test]
    async fn inactive_user_is_rejected_without_touching_membership() {
        let (uid, tid) = ids();
        let mut user = active_user(uid, tid);
        user.status = UserStatus::Disabled;
        let users = FakeUsers(Some(user));
        // メンバーシップ判定に到達したら panic する（無効ユーザーは先に弾く）。
        let memberships = FakeMemberships {
            tenant_id: tid,
            is_member: Err(DomainError::Repository("must not be called".to_string())),
        };
        let outcome = ensure_active_member(&users, &memberships, tid, uid)
            .await
            .expect_err("inactive user must be rejected");
        assert!(matches!(outcome, PasskeyAuthOutcome::InvalidCredential));
    }

    #[tokio::test]
    async fn unknown_user_is_rejected() {
        let (uid, tid) = ids();
        let users = FakeUsers(None);
        let memberships = FakeMemberships {
            tenant_id: tid,
            is_member: Ok(true),
        };
        let outcome = ensure_active_member(&users, &memberships, tid, uid)
            .await
            .expect_err("unknown user must be rejected");
        assert!(matches!(outcome, PasskeyAuthOutcome::InvalidCredential));
    }

    #[tokio::test]
    async fn membership_repository_error_maps_to_internal() {
        let (uid, tid) = ids();
        let users = FakeUsers(Some(active_user(uid, tid)));
        let memberships = FakeMemberships {
            tenant_id: tid,
            is_member: Err(DomainError::Repository("db down".to_string())),
        };
        let outcome = ensure_active_member(&users, &memberships, tid, uid)
            .await
            .expect_err("repository failure must not authorize");
        assert!(matches!(outcome, PasskeyAuthOutcome::Internal(_)));
    }
}
