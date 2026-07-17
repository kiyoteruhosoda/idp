//! Passkey（WebAuthn discoverable credentials）認証ユースケース。
//!
//! パスワード入力なしで Passkey だけでログインする。認証フロー:
//! 1. `begin()` — discoverable チャレンジを生成して options JSON を返す。
//! 2. `complete()` — ブラウザからのクレデンシャルを検証し、SSO セッション発行 → code 発行。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authorize::code_redirect;
use crate::application::code_issuance::{CodeIssuanceService, IssueCodeCommand};
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::clock::Clock;
use crate::domain::crypto;
use crate::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use crate::domain::repositories::{
    AuthSessionRepository, ClientConsentRepository, PasskeyChallengeRepository,
    SsoSessionRepository, TenantMembershipRepository, UserRepository, WebAuthnCredentialRepository,
};
use crate::domain::sso_session::SsoSession;
use crate::domain::tenant::TenantId;
use crate::domain::tenant_context::TenantContext;
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
    /// 内部エラー。
    Internal(String),
}

pub struct PasskeyAuthenticationService {
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
    auth_sessions: Arc<dyn AuthSessionRepository>,
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    sso_sessions: Arc<dyn SsoSessionRepository>,
    client_consents: Arc<dyn ClientConsentRepository>,
    code_issuance: Arc<CodeIssuanceService>,
    webauthn: Arc<dyn WebAuthnPort>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
    sso_idle_ttl: Duration,
    sso_absolute_ttl: Duration,
}

impl PasskeyAuthenticationService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
        auth_sessions: Arc<dyn AuthSessionRepository>,
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        sso_sessions: Arc<dyn SsoSessionRepository>,
        client_consents: Arc<dyn ClientConsentRepository>,
        code_issuance: Arc<CodeIssuanceService>,
        webauthn: Arc<dyn WebAuthnPort>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
        sso_idle_ttl: StdDuration,
        sso_absolute_ttl: StdDuration,
    ) -> Self {
        Self {
            webauthn_credentials,
            passkey_challenges,
            auth_sessions,
            users,
            memberships,
            sso_sessions,
            client_consents,
            code_issuance,
            webauthn,
            audit,
            clock,
            sso_idle_ttl: Duration::from_std(sso_idle_ttl).expect("SSO idle TTL out of range"),
            sso_absolute_ttl: Duration::from_std(sso_absolute_ttl)
                .expect("SSO absolute TTL out of range"),
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
            auth_session_id: auth_session_id.map(|s| s.to_string()),
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
        let Some(auth_session_id) = &challenge.auth_session_id else {
            return PasskeyAuthOutcome::Internal("no auth_session_id in challenge".to_string());
        };
        let session = match self
            .auth_sessions
            .find_by_id(tenant_id, auth_session_id)
            .await
        {
            Ok(Some(s)) => s,
            Ok(None) => return PasskeyAuthOutcome::SessionExpired,
            Err(e) => return PasskeyAuthOutcome::Internal(e.to_string()),
        };
        if session.is_expired_at(now) {
            let _ = self.auth_sessions.delete(&session.id).await;
            return PasskeyAuthOutcome::SessionExpired;
        }

        let client_id = session.client_id.clone();

        // 9. auth_time を設定する。
        if let Err(e) = self
            .auth_sessions
            .set_authenticated_user(&session.id, user_id, now)
            .await
        {
            return PasskeyAuthOutcome::Internal(e.to_string());
        }

        // 10. SSO セッション発行。
        let sso_session_id = crypto::random_hex(32);
        let sso = SsoSession {
            session_hash: crypto::sha256_hex(&sso_session_id),
            user_id,
            auth_time: now,
            idle_expires_at: now + self.sso_idle_ttl,
            absolute_expires_at: now + self.sso_absolute_ttl,
            user_agent: ctx.user_agent.clone(),
            ip_address: ctx.ip_address.clone(),
            created_at: now,
            updated_at: now,
        };
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
                auth_session_id: session.id,
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
        if let Err(e) = self.auth_sessions.delete(&session.id).await {
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
        async fn create(&self, _m: &TenantMembership) -> DomainResult<()> {
            unreachable!()
        }
        async fn find(&self, _t: TenantId, _u: Uuid) -> DomainResult<Option<TenantMembership>> {
            unreachable!()
        }
        async fn list_for_tenant(&self, _t: TenantId) -> DomainResult<Vec<TenantMembership>> {
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
