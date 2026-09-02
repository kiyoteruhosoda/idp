//! WebAuthn アサーション（discoverable credentials）の検証。
//!
//! パスキーの「ログイン」は 2 つの層でできている。**セレモニー**（チャレンジを発行し、ブラウザが返した
//! アサーションを検証して「どの利用者か」を確定する）と、その後の**ログイン経路ごとの処理**
//! （OIDC 認可フローの継続・管理コンソールの権限確認・ポータルの SSO 発行）である。
//!
//! 本モジュールは前者だけを持つ。パスキーを受け付ける画面は
//! [`crate::application::passkey_authentication`]（OIDC 認可フロー）・
//! [`crate::application::admin_login`]（管理コンソール）・
//! [`crate::application::portal_login`]（ポータル）の 3 つあり、**セレモニーはどれも同一**である。
//! 3 か所へ写すと、認証器登録簿の一時停止判定（AP9）や署名カウンタの更新といった見落とすと危険な
//! 手順が経路ごとにずれていくため、ここを唯一の出所とする。
//!
//! チャレンジは [`PasskeyFlow`] で用途を分ける。OIDC 経路のチャレンジは `auth_session_id` に結合して
//! おり（[`PasskeyFlow::Oidc`]）、直接ログイン（管理コンソール・ポータル）のチャレンジは結合を持たない
//! （[`PasskeyFlow::Direct`]）。重要操作の直前の本人確認（AP5）はどちらでもなく、種別そのもので
//! 分ける（[`PasskeyFlow::StepUp`]）—— セッションを作らないので `auth_session_id_hash` は用途を
//! 表せない。完了時に期待するフローと一致しないチャレンジは [`PasskeyAssertionError::WrongFlow`] で
//! 弾き、経路をまたいだ使い回しを起こさせない。

use crate::application::audit::{AuditService, RequestContext};
use crate::application::authenticator_management::is_blocked_in_registry;
use crate::domain::audit::{AuditEventType, AuditResult};
use crate::domain::auth_session;
use crate::domain::clock::Clock;
use crate::domain::passkey_challenge::{PasskeyChallenge, PasskeyChallengeType};
use crate::domain::repositories::{
    PasskeyChallengeRepository, TenantMembershipRepository, UserAuthenticatorRepository,
    UserRepository, WebAuthnCredentialRepository,
};
use crate::domain::tenant::TenantId;
use crate::domain::user_authenticator::AuthenticatorType;
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

/// パスキーを使おうとしている経路。チャレンジの発行時と完了時で一致していなければならない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyFlow {
    /// OIDC 認可フローの中のログイン。`auth_session_id` に結合する。
    Oidc,
    /// 認可フロー外の直接ログイン（管理コンソール・ポータル）。`auth_session_id` を持たない。
    Direct,
    /// 重要操作の直前の本人確認（AP5）。**セッションを作らず、既にあるセッションを引き上げる。**
    /// ログインの 2 つと `challenge_type` で分かれる。
    StepUp,
}

impl PasskeyFlow {
    /// この経路が発行・消費するチャレンジの種別。
    fn challenge_type(self) -> PasskeyChallengeType {
        match self {
            Self::Oidc | Self::Direct => PasskeyChallengeType::Authenticate,
            Self::StepUp => PasskeyChallengeType::StepUp,
        }
    }
}

/// アサーション検証の失敗。呼び出し側は自分の経路の outcome へ写す。
#[derive(Debug)]
pub enum PasskeyAssertionError {
    /// チャレンジが見つからない・期限切れ・使用済み。
    ChallengeNotFound,
    /// チャレンジの用途が期待する経路と違う。
    WrongFlow,
    /// クレデンシャルが無効（不存在・検証失敗・停止中・テナント非所属・アカウント無効）。
    /// 列挙を避けるため理由を分けない。
    InvalidCredential,
    Internal(String),
}

/// 検証を通ったパスキーの持ち主。
#[derive(Debug)]
pub struct VerifiedPasskeyUser {
    pub user_id: Uuid,
    /// OIDC 経路のチャレンジが持つ `auth_sessions.id_hash`（`Direct` では常に `None`）。
    pub auth_session_id_hash: Option<String>,
}

pub struct PasskeyAssertionService {
    webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
    /// 認証器の登録簿（AP9）。一時停止・失効はここにしか無いため、認証時に必ず見る。
    authenticators: Arc<dyn UserAuthenticatorRepository>,
    passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
    users: Arc<dyn UserRepository>,
    memberships: Arc<dyn TenantMembershipRepository>,
    webauthn: Arc<dyn WebAuthnPort>,
    audit: Arc<AuditService>,
    clock: Arc<dyn Clock>,
}

impl PasskeyAssertionService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        webauthn_credentials: Arc<dyn WebAuthnCredentialRepository>,
        authenticators: Arc<dyn UserAuthenticatorRepository>,
        passkey_challenges: Arc<dyn PasskeyChallengeRepository>,
        users: Arc<dyn UserRepository>,
        memberships: Arc<dyn TenantMembershipRepository>,
        webauthn: Arc<dyn WebAuthnPort>,
        audit: Arc<AuditService>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            webauthn_credentials,
            authenticators,
            passkey_challenges,
            users,
            memberships,
            webauthn,
            audit,
            clock,
        }
    }

    /// 認証開始。`auth_session_id` を渡すと OIDC フロー継続用のチャレンジになり、渡さなければ
    /// 直接ログイン用のチャレンジになる。
    ///
    /// 返り値: `(challenge_id, options_json)`
    pub async fn begin(
        &self,
        auth_session_id: Option<&str>,
    ) -> Result<(Uuid, serde_json::Value), String> {
        self.begin_for(PasskeyFlow::Direct, auth_session_id).await
    }

    /// 本人確認（AP5）の開始。ログイン用のチャレンジとは種別で分かれるため、**この経路で出した
    /// チャレンジではログインできない**（逆も同じ）。
    ///
    /// 返り値: `(challenge_id, options_json)`
    pub async fn begin_step_up(&self) -> Result<(Uuid, serde_json::Value), String> {
        self.begin_for(PasskeyFlow::StepUp, None).await
    }

    /// 用途を決めてチャレンジを 1 本作る。`Oidc` と `Direct` の別は `auth_session_id` の有無が
    /// 表すため、ログイン経路はどちらを渡しても同じ結果になる。
    async fn begin_for(
        &self,
        flow: PasskeyFlow,
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
            challenge_type: flow.challenge_type(),
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

    /// アサーションを検証し、持ち主を確定する。チャレンジは（成否によらず）1 回で使い切る。
    pub async fn verify(
        &self,
        tenant_id: TenantId,
        challenge_id: Uuid,
        credential_value: serde_json::Value,
        flow: PasskeyFlow,
        ctx: &RequestContext,
    ) -> Result<VerifiedPasskeyUser, PasskeyAssertionError> {
        let now = self.clock.now();

        // 1. チャレンジを取得して消費する。
        let challenge = match self.passkey_challenges.find_by_id(challenge_id).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err(PasskeyAssertionError::ChallengeNotFound),
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
        };
        if challenge.expires_at <= now {
            let _ = self.passkey_challenges.delete(challenge_id).await;
            return Err(PasskeyAssertionError::ChallengeNotFound);
        }
        // チャレンジを先に削除（リプレイ防止）。
        if let Err(e) = self.passkey_challenges.delete(challenge_id).await {
            return Err(PasskeyAssertionError::Internal(e.to_string()));
        }

        // 1.5. 用途の一致を確認する。ログインと本人確認は `challenge_type` で分かれ、ログインの
        //      2 経路（認可フロー・直接）は `auth_session_id_hash` の有無で分かれる。
        let flow_matches = challenge.challenge_type == flow.challenge_type()
            && match flow {
                PasskeyFlow::Oidc => challenge.auth_session_id_hash.is_some(),
                PasskeyFlow::Direct | PasskeyFlow::StepUp => {
                    challenge.auth_session_id_hash.is_none()
                }
            };
        if !flow_matches {
            return Err(PasskeyAssertionError::WrongFlow);
        }

        // 2. DiscoverableAuthentication 状態を復元する。
        let auth_state: DiscoverableAuthentication =
            match serde_json::from_str(&challenge.state_json) {
                Ok(s) => s,
                Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
            };

        // 3. ブラウザからのクレデンシャルをデシリアライズする。
        let public_key_credential: PublicKeyCredential =
            match serde_json::from_value(credential_value) {
                Ok(c) => c,
                Err(_) => return Err(PasskeyAssertionError::InvalidCredential),
            };

        // 4. credential_id から登録済みクレデンシャルを引く。
        let stored_cred = match self
            .webauthn_credentials
            .find_by_credential_id(public_key_credential.id.as_str())
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => return Err(PasskeyAssertionError::InvalidCredential),
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
        };

        let passkey: Passkey = match serde_json::from_str(&stored_cred.passkey_json) {
            Ok(p) => p,
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
        };

        let user_id = stored_cred.user_id;
        let cred_row_id = stored_cred.id;

        // 登録簿でこの 1 本が止められていないかを見る（AP9）。公開鍵を引く経路は「失効して
        // いない行」しか見ないので、**一時停止**を効かせるのはこの判定だけである。パスキーは
        // 1 利用者に複数あるため、止めた 1 本だけを塞ぐ。
        match is_blocked_in_registry(
            self.authenticators.as_ref(),
            user_id,
            AuthenticatorType::WebAuthn,
            Some(cred_row_id),
        )
        .await
        {
            Ok(true) => return Err(PasskeyAssertionError::InvalidCredential),
            Ok(false) => {}
            Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
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
                    return Err(PasskeyAssertionError::InvalidCredential);
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
                Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
            };
            if let Err(e) = self
                .webauthn_credentials
                .update_passkey(cred_row_id, &new_json, now)
                .await
            {
                return Err(PasskeyAssertionError::Internal(e.to_string()));
            }
        }

        // 7. ユーザーの有効性と、フローのテナントへの ACTIVE メンバーシップ（HOME または GUEST）を
        //    確認する。WebAuthn クレデンシャルはテナント列を持たずホスト単位で解決されるため、テナント
        //    境界はこのアプリ層の紐付けで強制する（ADR-0009 §8。`authorize` の SSO 復元と同じ判定）。
        //    非メンバー・無効・不明はいずれも `InvalidCredential` に倒す（列挙防止のため理由を分けない）。
        ensure_active_member(
            self.users.as_ref(),
            self.memberships.as_ref(),
            tenant_id,
            user_id,
        )
        .await?;

        Ok(VerifiedPasskeyUser {
            user_id,
            auth_session_id_hash: challenge.auth_session_id_hash,
        })
    }
}

/// 本人確認（AP5）がパスキーへ求めること。
///
/// [`StepUpService`](crate::application::step_up::StepUpService) がセレモニーの実装全体ではなく
/// この 2 つだけを見るのは、**本人確認の判定を試すのにセレモニー一式を組ませない**ためである
/// （クレデンシャル・チャレンジ・登録簿・テナント所属の 4 リポジトリと WebAuthn 実装）。
/// 実装は [`PasskeyAssertionService`] 1 つで、セレモニーそのものは 3 つのログイン経路と同じ
/// 1 か所に留まる（ADR-0040 決定 1）。
#[async_trait::async_trait]
pub trait PasskeyStepUpCeremony: Send + Sync {
    /// 本人確認用のチャレンジを 1 本発行する。
    async fn begin(&self) -> Result<(Uuid, serde_json::Value), String>;

    /// アサーションを検証して持ち主を確定する。**持ち主がセッションの利用者かは呼び出し側が見る**
    /// （セレモニーは「誰のパスキーか」までしか答えない）。
    async fn verify(
        &self,
        tenant_id: TenantId,
        challenge_id: Uuid,
        credential: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<VerifiedPasskeyUser, PasskeyAssertionError>;
}

#[async_trait::async_trait]
impl PasskeyStepUpCeremony for PasskeyAssertionService {
    async fn begin(&self) -> Result<(Uuid, serde_json::Value), String> {
        self.begin_step_up().await
    }

    async fn verify(
        &self,
        tenant_id: TenantId,
        challenge_id: Uuid,
        credential: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<VerifiedPasskeyUser, PasskeyAssertionError> {
        PasskeyAssertionService::verify(
            self,
            tenant_id,
            challenge_id,
            credential,
            PasskeyFlow::StepUp,
            ctx,
        )
        .await
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
) -> Result<(), PasskeyAssertionError> {
    match users.find_by_id(user_id).await {
        Ok(Some(u)) if u.is_active() => {}
        Ok(_) => return Err(PasskeyAssertionError::InvalidCredential),
        Err(e) => return Err(PasskeyAssertionError::Internal(e.to_string())),
    }
    match memberships.is_active_member(tenant_id, user_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(PasskeyAssertionError::InvalidCredential),
        Err(e) => Err(PasskeyAssertionError::Internal(e.to_string())),
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
            theme: None,
            password_hash: "x".to_string(),
            must_change_password: false,
            password_changed_at: None,
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
        /// このテストはログイン失敗経路を通らない（SEC13 の検証は login / mfa_login にある）。
        async fn record_login_failure(
            &self,
            _id: Uuid,
            _lockout: crate::domain::authentication_policy::LockoutPolicy,
            _now: chrono::DateTime<chrono::Utc>,
        ) -> DomainResult<crate::domain::user::LoginFailureRecord> {
            unreachable!()
        }
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
        async fn update_password(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
            unreachable!()
        }
        async fn reset_password_forced(
            &self,
            _id: Uuid,
            _expected: &str,
            _password_hash: &str,
        ) -> DomainResult<bool> {
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

    /// 監査を捨てるだけのシンク（本モジュールのテストは監査の内容を検証しない）。
    struct DiscardingSink;
    #[async_trait]
    impl crate::domain::repositories::AuditLogSink for DiscardingSink {
        async fn record(&self, _event: &crate::domain::audit::AuditEvent) -> DomainResult<()> {
            Ok(())
        }
    }

    struct FixedClock(chrono::DateTime<Utc>);
    impl crate::domain::clock::Clock for FixedClock {
        fn now(&self) -> chrono::DateTime<Utc> {
            self.0
        }
    }

    /// 1 件のチャレンジを返し、削除されたかを記録するフェイク。
    struct FakeChallenges {
        challenge: std::sync::Mutex<Option<PasskeyChallenge>>,
        deleted: std::sync::Mutex<Vec<Uuid>>,
    }
    #[async_trait]
    impl crate::domain::repositories::PasskeyChallengeRepository for FakeChallenges {
        async fn create(&self, _c: &PasskeyChallenge) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(&self, id: Uuid) -> DomainResult<Option<PasskeyChallenge>> {
            Ok(self
                .challenge
                .lock()
                .unwrap()
                .clone()
                .filter(|c| c.id == id))
        }
        async fn delete(&self, id: Uuid) -> DomainResult<()> {
            self.deleted.lock().unwrap().push(id);
            Ok(())
        }
        async fn delete_expired(&self, _now: chrono::DateTime<Utc>) -> DomainResult<u64> {
            unreachable!()
        }
    }

    /// フローの判定より先には進まないことを保証するフェイク（呼ばれたら panic）。
    struct UnreachableCredentials;
    #[async_trait]
    impl WebAuthnCredentialRepository for UnreachableCredentials {
        async fn create(
            &self,
            _c: &crate::domain::webauthn_credential::WebAuthnCredential,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn find_by_id(
            &self,
            _id: Uuid,
        ) -> DomainResult<Option<crate::domain::webauthn_credential::WebAuthnCredential>> {
            unreachable!()
        }
        async fn find_by_credential_id(
            &self,
            _credential_id: &str,
        ) -> DomainResult<Option<crate::domain::webauthn_credential::WebAuthnCredential>> {
            unreachable!("the flow check must reject before the credential lookup")
        }
        async fn list_by_user_id(
            &self,
            _user_id: Uuid,
        ) -> DomainResult<Vec<crate::domain::webauthn_credential::WebAuthnCredential>> {
            unreachable!()
        }
        async fn update_passkey(
            &self,
            _id: Uuid,
            _passkey_json: &str,
            _last_used_at: chrono::DateTime<Utc>,
        ) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete(&self, _id: Uuid, _user_id: Uuid) -> DomainResult<()> {
            unreachable!()
        }
        async fn delete_all_for_user(&self, _user_id: Uuid) -> DomainResult<u64> {
            unreachable!()
        }
    }

    /// 既定実装だけの登録簿フェイク（このテストでは到達しない）。
    struct UnreachableAuthenticators;
    #[async_trait]
    impl UserAuthenticatorRepository for UnreachableAuthenticators {
        async fn create(
            &self,
            _a: &crate::domain::user_authenticator::UserAuthenticator,
        ) -> DomainResult<()> {
            unreachable!()
        }
    }

    struct UnreachableWebAuthn;
    impl WebAuthnPort for UnreachableWebAuthn {
        fn begin_registration(
            &self,
            _user_id: Uuid,
            _user_name: &str,
            _user_display_name: &str,
            _exclude: &[Passkey],
        ) -> Result<
            (
                webauthn_rs::prelude::CreationChallengeResponse,
                webauthn_rs::prelude::PasskeyRegistration,
            ),
            String,
        > {
            unreachable!()
        }
        fn finish_registration(
            &self,
            _credential: &webauthn_rs::prelude::RegisterPublicKeyCredential,
            _state: &webauthn_rs::prelude::PasskeyRegistration,
        ) -> Result<Passkey, String> {
            unreachable!()
        }
        fn begin_authentication(
            &self,
        ) -> Result<
            (
                webauthn_rs::prelude::RequestChallengeResponse,
                DiscoverableAuthentication,
            ),
            String,
        > {
            unreachable!()
        }
        fn finish_authentication(
            &self,
            _credential: &PublicKeyCredential,
            _state: DiscoverableAuthentication,
            _creds: &[DiscoverableKey],
        ) -> Result<webauthn_rs::prelude::AuthenticationResult, String> {
            unreachable!()
        }
    }

    fn fixed_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 29, 12, 0, 0).unwrap()
    }

    /// 指定の `auth_session_id_hash` を持つ認証チャレンジ 1 件だけを知っているサービスを組む。
    fn service_with_challenge(
        auth_session_id_hash: Option<&str>,
        expires_at: chrono::DateTime<Utc>,
    ) -> (PasskeyAssertionService, Uuid, Arc<FakeChallenges>) {
        let challenge_id = Uuid::new_v4();
        let challenges = Arc::new(FakeChallenges {
            challenge: std::sync::Mutex::new(Some(PasskeyChallenge {
                id: challenge_id,
                user_id: None,
                challenge_type: PasskeyChallengeType::Authenticate,
                // フローの判定はこの JSON を読む前に行われるので、中身は問わない。
                state_json: "not-a-discoverable-authentication".to_string(),
                auth_session_id_hash: auth_session_id_hash.map(|s| s.to_string()),
                expires_at,
                created_at: fixed_now(),
            })),
            deleted: std::sync::Mutex::new(Vec::new()),
        });
        let service = PasskeyAssertionService::new(
            Arc::new(UnreachableCredentials),
            Arc::new(UnreachableAuthenticators),
            challenges.clone(),
            Arc::new(FakeUsers(None)),
            Arc::new(FakeMemberships {
                tenant_id: Uuid::now_v7().into(),
                is_member: Ok(true),
            }),
            Arc::new(UnreachableWebAuthn),
            Arc::new(crate::application::audit::AuditService::new(
                Arc::new(DiscardingSink),
                Arc::new(FixedClock(fixed_now())),
            )),
            Arc::new(FixedClock(fixed_now())),
        );
        (service, challenge_id, challenges)
    }

    fn request_context() -> RequestContext {
        RequestContext {
            correlation_id: "test".to_string(),
            ip_address: None,
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn an_authorization_flow_challenge_is_not_accepted_by_a_direct_login() {
        // 認可フロー用に発行したチャレンジ（auth_session に結合）を管理コンソール／ポータルの
        // 完了エンドポイントへ持ち込んでも通らない。
        let (service, challenge_id, challenges) = service_with_challenge(
            Some("auth-session-hash"),
            fixed_now() + Duration::minutes(5),
        );
        let err = service
            .verify(
                Uuid::now_v7().into(),
                challenge_id,
                serde_json::Value::Null,
                PasskeyFlow::Direct,
                &request_context(),
            )
            .await
            .expect_err("a challenge bound to an auth session must not complete a direct login");
        assert!(matches!(err, PasskeyAssertionError::WrongFlow));
        // 用途違いでもチャレンジは使い切る（同じチャレンジで正しい経路を試させない）。
        assert_eq!(
            challenges.deleted.lock().unwrap().as_slice(),
            [challenge_id]
        );
    }

    #[tokio::test]
    async fn a_direct_login_challenge_is_not_accepted_by_the_authorization_flow() {
        let (service, challenge_id, _) =
            service_with_challenge(None, fixed_now() + Duration::minutes(5));
        let err = service
            .verify(
                Uuid::now_v7().into(),
                challenge_id,
                serde_json::Value::Null,
                PasskeyFlow::Oidc,
                &request_context(),
            )
            .await
            .expect_err("a direct-login challenge must not continue an authorization flow");
        assert!(matches!(err, PasskeyAssertionError::WrongFlow));
    }

    #[tokio::test]
    async fn an_expired_challenge_is_rejected_before_the_flow_check() {
        let (service, challenge_id, challenges) =
            service_with_challenge(None, fixed_now() - Duration::seconds(1));
        let err = service
            .verify(
                Uuid::now_v7().into(),
                challenge_id,
                serde_json::Value::Null,
                PasskeyFlow::Direct,
                &request_context(),
            )
            .await
            .expect_err("an expired challenge must not be usable");
        assert!(matches!(err, PasskeyAssertionError::ChallengeNotFound));
        assert_eq!(
            challenges.deleted.lock().unwrap().as_slice(),
            [challenge_id]
        );
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
        assert!(matches!(outcome, PasskeyAssertionError::InvalidCredential));
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
        assert!(matches!(outcome, PasskeyAssertionError::InvalidCredential));
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
        assert!(matches!(outcome, PasskeyAssertionError::InvalidCredential));
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
        assert!(matches!(outcome, PasskeyAssertionError::Internal(_)));
    }
}
