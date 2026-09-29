//! AuthSession 集約（設計仕様 §3.3）。
//!
//! `/authorize` から code 発行までの一時的な認可フローの状態。受理した認可要求
//! （[`AuthorizationRequest`]）と、その要求に対して**誰の認証がどこまで進んだか**
//! （[`AuthenticationProgress`]）を持つ。
//!
//! # 状態の変え方
//!
//! 状態を変えるのは、この集約の意図を表すメソッドだけである:
//!
//! | メソッド | 起きること |
//! |---|---|
//! | [`AuthSession::start`] | 認可要求を受理してフローを始める（web へ渡す単回ハンドルを発行） |
//! | [`AuthSession::exchange_handoff`] | web がハンドルを `auth_session_id` と交換する |
//! | [`AuthSession::record_password_verification`] | パスワードまで通った（第二段待ち） |
//! | [`AuthSession::complete_authentication`] | 認証が完了した |
//!
//! 各メソッドは変更を表す値（[`HandoffExchange`] など）を返し、リポジトリはそれを**1 文で**永続化する。
//! 変更の中身を集約が決め、書き込みの原子性をリポジトリが持つ、という分担である。
//!
//! # `auth_session_id` は毎回付け替わる（SEC7）
//!
//! 認証の段が進むたびに id を再生成する（セッション固定攻撃対策）。付け替えは状態の記録と同じ
//! 変更に含まれ（[`IdRotation`]）、「認証前に発行した Cookie 値が認証後も通る瞬間」を作らない。

use crate::domain::authorization_request::AuthorizationRequest;
use crate::domain::crypto;
use crate::domain::tenant::TenantId;
use crate::domain::values::AuthenticationMethod;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// `auth_session_id` の平文（web が host-only Cookie に持つ 128bit 以上のランダム値）。
///
/// この値は **bearer credential そのもの**（提示できれば同意待ち／MFA 待ちの認可セッションを
/// 操作できる）。DB へは [`AuthSessionIdHash`] だけを保存し、平文はリクエスト／レスポンスの間
/// だけ存在する（SEC6）。`Debug` にも出さない。
#[derive(Clone, PartialEq, Eq)]
pub struct AuthSessionId(String);

impl AuthSessionId {
    /// 新しい id を作る。
    pub fn generate() -> Self {
        Self(crypto::random_hex(32))
    }

    /// web から提示された値を受け取る。空は「持っていない」と同じ。
    pub fn from_presented(raw: &str) -> Option<Self> {
        (!raw.is_empty()).then(|| Self(raw.to_string()))
    }

    /// 保存・照合に使うハッシュ。
    pub fn hash(&self) -> AuthSessionIdHash {
        AuthSessionIdHash::of_plain(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// web へ渡す平文。
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for AuthSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthSessionId(<redacted>)")
    }
}

/// `auth_session_id` の SHA-256。DB の主キー。
///
/// 他の bearer credential（`sso_sessions.session_hash`・`authorization_codes.code_hash`・
/// `refresh_tokens.token_hash`・同じ表の `handle_hash`）と同じく、DB にはハッシュだけを置く（SEC6）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthSessionIdHash(String);

impl AuthSessionIdHash {
    /// 平文から導出する。
    pub fn of_plain(plain: &str) -> Self {
        Self(crypto::sha256_hex(plain))
    }

    /// 保存済みのハッシュ値を受け取る（パスキーのチャレンジ等、別の表に控えてある値）。
    pub fn from_stored(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// web ハンドオフ用の単回ハンドルの平文（ADR-0018 決定 2）。
///
/// `/authorize` の 302 で web へ渡し、web は `/internal/authorize/resume` でこれを `auth_session_id`
/// と交換する。単回・短命で、発行した認可セッション（＝その `code_challenge`）に固定的に束ねられる。
#[derive(Clone, PartialEq, Eq)]
pub struct HandoffHandle(String);

impl HandoffHandle {
    fn generate() -> Self {
        Self(crypto::random_hex(32))
    }

    /// web から提示された値を受け取る。空は「持っていない」と同じ。
    pub fn from_presented(raw: &str) -> Option<Self> {
        (!raw.is_empty()).then(|| Self(raw.to_string()))
    }

    pub fn hash(&self) -> HandoffHandleHash {
        HandoffHandleHash(crypto::sha256_hex(&self.0))
    }

    /// web へ渡す平文（URL に載る）。
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for HandoffHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HandoffHandle(<redacted>)")
    }
}

/// ハンドオフ用ハンドルの SHA-256。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffHandleHash(String);

impl HandoffHandleHash {
    pub fn from_stored(hash: String) -> Self {
        Self(hash)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 未交換のハンドル（ハッシュと期限）。交換すると消える（単回使用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHandoff {
    handle_hash: HandoffHandleHash,
    /// auth_session 本体の `expires_at` より短命。
    expires_at: DateTime<Utc>,
}

impl PendingHandoff {
    pub fn handle_hash(&self) -> &HandoffHandleHash {
        &self.handle_hash
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// 完了した認証（誰が・いつ・どの SSO セッションで・何で認証したか）。
///
/// authorization code はこれに対して発行される（ID Token の `sub` / `auth_time` / `sid` / `acr` /
/// `amr` の出所）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    user_id: Uuid,
    auth_time: DateTime<Utc>,
    /// 認証で確立（または復元）した SSO セッションの `sid`（G5）。
    sso_sid: Option<String>,
    /// 実際に検証された認証方式（ADR-0043）。`None` = 記録なし（そのとき `acr` / `amr` は載らない）。
    methods: Option<Vec<AuthenticationMethod>>,
}

impl Authentication {
    pub fn new(
        user_id: Uuid,
        auth_time: DateTime<Utc>,
        sso_sid: Option<String>,
        methods: Option<Vec<AuthenticationMethod>>,
    ) -> Self {
        Self {
            user_id,
            auth_time,
            sso_sid,
            methods,
        }
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn auth_time(&self) -> DateTime<Utc> {
        self.auth_time
    }

    pub fn sso_sid(&self) -> Option<&str> {
        self.sso_sid.as_deref()
    }

    pub fn methods(&self) -> Option<&[AuthenticationMethod]> {
        self.methods.as_deref()
    }
}

/// 認可要求に対して、認証がどこまで進んだか。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationProgress {
    /// まだ誰も認証していない。
    Anonymous,
    /// パスワードまでは通った（第二要素かパスワード変更を待っている）。
    PasswordVerified {
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    },
    /// 認証が完了した（同意待ち）。
    Authenticated {
        authentication: Authentication,
        /// この認証の前にパスワードを検証した時刻（パスワードを経ない方式なら `None`）。
        password_verified_at: Option<DateTime<Utc>>,
    },
}

/// `auth_session_id` の付け替え（SEC7）。
///
/// 旧い id は `previous`、新しく web へ渡す平文は `issued`。リポジトリは旧い id の行を新しい id へ
/// 書き換える（旧い id では二度と引けなくなる）。
#[derive(Debug, Clone)]
pub struct IdRotation {
    previous: AuthSessionIdHash,
    issued: AuthSessionId,
}

impl IdRotation {
    pub fn previous(&self) -> &AuthSessionIdHash {
        &self.previous
    }

    pub fn issued_hash(&self) -> AuthSessionIdHash {
        self.issued.hash()
    }

    /// web へ渡す新しい `auth_session_id`。
    pub fn into_issued(self) -> AuthSessionId {
        self.issued
    }
}

/// ハンドルの交換（単回消費と id の付け替えを 1 つの変更として永続化する）。
///
/// ハンドル経路では平文 id が手元に無い（DB にはハッシュしか無い）ので、web へ返す
/// `auth_session_id` は交換の時点で新しく作るしかない。
#[derive(Debug, Clone)]
pub struct HandoffExchange {
    consumed: HandoffHandleHash,
    rotation: IdRotation,
}

impl HandoffExchange {
    /// 消費するハンドル（永続化は「このハンドルがまだ残っていれば」の条件付きで行う）。
    pub fn consumed(&self) -> &HandoffHandleHash {
        &self.consumed
    }

    pub fn rotation(&self) -> &IdRotation {
        &self.rotation
    }

    pub fn into_issued(self) -> AuthSessionId {
        self.rotation.into_issued()
    }
}

/// ハンドルを交換できない（無効・期限切れ・交換済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffUnavailable;

/// パスワード検証の記録（第二段待ちへの遷移）。
#[derive(Debug, Clone)]
pub struct PasswordVerification {
    user_id: Uuid,
    verified_at: DateTime<Utc>,
    rotation: IdRotation,
}

impl PasswordVerification {
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn verified_at(&self) -> DateTime<Utc> {
        self.verified_at
    }

    pub fn rotation(&self) -> &IdRotation {
        &self.rotation
    }

    pub fn into_issued(self) -> AuthSessionId {
        self.rotation.into_issued()
    }
}

/// 認証完了の記録。
#[derive(Debug, Clone)]
pub struct AuthenticationCompletion {
    authentication: Authentication,
    rotation: IdRotation,
}

impl AuthenticationCompletion {
    pub fn authentication(&self) -> &Authentication {
        &self.authentication
    }

    pub fn rotation(&self) -> &IdRotation {
        &self.rotation
    }

    pub fn into_issued(self) -> AuthSessionId {
        self.rotation.into_issued()
    }
}

/// AuthSession 集約。
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// `auth_session_id` の SHA-256。平文はここには入らない。
    id_hash: AuthSessionIdHash,
    /// フローを開始したテナント（`/{tenant_id}/authorize`。ADR-0009 §8）。
    tenant_id: TenantId,
    request: AuthorizationRequest,
    handoff: Option<PendingHandoff>,
    progress: AuthenticationProgress,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// 永続化から [`AuthSession`] を組み立て直すための部品（列の並びそのまま）。
///
/// ⚠ **Infrastructure 層（リポジトリ実装）と試験のためだけ**にある。
#[derive(Debug, Clone)]
pub struct AuthSessionParts {
    pub id_hash: AuthSessionIdHash,
    pub tenant_id: TenantId,
    pub request: AuthorizationRequest,
    pub handle_hash: Option<HandoffHandleHash>,
    pub handle_expires_at: Option<DateTime<Utc>>,
    pub authenticated_user_id: Option<Uuid>,
    pub auth_time: Option<DateTime<Utc>>,
    pub password_verified_at: Option<DateTime<Utc>>,
    pub sso_sid: Option<String>,
    pub authentication_methods: Option<Vec<AuthenticationMethod>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthSession {
    /// 認可要求を受理してフローを始める。web へ渡す単回ハンドルも発行する。
    ///
    /// この時点の `auth_session_id` は誰にも渡らない（web へ渡すのはハンドルだけ）ので、生成した
    /// 平文は保存用のハッシュにしてすぐ捨てる。web が受け取る `auth_session_id` はハンドル交換
    /// （[`Self::exchange_handoff`]）で作られる。
    pub fn start(
        tenant_id: TenantId,
        request: AuthorizationRequest,
        now: DateTime<Utc>,
        lifetime: Duration,
        handoff_lifetime: Duration,
    ) -> (Self, HandoffHandle) {
        let handle = HandoffHandle::generate();
        let session = Self {
            id_hash: AuthSessionId::generate().hash(),
            tenant_id,
            request,
            handoff: Some(PendingHandoff {
                handle_hash: handle.hash(),
                expires_at: now + handoff_lifetime,
            }),
            progress: AuthenticationProgress::Anonymous,
            expires_at: now + lifetime,
            created_at: now,
            updated_at: now,
        };
        (session, handle)
    }

    /// 永続化された値から復元する。
    ///
    /// 認証の進み具合は列の組み合わせから決める。利用者が無ければ `Anonymous`、`auth_time` が
    /// あれば `Authenticated`、パスワード検証時刻だけなら `PasswordVerified`。どれにも当たらない
    /// 組み合わせ（利用者だけがある）は書き込みの経路が無いので `Anonymous` とみなす。
    pub fn reconstitute(parts: AuthSessionParts) -> Self {
        let progress = match (
            parts.authenticated_user_id,
            parts.auth_time,
            parts.password_verified_at,
        ) {
            (Some(user_id), Some(auth_time), password_verified_at) => {
                AuthenticationProgress::Authenticated {
                    authentication: Authentication::new(
                        user_id,
                        auth_time,
                        parts.sso_sid,
                        parts.authentication_methods,
                    ),
                    password_verified_at,
                }
            }
            (Some(user_id), None, Some(verified_at)) => AuthenticationProgress::PasswordVerified {
                user_id,
                verified_at,
            },
            _ => AuthenticationProgress::Anonymous,
        };
        let handoff = match (parts.handle_hash, parts.handle_expires_at) {
            (Some(handle_hash), Some(expires_at)) => Some(PendingHandoff {
                handle_hash,
                expires_at,
            }),
            _ => None,
        };
        Self {
            id_hash: parts.id_hash,
            tenant_id: parts.tenant_id,
            request: parts.request,
            handoff,
            progress,
            expires_at: parts.expires_at,
            created_at: parts.created_at,
            updated_at: parts.updated_at,
        }
    }

    /// 永続化のための部品へ分解する（[`Self::reconstitute`] の逆）。
    pub fn to_parts(&self) -> AuthSessionParts {
        let (authenticated_user_id, auth_time, password_verified_at, sso_sid, methods) =
            match &self.progress {
                AuthenticationProgress::Anonymous => (None, None, None, None, None),
                AuthenticationProgress::PasswordVerified {
                    user_id,
                    verified_at,
                } => (Some(*user_id), None, Some(*verified_at), None, None),
                AuthenticationProgress::Authenticated {
                    authentication,
                    password_verified_at,
                } => (
                    Some(authentication.user_id),
                    Some(authentication.auth_time),
                    *password_verified_at,
                    authentication.sso_sid.clone(),
                    authentication.methods.clone(),
                ),
            };
        AuthSessionParts {
            id_hash: self.id_hash.clone(),
            tenant_id: self.tenant_id,
            request: self.request.clone(),
            handle_hash: self.handoff.as_ref().map(|h| h.handle_hash.clone()),
            handle_expires_at: self.handoff.as_ref().map(|h| h.expires_at),
            authenticated_user_id,
            auth_time,
            password_verified_at,
            sso_sid,
            authentication_methods: methods,
            expires_at: self.expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    pub fn id_hash(&self) -> &AuthSessionIdHash {
        &self.id_hash
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn request(&self) -> &AuthorizationRequest {
        &self.request
    }

    /// 認可要求を出したクライアント（監査・ポリシーの宛先）。
    pub fn client_id(&self) -> &str {
        self.request.client_id()
    }

    pub fn handoff(&self) -> Option<&PendingHandoff> {
        self.handoff.as_ref()
    }

    pub fn progress(&self) -> &AuthenticationProgress {
        &self.progress
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// web ハンドオフ用ハンドルが `now` 時点で交換可能か（未交換かつ期限内）。
    pub fn handoff_is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.handoff.as_ref().is_some_and(|h| h.expires_at > now)
    }

    /// 認証の途中でも完了後でも、この認可セッションで名乗った利用者。
    pub fn identified_user(&self) -> Option<Uuid> {
        match &self.progress {
            AuthenticationProgress::Anonymous => None,
            AuthenticationProgress::PasswordVerified { user_id, .. } => Some(*user_id),
            AuthenticationProgress::Authenticated { authentication, .. } => {
                Some(authentication.user_id)
            }
        }
    }

    /// パスワードを検証済みの利用者（第二要素・パスワード変更の入口で使う）。
    ///
    /// パスワードを経ずに完了した認証（パスキー・外部 IdP・SSO 復元）は該当しない。
    pub fn password_verified_user(&self) -> Option<Uuid> {
        match &self.progress {
            AuthenticationProgress::Anonymous => None,
            AuthenticationProgress::PasswordVerified { user_id, .. } => Some(*user_id),
            AuthenticationProgress::Authenticated {
                authentication,
                password_verified_at,
            } => password_verified_at.map(|_| authentication.user_id),
        }
    }

    /// 完了した認証（同意の承諾が code を発行する根拠）。
    pub fn completed_authentication(&self) -> Option<&Authentication> {
        match &self.progress {
            AuthenticationProgress::Authenticated { authentication, .. } => Some(authentication),
            _ => None,
        }
    }

    /// web ハンドオフのハンドルを消費し、web が持つ `auth_session_id` を発行する。
    ///
    /// `handle` はこの認可セッションを引いたハンドル（呼び出し側が照合済み）。永続化は
    /// 「ハンドルがまだ残っていれば」の条件付きで行う（並行する交換は片方だけが勝つ）。
    pub fn exchange_handoff(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<HandoffExchange, HandoffUnavailable> {
        if !self.handoff_is_valid_at(now) || self.is_expired_at(now) {
            return Err(HandoffUnavailable);
        }
        let consumed = self.handoff.take().expect("validated above").handle_hash;
        Ok(HandoffExchange {
            consumed,
            rotation: self.rotate_id(),
        })
    }

    /// パスワードまで通った（第二要素かパスワード変更を待つ）ことを記録する。
    ///
    /// ⚠ **前の認証は残さない。** 同じ認可セッションで先に誰かの認証が完了していても、ここで
    /// 別の（あるいは同じ）利用者が認証をやり直した以上、前の認証はもうこのフローの根拠ではない。
    /// 残すと、第二段を済ませていない利用者に同意の承諾が code を発行してしまう。
    pub fn record_password_verification(
        &mut self,
        user_id: Uuid,
        verified_at: DateTime<Utc>,
    ) -> PasswordVerification {
        self.progress = AuthenticationProgress::PasswordVerified {
            user_id,
            verified_at,
        };
        PasswordVerification {
            user_id,
            verified_at,
            rotation: self.rotate_id(),
        }
    }

    /// 認証が完了したことを記録する。
    pub fn complete_authentication(
        &mut self,
        authentication: Authentication,
    ) -> AuthenticationCompletion {
        let password_verified_at = match &self.progress {
            AuthenticationProgress::Anonymous => None,
            AuthenticationProgress::PasswordVerified { verified_at, .. } => Some(*verified_at),
            AuthenticationProgress::Authenticated {
                password_verified_at,
                ..
            } => *password_verified_at,
        };
        self.progress = AuthenticationProgress::Authenticated {
            authentication: authentication.clone(),
            password_verified_at,
        };
        AuthenticationCompletion {
            authentication,
            rotation: self.rotate_id(),
        }
    }

    fn rotate_id(&mut self) -> IdRotation {
        let issued = AuthSessionId::generate();
        let previous = std::mem::replace(&mut self.id_hash, issued.hash());
        IdRotation { previous, issued }
    }
}

/// 試験で認可セッションを手早く組み立てるための部品。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// ログイン画面に居る（まだ誰も認証していない）認可セッション。
    pub fn awaiting_login(
        tenant_id: TenantId,
        auth_session_id: &str,
        request: AuthorizationRequest,
        now: DateTime<Utc>,
    ) -> AuthSession {
        AuthSession::reconstitute(parts(tenant_id, auth_session_id, request, now))
    }

    /// パスワードまで通り、第二段を待っている認可セッション。
    pub fn awaiting_second_step(
        tenant_id: TenantId,
        auth_session_id: &str,
        request: AuthorizationRequest,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> AuthSession {
        AuthSession::reconstitute(AuthSessionParts {
            authenticated_user_id: Some(user_id),
            password_verified_at: Some(now),
            ..parts(tenant_id, auth_session_id, request, now)
        })
    }

    fn parts(
        tenant_id: TenantId,
        auth_session_id: &str,
        request: AuthorizationRequest,
        now: DateTime<Utc>,
    ) -> AuthSessionParts {
        AuthSessionParts {
            id_hash: AuthSessionIdHash::of_plain(auth_session_id),
            tenant_id,
            request,
            handle_hash: None,
            handle_expires_at: None,
            authenticated_user_id: None,
            auth_time: None,
            password_verified_at: None,
            sso_sid: None,
            authentication_methods: None,
            expires_at: now + Duration::seconds(600),
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::authorization_request::test_support::request;

    const HANDOFF_SECS: i64 = 60;

    fn started(now: DateTime<Utc>) -> (AuthSession, HandoffHandle) {
        AuthSession::start(
            Uuid::now_v7().into(),
            request("app", "https://client.example.com/cb"),
            now,
            Duration::minutes(10),
            Duration::seconds(HANDOFF_SECS),
        )
    }

    fn authentication(user_id: Uuid, at: DateTime<Utc>) -> Authentication {
        Authentication::new(
            user_id,
            at,
            Some("sid-1".to_string()),
            Some(vec![AuthenticationMethod::Password]),
        )
    }

    #[test]
    fn a_started_session_is_anonymous_and_bound_to_its_handle() {
        let now = Utc::now();
        let (session, handle) = started(now);
        assert_eq!(session.progress(), &AuthenticationProgress::Anonymous);
        assert_eq!(session.identified_user(), None);
        assert_eq!(
            session.handoff().map(|h| h.handle_hash().clone()),
            Some(handle.hash())
        );
        assert!(session.handoff_is_valid_at(now));
        assert!(!session.is_expired_at(now));
        assert!(session.is_expired_at(now + Duration::minutes(10)));
    }

    #[test]
    fn the_handle_is_single_use_and_short_lived() {
        let now = Utc::now();

        // 期限切れは交換できない。
        let (mut session, _) = started(now);
        assert_eq!(
            session
                .exchange_handoff(now + Duration::seconds(HANDOFF_SECS + 1))
                .unwrap_err(),
            HandoffUnavailable
        );

        // 交換は 1 度だけ。交換すると id が付け替わる。
        let (mut session, handle) = started(now);
        let before = session.id_hash().clone();
        let exchange = session.exchange_handoff(now).expect("first exchange");
        assert_eq!(exchange.consumed(), &handle.hash());
        assert_eq!(exchange.rotation().previous(), &before);
        assert_eq!(session.id_hash(), &exchange.rotation().issued_hash());
        assert_eq!(
            exchange.into_issued().hash(),
            session.id_hash().clone(),
            "web receives the plaintext of the new id"
        );
        assert!(session.handoff().is_none());
        assert_eq!(
            session.exchange_handoff(now).unwrap_err(),
            HandoffUnavailable
        );
    }

    #[test]
    fn password_verification_waits_for_the_second_step() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let user = Uuid::now_v7();
        let before = session.id_hash().clone();

        let verification = session.record_password_verification(user, now);
        assert_eq!(verification.rotation().previous(), &before);
        assert_ne!(session.id_hash(), &before, "SEC7: the id rotates");
        assert_eq!(session.identified_user(), Some(user));
        assert_eq!(session.password_verified_user(), Some(user));
        assert_eq!(session.completed_authentication(), None);
    }

    #[test]
    fn completing_after_a_password_keeps_the_password_timestamp() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let user = Uuid::now_v7();
        session.record_password_verification(user, now);
        let completion = session.complete_authentication(authentication(user, now));

        assert_eq!(completion.authentication().user_id(), user);
        assert_eq!(
            session.completed_authentication(),
            Some(&authentication(user, now))
        );
        // MFA 画面への再入を許してきた既存の振る舞い（パスワード検証済みの記録は残る）。
        assert_eq!(session.password_verified_user(), Some(user));
    }

    #[test]
    fn a_passwordless_completion_is_not_password_verified() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let user = Uuid::now_v7();
        session.complete_authentication(authentication(user, now));
        assert_eq!(session.identified_user(), Some(user));
        assert_eq!(session.password_verified_user(), None);
    }

    /// ⚠ 認証をやり直したら、前の認証は同意の根拠にならない。
    #[test]
    fn re_verifying_a_password_discards_the_previous_authentication() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        session.complete_authentication(authentication(first, now));

        session.record_password_verification(second, now);
        assert_eq!(session.completed_authentication(), None);
        assert_eq!(session.identified_user(), Some(second));
    }

    #[test]
    fn reconstitution_derives_the_progress_from_the_columns() {
        let now = Utc::now();
        let user = Uuid::now_v7();
        let base = || AuthSessionParts {
            id_hash: AuthSessionIdHash::of_plain("s"),
            tenant_id: Uuid::now_v7().into(),
            request: request("app", "https://client.example.com/cb"),
            handle_hash: Some(HandoffHandleHash::from_stored("h".to_string())),
            handle_expires_at: None,
            authenticated_user_id: None,
            auth_time: None,
            password_verified_at: None,
            sso_sid: None,
            authentication_methods: None,
            expires_at: now + Duration::minutes(10),
            created_at: now,
            updated_at: now,
        };

        // ハッシュと期限の片方だけでは、交換できるハンドルとみなさない。
        let session = AuthSession::reconstitute(base());
        assert!(session.handoff().is_none());
        assert_eq!(session.progress(), &AuthenticationProgress::Anonymous);

        let session = AuthSession::reconstitute(AuthSessionParts {
            authenticated_user_id: Some(user),
            password_verified_at: Some(now),
            ..base()
        });
        assert_eq!(
            session.progress(),
            &AuthenticationProgress::PasswordVerified {
                user_id: user,
                verified_at: now
            }
        );

        let session = AuthSession::reconstitute(AuthSessionParts {
            authenticated_user_id: Some(user),
            auth_time: Some(now),
            sso_sid: Some("sid".to_string()),
            ..base()
        });
        assert_eq!(
            session.completed_authentication(),
            Some(&Authentication::new(
                user,
                now,
                Some("sid".to_string()),
                None
            ))
        );
        assert_eq!(session.password_verified_user(), None);
    }

    #[test]
    fn parts_round_trip_through_reconstitution() {
        let now = Utc::now();
        let (mut session, _) = started(now);
        let user = Uuid::now_v7();
        session.record_password_verification(user, now);
        session.complete_authentication(authentication(user, now));

        let restored = AuthSession::reconstitute(session.to_parts());
        assert_eq!(restored.id_hash(), session.id_hash());
        assert_eq!(restored.progress(), session.progress());
        assert_eq!(restored.request(), session.request());
        assert_eq!(restored.handoff(), session.handoff());
    }

    #[test]
    fn plaintext_ids_are_not_printed() {
        let id = AuthSessionId::generate();
        assert!(!format!("{id:?}").contains(id.as_str()));
        assert_eq!(AuthSessionId::from_presented(""), None);
    }
}
