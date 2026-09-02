//! Passkey チャレンジ一時エンティティ。
//!
//! WebAuthn の begin → complete 二段階ハンドシェイクの間、`webauthn-rs` が返す
//! チャレンジ中間状態（`PasskeyRegistration` / `DiscoverableAuthentication`）を DB に保持する。
//! `expires_at` を過ぎたレコードはアプリケーション層が削除する。

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// チャレンジの用途。**完了側は自分の用途と違うチャレンジを受け付けない。**
///
/// セッションを作る（[`Self::Authenticate`]）ことと、既にあるセッションを引き上げる
/// （[`Self::StepUp`]。AP5）ことは別の操作である。分けないと、本人確認のために出した
/// チャレンジでログインが成立し、その逆も通る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyChallengeType {
    /// パスキーの登録（`navigator.credentials.create`）。
    Register,
    /// ログイン（`navigator.credentials.get`）。OIDC 認可フローか直接ログインかは
    /// `auth_session_id_hash` の有無で分かれる（ADR-0040 決定 4）。
    Authenticate,
    /// 重要操作の直前の本人確認（AP5）。ログインと違い、新しいセッションは作らない。
    StepUp,
}

impl PasskeyChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasskeyChallengeType::Register => "register",
            PasskeyChallengeType::Authenticate => "authenticate",
            PasskeyChallengeType::StepUp => "step_up",
        }
    }
}

impl std::fmt::Display for PasskeyChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PasskeyChallengeType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "register" => Ok(PasskeyChallengeType::Register),
            "authenticate" => Ok(PasskeyChallengeType::Authenticate),
            "step_up" => Ok(PasskeyChallengeType::StepUp),
            other => Err(format!("unknown challenge_type: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PasskeyChallenge {
    pub id: Uuid,
    /// 登録チャレンジ: SSO 済みユーザーの UUID。認証チャレンジ: discoverable のため `None`。
    pub user_id: Option<Uuid>,
    pub challenge_type: PasskeyChallengeType,
    /// `webauthn_rs::prelude::PasskeyRegistration` または `DiscoverableAuthentication` の JSON。
    pub state_json: String,
    /// 認証チャレンジ: OIDC フローの `auth_sessions.id_hash`（登録・本人確認チャレンジでは `None`）。
    /// auth_session_id は bearer credential なので、写しもハッシュで持つ（SEC6）。
    pub auth_session_id_hash: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
