//! Passkey チャレンジ一時エンティティ。
//!
//! WebAuthn の begin → complete 二段階ハンドシェイクの間、`webauthn-rs` が返す
//! チャレンジ中間状態（`PasskeyRegistration` / `DiscoverableAuthentication`）を DB に保持する。
//! `expires_at` を過ぎたレコードはアプリケーション層が削除する。

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyChallengeType {
    Register,
    Authenticate,
}

impl PasskeyChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PasskeyChallengeType::Register => "register",
            PasskeyChallengeType::Authenticate => "authenticate",
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
    /// 認証チャレンジ: OIDC フローの `auth_sessions.id`（登録チャレンジでは `None`）。
    pub auth_session_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
