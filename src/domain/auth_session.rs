//! AuthSessions エンティティ（設計仕様 §3.3）。
//! `/authorize` から `/login` 完了までの一時的な認可リクエスト状態。
#![allow(dead_code)]

use crate::domain::values::CodeChallengeMethod;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthSession {
    /// 128bit 以上の推測不能なランダム値（`auth_session_id` Cookie の値そのもの）。
    pub id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    pub authenticated_user_id: Option<Uuid>,
    pub auth_time: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthSession {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}
