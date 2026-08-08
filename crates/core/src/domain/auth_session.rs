//! AuthSessions エンティティ（設計仕様 §3.3）。
//! `/authorize` から `/login` 完了までの一時的な認可リクエスト状態。
#![allow(dead_code)]

use crate::domain::tenant::TenantId;
use crate::domain::values::{CodeChallengeMethod, Prompt};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthSession {
    /// 128bit 以上の推測不能なランダム値（web が host-only `auth_session_id` Cookie に保持する値）。
    pub id: String,
    /// フローを開始したテナント（`/{tenant_id}/authorize`。ADR-0009 §8）。
    pub tenant_id: TenantId,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    /// 認可リクエストの `prompt`（未指定・未知値は `None`）。SSO 判定が resume（ADR-0018 決定 2）へ
    /// 移ったため、評価時点まで保存して持ち越す。
    pub prompt: Option<Prompt>,
    /// 認可リクエストの `max_age`（秒。未指定は `None`）。`prompt` と同じく resume で評価する。
    pub max_age: Option<u64>,
    /// web ハンドオフ用ハンドルの SHA-256（ADR-0018 決定 2）。単回使用: resume での交換時に
    /// `None` へ消費する。ハンドルはこの行（＝その `code_challenge`）に固定的に束ねられ、
    /// 他の認可要求へ付け替えられない。
    pub handle_hash: Option<String>,
    /// ハンドルの有効期限（auth_session 本体の `expires_at` より短命）。
    pub handle_expires_at: Option<DateTime<Utc>>,
    pub authenticated_user_id: Option<Uuid>,
    pub auth_time: Option<DateTime<Utc>>,
    /// パスワード検証成功時刻。非 NULL = パスワード検証済みで TOTP 入力待ち（MFA pending）。
    pub password_verified_at: Option<DateTime<Utc>>,
    /// このフローで確立した SSO セッションの `sid`（G5）。同意画面を挟む経路では code 発行が
    /// ログインと別リクエストになり、その時点では SSO Cookie が手元に無いため、ここへ持ち回す。
    pub sso_sid: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AuthSession {
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// web ハンドオフ用ハンドルが `now` 時点で交換可能か（未消費かつ期限内）。
    pub fn handle_is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.handle_hash.is_some() && self.handle_expires_at.is_some_and(|exp| exp > now)
    }
}
