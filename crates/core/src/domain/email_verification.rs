//! メール検証トークン（自己登録アカウントのメール所有確認。SEC6b）。
//!
//! 平文トークンはメールのリンクでのみ本人へ渡し、保存は SHA-256 hex（`token_hash`）のみ。
//! `used_at` の設定で単回消費とする（password_reset_tokens と同じ one-time パターン）。

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EmailVerificationToken {
    /// 検証トークンの SHA-256 hex（平文は保存しない）。
    pub token_hash: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    /// 消費時刻。`None` = 未使用。
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
