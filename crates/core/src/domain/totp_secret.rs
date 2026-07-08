//! TOTP（Time-based One-Time Password）シークレットエンティティ。
//!
//! MFA は任意。ユーザーが自分で登録・確認・削除する。
//! `confirmed_at IS NULL` なら仮登録中（QR 確認未完了）。
//! `confirmed_at IS NOT NULL` なら有効な MFA 設定。

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TotpSecret {
    pub user_id: Uuid,
    /// AES-256-GCM で暗号化したシークレットバイト列（`crypto::encrypt` 方式）。
    pub secret_encrypted: String,
    /// NULL = 仮登録中、非 NULL = 有効化済み。
    pub confirmed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TotpSecret {
    /// TOTP が有効（ユーザーがセットアップを完了している）か。
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }
}
