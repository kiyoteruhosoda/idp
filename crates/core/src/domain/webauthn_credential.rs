//! WebAuthn（FIDO2 Passkey）クレデンシャルエンティティ。
//!
//! ユーザーが登録した Passkey デバイス 1 件を 1 レコードで管理する。
//! `passkey_json` は `webauthn-rs` の `Passkey` 構造体を JSON シリアライズした全体（公開鍵・
//! sign_count・transports など）を保持する。
//! `credential_id` は認証レスポンス到着時にどの `passkey_json` を使うか素早く特定するための
//! インデックス用フィールド（base64url 文字列）。

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct WebAuthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    /// WebAuthn credential ID（base64url）。`passkey_challenges` 解決時の逆引き用。
    pub credential_id: String,
    /// `webauthn_rs::prelude::Passkey` を JSON シリアライズした文字列。
    pub passkey_json: String,
    /// ユーザーが付けた任意のラベル（例: "MacBook Touch ID"）。
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// 直近の認証成功時刻（sign_count 更新時に併せて更新する）。
    pub last_used_at: Option<DateTime<Utc>>,
}
