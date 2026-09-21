//! パスワードリセット／アカウント設定のワンタイムトークン（MT18・ADR-0062）。
//!
//! 平文トークンはリンクでのみ本人へ渡し、保存は SHA-256 hex（`token_hash`）のみ。
//! `used_at` の設定で単回消費とする（authorization code と同じ one-time パターン）。

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// リンクの用途。**同じ 1 本のトークンで、リンク先にできることだけが変わる**（ADR-0062）。
///
/// DB はネイティブ ENUM を使わず `VARCHAR` + `CHECK` なので、許可値の単一の出所はこの enum。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetPurpose {
    /// 本人が要求したパスワード再設定（忘失時。MT18）。
    Reset,
    /// 管理者が発行したアカウント設定。パスワードの設定に加えて**パスキーの登録**も許す。
    Setup,
}

impl ResetPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResetPurpose::Reset => "reset",
            ResetPurpose::Setup => "setup",
        }
    }

    /// 保存値から復元する。⚠ **知らない値は `Reset` に丸めない** —— 丸めると、将来足した用途の
    /// 行が「本人の再設定」として扱われ、その用途でだけ許している操作が黙って通る。
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reset" => Some(ResetPurpose::Reset),
            "setup" => Some(ResetPurpose::Setup),
            _ => None,
        }
    }

    /// この用途のリンクで**パスキーを登録してよいか**。
    ///
    /// 許すのは `setup` だけ。`reset` は「パスワードを忘れた」経路で、そこに認証器を足せると、
    /// メールを一時的に読める相手が居座る手段を得てしまう（パスワードなら次の再設定で切れる）。
    pub fn allows_passkey_registration(&self) -> bool {
        matches!(self, ResetPurpose::Setup)
    }
}

#[derive(Debug, Clone)]
pub struct PasswordResetToken {
    /// トークンの SHA-256 hex（平文は保存しない）。
    pub token_hash: String,
    pub user_id: Uuid,
    pub purpose: ResetPurpose,
    pub expires_at: DateTime<Utc>,
    /// 消費時刻。`None` = 未使用。
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purpose_round_trips_through_its_stored_value() {
        for purpose in [ResetPurpose::Reset, ResetPurpose::Setup] {
            assert_eq!(ResetPurpose::parse(purpose.as_str()), Some(purpose));
        }
    }

    #[test]
    fn an_unknown_purpose_is_not_rounded_to_reset() {
        assert_eq!(ResetPurpose::parse("activation"), None);
        assert_eq!(ResetPurpose::parse(""), None);
    }

    /// パスキーを足せるのは管理者が出したリンクだけ。
    #[test]
    fn only_a_setup_link_may_register_a_passkey() {
        assert!(ResetPurpose::Setup.allows_passkey_registration());
        assert!(!ResetPurpose::Reset.allows_passkey_registration());
    }
}
