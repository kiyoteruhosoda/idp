//! メンバーの管理者メモ（ADR-0063）。
//!
//! 「どういう経緯のアカウントか」を管理者が書き残す自由記述。**人に向けたものであって、判定には
//! 一切使わない**（ログイン・トークン・名簿のどこにも写さない）。
//!
//! メモはテナントの管理者が持つ事実なので、利用者ではなく**メンバーシップ**（テナント × 利用者）に
//! 付く。同じ人でも HOME とゲスト先では別のことを書く。

use crate::domain::message::MessageKey;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// メモの上限（文字数）。経緯を数行書くには十分で、議事録を貼り付ける場所にはしない長さ。
///
/// 列は `TEXT`（64KB）なので、⚠ **バイトではなく文字で数える**（日本語は 1 文字 3 バイト）。
/// 値は web の入力欄と共有する（契約 crate が単一の出所）。
pub use assay_contracts::admin::MEMBER_NOTE_MAX_LEN;

/// 保存されているメモ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberNote {
    pub text: String,
    pub updated_at: DateTime<Utc>,
    /// 最後に書いた管理者。機械経由・書いた人が消えた場合は `None`。
    pub updated_by: Option<Uuid>,
}

/// 入力を検証し、保存する値を返す。**空（空白だけ）なら `None` ＝ メモを消す。**
///
/// 改行は `\n` に揃え、前後の空白は落とす。行の中の空白は書いたとおりに残す（字下げで
/// 箇条書きにする人がいる）。
pub fn normalize_member_note(raw: &str) -> Result<Option<String>, MessageKey> {
    let unified = raw.replace("\r\n", "\n").replace('\r', "\n");
    let value = unified.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > MEMBER_NOTE_MAX_LEN {
        return Err(MessageKey::with_value(
            "api-member-note-too-long",
            MEMBER_NOTE_MAX_LEN.to_string(),
        ));
    }
    Ok(Some(value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_input_clears_the_note() {
        assert_eq!(normalize_member_note(""), Ok(None));
        assert_eq!(normalize_member_note("  \r\n \n\t"), Ok(None));
    }

    #[test]
    fn line_endings_are_unified_and_outer_whitespace_is_trimmed() {
        assert_eq!(
            normalize_member_note("\r\n 家族。\r\n  - 2026-09 に招待\r\n"),
            Ok(Some("家族。\n  - 2026-09 に招待".to_string()))
        );
    }

    #[test]
    fn limit_is_counted_in_characters_not_bytes() {
        let at_limit = "あ".repeat(MEMBER_NOTE_MAX_LEN);
        assert_eq!(normalize_member_note(&at_limit), Ok(Some(at_limit.clone())));
        let over = "あ".repeat(MEMBER_NOTE_MAX_LEN + 1);
        assert!(normalize_member_note(&over).is_err());
    }
}
