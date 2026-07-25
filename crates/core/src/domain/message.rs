//! 利用者へ返すメッセージの翻訳キー（MT19）。
//!
//! Domain / Application 層は**訳文を持たず**、翻訳キーと差し込み値だけを返す。実際の訳出は
//! Presentation 層が `Accept-Language` に応じて行う（`CLAUDE.md`「国際化」の責務分離）。
//! これにより、同じユースケースのエラーが api の応答では利用者の言語、内部ログでは運用言語（英語）
//! という二重の要求を、文言をコピーせずに満たせる。
//!
//! `Display` はキー（と差し込み値）をそのまま出す。運用ログ・監査ログには翻訳前のキーが残るため、
//! 言語設定に関係なくグレップでき、訳文を変えてもログの検索性が壊れない。

use std::fmt;

/// 翻訳キーと、翻訳文の `{ $value }` へ差し込む値（対象の URI・scope 名など）。
///
/// キーは静的文字列に限る（動的キーは翻訳リソースとの対応が実行時までわからず、
/// 「訳が無いキー」を静かに増やす）。値だけを実行時に受け取る。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKey {
    key: &'static str,
    value: Option<String>,
}

impl MessageKey {
    /// 差し込み値を持たないメッセージ。
    pub const fn new(key: &'static str) -> Self {
        Self { key, value: None }
    }

    /// 差し込み値を持つメッセージ（翻訳文の `{ $value }` に入る）。
    pub fn with_value(key: &'static str, value: impl Into<String>) -> Self {
        Self {
            key,
            value: Some(value.into()),
        }
    }

    pub fn key(&self) -> &'static str {
        self.key
    }

    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl fmt::Display for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{}: {value}", self.key),
            None => write!(f, "{}", self.key),
        }
    }
}

impl From<&'static str> for MessageKey {
    fn from(key: &'static str) -> Self {
        Self::new(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_the_key_so_logs_stay_greppable() {
        assert_eq!(
            MessageKey::new("api-client-scopes-empty").to_string(),
            "api-client-scopes-empty"
        );
        assert_eq!(
            MessageKey::with_value("api-client-scope-unsupported", "offline_access").to_string(),
            "api-client-scope-unsupported: offline_access"
        );
    }

    #[test]
    fn value_is_optional() {
        assert_eq!(MessageKey::new("k").value(), None);
        assert_eq!(MessageKey::with_value("k", "v").value(), Some("v"));
    }
}
