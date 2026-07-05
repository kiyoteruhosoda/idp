//! ログイン画面の国際化（`fluent`、`CLAUDE.md`「国際化」）。
//!
//! 翻訳リソースは `i18n/<lang>/main.ftl` をバイナリへ埋め込む。新規メッセージは英語で定義し、
//! 日本語訳は `ja` リソースへ手動追記する。MVP の i18n 対象はログイン画面のみ。

use fluent::{FluentBundle, FluentResource};
use unic_langid::{langid, LanguageIdentifier};

const EN_FTL: &str = include_str!("../../i18n/en/main.ftl");
const JA_FTL: &str = include_str!("../../i18n/ja/main.ftl");

/// 対応ロケール。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    En,
    Ja,
}

impl Locale {
    /// `Accept-Language` ヘッダから表示ロケールを決める（MVP は en / ja の 2 択）。
    pub fn from_accept_language(header: Option<&str>) -> Self {
        let Some(header) = header else {
            return Locale::En;
        };
        // 品質値は見ず、先に現れた対応言語を選ぶ簡易実装。
        for part in header.split(',') {
            let tag = part
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if tag == "ja" || tag.starts_with("ja-") {
                return Locale::Ja;
            }
            if tag == "en" || tag.starts_with("en-") {
                return Locale::En;
            }
        }
        Locale::En
    }

    fn ftl(&self) -> &'static str {
        match self {
            Locale::En => EN_FTL,
            Locale::Ja => JA_FTL,
        }
    }

    fn lang_id(&self) -> LanguageIdentifier {
        match self {
            Locale::En => langid!("en"),
            Locale::Ja => langid!("ja"),
        }
    }
}

/// ログイン画面 1 回のレンダリング用メッセージ辞書。
pub struct Messages {
    bundle: FluentBundle<FluentResource>,
}

impl Messages {
    pub fn new(locale: Locale) -> Self {
        let resource =
            FluentResource::try_new(locale.ftl().to_string()).unwrap_or_else(|(res, errors)| {
                tracing::error!(?errors, "fluent resource has syntax errors");
                res
            });
        let mut bundle = FluentBundle::new(vec![locale.lang_id()]);
        // HTML へ埋め込むため Unicode 分離文字（FSI/PDI）は挿入しない。
        bundle.set_use_isolating(false);
        if let Err(errors) = bundle.add_resource(resource) {
            tracing::error!(?errors, "failed to add fluent resource");
        }
        Self { bundle }
    }

    /// 翻訳キーからメッセージを取得する。未定義キーはキー名をそのまま返す（フェイルソフト）。
    pub fn get(&self, key: &str) -> String {
        let Some(message) = self.bundle.get_message(key) else {
            tracing::warn!(key, "missing translation key");
            return key.to_string();
        };
        let Some(pattern) = message.value() else {
            return key.to_string();
        };
        let mut errors = Vec::new();
        let value = self.bundle.format_pattern(pattern, None, &mut errors);
        if !errors.is_empty() {
            tracing::warn!(key, ?errors, "fluent formatting errors");
        }
        value.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_locale_from_accept_language() {
        assert_eq!(Locale::from_accept_language(None), Locale::En);
        assert_eq!(
            Locale::from_accept_language(Some("ja,en-US;q=0.9")),
            Locale::Ja
        );
        assert_eq!(
            Locale::from_accept_language(Some("en-US,ja;q=0.8")),
            Locale::En
        );
        assert_eq!(Locale::from_accept_language(Some("fr-FR")), Locale::En);
    }

    #[test]
    fn resolves_messages_in_both_locales() {
        let en = Messages::new(Locale::En);
        assert_eq!(en.get("login-title"), "Sign in");
        let ja = Messages::new(Locale::Ja);
        assert_eq!(ja.get("login-title"), "サインイン");
        // 未定義キーはキー名を返す。
        assert_eq!(en.get("no-such-key"), "no-such-key");
    }
}
