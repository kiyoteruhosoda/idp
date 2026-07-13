//! ログイン画面の国際化（`fluent`、`CLAUDE.md`「国際化」）。
//!
//! 翻訳リソースはリポジトリルートの `i18n/<lang>/main.ftl` をバイナリへ埋め込む。新規メッセージは
//! 英語で定義し、日本語訳は `ja` リソースへ手動追記する。MVP の i18n 対象はログイン画面のみ。
//! （ADR-0007 の P3 で i18n は web crate へ移設予定。現時点では crate ルート相対で参照する。）

use fluent::{FluentBundle, FluentResource};
use unic_langid::{langid, LanguageIdentifier};

const EN_FTL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../i18n/en/main.ftl"
));
const JA_FTL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../i18n/ja/main.ftl"
));

/// 対応ロケール。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    En,
    Ja,
}

impl Locale {
    /// `Accept-Language` ヘッダから表示ロケールを決める（MVP は en / ja の 2 択）。
    /// 非対応・未指定は既定 `Ja` にフォールバックする（MT19: システム既定 `ja` 統一）。
    pub fn from_accept_language(header: Option<&str>) -> Self {
        let Some(header) = header else {
            return Locale::Ja;
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
        Locale::Ja
    }

    /// 言語タグ（`ja` / `en`）からロケールを引く。非対応・不正値は `None`。
    pub fn from_tag(tag: &str) -> Option<Locale> {
        match tag.trim().to_ascii_lowercase().as_str() {
            "ja" => Some(Locale::Ja),
            "en" => Some(Locale::En),
            _ => None,
        }
    }

    /// 言語タグ（`ja` / `en`）を返す（Cookie 保存・セレクタ初期選択に使う）。
    pub fn as_tag(&self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ja => "ja",
        }
    }

    /// 表示言語の決定チェーン（MT20）:
    /// `?lang=` > ユーザー設定（DB）> Cookie(`lang`) > `Accept-Language` > 既定 `Ja`。
    /// 不正・非対応値は無視して次順位へフォールバックする。
    pub fn resolve(
        query_lang: Option<&str>,
        user_language: Option<&str>,
        cookie_lang: Option<&str>,
        accept_language: Option<&str>,
    ) -> Locale {
        if let Some(locale) = query_lang.and_then(Locale::from_tag) {
            return locale;
        }
        if let Some(locale) = user_language.and_then(Locale::from_tag) {
            return locale;
        }
        if let Some(locale) = cookie_lang.and_then(Locale::from_tag) {
            return locale;
        }
        Locale::from_accept_language(accept_language)
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
        assert_eq!(Locale::from_accept_language(None), Locale::Ja);
        assert_eq!(
            Locale::from_accept_language(Some("ja,en-US;q=0.9")),
            Locale::Ja
        );
        assert_eq!(
            Locale::from_accept_language(Some("en-US,ja;q=0.8")),
            Locale::En
        );
        assert_eq!(Locale::from_accept_language(Some("fr-FR")), Locale::Ja);
    }

    #[test]
    fn resolve_prefers_query_then_user_language_then_cookie_then_accept_language() {
        // ?lang= が最優先。
        assert_eq!(
            Locale::resolve(Some("ja"), Some("en"), Some("en"), Some("en-US")),
            Locale::Ja
        );
        // ?lang= が無効ならユーザー設定（DB）。
        assert_eq!(
            Locale::resolve(Some("fr"), Some("ja"), Some("en"), Some("en-US")),
            Locale::Ja
        );
        // ?lang= ・ユーザー設定が無効なら Cookie。
        assert_eq!(
            Locale::resolve(Some("fr"), Some("zz"), Some("ja"), Some("en-US")),
            Locale::Ja
        );
        // いずれも無い場合は Accept-Language。
        assert_eq!(
            Locale::resolve(None, None, None, Some("ja,en;q=0.8")),
            Locale::Ja
        );
        // すべて無効・未指定なら既定 Ja（MT19: システム既定 ja 統一）。
        assert_eq!(
            Locale::resolve(Some("fr"), Some("zz"), Some("zz"), Some("fr")),
            Locale::Ja
        );
    }

    #[test]
    fn from_tag_and_as_tag_roundtrip() {
        assert_eq!(Locale::from_tag("JA"), Some(Locale::Ja));
        assert_eq!(Locale::from_tag(" en "), Some(Locale::En));
        assert_eq!(Locale::from_tag("fr"), None);
        assert_eq!(Locale::Ja.as_tag(), "ja");
        assert_eq!(Locale::En.as_tag(), "en");
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
