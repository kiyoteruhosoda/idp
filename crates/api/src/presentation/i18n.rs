//! API 層の国際化（MT19）。
//!
//! `Accept-Language` ヘッダから表示言語を決定し、管理 API のエラーメッセージを翻訳する。
//! エラーコードは言語不変。`message` フィールドのみ翻訳する。
//! 既定ロケールは `ja`（システム既定。`CLAUDE.md` § 国際化）。
//!
//! `FluentBundle` は `!Send` のためリクエスト境界を跨いだ保持が不可。
//! `ApiMessages::new(locale)` でリクエストごとに生成する。

use crate::domain::message::UserMessage;
use fluent::{FluentArgs, FluentBundle, FluentResource};
use unic_langid::{langid, LanguageIdentifier};

const EN_FTL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../i18n/en/main.ftl"
));
const JA_FTL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../i18n/ja/main.ftl"
));

/// API 応答に使うロケール（`Accept-Language` から決定。既定 `Ja`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiLocale {
    En,
    Ja,
}

impl ApiLocale {
    /// `Accept-Language` ヘッダ値からロケールを決める。
    /// 品質値は見ず先着優先。非対応・未指定は既定 `Ja` にフォールバックする。
    /// 地域コードは無視する（`ja-JP` → `Ja`、`en-US` → `En`）。
    pub fn from_accept_language(header: Option<&str>) -> Self {
        let Some(header) = header else {
            return ApiLocale::Ja;
        };
        for part in header.split(',') {
            let tag = part
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if tag == "ja" || tag.starts_with("ja-") {
                return ApiLocale::Ja;
            }
            if tag == "en" || tag.starts_with("en-") {
                return ApiLocale::En;
            }
        }
        ApiLocale::Ja
    }

    fn ftl(&self) -> &'static str {
        match self {
            ApiLocale::En => EN_FTL,
            ApiLocale::Ja => JA_FTL,
        }
    }

    fn lang_id(&self) -> LanguageIdentifier {
        match self {
            ApiLocale::En => langid!("en"),
            ApiLocale::Ja => langid!("ja"),
        }
    }
}

/// axum extractor: `Accept-Language` → `ApiLocale`。
/// ヘッダが無い・非対応の場合は既定 `Ja` を返す。
impl<S> axum::extract::FromRequestParts<S> for ApiLocale
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok());
        Ok(ApiLocale::from_accept_language(header))
    }
}

/// API リクエスト 1 件分の翻訳辞書。リクエストごとに生成する（`FluentBundle` は `!Send`）。
pub struct ApiMessages {
    bundle: FluentBundle<FluentResource>,
}

impl ApiMessages {
    pub fn new(locale: ApiLocale) -> Self {
        let resource =
            FluentResource::try_new(locale.ftl().to_string()).unwrap_or_else(|(res, errors)| {
                tracing::error!(?errors, "fluent resource has syntax errors");
                res
            });
        let mut bundle = FluentBundle::new(vec![locale.lang_id()]);
        bundle.set_use_isolating(false);
        if let Err(errors) = bundle.add_resource(resource) {
            tracing::error!(?errors, "failed to add fluent resource");
        }
        Self { bundle }
    }

    /// 翻訳キーからメッセージを取得する。未定義キーはキー名をそのまま返す（フェイルソフト）。
    pub fn get(&self, key: &str) -> String {
        self.format(key, None)
    }

    /// Application 層が返した [`UserMessage`]（翻訳キー + 埋め込み引数）を訳す（MT19）。
    ///
    /// 文言そのものではなくキーを受け取るため、Application 層は言語を知らなくてよい。
    pub fn message(&self, message: &UserMessage) -> String {
        if message.args().is_empty() {
            return self.format(message.key(), None);
        }
        let mut args = FluentArgs::new();
        for (name, value) in message.args() {
            args.set(*name, value.as_str());
        }
        self.format(message.key(), Some(&args))
    }

    fn format(&self, key: &str, args: Option<&FluentArgs>) -> String {
        let Some(message) = self.bundle.get_message(key) else {
            tracing::warn!(key, "missing api translation key");
            return key.to_string();
        };
        let Some(pattern) = message.value() else {
            return key.to_string();
        };
        let mut errors = Vec::new();
        let value = self.bundle.format_pattern(pattern, args, &mut errors);
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
    fn defaults_to_ja_when_no_header() {
        assert_eq!(ApiLocale::from_accept_language(None), ApiLocale::Ja);
    }

    #[test]
    fn selects_ja_for_ja_tags() {
        assert_eq!(ApiLocale::from_accept_language(Some("ja")), ApiLocale::Ja);
        assert_eq!(
            ApiLocale::from_accept_language(Some("ja-JP")),
            ApiLocale::Ja
        );
    }

    #[test]
    fn selects_en_for_en_tags() {
        assert_eq!(ApiLocale::from_accept_language(Some("en")), ApiLocale::En);
        assert_eq!(
            ApiLocale::from_accept_language(Some("en-US,ja;q=0.8")),
            ApiLocale::En
        );
    }

    #[test]
    fn falls_back_to_ja_for_unsupported_language() {
        assert_eq!(
            ApiLocale::from_accept_language(Some("fr-FR")),
            ApiLocale::Ja
        );
        assert_eq!(
            ApiLocale::from_accept_language(Some("zh-CN,ko;q=0.5")),
            ApiLocale::Ja
        );
    }

    #[test]
    fn api_messages_translates_known_keys() {
        let en = ApiMessages::new(ApiLocale::En);
        assert_eq!(en.get("api-user-not-found"), "User not found.");

        let ja = ApiMessages::new(ApiLocale::Ja);
        assert_eq!(ja.get("api-user-not-found"), "ユーザーが見つかりません。");
    }

    /// 利用者向けメッセージのキーは**両言語**に訳がなければならない。訳が無いとキー名がそのまま
    /// 応答に出る（`get` はフェイルソフトのため気付けない）。キー定数を増やして翻訳リソースへの
    /// 追記を忘れる、という取りこぼしをここで落とす。
    #[test]
    fn every_user_message_key_is_translated_in_both_locales() {
        for locale in [ApiLocale::Ja, ApiLocale::En] {
            let messages = ApiMessages::new(locale);
            for key in crate::domain::message::keys::ALL {
                let translated = messages.get(key);
                assert_ne!(
                    &translated, key,
                    "missing {locale:?} translation for message key `{key}`"
                );
                assert!(
                    !translated.is_empty(),
                    "empty {locale:?} translation for message key `{key}`"
                );
            }
        }
    }

    /// 事前チェックをすり抜けた一意制約違反のフォールバックは、**どちらの項目が重複したかを
    /// 断定しない**中立の文言でなければならない。DB が返すのは「email か preferred_username の
    /// どちらかが重複した」ことだけで、片方と断定すると `preferred_username` を明示指定した
    /// 利用者が username 衝突したときに「重複していないメールを直せ」と誤誘導する。
    #[test]
    fn the_uniqueness_race_fallback_does_not_name_a_single_field() {
        use crate::domain::message::keys;
        let en = ApiMessages::new(ApiLocale::En).get(keys::USER_ALREADY_EXISTS);
        let ja = ApiMessages::new(ApiLocale::Ja).get(keys::USER_ALREADY_EXISTS);
        // 両方の可能性を挙げる（「または」で並記する）文言であること。
        assert!(en.contains("email") && en.contains("username"), "{en}");
        assert!(
            ja.contains("メールアドレス") && ja.contains("ユーザー名"),
            "{ja}"
        );
        // 個別のキーは事前チェック用に残っており、こちらは片方だけを指す。
        let email_only = ApiMessages::new(ApiLocale::En).get(keys::USER_EMAIL_CONFLICT);
        assert!(!email_only.contains("username"), "{email_only}");
    }

    /// 埋め込み引数（Fluent の `{ $name }`）が展開されること。展開されないと利用者には
    /// どの値が問題なのか分からないメッセージが出る。
    #[test]
    fn message_arguments_are_interpolated() {
        use crate::domain::message::{keys, UserMessage};
        let messages = ApiMessages::new(ApiLocale::En);
        let rendered = messages
            .message(&UserMessage::new(keys::CLIENT_SCOPE_UNSUPPORTED).with("scope", "banana"));
        assert!(rendered.contains("banana"), "{rendered}");
        assert!(!rendered.contains("$scope"), "{rendered}");
    }

    #[test]
    fn api_messages_returns_key_for_unknown_keys() {
        let msg = ApiMessages::new(ApiLocale::En);
        assert_eq!(msg.get("no-such-api-key"), "no-such-api-key");
    }
}
