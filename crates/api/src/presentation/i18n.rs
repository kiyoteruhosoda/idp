//! API 層の国際化（MT19）。
//!
//! `Accept-Language` ヘッダから表示言語を決定し、管理 API のエラーメッセージを翻訳する。
//! エラーコードは言語不変。`message` フィールドのみ翻訳する。
//! 既定ロケールは `ja`（システム既定。`CLAUDE.md` § 国際化）。
//!
//! `FluentBundle` は `!Send` のためリクエスト境界を跨いだ保持が不可。
//! `ApiMessages::new(locale)` でリクエストごとに生成する。

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
        let Some(message) = self.bundle.get_message(key) else {
            tracing::warn!(key, "missing api translation key");
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
    fn defaults_to_ja_when_no_header() {
        assert_eq!(ApiLocale::from_accept_language(None), ApiLocale::Ja);
    }

    #[test]
    fn selects_ja_for_ja_tags() {
        assert_eq!(
            ApiLocale::from_accept_language(Some("ja")),
            ApiLocale::Ja
        );
        assert_eq!(
            ApiLocale::from_accept_language(Some("ja-JP")),
            ApiLocale::Ja
        );
    }

    #[test]
    fn selects_en_for_en_tags() {
        assert_eq!(
            ApiLocale::from_accept_language(Some("en")),
            ApiLocale::En
        );
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

    #[test]
    fn api_messages_returns_key_for_unknown_keys() {
        let msg = ApiMessages::new(ApiLocale::En);
        assert_eq!(msg.get("no-such-api-key"), "no-such-api-key");
    }
}
