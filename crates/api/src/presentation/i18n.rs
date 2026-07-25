//! API 層の国際化（MT19）。
//!
//! `Accept-Language` ヘッダから表示言語を決定し、API のエラーメッセージを翻訳する。
//! **エラーコードは言語不変**（`error` フィールドは固定値）で、`message` のみ翻訳する。
//! 既定ロケールは `ja`（システム既定。`CLAUDE.md`「国際化」）。参照するのは `Accept-Language`
//! だけで、Cookie・セッション・URL クエリ・DB のユーザー設定は見ない（表示言語の決定は web の責務）。
//!
//! Domain / Application 層は訳文を持たず [`crate::domain::message::MessageKey`] を返す。
//! [`ApiMessages::get_message`] がそれを訳出する（層をまたいで文言をコピーしないための境界）。
//!
//! **翻訳の対象外**:
//!
//! * OAuth 2.0 / OIDC のプロトコルエラー（`/token`・`/authorize`・`/introspect`・`/revoke`・
//!   `/userinfo`）。`error` はもちろん `error_description` も RFC 6749 §4.1.2.1 が
//!   「クライアント開発者向け」と定める機械/開発者向けの値であり、RP に届く固定文字列として扱う。
//!   RP のログや自動処理が文言に依存し得るため、リクエストごとに言語を変えない。
//! * 500（`server_error`）の本文。内部エラーの詳細はクライアントへ出さず固定文字列を返す
//!   （[`crate::presentation::error::ApiError`]）。利用者に取れる行動が無く、翻訳しても
//!   得られるものが無い一方、ロケール解決の経路を増やす。
//! * 内部ログ・監査ログ（運用言語＝英語で統一する。`CLAUDE.md`「ログ」）。
//!
//! `FluentBundle` は `!Send` のためリクエスト境界を跨いだ保持が不可。
//! `ApiMessages::new(locale)` でリクエストごとに生成する。

use crate::domain::message::MessageKey;
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

    /// Domain / Application 層が返した [`MessageKey`] を訳出する（MT19）。
    /// 差し込み値は翻訳文の `{ $value }` に入る。
    pub fn get_message(&self, message: &MessageKey) -> String {
        match message.value() {
            Some(value) => {
                let mut args = FluentArgs::new();
                args.set("value", value);
                self.format(message.key(), Some(&args))
            }
            None => self.format(message.key(), None),
        }
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

    #[test]
    fn api_messages_returns_key_for_unknown_keys() {
        let msg = ApiMessages::new(ApiLocale::En);
        assert_eq!(msg.get("no-such-api-key"), "no-such-api-key");
    }

    #[test]
    fn message_keys_interpolate_their_value() {
        let en = ApiMessages::new(ApiLocale::En);
        let msg = en.get_message(&MessageKey::with_value("api-password-too-short", "8"));
        assert!(msg.contains('8'), "{msg}");
        assert!(
            !msg.contains("$value"),
            "placeholder must be substituted: {msg}"
        );

        let ja = ApiMessages::new(ApiLocale::Ja);
        let msg = ja.get_message(&MessageKey::with_value("api-password-too-short", "8"));
        assert!(msg.contains('8'), "{msg}");
    }

    /// コード側で使う `api-*` キーは **en / ja の両方**に訳が無ければならない。
    /// 片方だけだと、その言語の利用者にキー名（`api-client-scope-unsupported`）がそのまま出る。
    /// 訳文を足し忘れたまま気付けないので、ソースからキーを抽出して突き合わせる。
    #[test]
    fn every_api_message_key_used_in_code_is_translated_in_both_locales() {
        let sources = [
            include_str!("handlers/admin_clients.rs"),
            include_str!("handlers/admin_invitations.rs"),
            include_str!("handlers/admin_members.rs"),
            include_str!("handlers/admin_permissions.rs"),
            include_str!("handlers/admin_saml_service_providers.rs"),
            include_str!("handlers/admin_signing_keys.rs"),
            include_str!("handlers/admin_system_settings.rs"),
            include_str!("handlers/admin_tenants.rs"),
            include_str!("handlers/admin_users.rs"),
            include_str!("handlers/admin_audit.rs"),
            include_str!("handlers/invitations.rs"),
            include_str!("handlers/register.rs"),
            include_str!("handlers/mod.rs"),
            // Domain / Application 層が返す MessageKey の定義元。
            include_str!("../../../core/src/domain/values.rs"),
            include_str!("../../../core/src/domain/password.rs"),
            include_str!("../../../core/src/domain/saml_service_provider.rs"),
            include_str!("../../../core/src/application/client_management.rs"),
            include_str!("../../../core/src/application/invitation.rs"),
            include_str!("../../../core/src/application/key_service.rs"),
            include_str!("../../../core/src/application/permission_management.rs"),
            include_str!("../../../core/src/application/register.rs"),
            include_str!("../../../core/src/application/tenant_management.rs"),
            include_str!("../../../core/src/application/user_lifecycle.rs"),
            include_str!("../../../core/src/application/user_management.rs"),
        ];

        let mut keys: Vec<String> = Vec::new();
        for source in sources {
            for (index, _) in source.match_indices("\"api-") {
                let rest = &source[index + 1..];
                let Some(end) = rest.find('"') else { continue };
                let key = &rest[..end];
                if key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                {
                    keys.push(key.to_string());
                }
            }
        }
        keys.sort();
        keys.dedup();
        assert!(
            keys.len() > 40,
            "expected to find the api keys, got {keys:?}"
        );

        for locale in [ApiLocale::En, ApiLocale::Ja] {
            let messages = ApiMessages::new(locale);
            let missing: Vec<&String> = keys
                .iter()
                .filter(|key| messages.get(key) == **key)
                .collect();
            assert!(
                missing.is_empty(),
                "{locale:?} is missing translations for {missing:?}"
            );
        }
    }
}
