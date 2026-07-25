//! 利用者向けメッセージの翻訳キー（MT19。CLAUDE.md「国際化」）。
//!
//! Application 層は利用者へ見せる文言そのものではなく **キー**（[`UserMessage`]）を返し、
//! Presentation 層が `Accept-Language` に応じて訳す。キーは言語不変で、エラーコード（HTTP 応答の
//! `error` フィールド）と同じく固定値として扱う。
//!
//! 対象は利用者向けメッセージだけである。ログ・監査ログ・例外詳細といった運用情報は
//! 多言語化せず英語で統一するため（CLAUDE.md「多言語化の対象範囲」）、各エラーの `Internal`
//! バリアントは従来どおり `String`（英語）を持つ。

use std::fmt;

/// 利用者向けメッセージの翻訳キーと、その埋め込み引数。
///
/// 文言を持たずキーだけを運ぶのが要点で、Application 層が言語を意識しなくて済む。
/// `Display` はキーと引数を素直に並べた運用向けの表現を返す（ログ用。翻訳結果ではない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMessage {
    key: &'static str,
    args: Vec<(&'static str, String)>,
}

impl UserMessage {
    /// 引数を持たないメッセージ。
    pub const fn new(key: &'static str) -> Self {
        Self {
            key,
            args: Vec::new(),
        }
    }

    /// 埋め込み引数を追加する（Fluent の `{ $name }` に対応）。
    pub fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.args.push((name, value.into()));
        self
    }

    pub fn key(&self) -> &'static str {
        self.key
    }

    pub fn args(&self) -> &[(&'static str, String)] {
        &self.args
    }
}

/// ログ・`thiserror` の `{0}` 展開向けの表現。**翻訳結果ではない**（運用言語は英語で統一する）。
impl fmt::Display for UserMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key)?;
        for (name, value) in &self.args {
            write!(f, " {name}={value}")?;
        }
        Ok(())
    }
}

/// 利用者向けメッセージの翻訳キー一覧。
///
/// 定数として集中管理するのは、翻訳リソース（`i18n/*/main.ftl`）との対応をテストで機械的に
/// 検証するためである（[`ALL`] を回して両言語に定義があることを確かめる）。キーを呼び出し側へ
/// 文字列で散らすと、訳の抜けはその画面を開くまで分からない。
pub mod keys {
    // --- 共通 -----------------------------------------------------------------------------
    pub const INVALID_REQUEST: &str = "api-invalid-request";
    pub const FORBIDDEN: &str = "api-permission-forbidden";

    // --- 利用者 ---------------------------------------------------------------------------
    pub const USER_NOT_FOUND: &str = "api-user-not-found";
    pub const USER_EMAIL_CONFLICT: &str = "api-user-email-conflict";
    pub const USER_USERNAME_CONFLICT: &str = "api-user-username-conflict";
    pub const USER_EMAIL_REQUIRED: &str = "api-user-email-required";
    pub const USER_EMAIL_INVALID: &str = "api-user-email-invalid";
    pub const USER_USERNAME_TOO_LONG: &str = "api-user-username-too-long";
    pub const USER_STATUS_INVALID: &str = "api-user-status-invalid";
    pub const USER_STATUS_LOCKED_NOT_ALLOWED: &str = "api-user-status-locked-not-allowed";
    pub const USER_SELF_OPERATION_FORBIDDEN: &str = "api-user-self-operation-forbidden";
    pub const PASSWORD_TOO_SHORT: &str = "api-password-too-short";
    pub const PASSWORD_TOO_LONG: &str = "api-password-too-long";

    // --- 自己登録 -------------------------------------------------------------------------
    pub const REGISTER_DISABLED: &str = "api-register-disabled";
    pub const REGISTER_RATE_LIMITED: &str = "api-register-rate-limited";
    pub const REGISTER_VERIFICATION_INVALID: &str = "api-register-verification-invalid";

    // --- メンバー・招待 -------------------------------------------------------------------
    pub const MEMBER_NOT_FOUND: &str = "api-member-not-found";
    pub const MEMBER_ALREADY: &str = "api-member-already";
    pub const MEMBER_HOME_CANNOT_REMOVE: &str = "api-member-home-cannot-remove";
    pub const MEMBER_SUSPEND_NOT_ALLOWED: &str = "api-member-suspend-not-allowed";
    pub const MEMBER_RESUME_NOT_ALLOWED: &str = "api-member-resume-not-allowed";
    pub const INVITATION_INVALID_OR_EXPIRED: &str = "api-invitation-invalid-or-expired";
    pub const INVITATION_ACCEPT_FORBIDDEN: &str = "api-invitation-accept-forbidden";
    pub const INVITATION_USER_NOT_FOUND: &str = "api-invitation-user-not-found";

    // --- 権限 -----------------------------------------------------------------------------
    pub const PERMISSION_UNKNOWN: &str = "api-permission-unknown";
    pub const PERMISSION_SYSTEM_ADMIN_ONLY: &str = "api-permission-system-admin-only";

    // --- クライアント ---------------------------------------------------------------------
    pub const CLIENT_NOT_FOUND: &str = "api-client-not-found";
    pub const CLIENT_TYPE_INVALID: &str = "api-client-type-invalid";
    pub const CLIENT_STATUS_INVALID: &str = "api-client-status-invalid";
    pub const CLIENT_ID_CONFLICT: &str = "api-client-id-conflict";
    pub const CLIENT_SECRET_PUBLIC: &str = "api-client-secret-public";
    pub const CLIENT_APP_NAME_REQUIRED: &str = "api-client-app-name-required";
    pub const CLIENT_REDIRECT_URI_REQUIRED: &str = "api-client-redirect-uri-required";
    pub const CLIENT_REDIRECT_URI_DUPLICATE: &str = "api-client-redirect-uri-duplicate";
    pub const CLIENT_REDIRECT_URI_WILDCARD: &str = "api-client-redirect-uri-wildcard";
    pub const CLIENT_REDIRECT_URI_INVALID: &str = "api-client-redirect-uri-invalid";
    pub const CLIENT_REDIRECT_URI_SCHEME: &str = "api-client-redirect-uri-scheme";
    pub const CLIENT_REDIRECT_URI_FRAGMENT: &str = "api-client-redirect-uri-fragment";
    pub const CLIENT_SCOPE_REQUIRED: &str = "api-client-scope-required";
    pub const CLIENT_SCOPE_UNSUPPORTED: &str = "api-client-scope-unsupported";
    pub const CLIENT_SCOPE_DUPLICATE: &str = "api-client-scope-duplicate";
    pub const CLIENT_SCOPE_OPENID_REQUIRED: &str = "api-client-scope-openid-required";

    // --- テナント -------------------------------------------------------------------------
    pub const TENANT_NOT_FOUND: &str = "api-tenant-not-found";
    pub const TENANT_NAME_REQUIRED: &str = "api-tenant-name-required";
    pub const TENANT_HAS_CHILDREN: &str = "api-tenant-has-children";
    pub const TENANT_NOT_EMPTY: &str = "api-tenant-not-empty";
    pub const TENANT_ALREADY_EXISTS: &str = "api-tenant-already-exists";
    pub const TENANT_ROOT_CANNOT_DELETE: &str = "api-tenant-root-cannot-delete";

    // --- 署名鍵 ---------------------------------------------------------------------------
    pub const SIGNING_KEY_NOT_FOUND: &str = "api-signing-key-not-found";
    pub const SIGNING_KEY_ALREADY_RETIRED: &str = "api-signing-key-already-retired";
    pub const SIGNING_KEY_ACTIVE_CANNOT_DELETE: &str = "api-signing-key-active-cannot-delete";

    // --- SAML SP --------------------------------------------------------------------------
    pub const SAML_SP_NOT_FOUND: &str = "api-saml-sp-not-found";
    pub const SAML_SP_ENTITY_ID_CONFLICT: &str = "api-saml-sp-entity-id-conflict";

    // --- 監査ログ -------------------------------------------------------------------------
    pub const AUDIT_INVALID_DATETIME: &str = "api-audit-invalid-datetime";

    /// 全キー。翻訳リソースとの対応を検証するテストが回す。
    pub const ALL: &[&str] = &[
        INVALID_REQUEST,
        FORBIDDEN,
        USER_NOT_FOUND,
        USER_EMAIL_CONFLICT,
        USER_USERNAME_CONFLICT,
        USER_EMAIL_REQUIRED,
        USER_EMAIL_INVALID,
        USER_USERNAME_TOO_LONG,
        USER_STATUS_INVALID,
        USER_STATUS_LOCKED_NOT_ALLOWED,
        USER_SELF_OPERATION_FORBIDDEN,
        PASSWORD_TOO_SHORT,
        PASSWORD_TOO_LONG,
        REGISTER_DISABLED,
        REGISTER_RATE_LIMITED,
        REGISTER_VERIFICATION_INVALID,
        MEMBER_NOT_FOUND,
        MEMBER_ALREADY,
        MEMBER_HOME_CANNOT_REMOVE,
        MEMBER_SUSPEND_NOT_ALLOWED,
        MEMBER_RESUME_NOT_ALLOWED,
        INVITATION_INVALID_OR_EXPIRED,
        INVITATION_ACCEPT_FORBIDDEN,
        INVITATION_USER_NOT_FOUND,
        PERMISSION_UNKNOWN,
        PERMISSION_SYSTEM_ADMIN_ONLY,
        CLIENT_NOT_FOUND,
        CLIENT_TYPE_INVALID,
        CLIENT_STATUS_INVALID,
        CLIENT_ID_CONFLICT,
        CLIENT_SECRET_PUBLIC,
        CLIENT_APP_NAME_REQUIRED,
        CLIENT_REDIRECT_URI_REQUIRED,
        CLIENT_REDIRECT_URI_DUPLICATE,
        CLIENT_REDIRECT_URI_WILDCARD,
        CLIENT_REDIRECT_URI_INVALID,
        CLIENT_REDIRECT_URI_SCHEME,
        CLIENT_REDIRECT_URI_FRAGMENT,
        CLIENT_SCOPE_REQUIRED,
        CLIENT_SCOPE_UNSUPPORTED,
        CLIENT_SCOPE_DUPLICATE,
        CLIENT_SCOPE_OPENID_REQUIRED,
        TENANT_NOT_FOUND,
        TENANT_NAME_REQUIRED,
        TENANT_HAS_CHILDREN,
        TENANT_NOT_EMPTY,
        TENANT_ALREADY_EXISTS,
        TENANT_ROOT_CANNOT_DELETE,
        SIGNING_KEY_NOT_FOUND,
        SIGNING_KEY_ALREADY_RETIRED,
        SIGNING_KEY_ACTIVE_CANNOT_DELETE,
        SAML_SP_NOT_FOUND,
        SAML_SP_ENTITY_ID_CONFLICT,
        AUDIT_INVALID_DATETIME,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_the_key_and_arguments_for_logs() {
        let message = UserMessage::new(keys::CLIENT_SCOPE_UNSUPPORTED).with("scope", "banana");
        assert_eq!(
            message.to_string(),
            "api-client-scope-unsupported scope=banana"
        );
        assert_eq!(message.key(), "api-client-scope-unsupported");
        assert_eq!(message.args(), [("scope", "banana".to_string())]);
    }

    /// キー一覧に重複があると、翻訳リソースとの突き合わせが漏れを見逃す。
    #[test]
    fn all_keys_are_unique() {
        let mut sorted = keys::ALL.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), before, "duplicate message key");
    }

    /// 定数として定義したキーは必ず `ALL` に載せる（載せ忘れると翻訳の検証から漏れる）。
    /// ソースを読んで `pub const NAME: &str = "..."` を数え、`ALL` の要素数と突き合わせる。
    #[test]
    fn every_declared_key_is_listed_in_all() {
        let source = include_str!("message.rs");
        let declared = source
            .lines()
            .filter(|line| line.trim_start().starts_with("pub const "))
            .filter(|line| line.contains(": &str = \"api-"))
            .count();
        assert_eq!(
            declared,
            keys::ALL.len(),
            "every `pub const ...: &str = \"api-...\"` must be listed in keys::ALL"
        );
    }
}
