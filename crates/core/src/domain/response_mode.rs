//! 認可応答の返し方（`response_mode`。OAuth 2.0 Multiple Response Type Encoding Practices。G12）。
//!
//! 認可応答（`code` と `state`、あるいはエラー）を **どうやって RP へ渡すか**を決める。
//!
//! - `query`（既定）: `redirect_uri` のクエリ文字列に載せて 302 する。
//! - `form_post`: 自動送信フォームの hidden フィールドに載せて `redirect_uri` へ POST する。
//!
//! # なぜ `form_post` が要るか
//!
//! `query` では認可コードが **URL に載る**。URL はブラウザの履歴・`Referer`・プロキシやサーバの
//! アクセスログに残る。コードは 60 秒・単回使用で PKCE も必須なので直ちに悪用できるわけではないが、
//! 「秘密を URL に置かない」ことを要求する配置は珍しくない。
//!
//! # URL からは復元できない
//!
//! 完成した URL を持ち回して、後から「送信先とパラメータ」へ戻すことはできない。`redirect_uri`
//! 自身がクエリを持ち得る（`https://rp.example.com/cb?tenant=a`）ため、どこまでが RP の
//! クエリでどこからが認可応答かを URL だけでは決められない。だから応答は**最初から
//! 「送信先＋パラメータ」の形**（[`AuthorizationResponse`]）で組み立て、`query` のときにだけ
//! URL へ畳む。

use crate::domain::error::DomainError;

/// assay が対応する `response_mode`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseMode {
    /// クエリ文字列に載せて 302（既定。RFC 6749 の `code` フローの標準）。
    #[default]
    Query,
    /// 自動送信フォームで POST（OAuth 2.0 Form Post Response Mode）。
    FormPost,
}

impl ResponseMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }

    /// 要求値を解釈する。**未知の値は既定へ丸めずエラーにする**（OAuth 2.0 Multiple Response
    /// Type Encoding Practices）。丸めると、RP は `form_post` を要求したつもりでコードが URL に
    /// 載って返り、しかもそれに気づけない——「秘密を URL に置かない」という要求が黙って破られる。
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw.trim() {
            "query" => Ok(Self::Query),
            "form_post" => Ok(Self::FormPost),
            other => Err(DomainError::InvalidValue(format!(
                "unsupported response_mode: {other}"
            ))),
        }
    }

    /// 保存値（`auth_sessions.response_mode`）から復元する。未知・未設定は既定（`query`）。
    ///
    /// ここだけ丸めるのは、**保存値は既に検証を通った値**だからである（未知の値は
    /// [`Self::parse`] が `/authorize` で弾いている）。読み出しで失敗させると、列が増える前から
    /// 進行中だったフローが完了できなくなる。
    pub fn from_stored(raw: Option<&str>) -> Self {
        raw.and_then(|v| Self::parse(v).ok()).unwrap_or_default()
    }

    /// 保存する値。既定（`query`）は `None`（列を使わない）。
    pub fn to_stored(self) -> Option<&'static str> {
        match self {
            Self::Query => None,
            Self::FormPost => Some(self.as_str()),
        }
    }
}

/// 認可応答（送信先とパラメータ）。
///
/// **URL 文字列ではなくこの形で持ち回す**のがこの型の要点である（理由はモジュールドキュメント）。
/// `query` のときだけ [`Self::location`] で URL へ畳む。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationResponse {
    pub redirect_uri: String,
    /// 認可応答のパラメータ（`code` / `state`、またはエラー）。値は未エンコードの生値。
    pub parameters: Vec<(String, String)>,
    pub response_mode: ResponseMode,
}

impl AuthorizationResponse {
    /// 成功応答（`code` と `state`）。`state` は透過返却（設計仕様 §2.2）。
    pub fn success(
        redirect_uri: &str,
        code: &str,
        state: &str,
        response_mode: ResponseMode,
    ) -> Self {
        let mut parameters = vec![("code".to_string(), code.to_string())];
        // `state` は「要求に含まれていたら返す」。空文字列を返すと、送っていない RP から見ると
        // 身に覚えのない `state=` が増える。
        if !state.is_empty() {
            parameters.push(("state".to_string(), state.to_string()));
        }
        Self {
            redirect_uri: redirect_uri.to_string(),
            parameters,
            response_mode,
        }
    }

    /// エラー応答。`response_mode` は成功時と同じものを使う（RP は同じ受け口で待っている）。
    pub fn error(
        redirect_uri: &str,
        error: &str,
        description: &str,
        state: &str,
        response_mode: ResponseMode,
    ) -> Self {
        let mut parameters = vec![
            ("error".to_string(), error.to_string()),
            ("error_description".to_string(), description.to_string()),
        ];
        if !state.is_empty() {
            parameters.push(("state".to_string(), state.to_string()));
        }
        Self {
            redirect_uri: redirect_uri.to_string(),
            parameters,
            response_mode,
        }
    }

    pub fn is_form_post(&self) -> bool {
        self.response_mode == ResponseMode::FormPost
    }

    /// `query` モードの 302 先 URL。
    ///
    /// `form_post` のときは**パラメータを載せない**（`redirect_uri` そのものを返す）。form_post を
    /// 見落とした経路がこの値で 302 すると、RP は「コードの無い戻り」を受け取ってエラーを出す
    /// ——認可コードが URL に載って履歴・`Referer` に残るよりは、目に見えて失敗する方がよい。
    pub fn location(&self) -> String {
        if self.is_form_post() {
            return self.redirect_uri.clone();
        }
        self.query_location()
    }

    /// パラメータをクエリ文字列へ畳んだ URL（`response_mode` を問わない）。
    fn query_location(&self) -> String {
        let encoded: Vec<String> = self
            .parameters
            .iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect();
        if encoded.is_empty() {
            return self.redirect_uri.clone();
        }
        let separator = if self.redirect_uri.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{}{separator}{}", self.redirect_uri, encoded.join("&"))
    }
}

/// クエリ文字列へ載せる値のパーセントエンコード（RFC 3986 の unreserved 以外を変換する）。
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_response_modes_are_rejected_not_defaulted() {
        assert_eq!(ResponseMode::parse("query").unwrap(), ResponseMode::Query);
        assert_eq!(
            ResponseMode::parse("form_post").unwrap(),
            ResponseMode::FormPost
        );
        // 丸めると「form_post を要求したのにコードが URL で返る」を RP が検知できない。
        assert!(ResponseMode::parse("fragment").is_err());
        assert!(ResponseMode::parse("").is_err());
    }

    /// 保存値の読み出しだけは丸める（列が増える前から進行中のフローを完了させるため）。
    #[test]
    fn stored_values_fall_back_to_the_default() {
        assert_eq!(ResponseMode::from_stored(None), ResponseMode::Query);
        assert_eq!(
            ResponseMode::from_stored(Some("nonsense")),
            ResponseMode::Query
        );
        assert_eq!(
            ResponseMode::from_stored(Some("form_post")),
            ResponseMode::FormPost
        );
        assert_eq!(ResponseMode::Query.to_stored(), None);
        assert_eq!(ResponseMode::FormPost.to_stored(), Some("form_post"));
    }

    /// `redirect_uri` が元からクエリを持っていても、認可応答は追記になる。
    #[test]
    fn query_mode_appends_to_an_existing_query_string() {
        let response = AuthorizationResponse::success(
            "https://rp.example.com/cb?tenant=a",
            "c o+de",
            "st&ate",
            ResponseMode::Query,
        );
        assert_eq!(
            response.location(),
            "https://rp.example.com/cb?tenant=a&code=c%20o%2Bde&state=st%26ate"
        );
    }

    /// **form_post ではパラメータを URL に載せない。** 見落とした経路が 302 しても、
    /// 認可コードが履歴・`Referer` に残らない（RP 側でエラーになるだけ）。
    #[test]
    fn form_post_mode_never_puts_the_code_in_the_url() {
        let response = AuthorizationResponse::success(
            "https://rp.example.com/cb",
            "the-code",
            "the-state",
            ResponseMode::FormPost,
        );
        assert_eq!(response.location(), "https://rp.example.com/cb");
        assert!(!response.location().contains("the-code"));
        assert_eq!(
            response.parameters,
            vec![
                ("code".to_string(), "the-code".to_string()),
                ("state".to_string(), "the-state".to_string())
            ]
        );
    }

    /// `state` は要求に含まれていたときだけ返す。
    #[test]
    fn an_absent_state_is_not_echoed_back() {
        let response = AuthorizationResponse::success(
            "https://rp.example.com/cb",
            "the-code",
            "",
            ResponseMode::Query,
        );
        assert_eq!(
            response.location(),
            "https://rp.example.com/cb?code=the-code"
        );
    }

    #[test]
    fn error_responses_use_the_same_response_mode() {
        let response = AuthorizationResponse::error(
            "https://rp.example.com/cb",
            "access_denied",
            "the user refused",
            "st",
            ResponseMode::FormPost,
        );
        assert!(response.is_form_post());
        assert_eq!(response.location(), "https://rp.example.com/cb");
        assert_eq!(response.parameters[0].0, "error");
    }
}
