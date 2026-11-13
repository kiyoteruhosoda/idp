//! How authorization responses are returned (`response_mode`; OAuth 2.0 Multiple Response Type
//! Encoding Practices; G12).
//!
//! Decides **how the authorization response** (`code` and `state`, or an error) **is delivered to
//! the RP**.
//!
//! - `query` (default): put in the query string of `redirect_uri` and 302.
//! - `form_post`: put in hidden fields of an auto-submitting form and POST to `redirect_uri`.
//!
//! # Why `form_post` is needed
//!
//! With `query`, the authorization code **appears in the URL**. URLs remain in browser history,
//! `Referer`, and proxy/server access logs. The code is valid for 60 seconds, single-use, and
//! requires PKCE, so it is not immediately exploitable, but deployments requiring "no secrets in
//! URLs" are not rare.
//!
//! # Cannot be recovered from a URL
//!
//! A finished URL cannot be carried around and later turned back into "destination and parameters".
//! `redirect_uri` itself may have a query (`https://rp.example.com/cb?tenant=a`), so the URL alone
//! cannot tell where the RP's query ends and the authorization response begins. So the response is
//! built **from the start in the shape "destination + parameters"** ([`AuthorizationResponse`]) and
//! folded into a URL only for `query`.

use crate::domain::error::DomainError;

/// `response_mode` values assay supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseMode {
    /// Put in the query string and 302 (default; the standard for RFC 6749's `code` flow).
    #[default]
    Query,
    /// POST via an auto-submitting form (OAuth 2.0 Form Post Response Mode).
    FormPost,
}

impl ResponseMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::FormPost => "form_post",
        }
    }

    /// Interprets the requested value. **Unknown values are an error, not coerced to the default**
    /// (OAuth 2.0 Multiple Response Type Encoding Practices). Coercing would return the code in the
    /// URL while the RP believes it requested `form_post`, without the RP noticing — the "no
    /// secrets in URLs" requirement would be silently broken.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw.trim() {
            "query" => Ok(Self::Query),
            "form_post" => Ok(Self::FormPost),
            other => Err(DomainError::InvalidValue(format!(
                "unsupported response_mode: {other}"
            ))),
        }
    }

    /// Restores from the stored value (`auth_sessions.response_mode`). Unknown / unset becomes the
    /// default (`query`).
    ///
    /// Coercing only here is fine because **stored values already passed validation** (unknown
    /// values are rejected by [`Self::parse`] at `/authorize`). Failing on read would leave flows
    /// that were in progress before the column was added unable to complete.
    pub fn from_stored(raw: Option<&str>) -> Self {
        raw.and_then(|v| Self::parse(v).ok()).unwrap_or_default()
    }

    /// Value to store. The default (`query`) is `None` (the column is unused).
    pub fn to_stored(self) -> Option<&'static str> {
        match self {
            Self::Query => None,
            Self::FormPost => Some(self.as_str()),
        }
    }
}

/// An authorization response (destination and parameters).
///
/// The point of this type is that it **is carried in this shape rather than as a URL string** (see
/// the module docs for why). Folded into a URL with [`Self::location`] only for `query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationResponse {
    pub redirect_uri: String,
    /// Parameters of the authorization response (`code` / `state`, or an error). Values are raw,
    /// unencoded.
    pub parameters: Vec<(String, String)>,
    pub response_mode: ResponseMode,
}

impl AuthorizationResponse {
    /// Success response (`code` and `state`). `state` is returned transparently (design spec §2.2).
    pub fn success(
        redirect_uri: &str,
        code: &str,
        state: &str,
        response_mode: ResponseMode,
    ) -> Self {
        let mut parameters = vec![("code".to_string(), code.to_string())];
        // `state` is "returned if it was in the request". Returning an empty string would, for an
        // RP that did not send one, add an unexpected `state=`.
        if !state.is_empty() {
            parameters.push(("state".to_string(), state.to_string()));
        }
        Self {
            redirect_uri: redirect_uri.to_string(),
            parameters,
            response_mode,
        }
    }

    /// Error response. Uses the same `response_mode` as on success (the RP is waiting at the same
    /// endpoint).
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

    /// The 302 target URL for `query` mode.
    ///
    /// For `form_post` it **carries no parameters** (returns `redirect_uri` itself). If a path that
    /// overlooked form_post 302s with this value, the RP gets "a return without a code" and errors
    /// — failing visibly is better than the authorization code staying in history / `Referer` via
    /// the URL.
    pub fn location(&self) -> String {
        if self.is_form_post() {
            return self.redirect_uri.clone();
        }
        self.query_location()
    }

    /// URL with the parameters folded into the query string (regardless of `response_mode`).
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

/// Percent-encoding of values put in the query string (converts everything except RFC 3986
/// unreserved).
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
        // Coercing would keep the RP from detecting "requested form_post but the code came back in
        // the URL".
        assert!(ResponseMode::parse("fragment").is_err());
        assert!(ResponseMode::parse("").is_err());
    }

    /// Only reading stored values coerces (to let flows in progress before the column was added
    /// complete).
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

    /// Even if `redirect_uri` already has a query, the authorization response is appended.
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

    /// **form_post does not put parameters in the URL.** Even if an overlooking path 302s,
    /// the authorization code does not remain in history / `Referer` (the RP just errors).
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

    /// `state` is returned only when it was in the request.
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
