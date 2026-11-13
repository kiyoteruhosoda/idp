//! Extracts client credentials for the token endpoints (`/token`, `/introspect`, `/revoke`).
//!
//! The three endpoints accept the same client authentication of RFC 6749 §2.3.1. Decoding of
//! `Authorization: Basic` and reading the body (`client_secret_post`, `private_key_jwt` assertion) live here;
//! the decision is made by `assay_core::application::client_authentication`.
//!
//! A malformed Basic header returns 401 (`invalid_client`). Here we cannot tell **which client** it is,
//! so no audit log is written; the use case records it once the client is known to exist.

use crate::domain::error::OAuthErrorCode;
use crate::presentation::dto::OAuthErrorResponse;
use assay_core::application::client_authentication::PresentedClientCredentials;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use percent_encoding::percent_decode_str;

/// Malformed `Authorization: Basic` header.
#[derive(Debug)]
pub struct MalformedBasicHeader;

/// Extracts `(client_id, client_secret)` from `Authorization: Basic`.
///
/// Per RFC 6749 §2.3.1 the credentials are assumed to be form-urlencoded, so they are
/// percent-decoded. `Ok(None)` when the header is absent.
pub fn basic_credentials(
    headers: &HeaderMap,
) -> Result<Option<(String, String)>, MalformedBasicHeader> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| MalformedBasicHeader)?;
    let encoded = value.strip_prefix("Basic ").ok_or(MalformedBasicHeader)?;
    let decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|_| MalformedBasicHeader)?;
    let decoded = String::from_utf8(decoded).map_err(|_| MalformedBasicHeader)?;
    let (id, secret) = decoded.split_once(':').ok_or(MalformedBasicHeader)?;
    let id = percent_decode_str(id)
        .decode_utf8()
        .map_err(|_| MalformedBasicHeader)?;
    let secret = percent_decode_str(secret)
        .decode_utf8()
        .map_err(|_| MalformedBasicHeader)?;
    Ok(Some((id.into_owned(), secret.into_owned())))
}

/// Client credentials read from the body (form payload).
///
/// Grouped because all three endpoints receive them in the same shape. When a method is added the
/// argument order need not be fixed in 3 places (the compiler cannot catch a swapped order, as the types match).
#[derive(Debug, Default)]
pub struct BodyClientCredentials {
    pub client_id: Option<String>,
    /// `client_secret_post`.
    pub client_secret: Option<String>,
    /// Signed `private_key_jwt` assertion (RFC 7523 §2.2, ADR-0030).
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
}

/// Combines header and body credentials. Empty strings are dropped as "not presented"
/// (so an empty form field is not treated as presenting a secret).
pub fn presented_credentials(
    headers: &HeaderMap,
    body: BodyClientCredentials,
) -> Result<PresentedClientCredentials, MalformedBasicHeader> {
    Ok(PresentedClientCredentials {
        basic: basic_credentials(headers)?,
        body_client_id: body.client_id.filter(|s| !s.is_empty()),
        body_client_secret: body.client_secret.filter(|s| !s.is_empty()),
        client_assertion: body.client_assertion.filter(|s| !s.is_empty()),
        client_assertion_type: body.client_assertion_type.filter(|s| !s.is_empty()),
    })
}

/// Shared 401 + `WWW-Authenticate: Basic realm="<realm>"` response (RFC 6749 §5.2).
pub fn unauthorized(realm: &'static str, description: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, format!("Basic realm=\"{realm}\""))],
        Json(OAuthErrorResponse {
            error: OAuthErrorCode::InvalidClient.as_str().to_string(),
            error_description: Some(description.to_string()),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn parses_basic_credentials_with_percent_encoding() {
        let mut headers = HeaderMap::new();
        // "my%3Aclient" : "s3cret%21" → ("my:client", "s3cret!")
        let token = STANDARD.encode("my%3Aclient:s3cret%21");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {token}")).unwrap(),
        );
        let parsed = basic_credentials(&headers).unwrap().unwrap();
        assert_eq!(parsed, ("my:client".to_string(), "s3cret!".to_string()));
    }

    #[test]
    fn missing_header_is_none_and_malformed_is_error() {
        assert!(basic_credentials(&HeaderMap::new()).unwrap().is_none());

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!"));
        assert!(basic_credentials(&headers).is_err());
    }

    #[test]
    fn empty_body_fields_are_not_treated_as_presented() {
        let creds = presented_credentials(
            &HeaderMap::new(),
            BodyClientCredentials {
                client_id: Some(String::new()),
                client_secret: Some(String::new()),
                client_assertion: Some(String::new()),
                client_assertion_type: Some(String::new()),
            },
        )
        .unwrap();
        assert!(creds.body_client_id.is_none());
        assert!(creds.body_client_secret.is_none());
        assert!(creds.client_assertion.is_none());
        assert!(creds.client_assertion_type.is_none());
    }
}
