//! トークン系エンドポイント（`/token`・`/introspect`・`/revoke`）のクライアント資格情報の取り出し。
//!
//! 3 つのエンドポイントは RFC 6749 §2.3.1 の同じクライアント認証を受け付ける。`Authorization: Basic`
//! の復号と body（`client_secret_post`・`private_key_jwt` の assertion）の読み取りをここへ集め、判定は
//! `assay_core::application::client_authentication` が行う。
//!
//! 形式不正な Basic ヘッダは 401（`invalid_client`）で返す。ここでは**どの client か**を特定
//! できないため監査ログは残さず、クライアントの存在が判明してからユースケース側で記録する。

use crate::domain::error::OAuthErrorCode;
use crate::presentation::dto::OAuthErrorResponse;
use assay_core::application::client_authentication::PresentedClientCredentials;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use percent_encoding::percent_decode_str;

/// `Authorization: Basic` ヘッダの形式不正。
#[derive(Debug)]
pub struct MalformedBasicHeader;

/// `Authorization: Basic` から `(client_id, client_secret)` を取り出す。
///
/// RFC 6749 §2.3.1 に従い、資格情報は form-urlencoded でエンコードされている前提で
/// パーセントデコードする。ヘッダが無ければ `Ok(None)`。
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

/// body（フォーム本文）から読み取ったクライアント資格情報。
///
/// 3 エンドポイントが同じ形で受け取るためにまとめてある。方式が増えたときに引数の並びを
/// 3 か所で直さずに済む（並びの取り違えは型が同じなのでコンパイラが捕まえられない）。
#[derive(Debug, Default)]
pub struct BodyClientCredentials {
    pub client_id: Option<String>,
    /// `client_secret_post`。
    pub client_secret: Option<String>,
    /// `private_key_jwt` の署名済み assertion（RFC 7523 §2.2。ADR-0030）。
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
}

/// ヘッダと body の資格情報をまとめる。空文字は「未提示」として落とす
/// （フォームの空欄が secret の提示として扱われないようにする）。
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

/// 401 + `WWW-Authenticate: Basic realm="<realm>"` の共通応答（RFC 6749 §5.2）。
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
