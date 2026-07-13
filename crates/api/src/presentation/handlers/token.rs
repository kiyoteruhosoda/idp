//! トークンエンドポイント（`POST /token`、設計仕様 §4.4）。

use crate::application::token::{TokenCommand, TokenError};
use crate::domain::error::OAuthErrorCode;
use crate::presentation::correlation::CorrelationId;
use crate::presentation::dto::{OAuthErrorResponse, TokenRequest, TokenResponse};
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use percent_encoding::percent_decode_str;

/// トークン発行。confidential client は `client_secret_basic`、public client は認証なし。
#[utoipa::path(
    post,
    path = "/{tenant_id}/token",
    tag = "oidc",
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "ID Token / Access Token を発行", body = TokenResponse),
        (status = 400, description = "リクエスト・grant の不正", body = OAuthErrorResponse),
        (status = 401, description = "クライアント認証失敗", body = OAuthErrorResponse),
    )
)]
pub async fn token(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Form(body): Form<TokenRequest>,
) -> Response {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );

    let basic_credentials = match parse_basic_credentials(&headers) {
        Ok(v) => v,
        Err(MalformedBasicHeader) => return malformed_basic_response(),
    };

    let command = TokenCommand {
        grant_type: body.grant_type,
        code: body.code,
        redirect_uri: body.redirect_uri,
        code_verifier: body.code_verifier,
        client_id: body.client_id,
        basic_credentials,
        refresh_token: body.refresh_token,
    };

    match state.token.exchange(tenant.context(), command, &ctx).await {
        Ok(tokens) => (
            // トークンレスポンスはキャッシュ禁止（設計仕様 §4.4）。
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(TokenResponse {
                access_token: tokens.access_token,
                token_type: "Bearer".to_string(),
                expires_in: tokens.expires_in,
                id_token: tokens.id_token,
                scope: tokens.scope,
                refresh_token: tokens.refresh_token,
            }),
        )
            .into_response(),
        Err(e) => error_response(e),
    }
}

fn error_response(e: TokenError) -> Response {
    let body = Json(OAuthErrorResponse {
        error: e.code.as_str().to_string(),
        error_description: Some(e.description),
    });
    match e.code {
        // RFC 6749 §5.2: invalid_client は 401 + WWW-Authenticate。
        OAuthErrorCode::InvalidClient => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"token\"")],
            body,
        )
            .into_response(),
        OAuthErrorCode::ServerError => (StatusCode::INTERNAL_SERVER_ERROR, body).into_response(),
        _ => (StatusCode::BAD_REQUEST, body).into_response(),
    }
}

/// `Authorization: Basic` ヘッダの形式不正。
#[derive(Debug)]
struct MalformedBasicHeader;

fn malformed_basic_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"token\"")],
        Json(OAuthErrorResponse {
            error: OAuthErrorCode::InvalidClient.as_str().to_string(),
            error_description: Some("malformed Basic authorization header".to_string()),
        }),
    )
        .into_response()
}

/// `Authorization: Basic` から `(client_id, client_secret)` を取り出す。
/// RFC 6749 §2.3.1 に従い、資格情報は form-urlencoded でエンコードされている前提で
/// パーセントデコードする。形式不正は 401 を返す。
fn parse_basic_credentials(
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
        let parsed = parse_basic_credentials(&headers).unwrap().unwrap();
        assert_eq!(parsed, ("my:client".to_string(), "s3cret!".to_string()));
    }

    #[test]
    fn missing_header_is_none_and_malformed_is_error() {
        assert!(parse_basic_credentials(&HeaderMap::new())
            .unwrap()
            .is_none());

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!"));
        assert!(parse_basic_credentials(&headers).is_err());
    }
}
