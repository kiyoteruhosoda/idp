//! OIDC Discovery（`GET /.well-known/openid-configuration`）と
//! JWKS（`GET /.well-known/jwks.json`）（設計仕様 §4.5 / §4.6）。

use crate::presentation::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// Discovery ドキュメント。`issuer` は末尾スラッシュ無しで ID Token の `iss` と完全一致する。
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = "oidc",
    responses((status = 200, description = "OIDC Discovery ドキュメント"))
)]
pub async fn openid_configuration(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.config.issuer();
    Json(discovery_document(issuer))
}

/// JWKS（ACTIVE + RETIRED の公開鍵）。
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    tag = "oidc",
    responses((status = 200, description = "JWK Set"))
)]
pub async fn jwks(State(state): State<AppState>) -> Response {
    match state.keys.jwks().await {
        Ok(jwks) => Json(jwks).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to build JWKS");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn discovery_document(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
            "email", "email_verified", "preferred_username", "name"
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_endpoints_derive_from_issuer() {
        let doc = discovery_document("https://idp.example.com");
        assert_eq!(doc["issuer"], "https://idp.example.com");
        assert_eq!(
            doc["authorization_endpoint"],
            "https://idp.example.com/authorize"
        );
        assert_eq!(
            doc["jwks_uri"],
            "https://idp.example.com/.well-known/jwks.json"
        );
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
    }
}
