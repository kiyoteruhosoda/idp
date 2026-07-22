//! OIDC Discovery（`GET /.well-known/openid-configuration`）と
//! JWKS（`GET /.well-known/jwks.json`）（設計仕様 §4.5 / §4.6）。

use crate::domain::issuer::tenant_issuer;
use crate::domain::saml_metadata::build_sp_metadata_xml;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// Discovery ドキュメント。`issuer` は末尾スラッシュ無しで ID Token の `iss` と完全一致する。
///
/// `issuer` はテナント毎に `<基底 issuer>/<tenant_id>` を合成する（ADR-0009 §6）。要求テナントは
/// パス由来（`resolve_tenant` が注入）。全エンドポイントもこの issuer から導出する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/.well-known/openid-configuration",
    tag = "oidc",
    responses((status = 200, description = "OIDC Discovery ドキュメント"))
)]
pub async fn openid_configuration(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Json<Value> {
    let issuer = tenant_issuer(state.config.issuer(), tenant.id());
    Json(discovery_document(&issuer))
}

/// JWKS（ACTIVE + RETIRED の公開鍵）。
#[utoipa::path(
    get,
    path = "/{tenant_id}/.well-known/jwks.json",
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

/// SAML SP メタデータ（`GET /{tenant_id}/saml/metadata`）。
///
/// 本 IdP を SAML SP として記述する `EntityDescriptor`（`SPSSODescriptor`）を XML で返す。外部 SAML
/// IdP の管理者がこの SP を登録するための公開メタデータで、テナント issuer を entityID とし、ACS URL も
/// issuer から導出する。アサーション受信フロー自体は未実装のため、メタデータのみを提供する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/saml/metadata",
    tag = "saml",
    responses((status = 200, description = "SAML SP メタデータ（application/samlmetadata+xml）"))
)]
pub async fn saml_sp_metadata(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Response {
    let issuer = tenant_issuer(state.config.issuer(), tenant.id());
    let acs_url = format!("{issuer}/saml/acs");
    let xml = build_sp_metadata_xml(&issuer, &acs_url);
    (
        [
            (header::CONTENT_TYPE, "application/samlmetadata+xml"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"sp-metadata.xml\"",
            ),
        ],
        xml,
    )
        .into_response()
}

fn discovery_document(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
        "code_challenge_methods_supported": ["S256"],
        "frontchannel_logout_supported": true,
        "backchannel_logout_supported": true,
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
        assert_eq!(
            doc["end_session_endpoint"],
            "https://idp.example.com/logout"
        );
        assert_eq!(doc["revocation_endpoint"], "https://idp.example.com/revoke");
        assert_eq!(
            doc["introspection_endpoint"],
            "https://idp.example.com/introspect"
        );
        assert_eq!(doc["frontchannel_logout_supported"], true);
        assert_eq!(doc["backchannel_logout_supported"], true);
    }
}
