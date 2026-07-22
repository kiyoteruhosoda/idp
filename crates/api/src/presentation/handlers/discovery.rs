//! OIDC Discovery（`GET /.well-known/openid-configuration`）と
//! JWKS（`GET /.well-known/jwks.json`）（設計仕様 §4.5 / §4.6）。

use crate::domain::issuer::tenant_issuer;
use crate::domain::saml_metadata::{build_idp_metadata_xml, IdpSigningKey};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
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

/// SAML IdP メタデータ（`GET /{tenant_id}/saml/metadata`）。
///
/// 本 IdP を記述する `EntityDescriptor`（`IDPSSODescriptor`）を XML で返す。SP（クライアント）がこの IdP を
/// 信頼するために取り込む公開メタデータで、テナント issuer を entityID とし、SSO URL も issuer から導出する。
/// 署名用 `KeyDescriptor` には ACTIVE 署名鍵（RSA）を `RSAKeyValue` で含める。SSO エンドポイントの
/// 認証フロー自体は未実装のため、現時点ではメタデータのみを提供する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/saml/metadata",
    tag = "saml",
    responses((status = 200, description = "SAML IdP メタデータ（application/xml。SP 取り込み用にダウンロード）"))
)]
pub async fn saml_idp_metadata(
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Response {
    let issuer = tenant_issuer(state.config.issuer(), tenant.id());
    let sso_url = format!("{issuer}/saml/sso");
    let signing_key = active_idp_signing_key(&state).await;
    let xml = build_idp_metadata_xml(&issuer, &sso_url, signing_key.as_ref());
    (
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"idp-metadata.xml\"",
            ),
        ],
        xml,
    )
        .into_response()
}

/// ACTIVE 署名鍵の公開値を SAML `KeyValue` 用に取り出す。RSA は `RSAKeyValue`（modulus/exponent）、
/// EC は `ECKeyValue`（NamedCurve URI と非圧縮点）へ変換する。取得できない場合は `None`（KeyDescriptor 省略）。
async fn active_idp_signing_key(state: &AppState) -> Option<IdpSigningKey> {
    let kid = state.keys.active_signing_key().await.ok()?.kid;
    let jwks = state.keys.jwks().await.ok()?;
    let jwk = jwks.keys.into_iter().find(|k| k.kid == kid)?;
    match jwk.kty.as_str() {
        "RSA" => Some(IdpSigningKey::Rsa {
            modulus_b64: base64url_to_base64(jwk.n.as_deref()?)?,
            exponent_b64: base64url_to_base64(jwk.e.as_deref()?)?,
        }),
        "EC" => {
            let named_curve_uri = named_curve_uri(jwk.crv.as_deref()?)?;
            // XMLDSIG の ECKeyValue は非圧縮点（0x04 || X || Y）を base64 で持つ。
            let mut point = vec![0x04u8];
            point.extend_from_slice(
                &URL_SAFE_NO_PAD
                    .decode(jwk.x.as_deref()?.trim_end_matches('='))
                    .ok()?,
            );
            point.extend_from_slice(
                &URL_SAFE_NO_PAD
                    .decode(jwk.y.as_deref()?.trim_end_matches('='))
                    .ok()?,
            );
            Some(IdpSigningKey::Ec {
                named_curve_uri,
                public_key_b64: STANDARD.encode(point),
            })
        }
        _ => None,
    }
}

/// JWK の `crv` を XMLDSIG11 `NamedCurve` の URN へ変換する（MVP は P-256 のみ）。
fn named_curve_uri(crv: &str) -> Option<String> {
    match crv {
        "P-256" => Some("urn:oid:1.2.840.10045.3.1.7".to_string()),
        "P-384" => Some("urn:oid:1.3.132.0.34".to_string()),
        "P-521" => Some("urn:oid:1.3.132.0.35".to_string()),
        _ => None,
    }
}

fn base64url_to_base64(value: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()?;
    Some(STANDARD.encode(bytes))
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
