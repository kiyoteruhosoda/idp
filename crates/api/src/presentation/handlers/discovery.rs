//! OIDC Discovery (`GET /.well-known/openid-configuration`) and
//! JWKS (`GET /.well-known/jwks.json`) (design spec §4.5 / §4.6).

use crate::domain::issuer::tenant_issuer;
use crate::domain::jwt;
use crate::domain::saml_metadata::{build_idp_metadata_xml, named_curve_uri, IdpSigningKey};
use crate::domain::values::SUPPORTED_ACR_VALUES;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

/// Discovery document. `issuer` has no trailing slash and exactly matches the ID Token's `iss`.
///
/// `issuer` is composed per tenant as `<base issuer>/<tenant_id>` (ADR-0009 §6). The requested tenant is
/// path-derived (injected by `resolve_tenant`). All endpoints are also derived from this issuer.
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
    // end_session_endpoint is received by web (ADR-0018 decision 2; the api doesn't read browser cookies, so
    // RP-initiated logout starts on the web side, which can handle the SSO cookie on its own domain).
    let end_session_endpoint = format!(
        "{}/{}/logout",
        state.config.public_web_base_url(),
        tenant.id()
    );
    Json(discovery_document(&issuer, &end_session_endpoint))
}

/// JWKS (public keys of ACTIVE + RETIRED).
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

/// SAML IdP metadata (`GET /{tenant_id}/saml/metadata`).
///
/// Returns as XML the `EntityDescriptor` (`IDPSSODescriptor`) describing assay. Public metadata SPs (clients) import
/// to trust assay; the entityID is the tenant issuer and the SSO URL is derived from the issuer too.
/// The signing `KeyDescriptor` contains the ACTIVE signing key (RSA) as `RSAKeyValue`. The advertised
/// SingleSignOnService is implemented by [`super::saml_sso`] (`/{tenant_id}/saml/sso`).
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
    // If the key set cannot be fetched, **no metadata is returned**. Returning 200 with metadata lacking `KeyDescriptor`
    // would leave an SP that re-imports at that moment with no verification key at all, rejecting every assertion until
    // the next re-import (the very outage this change aims to remove).
    let signing_keys = match published_idp_signing_keys(&state).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = %e, "failed to build SAML IdP metadata signing keys");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let xml = build_idp_metadata_xml(&issuer, &sso_url, &signing_keys);
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

/// Converts the published signing keys for SAML `KeyDescriptor` (ADR-0039).
///
/// **Emits the same set as JWKS.** `jwks()` returns all published keys (signing, successors not yet signing, retired
/// within validity), so listing them as is makes the OIDC and SAML sides show the same thing. Emitting only one
/// would make SP verification fail when signing switches over.
///
/// **The signing key goes first.** `jwks()` is in publication order (newest first), so as is
/// **a successor key not yet signing** would come first. Some SP implementations read only the first `KeyDescriptor`.
async fn published_idp_signing_keys(state: &AppState) -> anyhow::Result<Vec<IdpSigningKey>> {
    let jwks = state.keys.jwks().await?;
    let published = jwks.keys.len();
    // If the signing key cannot be fetched we just don't reorder and keep publishing (losing the verifier's keys
    // would be worse). Only the `kid` is needed, so the private key is not decrypted.
    let signing_kid = state.keys.signing_kid().await.ok().flatten();
    let keys = signing_key_first(jwks.keys, signing_kid.as_deref());
    let converted: Vec<IdpSigningKey> = keys.iter().filter_map(jwk_to_idp_signing_key).collect();
    // Also **return no metadata** when not a single key could be converted. Unparseable keys are dropped one by one, but
    // returning 200 with all of them gone would emit metadata without `KeyDescriptor`, the same outage as when `jwks()`
    // fails (an SP that re-imports holds no verification key at all).
    if published > 0 && converted.is_empty() {
        anyhow::bail!(
            "none of the {published} published keys could be rendered as a KeyDescriptor"
        );
    }
    Ok(converted)
}

/// Moves the signing key to the front. **Some SP implementations read only the first `KeyDescriptor`**, so
/// leaving publication order (newest first) would hand them a successor key that is not signing yet.
///
/// No reordering when `signing_kid` is absent or not found (publishing continues; losing the verifier's keys
/// would be worse).
fn signing_key_first(mut keys: Vec<jwt::Jwk>, signing_kid: Option<&str>) -> Vec<jwt::Jwk> {
    if let Some(kid) = signing_kid {
        if let Some(at) = keys.iter().position(|k| k.kid == kid) {
            // Move it forward rather than `swap`. With `swap` the key at the front would jump to `at`,
            // breaking the publication order (newest first) of the rest.
            let signing = keys.remove(at);
            keys.insert(0, signing);
        }
    }
    keys
}

/// Converts one JWK to the SAML `KeyValue` representation. RSA becomes `RSAKeyValue` (modulus/exponent),
/// EC becomes `ECKeyValue` (NamedCurve URI and uncompressed point). Unparseable keys yield `None` (only that key is dropped).
fn jwk_to_idp_signing_key(jwk: &jwt::Jwk) -> Option<IdpSigningKey> {
    match jwk.kty.as_str() {
        "RSA" => Some(IdpSigningKey::Rsa {
            modulus_b64: base64url_to_base64(jwk.n.as_deref()?)?,
            exponent_b64: base64url_to_base64(jwk.e.as_deref()?)?,
        }),
        "EC" => {
            let named_curve_uri = named_curve_uri(jwk.crv.as_deref()?)?.to_string();
            // XMLDSIG's ECKeyValue holds the uncompressed point (0x04 || X || Y) in base64.
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

fn base64url_to_base64(value: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()?;
    Some(STANDARD.encode(bytes))
}

fn discovery_document(issuer: &str, end_session_endpoint: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "end_session_endpoint": end_session_endpoint,
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        // DPoP (RFC 9449 §5.1, ADR-0075). Proofs are signed only with ES256.
        "dpop_signing_alg_values_supported": crate::domain::dpop::SUPPORTED_ALGORITHMS,
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        // Client authentication (RFC 6749 §2.3.1). `client_secret_post` is accepted because many RP libraries
        // default to it (G3). `private_key_jwt` (RFC 7523) is for systems that hold no shared secret
        // (ADR-0030). Which one is used is decided by the client's registered value (no coexistence).
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        // Signing algorithms usable for `private_key_jwt` assertions. Without advertising them, RP and client
        // libraries guess the supported algorithms and diverge.
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        // `/revoke` and `/introspect` use the same methods (RFC 7009 §2.1, RFC 7662 §2.1).
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "revocation_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "introspection_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        "code_challenge_methods_supported": ["S256"],
        // The response mode is `query` only (`form_post` not implemented, G12). Without advertising it, RP
        // implementations with strict metadata validation (including the OIDC certification tests) guess the default and diverge.
        // `form_post` returns the authorization code in a form body instead of the URL (G12).
        "response_modes_supported": ["query", "form_post"],
        // `prompt` (OIDC Core §3.1.2.1). `select_account` is handled as "don't silently continue with the current account"
        // = stop SSO restoration and return to the login screen (assay holds only one SSO session per browser,
        // so it cannot show a list of multiple accounts, G12).
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        // `request` / `request_uri` (signed request objects) and `claims` are not supported.
        // The default is false, but stating it explicitly speeds up RP-side implementation decisions.
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "claims_parameter_supported": false,
        // Only reserved words whose meaning assay defines and which **always take effect when requested** are listed (ADR-0043).
        // Tenants can still write their own strings in an authentication policy's `requested_acr` condition
        // as before, but assay doesn't define their meaning so they are not published (claiming values we can't
        // guarantee would make RPs depend on them without being able to check whether they took effect).
        "acr_values_supported": SUPPORTED_ACR_VALUES,
        // Languages the login screen can actually render (kept in line with web's i18n resources).
        "ui_locales_supported": ["ja", "en"],
        "frontchannel_logout_supported": true,
        "backchannel_logout_supported": true,
        // `sid` is put in logout_token, so RPs can revoke per session (G5).
        "backchannel_logout_session_supported": true,
        "frontchannel_logout_session_supported": false,
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid",
            // `acr` is the authentication strength (ADR-0043). `amr` is the methods used (RFC 8176) and
            // **cannot be used to judge strength** (assay doesn't know either what was used beyond `fed`).
            "acr", "amr",
            "email", "email_verified", "preferred_username", "name"
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwk(kid: &str) -> jwt::Jwk {
        jwt::Jwk {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            kid: kid.to_string(),
            alg: "RS256".to_string(),
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        }
    }

    fn kids(keys: &[jwt::Jwk]) -> Vec<&str> {
        keys.iter().map(|k| k.kid.as_str()).collect()
    }

    /// Publication order is newest first, so with ADR-0039's "publish, then sign" **a successor key not yet
    /// signing** comes first. Don't hand that to SPs that read only the first `KeyDescriptor`.
    #[test]
    fn the_signing_key_comes_first_even_when_a_successor_is_newer() {
        let keys = vec![jwk("successor"), jwk("signing"), jwk("retired")];
        assert_eq!(
            kids(&signing_key_first(keys, Some("signing"))),
            ["signing", "successor", "retired"]
        );
    }

    /// If it is already first, the order doesn't change.
    #[test]
    fn an_already_leading_signing_key_is_left_alone() {
        let keys = vec![jwk("signing"), jwk("retired")];
        assert_eq!(
            kids(&signing_key_first(keys, Some("signing"))),
            ["signing", "retired"]
        );
    }

    /// When the signing key cannot be fetched or is not in the published set, we just don't reorder and keep publishing
    /// (losing usable verification keys from the metadata would be worse).
    #[test]
    fn an_unknown_signing_kid_leaves_the_published_set_intact() {
        let keys = vec![jwk("a"), jwk("b")];
        assert_eq!(kids(&signing_key_first(keys.clone(), None)), ["a", "b"]);
        assert_eq!(kids(&signing_key_first(keys, Some("gone"))), ["a", "b"]);
    }

    #[test]
    fn discovery_endpoints_derive_from_issuer() {
        // Only end_session_endpoint is web's URL (ADR-0018 decision 2: RP-initiated logout starts at web).
        let doc = discovery_document(
            "https://api.idp.example.com",
            "https://idp.example.com/tenant-a/logout",
        );
        assert_eq!(doc["issuer"], "https://api.idp.example.com");
        assert_eq!(
            doc["authorization_endpoint"],
            "https://api.idp.example.com/authorize"
        );
        assert_eq!(
            doc["jwks_uri"],
            "https://api.idp.example.com/.well-known/jwks.json"
        );
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
        // G3: advertise `client_secret_post`, ADR-0030: `private_key_jwt`
        // (`/revoke` and `/introspect` use the same methods).
        assert_eq!(
            doc["token_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none"
            ])
        );
        assert_eq!(
            doc["token_endpoint_auth_signing_alg_values_supported"],
            json!(["RS256", "ES256"])
        );
        assert_eq!(
            doc["revocation_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none"
            ])
        );
        assert_eq!(
            doc["introspection_endpoint_auth_methods_supported"],
            json!([
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt"
            ])
        );
        // G12: explicitly advertise the fields RP metadata validation looks at.
        assert_eq!(
            doc["response_modes_supported"],
            json!(["query", "form_post"])
        );
        assert_eq!(doc["request_parameter_supported"], json!(false));
        assert_eq!(doc["claims_parameter_supported"], json!(false));
        assert_eq!(doc["ui_locales_supported"], json!(["ja", "en"]));
        assert_eq!(
            doc["prompt_values_supported"],
            json!(["none", "login", "consent", "select_account"])
        );
        assert_eq!(
            doc["end_session_endpoint"],
            "https://idp.example.com/tenant-a/logout"
        );
        assert_eq!(
            doc["revocation_endpoint"],
            "https://api.idp.example.com/revoke"
        );
        assert_eq!(
            doc["introspection_endpoint"],
            "https://api.idp.example.com/introspect"
        );
        assert_eq!(doc["frontchannel_logout_supported"], true);
        assert_eq!(doc["backchannel_logout_supported"], true);
        // Since `sid` is included, also advertise per-session logout support (G5).
        assert_eq!(doc["backchannel_logout_session_supported"], true);
        assert!(doc["claims_supported"]
            .as_array()
            .expect("claims_supported")
            .iter()
            .any(|v| v == "sid"));
    }
}
