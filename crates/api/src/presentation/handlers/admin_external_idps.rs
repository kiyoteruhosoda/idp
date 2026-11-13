//! External IdP settings management API (`/{tenant_id}/admin/external-idps`, AP10).
//!
//! Tenant admins register, update and delete the external IdPs (OpenID Providers, SAML IdPs) usable in the tenant.
//! Listing needs `idp.external-idps:read`; register/update/delete and importing metadata/discovery need
//! `idp.external-idps:write` (`RequirePerms<ExternalIdpsRead>` / `<ExternalIdpsWrite>`;
//! `idp.tenant.admin` implies both).
//! Client secrets are **write-only** and never included in responses (stored encrypted; decrypted only
//! at the moment a token request is sent to the external IdP).

use crate::application::external_idp_discovery::DiscoveryImportError;
use crate::application::external_idp_management::{
    ExternalIdpConfigCommand, ExternalIdpManagementError, RegisterExternalIdpCommand,
    UpdateExternalIdpCommand,
};
use crate::domain::external_idp::{ExternalIdentityProvider, ExternalIdpProtocol};
use crate::domain::saml_metadata::parse_idp_metadata;
use crate::presentation::admin::{ExternalIdpsRead, ExternalIdpsWrite, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Public representation of an external IdP (`client_secret` is not returned).
#[derive(Debug, Serialize, ToSchema)]
pub struct ExternalIdpResponse {
    pub id: String,
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    /// `oidc` / `saml` (ADR-0027). Which of the following fields are used depends on the protocol.
    pub protocol: String,
    /// OIDC only.
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: Option<String>,
    /// OIDC only. Whether a secret is set (the value is not returned).
    pub has_client_secret: bool,
    pub scopes: Vec<String>,
    /// SAML only. The IdP's `SingleSignOnService` URL.
    pub saml_sso_url: Option<String>,
    /// SAML only. Certificates used for signature verification (base64 DER). Not secret, so returned.
    pub saml_certificates: Vec<String>,
    pub saml_name_id_format: Option<String>,
    /// SAML only. assay's entityID and ACS URL to register with the external IdP.
    pub saml_sp_entity_id: Option<String>,
    pub saml_acs_url: Option<String>,
    pub enabled: bool,
    pub allow_auto_link: bool,
    /// Callback URL to register with the external IdP (returned as a hint for the setup work).
    pub redirect_uri: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExternalIdpRegisterRequest {
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    /// `oidc` (default) / `saml`.
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Required for OIDC.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// Plaintext client secret (omit when registering as a public client).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// `openid profile email` when omitted.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Required for SAML.
    #[serde(default)]
    pub saml_sso_url: Option<String>,
    #[serde(default)]
    pub saml_certificates: Option<Vec<String>>,
    #[serde(default)]
    pub saml_name_id_format: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether to auto-link to an existing user on a verified email match (default false).
    #[serde(default)]
    pub allow_auto_link: bool,
}

fn default_true() -> bool {
    true
}

fn default_protocol() -> String {
    "oidc".to_string()
}

/// Builds the protocol-specific settings from the input. Reads **only one protocol's fields** --
/// reading both would allow half-baked registrations with SAML fields mixed into OIDC settings.
#[allow(clippy::too_many_arguments)]
fn config_command(
    protocol: &str,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Option<Vec<String>>,
    saml_sso_url: Option<String>,
    saml_certificates: Option<Vec<String>>,
    saml_name_id_format: Option<String>,
) -> Result<ExternalIdpConfigCommand, ApiError> {
    let required = |value: Option<String>, field: &str| {
        value
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| ApiError::BadRequest(format!("{field} is required for this protocol")))
    };
    match ExternalIdpProtocol::parse(protocol).map_err(|e| ApiError::BadRequest(e.to_string()))? {
        ExternalIdpProtocol::Oidc => Ok(ExternalIdpConfigCommand::Oidc {
            authorization_endpoint: required(authorization_endpoint, "authorization_endpoint")?,
            token_endpoint: required(token_endpoint, "token_endpoint")?,
            jwks_uri: required(jwks_uri, "jwks_uri")?,
            client_id: required(client_id, "client_id")?,
            client_secret,
            scopes: scopes.unwrap_or_default(),
        }),
        ExternalIdpProtocol::Saml => Ok(ExternalIdpConfigCommand::Saml {
            sso_url: required(saml_sso_url, "saml_sso_url")?,
            certificates: saml_certificates.unwrap_or_default(),
            name_id_format: saml_name_id_format,
        }),
    }
}

/// Partial update. Only the given fields are updated. Setting `client_secret` to an empty string deletes it (becomes public).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ExternalIdpUpdateRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    /// Given only when replacing the protocol-specific settings (the protocol itself cannot be changed).
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub saml_sso_url: Option<String>,
    #[serde(default)]
    pub saml_certificates: Option<Vec<String>>,
    #[serde(default)]
    pub saml_name_id_format: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub allow_auto_link: Option<bool>,
}

/// Lists external IdPs.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/external-idps",
    tag = "admin",
    responses(
        (status = 200, description = "外部 IdP 一覧", body = [ExternalIdpResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.external-idps:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list_external_idps(
    RequirePerms(_admin, _): RequirePerms<ExternalIdpsRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
) -> Result<Json<Vec<ExternalIdpResponse>>, ApiError> {
    let providers = state
        .external_idps
        .list(tenant.context())
        .await
        .map_err(map_error)?;
    Ok(Json(
        providers
            .iter()
            .map(|p| response(&state, p))
            .collect::<Vec<_>>(),
    ))
}

/// Registers an external IdP.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/external-idps",
    tag = "admin",
    request_body = ExternalIdpRegisterRequest,
    responses(
        (status = 201, description = "登録完了", body = ExternalIdpResponse),
        (status = 400, description = "入力が不正（プロトコルに要る項目が無い・エンドポイントが https でない・内部宛先 等）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.external-idps:write 必須）"),
        (status = 409, description = "provider_code の重複"),
    ),
    security(("bearer_token" = []))
)]
pub async fn register_external_idp(
    RequirePerms(admin, _): RequirePerms<ExternalIdpsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Json(body): Json<ExternalIdpRegisterRequest>,
) -> Result<(StatusCode, Json<ExternalIdpResponse>), ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let provider = state
        .external_idps
        .register(
            tenant.context(),
            RegisterExternalIdpCommand {
                provider_code: body.provider_code,
                display_name: body.display_name,
                issuer: body.issuer,
                config: config_command(
                    &body.protocol,
                    body.authorization_endpoint,
                    body.token_endpoint,
                    body.jwks_uri,
                    body.client_id,
                    body.client_secret,
                    body.scopes,
                    body.saml_sso_url,
                    body.saml_certificates,
                    body.saml_name_id_format,
                )?,
                enabled: body.enabled,
                allow_auto_link: body.allow_auto_link,
            },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(response(&state, &provider))))
}

/// Partially updates an external IdP.
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/external-idps/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "対象プロバイダの内部 ID（UUID）")),
    request_body = ExternalIdpUpdateRequest,
    responses(
        (status = 200, description = "更新完了", body = ExternalIdpResponse),
        (status = 400, description = "入力が不正（プロトコルの変更・プロトコルに要る項目が無い 等）"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.external-idps:write 必須）"),
        (status = 404, description = "対象が無い"),
    ),
    security(("bearer_token" = []))
)]
pub async fn update_external_idp(
    RequirePerms(admin, _): RequirePerms<ExternalIdpsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Path((_tenant_id, id)): Path<(String, String)>,
    Json(body): Json<ExternalIdpUpdateRequest>,
) -> Result<Json<ExternalIdpResponse>, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let id = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound("not found".to_string()))?;
    // An empty string means the intent "remove the secret" (distinguished from unspecified = keep).
    let client_secret = body.client_secret.map(|s| {
        let trimmed = s.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    // Protocol-specific settings are replaced **as a whole** (only when `protocol` is given). Per-field
    // partial updates would allow half-baked combinations.
    let config = match body.protocol.as_deref() {
        Some(protocol) => Some(config_command(
            protocol,
            body.authorization_endpoint,
            body.token_endpoint,
            body.jwks_uri,
            body.client_id,
            None,
            body.scopes,
            body.saml_sso_url,
            body.saml_certificates,
            body.saml_name_id_format,
        )?),
        None => None,
    };
    let provider = state
        .external_idps
        .update(
            tenant.context(),
            id,
            UpdateExternalIdpCommand {
                display_name: body.display_name,
                issuer: body.issuer,
                config,
                client_secret,
                enabled: body.enabled,
                allow_auto_link: body.allow_auto_link,
            },
            &admin.actor,
            &ctx,
        )
        .await
        .map_err(map_error)?;
    Ok(Json(response(&state, &provider)))
}

/// Parses an external IdP's metadata XML and returns initial values for the registration form (AP12). Nothing is persisted.
///
/// Pasting the entityID, SSO URL and signing certificate tends to become admins copying them one by one from the IdP's metadata.
/// Certificates span several lines of base64, so a copy mistake doesn't surface until **a user signs in**.
///
/// Input/output use api-side DTOs with `utoipa` ([`SamlIdpMetadataImportRequest`] /
/// [`SamlIdpMetadataImportResponse`]) (same design as the discovery import, task #124). If their shape diverges from
/// the `assay_contracts::admin` DTOs web uses (`assay_contracts` has no `utoipa`), the import silently
/// breaks, so a test (`saml_metadata_import_contract_matches_the_api_dto`) catches any divergence.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/external-idps/import-metadata",
    tag = "admin",
    request_body = SamlIdpMetadataImportRequest,
    responses(
        (status = 200, description = "取り込んだ登録候補値（保存はしていない）", body = SamlIdpMetadataImportResponse),
        (status = 400, description = "メタデータを解析できない・IdP の entityID / SingleSignOnService が無い"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.external-idps:write 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn import_external_idp_metadata(
    RequirePerms(_admin, _): RequirePerms<ExternalIdpsWrite>,
    State(_state): State<AppState>,
    Extension(_tenant): Extension<ResolvedTenant>,
    Json(body): Json<SamlIdpMetadataImportRequest>,
) -> Result<Json<SamlIdpMetadataImportResponse>, ApiError> {
    // Parse failure reasons (no entityID, no SSO, etc.) are returned as is. They are validation messages for admins,
    // so not translated (CLAUDE.md "翻訳の対象外"). Whether a mix-up -- pasting the SP's metadata -- can be
    // reported as "the IdP has no SingleSignOnService" decides whether it gets noticed.
    let parsed =
        parse_idp_metadata(&body.metadata_xml).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(SamlIdpMetadataImportResponse {
        display_name: parsed.display_name.unwrap_or_default(),
        entity_id: parsed.entity_id,
        sso_url: parsed.sso_url,
        certificates: parsed.certificates,
        name_id_format: parsed.name_id_format.unwrap_or_default(),
    }))
}

/// SAML IdP metadata import request (same shape as `assay_contracts::admin::SamlMetadataImportRequest`
/// used by web).
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlIdpMetadataImportRequest {
    /// SAML metadata XML (the IdP's `EntityDescriptor`).
    pub metadata_xml: String,
}

/// SAML IdP metadata import response (initial values for the registration form; **nothing is registered**. Same shape as
/// `assay_contracts::admin::SamlIdpMetadataImportResponse` used by web).
#[derive(Debug, Serialize, ToSchema)]
pub struct SamlIdpMetadataImportResponse {
    /// Display name from the metadata (empty string if none).
    pub display_name: String,
    /// The IdP's entityID. Becomes `issuer` on registration (the value matched exactly against the assertion's `<Issuer>`).
    pub entity_id: String,
    /// The IdP's `SingleSignOnService` URL. Becomes `saml_sso_url` on registration.
    pub sso_url: String,
    /// Certificates used for signature verification (base64 DER). **May be several** (old and new are both valid during rollover).
    pub certificates: Vec<String>,
    /// NameID format (empty string if none).
    pub name_id_format: String,
}

/// Discovery import request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OidcDiscoveryImportRequest {
    /// The external IdP's issuer (https; `{issuer}/.well-known/openid-configuration` is read).
    pub issuer: String,
}

/// Discovery import response (initial values for the registration form; **nothing is registered**).
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcDiscoveryImportResponse {
    /// The document's `issuer` (exactly matching the input). Becomes `issuer` on registration.
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// Reads an external OIDC IdP's discovery document and returns initial values for the registration form (task #77).
/// **Nothing is persisted** (like the SAML IdP metadata import, admins check the values before registering).
///
/// Unlike the SAML import, the api sends HTTP to the issuer the admin entered. So before fetching it runs
/// the same destination check as registration (https only, internal destinations rejected, ADR-0023 decision 5), and the fetch
/// doesn't follow redirects and has timeout and size limits. If the document's `issuer` doesn't match the input,
/// it is rejected (OIDC Discovery §4.3). The permission is the same `idp.external-idps:write` as registration (an admin operation
/// preceding registration, and also one that makes us send HTTP outward).
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/external-idps/import-discovery",
    tag = "admin",
    request_body = OidcDiscoveryImportRequest,
    responses(
        (status = 200, description = "取り込んだ登録候補値（保存はしていない）", body = OidcDiscoveryImportResponse),
        (status = 400, description = "issuer が宛先の検査に通らない・文書を取得できない・文書の issuer が一致しない・必要な項目が無い"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.external-idps:write 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn import_external_idp_discovery(
    RequirePerms(_admin, _): RequirePerms<ExternalIdpsWrite>,
    State(state): State<AppState>,
    Extension(_tenant): Extension<ResolvedTenant>,
    Json(body): Json<OidcDiscoveryImportRequest>,
) -> Result<Json<OidcDiscoveryImportResponse>, ApiError> {
    // Failure reasons are validation messages for admins, so not translated (CLAUDE.md "翻訳の対象外"; same as the SAML
    // import). Connection-level details (why it was unreachable) are left only in the ops log by the fetch implementation.
    let imported = state
        .external_idp_discovery
        .import(&body.issuer)
        .await
        .map_err(|e| match e {
            DiscoveryImportError::Validation(m) | DiscoveryImportError::Unavailable(m) => {
                ApiError::BadRequest(m)
            }
        })?;
    Ok(Json(OidcDiscoveryImportResponse {
        issuer: imported.issuer,
        authorization_endpoint: imported.authorization_endpoint,
        token_endpoint: imported.token_endpoint,
        jwks_uri: imported.jwks_uri,
    }))
}

/// Deletes an external IdP (the linked users' mapping rows are deleted by FK CASCADE too).
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/external-idps/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "対象プロバイダの内部 ID（UUID）")),
    responses(
        (status = 204, description = "削除完了"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.external-idps:write 必須）"),
        (status = 404, description = "対象が無い"),
    ),
    security(("bearer_token" = []))
)]
pub async fn delete_external_idp(
    RequirePerms(admin, _): RequirePerms<ExternalIdpsWrite>,
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationId>,
    Extension(tenant): Extension<ResolvedTenant>,
    headers: HeaderMap,
    Path((_tenant_id, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let ctx = request_context(
        &headers,
        &correlation,
        state.config.trust_forwarded_headers(),
    );
    let id = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound("not found".to_string()))?;
    state
        .external_idps
        .delete(tenant.context(), id, &admin.actor, &ctx)
        .await
        .map_err(map_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn response(state: &AppState, p: &ExternalIdentityProvider) -> ExternalIdpResponse {
    ExternalIdpResponse {
        id: p.id.to_string(),
        provider_code: p.provider_code.clone(),
        display_name: p.display_name.clone(),
        issuer: p.issuer.clone(),
        protocol: p.protocol().as_str().to_string(),
        authorization_endpoint: p.config.as_oidc().map(|o| o.authorization_endpoint.clone()),
        token_endpoint: p.config.as_oidc().map(|o| o.token_endpoint.clone()),
        jwks_uri: p.config.as_oidc().map(|o| o.jwks_uri.clone()),
        client_id: p.config.as_oidc().map(|o| o.client_id.clone()),
        has_client_secret: p
            .config
            .as_oidc()
            .is_some_and(|o| o.client_secret_encrypted.is_some()),
        scopes: p
            .config
            .as_oidc()
            .map(|o| o.effective_scopes())
            .unwrap_or_default(),
        saml_sso_url: p.config.as_saml().map(|s| s.sso_url.clone()),
        saml_certificates: p
            .config
            .as_saml()
            .map(|s| s.certificates.clone())
            .unwrap_or_default(),
        saml_name_id_format: p.config.as_saml().map(|s| s.name_id_format.clone()),
        // Values needed for SAML setup (to have registered on the external IdP side). Don't make admins
        // guess the composition rules.
        saml_sp_entity_id: p.config.as_saml().map(|_| {
            format!(
                "{}/{}/saml/sp",
                state.config.public_web_base_url(),
                p.tenant_id
            )
        }),
        saml_acs_url: p.config.as_saml().map(|_| {
            format!(
                "{}/{}/external/{}/saml/acs",
                state.config.public_web_base_url(),
                p.tenant_id,
                p.provider_code
            )
        }),
        enabled: p.enabled,
        allow_auto_link: p.allow_auto_link,
        // Value to have registered on the external IdP side. Don't make admins guess the composition rules.
        redirect_uri: format!(
            "{}/{}/external/{}/callback",
            state.config.public_web_base_url(),
            p.tenant_id,
            p.provider_code
        ),
        created_at: p.created_at.to_rfc3339(),
        updated_at: p.updated_at.to_rfc3339(),
    }
}

fn map_error(e: ExternalIdpManagementError) -> ApiError {
    match e {
        // Validation messages are for admins (not end users), so returned in English untranslated
        // (same treatment as OAuth's `error_description`; CLAUDE.md "翻訳の対象外").
        ExternalIdpManagementError::Validation(m) => ApiError::BadRequest(m),
        ExternalIdpManagementError::NotFound => {
            ApiError::NotFound("external identity provider not found".to_string())
        }
        ExternalIdpManagementError::Conflict(m) => ApiError::Conflict(m),
        ExternalIdpManagementError::Internal(m) => ApiError::Internal(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract web uses (`assay_contracts::admin`) and the api DTO have the same shape. If they diverge,
    /// the admin console's import silently breaks.
    #[test]
    fn discovery_import_contract_matches_the_api_dto() {
        let shared = assay_contracts::admin::OidcDiscoveryImportRequest {
            issuer: "https://idp.example.com".to_string(),
        };
        let parsed: OidcDiscoveryImportRequest =
            serde_json::from_value(serde_json::to_value(&shared).unwrap()).unwrap();
        assert_eq!(parsed.issuer, shared.issuer);

        let api = OidcDiscoveryImportResponse {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };
        let shared: assay_contracts::admin::OidcDiscoveryImportResponse =
            serde_json::from_value(serde_json::to_value(&api).unwrap()).unwrap();
        assert_eq!(shared.issuer, api.issuer);
        assert_eq!(shared.authorization_endpoint, api.authorization_endpoint);
        assert_eq!(shared.token_endpoint, api.token_endpoint);
        assert_eq!(shared.jwks_uri, api.jwks_uri);
    }

    /// The same for the SAML IdP metadata import (split because task #124 added `ToSchema` to the api-side DTO).
    #[test]
    fn saml_metadata_import_contract_matches_the_api_dto() {
        let shared = assay_contracts::admin::SamlMetadataImportRequest {
            metadata_xml: "<EntityDescriptor/>".to_string(),
        };
        let parsed: SamlIdpMetadataImportRequest =
            serde_json::from_value(serde_json::to_value(&shared).unwrap()).unwrap();
        assert_eq!(parsed.metadata_xml, shared.metadata_xml);

        let api = SamlIdpMetadataImportResponse {
            display_name: "Corp".to_string(),
            entity_id: "https://idp.example.com/metadata".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            certificates: vec!["MIIB-old".to_string(), "MIIB-new".to_string()],
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
        };
        let shared: assay_contracts::admin::SamlIdpMetadataImportResponse =
            serde_json::from_value(serde_json::to_value(&api).unwrap()).unwrap();
        assert_eq!(shared.display_name, api.display_name);
        assert_eq!(shared.entity_id, api.entity_id);
        assert_eq!(shared.sso_url, api.sso_url);
        assert_eq!(shared.certificates, api.certificates);
        assert_eq!(shared.name_id_format, api.name_id_format);
    }
}
