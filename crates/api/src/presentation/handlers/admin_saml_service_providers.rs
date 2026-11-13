//! SAML SP (client) registration endpoints (`/{tenant_id}/admin/saml-service-providers`).
//! Manages the SPs this product (the IdP) trusts.
//!
//! Listing needs `idp.saml-service-providers:read`; register/update/delete and metadata import need
//! `idp.saml-service-providers:write` (`RequirePerms<SamlServiceProvidersRead>` /
//! `<SamlServiceProvidersWrite>`; `idp.tenant.admin` implies both).
//!
//! Input/output use api-side DTOs with `utoipa` (to appear in OpenAPI, task #146). If their shape diverges from the
//! `assay_contracts::admin` DTOs web uses (`assay_contracts` has no `utoipa`), registering and editing from
//! the admin screen silently breaks, so the tests in this file catch any divergence.

use crate::application::saml_service_provider_management::{
    RegisterSamlServiceProviderCommand, SamlServiceProviderManagementError,
    UpdateSamlServiceProviderCommand,
};
use crate::domain::saml_metadata::parse_sp_metadata;
use crate::domain::saml_service_provider::SamlServiceProvider;
use crate::presentation::admin::{
    RequirePerms, SamlServiceProvidersRead, SamlServiceProvidersWrite,
};
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// SAML SP registration request (same shape as `assay_contracts::admin::SamlServiceProviderRegisterRequest`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlServiceProviderRegisterRequest {
    pub display_name: String,
    /// The SP's entityID (unique within the tenant).
    pub entity_id: String,
    /// The SP's AssertionConsumerService URL.
    pub acs_url: String,
    /// NameID format (default persistent if empty).
    #[serde(default)]
    pub name_id_format: String,
    /// Signing/encryption certificate (optional).
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// SAML SP update request (replaces with the same fields as registration; the tenant does not change.
/// Same shape as `assay_contracts::admin::SamlServiceProviderUpdateRequest`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlServiceProviderUpdateRequest {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    /// NameID format (default persistent if empty).
    #[serde(default)]
    pub name_id_format: String,
    /// Signing/encryption certificate (optional).
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// Admin API representation of a SAML SP (same shape as `assay_contracts::admin::SamlServiceProviderResponse`).
#[derive(Debug, Serialize, ToSchema)]
pub struct SamlServiceProviderResponse {
    pub id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// Signing/encryption certificate (null if not set).
    pub x509_certificate: Option<String>,
    pub enabled: bool,
    /// RFC3339.
    pub created_at: String,
    /// RFC3339.
    pub updated_at: String,
}

/// SP metadata import request (same shape as `assay_contracts::admin::SamlMetadataImportRequest`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlSpMetadataImportRequest {
    /// SAML metadata XML (the SP's `EntityDescriptor`).
    pub metadata_xml: String,
}

/// SP metadata import response (initial values for the registration form; **nothing is registered**.
/// Same shape as `assay_contracts::admin::SamlSpMetadataImportResponse`).
#[derive(Debug, Serialize, ToSchema)]
pub struct SamlSpMetadataImportResponse {
    /// Display name from the metadata (empty string if none).
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    /// NameID format (empty string if none).
    pub name_id_format: String,
    /// Certificate (base64 DER; empty string if none).
    pub x509_certificate: String,
}

/// Registers an SP. 201 on success.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/saml-service-providers",
    operation_id = "register_saml_service_provider",
    tag = "admin",
    request_body = SamlServiceProviderRegisterRequest,
    responses(
        (status = 201, description = "登録完了", body = SamlServiceProviderResponse),
        (status = 400, description = "入力が不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.saml-service-providers:write 必須）"),
        (status = 409, description = "entity_id の重複"),
    ),
    security(("bearer_token" = []))
)]
pub async fn register(
    RequirePerms(_admin, _): RequirePerms<SamlServiceProvidersWrite>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Json(body): Json<SamlServiceProviderRegisterRequest>,
) -> Result<(StatusCode, Json<SamlServiceProviderResponse>), ApiError> {
    let provider = state
        .saml_service_providers
        .register(RegisterSamlServiceProviderCommand {
            tenant_id: tenant.id(),
            display_name: body.display_name,
            entity_id: body.entity_id,
            acs_url: body.acs_url,
            name_id_format: body.name_id_format,
            x509_certificate: body.x509_certificate,
            enabled: body.enabled,
        })
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(to_response(&provider))))
}

/// Updates an existing SP (only `id`s within the tenant boundary).
#[utoipa::path(
    put,
    path = "/{tenant_id}/admin/saml-service-providers/{id}",
    operation_id = "update_saml_service_provider",
    tag = "admin",
    params(("id" = String, Path, description = "対象 SP の内部 ID（UUID）")),
    request_body = SamlServiceProviderUpdateRequest,
    responses(
        (status = 200, description = "更新完了", body = SamlServiceProviderResponse),
        (status = 400, description = "入力が不正"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.saml-service-providers:write 必須）"),
        (status = 404, description = "対象が無い（id が UUID でない場合を含む）"),
        (status = 409, description = "entity_id の重複"),
    ),
    security(("bearer_token" = []))
)]
pub async fn update(
    RequirePerms(_admin, _): RequirePerms<SamlServiceProvidersWrite>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, id)): Path<(String, String)>,
    Json(body): Json<SamlServiceProviderUpdateRequest>,
) -> Result<Json<SamlServiceProviderResponse>, ApiError> {
    let id = parse_id(&id, locale)?;
    let provider = state
        .saml_service_providers
        .update(UpdateSamlServiceProviderCommand {
            tenant_id: tenant.id(),
            id,
            display_name: body.display_name,
            entity_id: body.entity_id,
            acs_url: body.acs_url,
            name_id_format: body.name_id_format,
            x509_certificate: body.x509_certificate,
            enabled: body.enabled,
        })
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(to_response(&provider)))
}

/// Deletes an SP (only `id`s within the tenant boundary). 204 on success.
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/saml-service-providers/{id}",
    operation_id = "delete_saml_service_provider",
    tag = "admin",
    params(("id" = String, Path, description = "対象 SP の内部 ID（UUID）")),
    responses(
        (status = 204, description = "削除完了"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.saml-service-providers:write 必須）"),
        (status = 404, description = "対象が無い（id が UUID でない場合を含む）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn delete(
    RequirePerms(_admin, _): RequirePerms<SamlServiceProvidersWrite>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Path((_tenant_id, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let id = parse_id(&id, locale)?;
    state
        .saml_service_providers
        .delete(tenant.id(), id)
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Lists SPs.
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/saml-service-providers",
    operation_id = "list_saml_service_providers",
    tag = "admin",
    responses(
        (status = 200, description = "SAML SP 一覧", body = [SamlServiceProviderResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.saml-service-providers:read 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn list(
    RequirePerms(_admin, _): RequirePerms<SamlServiceProvidersRead>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<Vec<SamlServiceProviderResponse>>, ApiError> {
    let providers = state
        .saml_service_providers
        .list(tenant.id())
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(providers.iter().map(to_response).collect()))
}

/// Parses SP metadata XML and returns initial values for the registration form. Nothing is persisted.
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/saml-service-providers/import-metadata",
    operation_id = "import_saml_service_provider_metadata",
    tag = "admin",
    request_body = SamlSpMetadataImportRequest,
    responses(
        (status = 200, description = "取り込んだ登録候補値（保存はしていない）", body = SamlSpMetadataImportResponse),
        (status = 400, description = "メタデータを解析できない"),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.saml-service-providers:write 必須）"),
    ),
    security(("bearer_token" = []))
)]
pub async fn import_metadata(
    RequirePerms(_admin, _): RequirePerms<SamlServiceProvidersWrite>,
    State(_state): State<AppState>,
    Extension(_tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Json(body): Json<SamlSpMetadataImportRequest>,
) -> Result<Json<SamlSpMetadataImportResponse>, ApiError> {
    let parsed = parse_sp_metadata(&body.metadata_xml)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    Ok(Json(SamlSpMetadataImportResponse {
        display_name: parsed.display_name.unwrap_or_default(),
        entity_id: parsed.entity_id,
        acs_url: parsed.acs_url,
        name_id_format: parsed.name_id_format.unwrap_or_default(),
        x509_certificate: parsed.x509_certificate,
    }))
}

/// Validates the SP id (UUID string) in the path. An invalid UUID is treated like "not found", 404
/// (no information given by finely distinguishing nonexistent ids).
fn parse_id(raw: &str, locale: ApiLocale) -> Result<Uuid, ApiError> {
    Uuid::parse_str(raw)
        .map_err(|_| ApiError::NotFound(ApiMessages::new(locale).get("api-saml-sp-not-found")))
}

fn to_response(provider: &SamlServiceProvider) -> SamlServiceProviderResponse {
    SamlServiceProviderResponse {
        id: provider.id.to_string(),
        tenant_id: provider.tenant_id.to_string(),
        display_name: provider.display_name.clone(),
        entity_id: provider.entity_id.clone(),
        acs_url: provider.acs_url.clone(),
        name_id_format: provider.name_id_format.clone(),
        x509_certificate: provider.x509_certificate.clone(),
        enabled: provider.enabled,
        created_at: provider.created_at.to_rfc3339(),
        updated_at: provider.updated_at.to_rfc3339(),
    }
}

fn map_error(error: SamlServiceProviderManagementError, locale: ApiLocale) -> ApiError {
    let messages = ApiMessages::new(locale);
    match error {
        SamlServiceProviderManagementError::Validation(m) => {
            ApiError::BadRequest(messages.get_message(&m))
        }
        SamlServiceProviderManagementError::Conflict(m) => {
            ApiError::Conflict(messages.get_message(&m))
        }
        SamlServiceProviderManagementError::NotFound => {
            ApiError::NotFound(messages.get("api-saml-sp-not-found"))
        }
        SamlServiceProviderManagementError::Internal(message) => ApiError::Internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "MIIB-sp";

    /// The api DTO accepts as is the `assay_contracts` request sent by the admin console (web).
    #[test]
    fn saml_sp_request_contracts_match_the_api_dto() {
        let shared = assay_contracts::admin::SamlServiceProviderRegisterRequest {
            display_name: "Wiki".to_string(),
            entity_id: "https://sp.example.com/metadata".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string(),
            x509_certificate: Some(CERT.to_string()),
            enabled: true,
        };
        let api: SamlServiceProviderRegisterRequest =
            serde_json::from_value(serde_json::to_value(&shared).unwrap()).unwrap();
        assert_eq!(api.display_name, shared.display_name);
        assert_eq!(api.entity_id, shared.entity_id);
        assert_eq!(api.acs_url, shared.acs_url);
        assert_eq!(api.name_id_format, shared.name_id_format);
        assert_eq!(api.x509_certificate, shared.x509_certificate);
        assert_eq!(api.enabled, shared.enabled);

        let shared = assay_contracts::admin::SamlServiceProviderUpdateRequest {
            display_name: "Wiki".to_string(),
            entity_id: "https://sp.example.com/metadata".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            name_id_format: String::new(),
            x509_certificate: None,
            enabled: false,
        };
        let api: SamlServiceProviderUpdateRequest =
            serde_json::from_value(serde_json::to_value(&shared).unwrap()).unwrap();
        assert_eq!(api.display_name, shared.display_name);
        assert_eq!(api.entity_id, shared.entity_id);
        assert_eq!(api.acs_url, shared.acs_url);
        assert_eq!(api.name_id_format, shared.name_id_format);
        assert_eq!(api.x509_certificate, shared.x509_certificate);
        assert_eq!(api.enabled, shared.enabled);

        let shared = assay_contracts::admin::SamlMetadataImportRequest {
            metadata_xml: "<EntityDescriptor/>".to_string(),
        };
        let api: SamlSpMetadataImportRequest =
            serde_json::from_value(serde_json::to_value(&shared).unwrap()).unwrap();
        assert_eq!(api.metadata_xml, shared.metadata_xml);
    }

    /// The JSON the api returns and the JSON web builds from the `assay_contracts` types are **identical down to the keys**.
    #[test]
    fn saml_sp_response_contracts_match_the_api_dto() {
        let api = SamlServiceProviderResponse {
            id: "019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string(),
            tenant_id: "01a00dfe-bffb-7f23-88b5-8bbef50d23f0".to_string(),
            display_name: "Wiki".to_string(),
            entity_id: "https://sp.example.com/metadata".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string(),
            x509_certificate: None,
            enabled: true,
            created_at: "2026-09-30T00:00:00+00:00".to_string(),
            updated_at: "2026-09-30T00:00:00+00:00".to_string(),
        };
        let shared = assay_contracts::admin::SamlServiceProviderResponse {
            id: api.id.clone(),
            tenant_id: api.tenant_id.clone(),
            display_name: api.display_name.clone(),
            entity_id: api.entity_id.clone(),
            acs_url: api.acs_url.clone(),
            name_id_format: api.name_id_format.clone(),
            x509_certificate: None,
            enabled: api.enabled,
            created_at: api.created_at.clone(),
            updated_at: api.updated_at.clone(),
        };
        assert_eq!(
            serde_json::to_value(&api).unwrap(),
            serde_json::to_value(&shared).unwrap()
        );

        let api = SamlSpMetadataImportResponse {
            display_name: "Wiki".to_string(),
            entity_id: "https://sp.example.com/metadata".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            name_id_format: String::new(),
            x509_certificate: CERT.to_string(),
        };
        let shared = assay_contracts::admin::SamlSpMetadataImportResponse {
            display_name: api.display_name.clone(),
            entity_id: api.entity_id.clone(),
            acs_url: api.acs_url.clone(),
            name_id_format: api.name_id_format.clone(),
            x509_certificate: api.x509_certificate.clone(),
        };
        assert_eq!(
            serde_json::to_value(&api).unwrap(),
            serde_json::to_value(&shared).unwrap()
        );
    }
}
