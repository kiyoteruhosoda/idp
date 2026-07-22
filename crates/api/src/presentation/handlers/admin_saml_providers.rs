//! SAML 外部 IdP 連携設定エンドポイント。

use crate::application::saml_provider_management::{
    RegisterSamlProviderCommand, SamlProviderManagementError,
};
use crate::domain::saml_metadata::parse_idp_metadata;
use crate::domain::saml_provider::SamlIdentityProvider;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use idp_contracts::admin::{
    SamlMetadataImportRequest, SamlMetadataImportResponse, SamlProviderRegisterRequest,
    SamlProviderResponse,
};

pub async fn register(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Json(body): Json<SamlProviderRegisterRequest>,
) -> Result<(StatusCode, Json<SamlProviderResponse>), ApiError> {
    let provider = state
        .saml_providers
        .register(RegisterSamlProviderCommand {
            tenant_id: tenant.id(),
            display_name: body.display_name,
            entity_id: body.entity_id,
            sso_url: body.sso_url,
            x509_certificate: body.x509_certificate,
            enabled: body.enabled,
        })
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok((StatusCode::CREATED, Json(to_response(&provider))))
}

pub async fn list(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(state): State<AppState>,
    Extension(tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
) -> Result<Json<Vec<SamlProviderResponse>>, ApiError> {
    let providers = state
        .saml_providers
        .list(tenant.id())
        .await
        .map_err(|e| map_error(e, locale))?;
    Ok(Json(providers.iter().map(to_response).collect()))
}

/// 外部 IdP メタデータ XML を解析し、登録フォームの初期値を返す（A5）。データは永続化しない。
pub async fn import_metadata(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(_state): State<AppState>,
    Extension(_tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Json(body): Json<SamlMetadataImportRequest>,
) -> Result<Json<SamlMetadataImportResponse>, ApiError> {
    let parsed = parse_idp_metadata(&body.metadata_xml)
        .map_err(|_| ApiError::BadRequest(ApiMessages::new(locale).get("api-invalid-request")))?;
    Ok(Json(SamlMetadataImportResponse {
        display_name: parsed.display_name.unwrap_or_default(),
        entity_id: parsed.entity_id,
        sso_url: parsed.sso_url,
        x509_certificate: parsed.x509_certificate,
    }))
}

fn to_response(provider: &SamlIdentityProvider) -> SamlProviderResponse {
    SamlProviderResponse {
        id: provider.id.to_string(),
        tenant_id: provider.tenant_id.to_string(),
        display_name: provider.display_name.clone(),
        entity_id: provider.entity_id.clone(),
        sso_url: provider.sso_url.clone(),
        enabled: provider.enabled,
        created_at: provider.created_at.to_rfc3339(),
        updated_at: provider.updated_at.to_rfc3339(),
    }
}

fn map_error(error: SamlProviderManagementError, locale: ApiLocale) -> ApiError {
    let messages = ApiMessages::new(locale);
    match error {
        SamlProviderManagementError::Validation(_) => {
            ApiError::BadRequest(messages.get("api-invalid-request"))
        }
        SamlProviderManagementError::Conflict(message) => ApiError::Conflict(message),
        SamlProviderManagementError::Internal(message) => ApiError::Internal(message),
    }
}
