//! SAML 外部 IdP 連携設定エンドポイント。

use crate::application::saml_provider_management::{
    RegisterSamlProviderCommand, SamlProviderManagementError,
};
use crate::domain::saml_provider::SamlIdentityProvider;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::Json;
use idp_contracts::admin::{SamlProviderRegisterRequest, SamlProviderResponse};

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
