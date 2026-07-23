//! SAML SP（クライアント）登録エンドポイント。本プロダクト（IdP）が信頼する SP を管理する。

use crate::application::saml_service_provider_management::{
    RegisterSamlServiceProviderCommand, SamlServiceProviderManagementError,
    UpdateSamlServiceProviderCommand,
};
use crate::domain::saml_metadata::parse_sp_metadata;
use crate::domain::saml_service_provider::SamlServiceProvider;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::error::ApiError;
use crate::presentation::i18n::{ApiLocale, ApiMessages};
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use idp_contracts::admin::{
    SamlMetadataImportRequest, SamlServiceProviderRegisterRequest, SamlServiceProviderResponse,
    SamlServiceProviderUpdateRequest, SamlSpMetadataImportResponse,
};
use uuid::Uuid;

pub async fn register(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
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

/// 既存 SP を更新する（テナント境界内の `id` のみ）。
pub async fn update(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
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

/// SP を削除する（テナント境界内の `id` のみ）。成功時 204。
pub async fn delete(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
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

pub async fn list(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
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

/// SP メタデータ XML を解析し、登録フォームの初期値を返す。データは永続化しない。
pub async fn import_metadata(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(_state): State<AppState>,
    Extension(_tenant): Extension<ResolvedTenant>,
    locale: ApiLocale,
    Json(body): Json<SamlMetadataImportRequest>,
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

/// パスの SP id（UUID 文字列）を検証する。不正な UUID は「見つからない」と同義に 404 とする
/// （存在しない id を細かく区別して情報を与えない）。
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
        SamlServiceProviderManagementError::Validation(_) => {
            ApiError::BadRequest(messages.get("api-invalid-request"))
        }
        SamlServiceProviderManagementError::Conflict(message) => ApiError::Conflict(message),
        SamlServiceProviderManagementError::NotFound => {
            ApiError::NotFound(messages.get("api-saml-sp-not-found"))
        }
        SamlServiceProviderManagementError::Internal(message) => ApiError::Internal(message),
    }
}
