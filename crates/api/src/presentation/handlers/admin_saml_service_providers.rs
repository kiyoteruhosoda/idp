//! SAML SP（クライアント）登録エンドポイント（`/{tenant_id}/admin/saml-service-providers`）。
//! 本プロダクト（IdP）が信頼する SP を管理する。
//!
//! 一覧は `idp.saml-service-providers:read`、登録・更新・削除とメタデータの取り込みは
//! `idp.saml-service-providers:write` が要る（`RequirePerms<SamlServiceProvidersRead>` /
//! `<SamlServiceProvidersWrite>`。`idp.tenant.admin` は両方を含意する）。
//!
//! 入出力は api 側の `utoipa` 付き DTO で受け渡す（OpenAPI に載せるため。task #146）。web が使う
//! `assay_contracts::admin` の DTO（`assay_contracts` は `utoipa` を持たない）と形が食い違うと
//! 管理画面からの登録・編集が静かに壊れるため、食い違いはこのファイルのテストが落とす。

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

/// SAML SP の登録要求（`assay_contracts::admin::SamlServiceProviderRegisterRequest` と同じ形）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlServiceProviderRegisterRequest {
    pub display_name: String,
    /// SP の entityID（テナント内で一意）。
    pub entity_id: String,
    /// SP の AssertionConsumerService URL。
    pub acs_url: String,
    /// NameID フォーマット（空なら既定の persistent）。
    #[serde(default)]
    pub name_id_format: String,
    /// 署名/暗号証明書（任意）。
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// SAML SP の更新要求（登録と同じ項目で置き換える。テナントは変えない。
/// `assay_contracts::admin::SamlServiceProviderUpdateRequest` と同じ形）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlServiceProviderUpdateRequest {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    /// NameID フォーマット（空なら既定の persistent）。
    #[serde(default)]
    pub name_id_format: String,
    /// 署名/暗号証明書（任意）。
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// SAML SP の管理 API 表現（`assay_contracts::admin::SamlServiceProviderResponse` と同じ形）。
#[derive(Debug, Serialize, ToSchema)]
pub struct SamlServiceProviderResponse {
    pub id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// 署名/暗号証明書（設定されていなければ null）。
    pub x509_certificate: Option<String>,
    pub enabled: bool,
    /// RFC3339。
    pub created_at: String,
    /// RFC3339。
    pub updated_at: String,
}

/// SP メタデータ取り込みの要求（`assay_contracts::admin::SamlMetadataImportRequest` と同じ形）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct SamlSpMetadataImportRequest {
    /// SAML メタデータ XML（SP の `EntityDescriptor`）。
    pub metadata_xml: String,
}

/// SP メタデータ取り込みの応答（登録フォームの初期値。**登録はしていない**。
/// `assay_contracts::admin::SamlSpMetadataImportResponse` と同じ形）。
#[derive(Debug, Serialize, ToSchema)]
pub struct SamlSpMetadataImportResponse {
    /// メタデータの表示名（無ければ空文字）。
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    /// NameID フォーマット（無ければ空文字）。
    pub name_id_format: String,
    /// 証明書（base64 DER。無ければ空文字）。
    pub x509_certificate: String,
}

/// SP を登録する。成功時 201。
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

/// 既存 SP を更新する（テナント境界内の `id` のみ）。
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

/// SP を削除する（テナント境界内の `id` のみ）。成功時 204。
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

/// SP を一覧する。
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

/// SP メタデータ XML を解析し、登録フォームの初期値を返す。データは永続化しない。
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

    /// 管理コンソール（web）が送る `assay_contracts` の要求を、api の DTO がそのまま受け取れる。
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

    /// api が返す JSON と、web が `assay_contracts` の型から作る JSON が**鍵まで同じ**。
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
