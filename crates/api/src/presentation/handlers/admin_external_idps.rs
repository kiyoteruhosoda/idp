//! 外部 IdP 設定の管理 API（`/{tenant_id}/admin/external-idps`。AP10）。
//!
//! テナント管理者が、テナントで使える外部 OpenID Provider を登録・更新・削除する。
//! クライアントシークレットは**書き込み専用**で、応答には含めない（保存は暗号化。復号するのは
//! 外部 IdP へトークン要求を出す瞬間だけ）。

use crate::application::external_idp_management::{
    ExternalIdpManagementError, RegisterExternalIdpCommand, UpdateExternalIdpCommand,
};
use crate::domain::external_idp::ExternalIdentityProvider;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
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

/// 外部 IdP の公開表現（`client_secret` は返さない）。
#[derive(Debug, Serialize, ToSchema)]
pub struct ExternalIdpResponse {
    pub id: String,
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    /// シークレットを設定済みか（値は返さない）。
    pub has_client_secret: bool,
    pub scopes: Vec<String>,
    pub enabled: bool,
    pub allow_auto_link: bool,
    /// 外部 IdP へ登録すべきコールバック URL（設定作業の手掛かりとして返す）。
    pub redirect_uri: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ExternalIdpRegisterRequest {
    pub provider_code: String,
    pub display_name: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    /// 平文のクライアントシークレット（public クライアントとして登録するなら省略）。
    #[serde(default)]
    pub client_secret: Option<String>,
    /// 省略時は `openid profile email`。
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 検証済みメール一致で既存利用者へ自動連携するか（既定 false）。
    #[serde(default)]
    pub allow_auto_link: bool,
}

fn default_true() -> bool {
    true
}

/// 部分更新。指定した項目のみ更新する。`client_secret` を空文字にすると削除（public 化）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct ExternalIdpUpdateRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
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
    pub enabled: Option<bool>,
    #[serde(default)]
    pub allow_auto_link: Option<bool>,
}

/// 外部 IdP を一覧する。
#[utoipa::path(
    get,
    path = "/{tenant_id}/admin/external-idps",
    tag = "admin",
    responses(
        (status = 200, description = "外部 IdP 一覧", body = [ExternalIdpResponse]),
        (status = 401, description = "未認証"),
        (status = 403, description = "権限不足（idp.tenant.admin 必須）"),
    )
)]
pub async fn list_external_idps(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
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

/// 外部 IdP を登録する。
#[utoipa::path(
    post,
    path = "/{tenant_id}/admin/external-idps",
    tag = "admin",
    request_body = ExternalIdpRegisterRequest,
    responses(
        (status = 201, description = "登録完了", body = ExternalIdpResponse),
        (status = 400, description = "入力が不正"),
        (status = 409, description = "provider_code の重複"),
    )
)]
pub async fn register_external_idp(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
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
                authorization_endpoint: body.authorization_endpoint,
                token_endpoint: body.token_endpoint,
                jwks_uri: body.jwks_uri,
                client_id: body.client_id,
                client_secret: body.client_secret,
                scopes: body.scopes.unwrap_or_default(),
                enabled: body.enabled,
                allow_auto_link: body.allow_auto_link,
            },
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(response(&state, &provider))))
}

/// 外部 IdP を部分更新する。
#[utoipa::path(
    patch,
    path = "/{tenant_id}/admin/external-idps/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "対象プロバイダの内部 ID（UUID）")),
    request_body = ExternalIdpUpdateRequest,
    responses(
        (status = 200, description = "更新完了", body = ExternalIdpResponse),
        (status = 404, description = "対象が無い"),
    )
)]
pub async fn update_external_idp(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
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
    // 空文字は「シークレットを外す」意図として扱う（未指定＝維持と区別する）。
    let client_secret = body.client_secret.map(|s| {
        let trimmed = s.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let provider = state
        .external_idps
        .update(
            tenant.context(),
            id,
            UpdateExternalIdpCommand {
                display_name: body.display_name,
                issuer: body.issuer,
                authorization_endpoint: body.authorization_endpoint,
                token_endpoint: body.token_endpoint,
                jwks_uri: body.jwks_uri,
                client_id: body.client_id,
                client_secret,
                scopes: body.scopes,
                enabled: body.enabled,
                allow_auto_link: body.allow_auto_link,
            },
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(map_error)?;
    Ok(Json(response(&state, &provider)))
}

/// 外部 IdP を削除する（連携済みの利用者の対応行も FK CASCADE で消える）。
#[utoipa::path(
    delete,
    path = "/{tenant_id}/admin/external-idps/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "対象プロバイダの内部 ID（UUID）")),
    responses(
        (status = 204, description = "削除完了"),
        (status = 404, description = "対象が無い"),
    )
)]
pub async fn delete_external_idp(
    RequirePerms(admin, _): RequirePerms<IdpAdmin>,
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
        .delete(tenant.context(), id, admin.user_id, &ctx)
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
        authorization_endpoint: p.authorization_endpoint.clone(),
        token_endpoint: p.token_endpoint.clone(),
        jwks_uri: p.jwks_uri.clone(),
        client_id: p.client_id.clone(),
        has_client_secret: p.client_secret_encrypted.is_some(),
        scopes: p.effective_scopes(),
        enabled: p.enabled,
        allow_auto_link: p.allow_auto_link,
        // 外部 IdP 側に登録してもらう値。組み立て規則を管理者に推測させない。
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
        // 検証メッセージは管理者向け（利用者向けではない）ため、翻訳せず英語で返す
        // （OAuth の `error_description` と同じ扱い。CLAUDE.md「翻訳の対象外」）。
        ExternalIdpManagementError::Validation(m) => ApiError::BadRequest(m),
        ExternalIdpManagementError::NotFound => {
            ApiError::NotFound("external identity provider not found".to_string())
        }
        ExternalIdpManagementError::Conflict(m) => ApiError::Conflict(m),
        ExternalIdpManagementError::Internal(m) => ApiError::Internal(m),
    }
}
