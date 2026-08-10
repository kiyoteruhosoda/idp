//! 外部 IdP 設定の管理 API（`/{tenant_id}/admin/external-idps`。AP10）。
//!
//! テナント管理者が、テナントで使える外部 OpenID Provider を登録・更新・削除する。
//! クライアントシークレットは**書き込み専用**で、応答には含めない（保存は暗号化。復号するのは
//! 外部 IdP へトークン要求を出す瞬間だけ）。

use crate::application::external_idp_management::{
    ExternalIdpConfigCommand, ExternalIdpManagementError, RegisterExternalIdpCommand,
    UpdateExternalIdpCommand,
};
use crate::domain::external_idp::{ExternalIdentityProvider, ExternalIdpProtocol};
use crate::domain::saml_metadata::parse_idp_metadata;
use crate::presentation::admin::{IdpAdmin, RequirePerms};
use crate::presentation::correlation::CorrelationId;
use crate::presentation::error::ApiError;
use crate::presentation::handlers::request_context;
use crate::presentation::state::AppState;
use crate::presentation::tenant::ResolvedTenant;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use idp_contracts::admin::{SamlIdpMetadataImportResponse, SamlMetadataImportRequest};
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
    /// `oidc` / `saml`（ADR-0027）。以降の項目はプロトコルによって使う・使わないが分かれる。
    pub protocol: String,
    /// OIDC のみ。
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub client_id: Option<String>,
    /// OIDC のみ。シークレットを設定済みか（値は返さない）。
    pub has_client_secret: bool,
    pub scopes: Vec<String>,
    /// SAML のみ。IdP の `SingleSignOnService` URL。
    pub saml_sso_url: Option<String>,
    /// SAML のみ。署名検証に使う証明書（base64 DER）。秘密ではないので返す。
    pub saml_certificates: Vec<String>,
    pub saml_name_id_format: Option<String>,
    /// SAML のみ。外部 IdP へ登録すべき本 IdP の entityID と ACS URL。
    pub saml_sp_entity_id: Option<String>,
    pub saml_acs_url: Option<String>,
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
    /// `oidc`（既定）/ `saml`。
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// OIDC のとき必須。
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    /// 平文のクライアントシークレット（public クライアントとして登録するなら省略）。
    #[serde(default)]
    pub client_secret: Option<String>,
    /// 省略時は `openid profile email`。
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// SAML のとき必須。
    #[serde(default)]
    pub saml_sso_url: Option<String>,
    #[serde(default)]
    pub saml_certificates: Option<Vec<String>>,
    #[serde(default)]
    pub saml_name_id_format: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 検証済みメール一致で既存利用者へ自動連携するか（既定 false）。
    #[serde(default)]
    pub allow_auto_link: bool,
}

fn default_true() -> bool {
    true
}

fn default_protocol() -> String {
    "oidc".to_string()
}

/// 入力からプロトコル固有の設定を組み立てる。**片方のプロトコルの項目だけ**を読む——
/// 両方読めるようにすると、OIDC の設定に SAML の欄が混ざった半端な登録ができてしまう。
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

/// 部分更新。指定した項目のみ更新する。`client_secret` を空文字にすると削除（public 化）。
#[derive(Debug, Deserialize, ToSchema)]
pub struct ExternalIdpUpdateRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    /// プロトコル固有の設定を差し替えるときだけ指定する（プロトコルそのものは変更できない）。
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
    // プロトコル固有の設定は**まとめて**差し替える（`protocol` を指定したときだけ）。項目ごとの
    // 部分更新にすると、中途半端な組み合わせを作れてしまう。
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
            admin.user_id,
            &ctx,
        )
        .await
        .map_err(map_error)?;
    Ok(Json(response(&state, &provider)))
}

/// 外部 IdP のメタデータ XML を解析し、登録フォームの初期値を返す（AP12）。データは永続化しない。
///
/// entityID・SSO URL・署名証明書の貼り付けは、管理者が IdP のメタデータから 1 項目ずつ写す作業に
/// なりやすい。証明書は base64 が数行続くため、写し間違えても**利用者のログイン時**まで表に出ない。
///
/// 入出力は `idp_contracts::admin` の DTO をそのまま使う（SP メタデータ取り込みと同じ）。api 側に
/// 同じ形をもう一度定義すると、web と食い違ったときに取り込みが静かに壊れる。
pub async fn import_external_idp_metadata(
    RequirePerms(_admin, _): RequirePerms<IdpAdmin>,
    State(_state): State<AppState>,
    Extension(_tenant): Extension<ResolvedTenant>,
    Json(body): Json<SamlMetadataImportRequest>,
) -> Result<Json<SamlIdpMetadataImportResponse>, ApiError> {
    // 解析の失敗理由（entityID が無い・SSO が無い等）はそのまま返す。管理者向けの検証メッセージ
    // なので翻訳しない（CLAUDE.md「翻訳の対象外」）。取り違え——SP のメタデータを貼った——を
    // 「IdP の SingleSignOnService が無い」と言えるかどうかで、気づけるかが変わる。
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
        // SAML の設定作業に要る値（外部 IdP 側へ登録してもらう）。組み立て規則を管理者に
        // 推測させない。
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
