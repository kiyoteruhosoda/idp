//! OpenAPI ドキュメント（utoipa による自動生成）。
//!
//! API エンドポイント仕様はここから生成される `/api/openapi.json`・Swagger UI（`/api/docs`）が
//! 唯一の出所（`CLAUDE.md`「ドキュメント運用」）。仕様はハンドラの `#[utoipa::path]` 属性と
//! DTO の `ToSchema` から組み立てられる。

use crate::presentation::dto::{
    AuditLogEntryResponse, ClientCreatedResponse, ClientRegisterRequest, ClientResponse,
    ClientSecretResponse, ClientUpdateRequest, GenerateSigningKeyRequest, GrantPermissionRequest,
    OAuthErrorResponse, RegisterRequest, RegisterResponse, SigningKeyResponse, TokenRequest,
    TokenResponse, UserInfoResponse, UserPermissionsResponse,
};
use crate::presentation::handlers;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OIDC Identity Provider (MVP)",
        description = "OpenID Connect Identity Provider。Authorization Code Flow + PKCE(S256)。",
    ),
    paths(
        handlers::register::register,
        handlers::authorize::authorize,
        handlers::token::token,
        handlers::userinfo::userinfo,
        handlers::discovery::openid_configuration,
        handlers::discovery::jwks,
        handlers::logout::logout,
        handlers::revoke::revoke,
        handlers::introspect::introspect,
        handlers::admin_clients::create_client,
        handlers::admin_clients::list_clients,
        handlers::admin_clients::get_client,
        handlers::admin_clients::update_client,
        handlers::admin_clients::rotate_client_secret,
        handlers::admin_permissions::list_permissions,
        handlers::admin_permissions::grant_permission,
        handlers::admin_permissions::revoke_permission,
        handlers::admin_audit::list_audit_logs,
        handlers::admin_signing_keys::list_keys,
        handlers::admin_signing_keys::generate_key,
        handlers::admin_signing_keys::retire_key,
        handlers::admin_signing_keys::delete_key,
    ),
    components(schemas(
        RegisterRequest,
        RegisterResponse,
        TokenRequest,
        TokenResponse,
        UserInfoResponse,
        OAuthErrorResponse,
        ClientRegisterRequest,
        ClientUpdateRequest,
        ClientResponse,
        ClientCreatedResponse,
        ClientSecretResponse,
        GrantPermissionRequest,
        UserPermissionsResponse,
        AuditLogEntryResponse,
        SigningKeyResponse,
        GenerateSigningKeyRequest,
    )),
    modifiers(&BearerToken),
    tags(
        (name = "oidc", description = "OIDC コアエンドポイント"),
        (name = "auth", description = "ユーザー登録・認証"),
        (name = "admin", description = "管理 API（idp.admin 権限が必要。内部用）"),
    )
)]
pub struct ApiDoc;

/// `/userinfo` の Bearer 認証スキーム定義。
struct BearerToken;

impl Modify for BearerToken {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}
