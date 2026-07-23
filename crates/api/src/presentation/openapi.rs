//! OpenAPI ドキュメント（utoipa による自動生成）。
//!
//! API エンドポイント仕様はここから生成される `/api/openapi.json`・Swagger UI（`/api/docs`）が
//! 唯一の出所（`CLAUDE.md`「ドキュメント運用」）。仕様はハンドラの `#[utoipa::path]` 属性と
//! DTO の `ToSchema` から組み立てられる。

use crate::presentation::dto::{
    AcceptInvitationRequest, AuditLogEntryResponse, ClientCreatedResponse, ClientRegisterRequest,
    ClientResponse, ClientSecretResponse, ClientUpdateRequest, CreateInvitationRequest,
    CreateTenantRequest, CreateUserRequest, GenerateSigningKeyRequest, GrantPermissionRequest,
    InvitationCreatedResponse, MemberResponse, OAuthErrorResponse, RegisterRequest,
    RegisterResponse, RuntimeSettingResponse, SigningKeyResponse, SystemSettingsResponse,
    TenantAdminPasswordResetRequest, TenantResponse, TokenRequest, TokenResponse,
    UpdateRuntimeSettingRequest, UpdateSystemSettingsRequest, UpdateTenantRequest,
    UpdateTenantSettingsRequest, UpdateUserStatusRequest, UserCreatedResponse, UserInfoResponse,
    UserPasswordResetResponse, UserPermissionsResponse, VerifyEmailRequest,
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
        handlers::register::verify_email,
        handlers::authorize::authorize,
        handlers::token::token,
        handlers::userinfo::userinfo,
        handlers::discovery::openid_configuration,
        handlers::discovery::jwks,
        handlers::discovery::saml_idp_metadata,
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
        handlers::admin_tenants::list_tenants,
        handlers::admin_tenants::create_tenant,
        handlers::admin_tenants::get_tenant,
        handlers::admin_tenants::update_tenant,
        handlers::admin_tenants::delete_tenant,
        handlers::admin_tenants::reset_tenant_admin_password,
        handlers::admin_tenants::get_current_tenant,
        handlers::admin_tenants::update_current_tenant,
        handlers::admin_system_settings::get_system_settings,
        handlers::admin_system_settings::update_system_settings,
        handlers::admin_system_settings::update_runtime_setting,
        handlers::admin_users::create_user,
        handlers::admin_users::update_user_status,
        handlers::admin_users::delete_user,
        handlers::admin_users::reset_user_password,
        handlers::admin_members::list_members,
        handlers::admin_members::revoke_member,
        handlers::admin_invitations::create_invitation,
        handlers::invitations::accept_invitation,
        handlers::admin_audit::list_audit_logs,
        handlers::admin_signing_keys::list_keys,
        handlers::admin_signing_keys::generate_key,
        handlers::admin_signing_keys::retire_key,
        handlers::admin_signing_keys::delete_key,
    ),
    components(schemas(
        RegisterRequest,
        RegisterResponse,
        VerifyEmailRequest,
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
        CreateTenantRequest,
        UpdateTenantRequest,
        UpdateTenantSettingsRequest,
        TenantResponse,
        SystemSettingsResponse,
        UpdateSystemSettingsRequest,
        UpdateRuntimeSettingRequest,
        RuntimeSettingResponse,
        CreateUserRequest,
        UserCreatedResponse,
        UpdateUserStatusRequest,
        UserPasswordResetResponse,
        TenantAdminPasswordResetRequest,
        MemberResponse,
        CreateInvitationRequest,
        InvitationCreatedResponse,
        AcceptInvitationRequest,
        AuditLogEntryResponse,
        SigningKeyResponse,
        GenerateSigningKeyRequest,
    )),
    modifiers(&BearerToken),
    tags(
        (name = "oidc", description = "OIDC コアエンドポイント"),
        (name = "saml", description = "SAML メタデータ（IdP メタデータ出力）"),
        (name = "auth", description = "ユーザー登録・認証"),
        (name = "admin", description = "管理 API（idp.tenant.admin 権限が必要。内部用）"),
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
