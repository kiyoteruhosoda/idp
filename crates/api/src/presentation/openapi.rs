//! OpenAPI ドキュメント（utoipa による自動生成）。
//!
//! API エンドポイント仕様はここから生成される `/api/openapi.json`・Swagger UI（`/api/docs`）が
//! 唯一の出所（`CLAUDE.md`「ドキュメント運用」）。仕様はハンドラの `#[utoipa::path]` 属性と
//! DTO の `ToSchema` から組み立てられる。

use crate::presentation::dto::{
    AcceptInvitationRequest, AddTenantDomainRequest, AuditLogEntryResponse,
    AuthenticationPoliciesResponse, AuthenticationPolicyResponse,
    AuthenticationPolicyUpsertRequest, ClientCreatedResponse, ClientListResponse,
    ClientRegisterRequest, ClientResponse, ClientSecretResponse, ClientUpdateRequest,
    CreateInvitationRequest, CreateTenantRequest, CreateUserRequest, GenerateSigningKeyRequest,
    GrantPermissionRequest, InvitationCreatedResponse, MemberListResponse, MemberResponse,
    OAuthErrorResponse, RegisterRequest, RegisterResponse, RestartServiceResponse,
    RuntimeSettingResponse, SigningKeyResponse, SystemSettingsResponse,
    TenantAdminPasswordResetRequest, TenantDomainResponse, TenantListResponse, TenantResponse,
    TokenRequest, TokenResponse, UpdateMemberStatusRequest, UpdateRuntimeSettingRequest,
    UpdateSystemSettingsRequest, UpdateTenantRequest, UpdateTenantSettingsRequest,
    UpdateUserProfileRequest, UpdateUserStatusRequest, UserCreatedResponse, UserInfoResponse,
    UserMfaResetResponse, UserPasswordResetResponse, UserPermissionsResponse, UserUnlockResponse,
    VerifyEmailRequest,
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
        handlers::saml_sso::sso_redirect,
        handlers::saml_sso::sso_post,
        handlers::revoke::revoke,
        handlers::introspect::introspect,
        handlers::admin_clients::create_client,
        handlers::admin_clients::list_clients,
        handlers::admin_clients::get_client,
        handlers::admin_clients::update_client,
        handlers::admin_clients::rotate_client_secret,
        handlers::admin_clients::delete_client,
        handlers::admin_permissions::list_permissions,
        handlers::admin_permissions::grant_permission,
        handlers::admin_permissions::revoke_permission,
        handlers::admin_client_permissions::list_client_permissions,
        handlers::admin_client_permissions::grant_client_permission,
        handlers::admin_client_permissions::revoke_client_permission,
        handlers::admin_tenants::list_tenants,
        handlers::admin_tenants::create_tenant,
        handlers::admin_tenants::get_tenant,
        handlers::admin_tenants::update_tenant,
        handlers::admin_tenants::delete_tenant,
        handlers::admin_tenants::reset_tenant_admin_password,
        handlers::admin_tenants::list_tenant_domains,
        handlers::admin_tenants::add_tenant_domain,
        handlers::admin_tenants::remove_tenant_domain,
        handlers::admin_tenants::get_current_tenant,
        handlers::admin_tenants::update_current_tenant,
        handlers::admin_system_settings::get_system_settings,
        handlers::admin_system_settings::update_system_settings,
        handlers::admin_system_settings::update_runtime_setting,
        handlers::admin_restart::restart_service,
        handlers::admin_users::create_user,
        handlers::admin_users::update_user_status,
        handlers::admin_users::update_user_profile,
        handlers::admin_users::delete_user,
        handlers::admin_users::reset_user_password,
        handlers::admin_users::reset_user_mfa,
        handlers::admin_users::unlock_user,
        handlers::admin_login_identifiers::list_login_identifiers,
        handlers::admin_login_identifiers::add_login_identifier,
        handlers::admin_login_identifiers::update_login_identifier,
        handlers::admin_login_identifiers::delete_login_identifier,
        handlers::admin_members::list_members,
        handlers::admin_members::revoke_member,
        handlers::admin_members::update_member_status,
        handlers::admin_invitations::create_invitation,
        handlers::invitations::accept_invitation,
        handlers::admin_authentication_policies::list_authentication_policies,
        handlers::admin_authentication_policies::create_authentication_policy,
        handlers::admin_authentication_policies::update_authentication_policy,
        handlers::admin_authentication_policies::delete_authentication_policy,
        handlers::admin_audit::list_audit_logs,
        handlers::admin_application_logs::list_application_logs,
        handlers::admin_signing_keys::list_keys,
        handlers::admin_signing_keys::generate_key,
        handlers::admin_signing_keys::retire_key,
        handlers::admin_signing_keys::delete_key,
    ),
    components(schemas(
        handlers::saml_sso::SamlSsoForm,
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
        ClientListResponse,
        ClientCreatedResponse,
        ClientSecretResponse,
        GrantPermissionRequest,
        UserPermissionsResponse,
        CreateTenantRequest,
        UpdateTenantRequest,
        UpdateTenantSettingsRequest,
        TenantResponse,
        TenantListResponse,
        TenantDomainResponse,
        AddTenantDomainRequest,
        SystemSettingsResponse,
        UpdateSystemSettingsRequest,
        UpdateRuntimeSettingRequest,
        RuntimeSettingResponse,
        RestartServiceResponse,
        CreateUserRequest,
        UserCreatedResponse,
        UpdateUserStatusRequest,
        UpdateMemberStatusRequest,
        UpdateUserProfileRequest,
        UserMfaResetResponse,
        UserUnlockResponse,
        UserPasswordResetResponse,
        TenantAdminPasswordResetRequest,
        handlers::admin_login_identifiers::LoginIdentifierResponse,
        handlers::admin_login_identifiers::LoginIdentifierCreateRequest,
        handlers::admin_login_identifiers::LoginIdentifierUpdateRequest,
        MemberResponse,
        MemberListResponse,
        CreateInvitationRequest,
        InvitationCreatedResponse,
        AcceptInvitationRequest,
        AuditLogEntryResponse,
        AuthenticationPolicyResponse,
        AuthenticationPoliciesResponse,
        AuthenticationPolicyUpsertRequest,
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
