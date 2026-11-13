//! Shared axum state. Holds each service in an `Arc` and injects parts into handlers via `FromRef`.
//!
//! [`AppState::build`] alone assembles the use cases (dependency injection).
//! Both the binary (`lib.rs::run`) and the integration tests use the same assembly.
//!
//! The tenant is resolved by the `TenantResolver` middleware on `/{tenant_id}/...` routes, and on
//! `/internal/*` by the `tenant_id` web sends in the DTO (`require_internal_tenant`; missing / invalid is 400).
//! The former transitional mode "apply the root resolved at startup to every request as the default
//! tenant" (`default_tenant`) was removed in SEC4.

use crate::application::access_token_verification::AccessTokenVerifier;
use crate::application::account_directory::AccountDirectoryService;
use crate::application::account_language::AccountLanguageService;
use crate::application::account_note::AccountNoteService;
use crate::application::account_password::AccountPasswordService;
use crate::application::account_profile::AccountProfileService;
use crate::application::account_security::AccountSecurityService;
use crate::application::account_setup::{AccountSetupLinkIssuer, AccountSetupService};
use crate::application::account_tenants::AccountTenantsService;
use crate::application::account_theme::AccountThemeService;
use crate::application::admin_access::AdminAccessService;
use crate::application::admin_account_guard::AdminAccountGuard;
use crate::application::admin_login::AdminLoginService;
use crate::application::app_approval::{AppApprovalDependencies, AppApprovalService};
use crate::application::application_access::ApplicationAccessService;
use crate::application::application_log::ApplicationLogService;
use crate::application::application_management::ApplicationManagementService;
use crate::application::application_user_directory::ApplicationUserDirectoryService;
use crate::application::audit::AuditService;
use crate::application::audit_query::AuditQueryService;
use crate::application::authentication_policy_gate::AuthenticationPolicyGate;
use crate::application::authentication_policy_management::AuthenticationPolicyManagementService;
use crate::application::authenticator_management::AuthenticatorManagementService;
use crate::application::authorize::AuthorizeService;
use crate::application::backchannel_logout::{
    BackchannelLogoutDeliveryService, KeyServiceLogoutTokenSigner,
};
use crate::application::change_password::ChangePasswordService;
use crate::application::client_authentication::ClientAuthenticator;
use crate::application::client_management::ClientManagementService;
use crate::application::client_permission_management::ClientPermissionManagementService;
use crate::application::client_status::ClientStatusService;
use crate::application::code_issuance::CodeIssuanceService;
use crate::application::consent::ConsentService;
use crate::application::cors_policy::ApiCorsPolicy;
use crate::application::device_enrollment::{DeviceEnrollmentService, DeviceGate};
use crate::application::device_registry::DeviceRegistryService;
use crate::application::email_verification::EmailVerificationService;
use crate::application::expired_record_purge::ExpiredRecordPurgeService;
use crate::application::external_idp_discovery::ExternalIdpDiscoveryService;
use crate::application::external_idp_management::ExternalIdpManagementService;
use crate::application::external_login::ExternalLoginService;
use crate::application::introspection::IntrospectionService;
use crate::application::invitation::InvitationService;
use crate::application::key_service::KeyService;
use crate::application::login::LoginService;
use crate::application::login_identifier_management::LoginIdentifierManagementService;
use crate::application::logout::LogoutService;
use crate::application::management_token::ManagementTokenService;
use crate::application::member_directory::MemberDirectoryService;
use crate::application::mfa_login::MfaLoginService;
use crate::application::passkey_assertion::PasskeyAssertionService;
use crate::application::passkey_authentication::PasskeyAuthenticationService;
use crate::application::passkey_registration::PasskeyRegistrationService;
use crate::application::password_policy::PasswordPolicyService;
use crate::application::password_reset::PasswordResetService;
use crate::application::permission_management::PermissionManagementService;
use crate::application::portal_login::PortalLoginService;
use crate::application::register::RegisterService;
use crate::application::resource_management::ResourceManagementService;
use crate::application::revocation::RevocationService;
use crate::application::saml_service_provider_management::SamlServiceProviderManagementService;
use crate::application::saml_sso::SamlSsoService;
use crate::application::security_status::{SecurityStatusDeps, SecurityStatusService};
use crate::application::service_restart::ServiceRestartService;
use crate::application::session_key_binding::SessionKeyBindingService;
use crate::application::sign_in_completion::SignInCompletion;
use crate::application::sign_in_history::{SignInFailureRecordingSink, SignInHistoryService};
use crate::application::ssh_key_registry::SshKeyRegistryService;
use crate::application::sso_restore::SsoRestorer;
use crate::application::step_up::StepUpService;
use crate::application::stop_announcement::StopAnnouncementService;
use crate::application::system_settings::SystemSettingsService;
use crate::application::tenant_management::TenantManagementService;
use crate::application::tenant_resolution::TenantResolutionService;
use crate::application::token::TokenService;
use crate::application::totp_registration::TotpRegistrationService;
use crate::application::user_lifecycle::UserLifecycleService;
use crate::application::user_management::UserManagementService;
use crate::application::userinfo::UserInfoService;
use crate::config::Config;
use crate::domain::cache::Cache;
use crate::domain::clock::Clock;
use crate::domain::id_generator::IdGenerator;
use crate::domain::repositories::{
    AccountNoteRepository, SignInHistoryRepository, UserDeviceRepository, UserPermissionRepository,
};
use crate::domain::security_alert::{DisabledSecurityAlertSink, SecurityAlertSink};
use crate::domain::tenant::{Tenant, TenantId};
use crate::infrastructure::backchannel_logout::ReqwestBackchannelLogoutSender;
use crate::infrastructure::breached_password::RangeApiBreachedPasswordChecker;
use crate::infrastructure::cache::InMemoryTtlCache;
use crate::infrastructure::db::Db;
use crate::infrastructure::external_oidc::ReqwestExternalOidcClient;
use crate::infrastructure::id_generator::UuidV7Generator;
use crate::infrastructure::mailer::LettreSmtpMailer;
use crate::infrastructure::password::Argon2PasswordHasher;
use crate::infrastructure::rate_limit::InMemoryLoginRateLimiter;
use crate::infrastructure::repositories::account_note::SqlxAccountNoteRepository;
use crate::infrastructure::repositories::account_query::SqlxAccountQuery;
use crate::infrastructure::repositories::app_approver::{
    SqlxApprovalRequestRepository, SqlxApproverEnrollmentRepository, SqlxApproverKeyRepository,
};
use crate::infrastructure::repositories::application::SqlxApplicationRepository;
use crate::infrastructure::repositories::application_log::{
    SqlxApplicationLogQuery, SqlxApplicationLogSink,
};
use crate::infrastructure::repositories::application_user_query::SqlxApplicationUserQuery;
use crate::infrastructure::repositories::audit_log::{SqlxAuditLogQuery, SqlxAuditLogSink};
use crate::infrastructure::repositories::auth_session::SqlxAuthSessionRepository;
use crate::infrastructure::repositories::authentication_policy::SqlxAuthenticationPolicyRepository;
use crate::infrastructure::repositories::authorization_code::SqlxAuthorizationCodeRepository;
use crate::infrastructure::repositories::backchannel_logout::SqlxBackchannelLogoutDeliveryRepository;
use crate::infrastructure::repositories::cached_user_permission::{
    CachedUserPermissionRepository, PermissionKey,
};
use crate::infrastructure::repositories::client::SqlxClientRepository;
use crate::infrastructure::repositories::client_assertion::SqlxClientAssertionReplayRepository;
use crate::infrastructure::repositories::client_permission::SqlxClientPermissionRepository;
use crate::infrastructure::repositories::consent::SqlxClientConsentRepository;
use crate::infrastructure::repositories::dpop_proof::SqlxDpopProofReplayRepository;
use crate::infrastructure::repositories::email_verification_token::SqlxEmailVerificationTokenRepository;
use crate::infrastructure::repositories::external_idp::{
    SqlxExternalIdentityProviderRepository, SqlxExternalIdentityRepository,
    SqlxExternalLoginRequestRepository,
};
use crate::infrastructure::repositories::passkey_challenge::SqlxPasskeyChallengeRepository;
use crate::infrastructure::repositories::password_history::SqlxPasswordHistoryRepository;
use crate::infrastructure::repositories::password_reset_token::SqlxPasswordResetTokenRepository;
use crate::infrastructure::repositories::protected_resource::SqlxProtectedResourceRepository;
use crate::infrastructure::repositories::refresh_token::SqlxRefreshTokenRepository;
use crate::infrastructure::repositories::revoked_access_token::SqlxRevokedAccessTokenRepository;
use crate::infrastructure::repositories::saml_service_provider::SqlxSamlServiceProviderRepository;
use crate::infrastructure::repositories::saml_sso_request::SqlxSamlSsoRequestRepository;
use crate::infrastructure::repositories::security_status_query::SqlxSecurityStatusQuery;
use crate::infrastructure::repositories::session_key_binding::SqlxSessionKeyBindingRepository;
use crate::infrastructure::repositories::sign_in_history::SqlxSignInHistoryRepository;
use crate::infrastructure::repositories::signing_key::SqlxSigningKeyRepository;
use crate::infrastructure::repositories::sso_session::SqlxSsoSessionRepository;
use crate::infrastructure::repositories::system_setting::SqlxSystemSettingsRepository;
use crate::infrastructure::repositories::tenant::SqlxTenantRepository;
use crate::infrastructure::repositories::tenant_domain::SqlxTenantDomainRepository;
use crate::infrastructure::repositories::tenant_member_query::SqlxTenantMemberQuery;
use crate::infrastructure::repositories::tenant_membership::SqlxTenantMembershipRepository;
use crate::infrastructure::repositories::tenant_provisioning::SqlxTenantProvisioningRepository;
use crate::infrastructure::repositories::totp_secret::SqlxTotpSecretRepository;
use crate::infrastructure::repositories::user::SqlxUserRepository;
use crate::infrastructure::repositories::user_authenticator::SqlxUserAuthenticatorRepository;
use crate::infrastructure::repositories::user_device::SqlxUserDeviceRepository;
use crate::infrastructure::repositories::user_login_identifier::SqlxUserLoginIdentifierRepository;
use crate::infrastructure::repositories::user_permission::SqlxUserPermissionRepository;
use crate::infrastructure::repositories::user_ssh_key::SqlxUserSshKeyRepository;
use crate::infrastructure::repositories::webauthn_credential::SqlxWebAuthnCredentialRepository;
use crate::infrastructure::security_alert_webhook::WebhookSecurityAlertSink;
use crate::infrastructure::webauthn::WebAuthnService;
use crate::service_restart::ServiceRestart;
use axum::extract::FromRef;
use std::sync::Arc;

/// Per-IP login rate limit: at most 30 attempts in 5 minutes (design spec §4.3 "rate limit per IP too").
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS: usize = 30;
const LOGIN_RATE_LIMIT_WINDOW_MINUTES: i64 = 5;

/// Per-IP self-registration rate limit: at most 10 attempts in 5 minutes (SEC6; deters enumeration and mass creation).
const REGISTER_RATE_LIMIT_MAX_ATTEMPTS: usize = 10;
const REGISTER_RATE_LIMIT_WINDOW_MINUTES: i64 = 5;

/// Per-IP password reset request rate limit: at most 5 attempts in 15 minutes (MT18; deters mail bombing and enumeration).
const PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS: usize = 5;
const PASSWORD_RESET_RATE_LIMIT_WINDOW_MINUTES: i64 = 15;

#[derive(Clone)]
pub struct AppState {
    pub pool: Db,
    pub config: Arc<Config>,
    /// Process start time. Kept so `/internal/health` can report uptime (ADR-0031).
    /// Whether a restart happened cannot be told from the version alone.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Clock source (replaced by a fixed implementation in tests). Used where the presentation layer
    /// needs "now" (e.g. checking lock expiry).
    pub clock: Arc<dyn Clock>,
    /// Prometheus metrics renderer (G6). `None` when installing the recorder failed.
    pub metrics: Option<Arc<metrics_exporter_prometheus::PrometheusHandle>>,
    /// Load gate for the token endpoints (`/token`, `/introspect`, `/revoke`) (SEC10).
    /// Limits concurrent Argon2 verifications and requests per source.
    pub token_endpoint_load: Arc<crate::presentation::token_endpoint_load::TokenEndpointLoadGate>,
    /// Tenant resolution (id → tenant). Used by the `TenantResolver` middleware (mounted on the router in MT9).
    pub tenant_resolution: Arc<TenantResolutionService>,
    /// Tenant setting resolution (ADR-0058; tenant row > global row > env var > built-in default).
    /// ⚠ Do not read keys a tenant can override from `Config` (`Config` no longer holds them).
    /// The concrete type is held here for the admin endpoints (list, write, cache invalidation). Use
    /// cases that read values get it as `EffectiveTenantSettings`.
    pub tenant_settings: Arc<crate::application::tenant_settings::TenantSettingsService>,
    pub register: Arc<RegisterService>,
    /// Email verification for self-registered accounts (sending and consuming the confirmation link; SEC6b).
    pub email_verification: Arc<EmailVerificationService>,
    pub authorize: Arc<AuthorizeService>,
    pub login: Arc<LoginService>,
    /// Forced password change (ADR-0009 §5). Sets the password by `auth_session_id` after
    /// `LoginService` detects `must_change_password`.
    pub change_password: Arc<ChangePasswordService>,
    pub consent: Arc<ConsentService>,
    pub token: Arc<TokenService>,
    pub userinfo: Arc<UserInfoService>,
    pub keys: Arc<KeyService>,
    pub admin_access: Arc<AdminAccessService>,
    /// Admin API authorization (ADR-0037). The check `RequirePerms` calls, and the SSO session → admin token exchange.
    pub management_tokens: Arc<ManagementTokenService>,
    /// Grants and revokes admin permissions for clients (`/admin/clients/{client_id}/permissions`).
    pub client_permissions_admin: Arc<ClientPermissionManagementService>,
    /// Registration of protected resources (audiences put in `aud`) and lending them to clients (ADR-0042).
    pub resources_admin: Arc<ResourceManagementService>,
    /// App (ADR-0054) registration, bindings and user assignments.
    pub applications_admin: Arc<ApplicationManagementService>,
    /// App roster lookup (ADR-0057). A read-only path read by the RP's periodic reconciliation, kept
    /// separate from assignment changes (`applications_admin`).
    pub application_users: Arc<ApplicationUserDirectoryService>,
    pub admin_login: Arc<AdminLoginService>,
    /// Direct login to the end-user portal (client-independent; issues SSO directly while honouring TOTP).
    pub portal_login: Arc<PortalLoginService>,
    pub clients_admin: Arc<ClientManagementService>,
    pub clients_status: Arc<ClientStatusService>,
    pub permissions_admin: Arc<PermissionManagementService>,
    /// Protects admin accounts and admin permissions from holders of fine-grained codes (task #579).
    /// Each account operation and permission grant endpoint calls it before the main processing.
    pub admin_account_guard: Arc<AdminAccountGuard>,
    /// Authentication policy management (CRUD; user authentication / auth policy spec §7). Evaluation is done by the login services.
    pub authentication_policies_admin: Arc<AuthenticationPolicyManagementService>,
    /// User creation by an admin (auto-generated password, must_change_password; ADR-0009 §5).
    pub users_admin: Arc<UserManagementService>,
    /// Login identifier assignment by an admin (AP8).
    pub login_identifiers_admin: Arc<LoginIdentifierManagementService>,
    /// User lifecycle operations by an admin (disable, delete, password reissue; ADR-0009 §5).
    pub users_lifecycle: Arc<UserLifecycleService>,
    /// Tenant creation and management (requires idp.system.admin; ADR-0009 §5, §6). The tenant settings
    /// section of the settings screen (own tenant lookup, display name update; MT14) also goes through it.
    pub tenants_admin: Arc<TenantManagementService>,
    /// System settings (SMTP etc.; root / idp.system.admin only; MT14).
    pub system_settings: Arc<SystemSettingsService>,
    /// Self-service password change (settings screen of a signed-in user; MT15).
    pub account_password: Arc<AccountPasswordService>,
    /// Self-service display language change (settings screen of a signed-in user; MT20).
    pub account_language: Arc<AccountLanguageService>,
    pub account_theme: Arc<AccountThemeService>,
    /// Self-service display name (profile) read and update (settings screen of a signed-in user).
    pub account_profile: Arc<AccountProfileService>,
    /// Lists the tenants of the signed-in user (tenant switcher UI).
    pub account_tenants: Arc<AccountTenantsService>,
    /// Self-service password reset (when forgotten; via email link; MT18).
    pub password_reset: Arc<PasswordResetService>,
    /// Guest invitations and memberships (ADR-0009 §3).
    pub invitations: Arc<InvitationService>,
    pub member_directory: Arc<MemberDirectoryService>,
    /// Admin notes on accounts (people, service accounts) (ADR-0063 / ADR-0065).
    pub account_notes: Arc<AccountNoteService>,
    /// Account list (people and service accounts; ADR-0065).
    pub account_directory: Arc<AccountDirectoryService>,
    pub audit_query: Arc<AuditQueryService>,
    /// Records audit events and purges them by retention period (design spec §7, G8). The same instance
    /// injected into each use case; the retention purge task references it from here.
    pub audit: Arc<AuditService>,
    /// Ingests, reads and purges error / warning logs (`log` table) (CLAUDE.md "Logs").
    /// Shared by api's own `tracing` ingest task, `/internal/logs` from web, and the admin screen.
    pub application_logs: Arc<ApplicationLogService>,
    pub logout: Arc<LogoutService>,
    /// Self-service security screen (session list, revocation / unlinking apps; G10).
    pub account_security: Arc<AccountSecurityService>,
    /// The user's device list and notices of logins from unregistered devices (task #872).
    pub device_registry: Arc<DeviceRegistryService>,
    /// The registered-device gate (task #916). Also looks up "who would be locked out" before an org enables the setting.
    pub device_gate: Arc<DeviceGate>,
    /// Registering the device on the spot when signing in correctly from an unregistered device (task #916).
    pub device_enrollment: Arc<DeviceEnrollmentService>,
    /// Sign-in history the user sees (task #879).
    pub sign_in_history: Arc<SignInHistoryService>,
    /// The "Status" the user sees (task #896).
    pub security_status: Arc<SecurityStatusService>,
    /// SSH public keys registered by users, and the list for the distributing machine (task #885).
    pub ssh_keys: Arc<SshKeyRegistryService>,
    /// Binding the SSO session to the device key (DBSC; task #887).
    pub session_key_binding: Arc<SessionKeyBindingService>,
    /// Logins approved in the authenticator app, and the authenticator app keys (task #892).
    pub app_approval: Arc<AppApprovalService>,
    /// Step-up authentication (re-verifying identity right before a sensitive operation; AP5).
    pub step_up: Arc<StepUpService>,
    /// Unified authenticator management (list, state change, recovery codes, email OTP; AP9).
    pub authenticators: Arc<AuthenticatorManagementService>,
    /// Authenticator registry (AP9).
    pub authenticator_repository: Arc<dyn crate::domain::repositories::UserAuthenticatorRepository>,
    /// External IdP login (AP10).
    pub external_login: Arc<ExternalLoginService>,
    /// External IdP settings management (AP10).
    pub external_idps: Arc<ExternalIdpManagementService>,
    /// External IdP (OIDC) discovery document import (does not register; task #77).
    pub external_idp_discovery: Arc<ExternalIdpDiscoveryService>,
    /// External IdP settings lookup (for login screen buttons). Used directly by GC and listing.
    pub external_providers:
        Arc<dyn crate::domain::repositories::ExternalIdentityProviderRepository>,
    /// External IdP login progress state (AP10).
    pub external_login_requests:
        Arc<dyn crate::domain::repositories::ExternalLoginRequestRepository>,
    /// Bulk GC of expired records (G2). The list of target tables is in
    /// [`crate::infrastructure::repositories::expired_records`].
    pub expired_records: Arc<ExpiredRecordPurgeService>,
    /// CORS allowed-origin check (G1). Used by the middleware.
    pub cors_policy: Arc<ApiCorsPolicy>,
    /// Back-channel logout send queue (G5). Handlers only enqueue; the worker sends.
    pub backchannel_logout: Arc<BackchannelLogoutDeliveryService>,
    pub revocation: Arc<RevocationService>,
    pub introspection: Arc<IntrospectionService>,
    pub totp_registration: Arc<TotpRegistrationService>,
    pub mfa_login: Arc<MfaLoginService>,
    pub passkey_registration: Arc<PasskeyRegistrationService>,
    /// Account setup links issued by admins (ADR-0062). Read and used by the linked screen.
    pub account_setup: Arc<AccountSetupService>,
    pub passkey_authentication: Arc<PasskeyAuthenticationService>,
    /// SAML SP (client) registration (for tenant admins).
    pub saml_service_providers: Arc<SamlServiceProviderManagementService>,
    /// SAML SP-initiated SSO (receiving `/saml/sso` and issuing the response for `/internal/saml/resume`).
    pub saml_sso: Arc<SamlSsoService>,
    /// Restart request from the settings screen (ADR-0017). The graceful shutdown in `run()` waits on this value.
    /// In tests nobody waits on the value `build` creates, so requesting does nothing.
    pub restart: ServiceRestart,
    /// Restart use case (audit record → stop request; ADR-0017). Points to the same signal as `restart`.
    pub service_restart: Arc<ServiceRestartService>,
}

/// Maximum number of notifications the back-channel logout worker handles per run.
///
/// Larger values catch up faster on recovery, but with many RPs down a run takes longer (each item
/// waits for its timeout). Keep it low enough that a run does not grow too long relative to the
/// polling interval (`BACKCHANNEL_LOGOUT_POLL_INTERVAL_SECS`).
const BACKCHANNEL_LOGOUT_BATCH_SIZE: u32 = 50;

impl AppState {
    /// Assembles all use cases (constructor injection through traits).
    pub fn build(pool: Db, config: Arc<Config>, clock: Arc<dyn Clock>) -> Self {
        let started_at = clock.now();
        let users = Arc::new(SqlxUserRepository::new(pool.clone()));
        let tenant_memberships = Arc::new(SqlxTenantMembershipRepository::new(pool.clone()));
        // Domains assigned to tenants (ADR-0029). Shared by login resolution and the admin API.
        let tenant_domains = Arc::new(SqlxTenantDomainRepository::new(pool.clone()));
        let clients = Arc::new(SqlxClientRepository::new(pool.clone()));
        let auth_sessions = Arc::new(SqlxAuthSessionRepository::new(pool.clone()));
        let sso_sessions = Arc::new(SqlxSsoSessionRepository::new(pool.clone()));
        let codes = Arc::new(SqlxAuthorizationCodeRepository::new(pool.clone()));
        let refresh_tokens = Arc::new(SqlxRefreshTokenRepository::new(pool.clone()));
        let revoked_access_tokens = Arc::new(SqlxRevokedAccessTokenRepository::new(pool.clone()));
        let signing_keys = Arc::new(SqlxSigningKeyRepository::new(pool.clone()));
        let saml_service_provider_repo =
            Arc::new(SqlxSamlServiceProviderRepository::new(pool.clone()));
        let tenants = Arc::new(SqlxTenantRepository::new(pool.clone()));
        // scope → permission resolution (ADR-0009 §7): caches `has_permission` results with a TTL and
        // invalidates on grant / revoke. The check (admin_access) and changes (permissions_admin) share the
        // same instance, which avoids stale allow/deny right after a grant.
        let permission_cache: Arc<dyn Cache<PermissionKey, bool>> =
            Arc::new(InMemoryTtlCache::new(
                chrono_from_std(config.permission_cache_ttl()),
                clock.clone(),
            ));
        let user_permissions: Arc<dyn UserPermissionRepository> =
            Arc::new(CachedUserPermissionRepository::new(
                Arc::new(SqlxUserPermissionRepository::new(pool.clone())),
                permission_cache,
            ));
        let client_consents = Arc::new(SqlxClientConsentRepository::new(pool.clone()));
        let totp_secrets = Arc::new(SqlxTotpSecretRepository::new(pool.clone()));
        let authentication_policies =
            Arc::new(SqlxAuthenticationPolicyRepository::new(pool.clone()));
        let webauthn_credentials = Arc::new(SqlxWebAuthnCredentialRepository::new(pool.clone()));
        let passkey_challenges = Arc::new(SqlxPasskeyChallengeRepository::new(pool.clone()));
        // Rejected logins are also copied to the user's history where they are written to the audit log (task #879).
        let sign_in_history_repository: Arc<dyn SignInHistoryRepository> =
            Arc::new(SqlxSignInHistoryRepository::new(pool.clone()));
        let audit_sink = Arc::new(SignInFailureRecordingSink::new(
            Arc::new(SqlxAuditLogSink::new(pool.clone())),
            sign_in_history_repository.clone(),
            // The country is only the value web attached to the internal call (task #895; read only on `/internal/*`).
            Arc::new(crate::presentation::client_country::TaskLocalRequestCountry),
        ));
        let audit_logs = Arc::new(SqlxAuditLogQuery::new(pool.clone()));
        let hasher = Arc::new(Argon2PasswordHasher::new());
        let ids: Arc<dyn IdGenerator> = Arc::new(UuidV7Generator);
        // AP8: login identifier registry. Resolution at login is on the `SqlxUserRepository` side (one query);
        // what lives here is admin operations and syncing the `users.preferred_username` copy.
        let login_identifier_repository: Arc<
            dyn crate::domain::repositories::UserLoginIdentifierRepository,
        > = Arc::new(SqlxUserLoginIdentifierRepository::new(pool.clone()));
        // Auditing is also used by tenant setting writes (#111), so it is assembled before tenant settings.
        let audit = Arc::new(AuditService::new(audit_sink, clock.clone()));
        // Tenant setting resolution (ADR-0058). Tenant and global rows are read on every lookup and bounded
        // by a TTL cache with the same lifetime as tenant resolution. ⚠ Do not make the cache lifetime itself
        // a tenant setting (a tenant could stop its own resolution). The env var → built-in default layers do
        // not change at runtime, so they are built once here and passed in.
        // Password policy, default auth policy behaviour and app assignment enforcement are also read from
        // here (ADR-0058 §4), so it is assembled before the deciders (password policy, app gate, auth paths).
        // Readers get it as the domain trait `EffectiveTenantSettings`, **only once** (never pass the same
        // resolver twice through different handles). Only `AppState`'s admin endpoints (list, write, invalidate) keep the concrete type.
        let tenant_settings_fallback =
            crate::domain::system_setting::tenant_overridable_setting_keys()
                .filter_map(|key| {
                    config
                        .value_without_db(key)
                        .map(|value| (key.to_string(), value))
                })
                .collect();
        let tenant_settings = Arc::new(
            crate::application::tenant_settings::TenantSettingsService::new(
                Arc::new(
                    crate::infrastructure::repositories::tenant_setting::SqlxTenantSettingsRepository::new(
                        pool.clone(),
                    ),
                ),
                Arc::new(SqlxSystemSettingsRepository::new(pool.clone())),
                tenant_settings_fallback,
                Arc::new(InMemoryTtlCache::new(
                    chrono_from_std(config.tenant_cache_ttl()),
                    clock.clone(),
                )),
                Arc::new(InMemoryTtlCache::new(
                    chrono_from_std(config.tenant_cache_ttl()),
                    clock.clone(),
                )),
                audit.clone(),
            ),
        );

        // AP7: password policy. Every path that sets a password (self-registration, forced change, self-service
        // change, reset) goes through this one. The breach check is off by default (no outbound traffic assumed).
        let password_history: Arc<dyn crate::domain::repositories::PasswordHistoryRepository> =
            Arc::new(SqlxPasswordHistoryRepository::new(pool.clone()));
        // Whether to use the breach check is decided per tenant (`PASSWORD_BREACH_CHECK_ENABLED`; ADR-0058), so
        // the checker is always built. Outbound traffic only happens when validating for tenants that enabled it.
        let breach_checker: Arc<dyn crate::domain::password_policy::BreachedPasswordChecker> =
            match RangeApiBreachedPasswordChecker::new(
                config.password_breach_api_base_url(),
                config.password_breach_check_timeout(),
            ) {
                Ok(checker) => Arc::new(checker),
                Err(e) => {
                    // Cannot build the client = cannot check. Keep starting and drop only the breach
                    // check (the same fail-open as the implementation; failing here would stop the whole of
                    // assay from starting because of a misconfiguration).
                    tracing::error!(
                        error = %e,
                        "failed to build breached password checker; breach check is disabled"
                    );
                    Arc::new(crate::domain::password_policy::NoBreachCheck)
                }
            };
        let password_policy = Arc::new(PasswordPolicyService::new(
            tenant_settings.clone(),
            password_history,
            breach_checker,
            hasher.clone(),
            clock.clone(),
        ));

        let rate_limiter = Arc::new(InMemoryLoginRateLimiter::new(
            LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
            chrono::Duration::minutes(LOGIN_RATE_LIMIT_WINDOW_MINUTES),
        ));

        let saml_service_providers = Arc::new(SamlServiceProviderManagementService::new(
            saml_service_provider_repo.clone(),
            ids.clone(),
            clock.clone(),
        ));
        // System settings (SMTP etc.; root only; MT14). Secrets are stored encrypted with key_encryption_key.
        // Also passes whether the development default secrets are in use (to decide, before saving runtime
        // settings, "can the next start succeed with that value"; ADR-0017).
        let system_settings = Arc::new(SystemSettingsService::new(
            Arc::new(SqlxSystemSettingsRepository::new(pool.clone())),
            // The tenant's mail route (ADR-0058 §8).
            Arc::new(
                crate::infrastructure::repositories::tenant_setting::SqlxTenantSettingsRepository::new(
                    pool.clone(),
                ),
            ),
            *config.key_encryption_key(),
            config.deployment_state(),
            audit.clone(),
            clock.clone(),
        ));
        // AP9: unified authenticator management. Gathers registration status scattered over per-kind tables
        // into one registry, and adds recovery codes and email OTP.
        let authenticator_repository: Arc<
            dyn crate::domain::repositories::UserAuthenticatorRepository,
        > = Arc::new(SqlxUserAuthenticatorRepository::new(pool.clone()));
        let authenticators = Arc::new(AuthenticatorManagementService::new(
            authenticator_repository.clone(),
            users.clone(),
            system_settings.clone(),
            Arc::new(LettreSmtpMailer::with_trust(config.outbound_trust())),
            Arc::new(crate::infrastructure::sms::HttpSmsGateway::with_trust(
                config.outbound_trust(),
            )),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));

        // Self-service password change (signed-in user; MT15).
        let account_password = Arc::new(AccountPasswordService::new(
            sso_sessions.clone(),
            users.clone(),
            // After the change, drops refresh tokens and unconsumed codes for other devices (ADR-0045).
            refresh_tokens.clone(),
            codes.clone(),
            hasher.clone(),
            password_policy.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // Self-service display language change (signed-in user; MT20).
        let account_language = Arc::new(AccountLanguageService::new(
            sso_sessions.clone(),
            users.clone(),
            clock.clone(),
        ));
        // Self-service color scheme change (signed-in user).
        let account_theme = Arc::new(AccountThemeService::new(
            sso_sessions.clone(),
            users.clone(),
            clock.clone(),
        ));
        // Self-service display name (profile) read and update (signed-in user).
        let account_profile = Arc::new(AccountProfileService::new(
            sso_sessions.clone(),
            users.clone(),
            clock.clone(),
        ));
        // Lists the tenants of the signed-in user (tenant switcher UI).
        let account_tenants = Arc::new(AccountTenantsService::new(
            sso_sessions.clone(),
            tenant_memberships.clone(),
            tenants.clone(),
            clock.clone(),
        ));
        // Password reset (when forgotten; MT18). SMTP comes from system settings (MT14), delivery reuses the
        // MT17 Mailer. Requests are rate-limited per IP; on success all sessions and tokens are revoked.
        // ⚠ Password reset and account setup links use **the same table** (ADR-0062). Do not create the same
        // value twice; pass one repository to both.
        let reset_tokens = Arc::new(SqlxPasswordResetTokenRepository::new(pool.clone()));
        let password_reset = Arc::new(PasswordResetService::new(
            users.clone(),
            reset_tokens.clone(),
            sso_sessions.clone(),
            refresh_tokens.clone(),
            codes.clone(),
            hasher.clone(),
            password_policy.clone(),
            system_settings.clone(),
            Arc::new(LettreSmtpMailer::with_trust(config.outbound_trust())),
            Arc::new(InMemoryLoginRateLimiter::new(
                PASSWORD_RESET_RATE_LIMIT_MAX_ATTEMPTS,
                chrono::Duration::minutes(PASSWORD_RESET_RATE_LIMIT_WINDOW_MINUTES),
            )),
            audit.clone(),
            clock.clone(),
            tenant_settings.clone(),
            config.public_web_base_url().to_string(),
        ));
        let keys = Arc::new(KeyService::new(
            signing_keys.clone(),
            clock.clone(),
            *config.key_encryption_key(),
        ));
        // Apps (ADR-0054). The single source of "which user may use which app", read by both the
        // code issuance gate (`CodeIssuanceService`) and auth policy target resolution.
        let applications: Arc<dyn crate::domain::repositories::ApplicationRepository> =
            Arc::new(SqlxApplicationRepository::new(pool.clone()));
        let application_access = Arc::new(ApplicationAccessService::new(
            applications.clone(),
            audit.clone(),
            tenant_settings.clone(),
        ));
        // Entry point of auth policy evaluation (shared by 8 paths; `authentication_policy_gate`).
        let policy_gate = Arc::new(AuthenticationPolicyGate::new(
            authentication_policies.clone(),
            tenant_settings.clone(),
            application_access.clone(),
        ));
        let code_issuance = Arc::new(CodeIssuanceService::new(
            codes.clone(),
            application_access.clone(),
            audit.clone(),
            clock.clone(),
            config.authorization_code_ttl(),
        ));
        // task #872: the user's device list and the notice sender. Also used by the task #916 gate.
        let security_alerts = security_alert_sink(&config);
        let user_devices: Arc<dyn UserDeviceRepository> =
            Arc::new(SqlxUserDeviceRepository::new(pool.clone()));
        // The gate that lets logins finish only from registered devices (task #916, ADR-0079). All 8 places
        // that create an SSO session (`sign_in_completion`, portal, admin console) go through it.
        let device_gate = Arc::new(DeviceGate::new(
            user_devices.clone(),
            users.clone(),
            tenant_settings.clone(),
            // The device mark is only the value web attached to the internal call (read only on `/internal/*`).
            Arc::new(crate::presentation::client_device::TaskLocalRequestDevice),
            Arc::new(crate::presentation::client_country::TaskLocalRequestCountry),
            security_alerts.clone(),
            audit.clone(),
            *config.csrf_secret(),
        ));
        // Common post-processing after authentication succeeds (shared by 5 paths; `sign_in_completion`).
        let sign_in = Arc::new(
            SignInCompletion::new(
                sso_sessions.clone(),
                auth_sessions.clone(),
                client_consents.clone(),
                code_issuance.clone(),
                audit.clone(),
                tenant_settings.clone(),
            )
            .with_device_gate(device_gate.clone()),
        );

        // Self-registration (SEC6): tenant setting toggle (default OFF) + per-IP rate limit. Uses a limiter
        // separate from login (so failed registrations do not consume the login attempt budget).
        let register_rate_limiter = Arc::new(InMemoryLoginRateLimiter::new(
            REGISTER_RATE_LIMIT_MAX_ATTEMPTS,
            chrono::Duration::minutes(REGISTER_RATE_LIMIT_WINDOW_MINUTES),
        ));
        let register = Arc::new(RegisterService::new(
            users.clone(),
            tenant_memberships.clone(),
            tenants.clone(),
            hasher.clone(),
            password_policy.clone(),
            register_rate_limiter,
            clock.clone(),
            ids.clone(),
        ));
        // Email verification (SEC6b): sends a confirmation link on self-registration; consuming it sets
        // email_verified. SMTP comes from system settings (MT14), delivery reuses the MT17 Mailer.
        let email_verification = Arc::new(EmailVerificationService::new(
            users.clone(),
            Arc::new(SqlxEmailVerificationTokenRepository::new(pool.clone())),
            system_settings.clone(),
            Arc::new(LettreSmtpMailer::with_trust(config.outbound_trust())),
            audit.clone(),
            clock.clone(),
            tenant_settings.clone(),
            config.public_web_base_url().to_string(),
        ));
        // Common SSO restore check (shared by OIDC authorize and SAML SSO).
        let sso_restorer = Arc::new(SsoRestorer::new(
            sso_sessions.clone(),
            users.clone(),
            tenant_memberships.clone(),
            audit.clone(),
            clock.clone(),
            tenant_settings.clone(),
        ));
        // Tenant resolution (ADR-0009 §7): keeps the id → tenant hot path cheap with a TTL cache + invalidation
        // on update. In MT9 the `TenantResolver` middleware mounts this service on the router.
        // `AuthorizeService` (tenant display name on the login screen) also rides on the same cache, so it is
        // assembled before its dependents.
        let tenant_cache: Arc<dyn Cache<TenantId, Tenant>> = Arc::new(InMemoryTtlCache::new(
            chrono_from_std(config.tenant_cache_ttl()),
            clock.clone(),
        ));
        let tenant_resolution =
            Arc::new(TenantResolutionService::new(tenants.clone(), tenant_cache));
        let authorize = Arc::new(AuthorizeService::new(
            clients.clone(),
            auth_sessions.clone(),
            sso_restorer.clone(),
            client_consents.clone(),
            code_issuance.clone(),
            clock.clone(),
            config.auth_session_ttl(),
            policy_gate.clone(),
            tenant_resolution.clone(),
        ));
        // SAML SP-initiated SSO. The progress state TTL uses the same value as the OIDC auth_session.
        let saml_sso = Arc::new(SamlSsoService::new(
            Arc::new(SqlxSamlServiceProviderRepository::new(pool.clone())),
            Arc::new(SqlxSamlSsoRequestRepository::new(pool.clone())),
            users.clone(),
            sso_restorer.clone(),
            application_access.clone(),
            keys.clone(),
            audit.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.auth_session_ttl(),
        ));
        let login = Arc::new(LoginService::new(
            users.clone(),
            tenant_domains.clone(),
            auth_sessions.clone(),
            totp_secrets.clone(),
            policy_gate.clone(),
            sign_in.clone(),
            hasher.clone(),
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            tenant_settings.clone(),
            *config.csrf_secret(),
        ));
        let change_password = Arc::new(ChangePasswordService::new(
            auth_sessions.clone(),
            users.clone(),
            totp_secrets.clone(),
            policy_gate.clone(),
            sign_in.clone(),
            hasher.clone(),
            password_policy.clone(),
            audit.clone(),
            clock.clone(),
            *config.csrf_secret(),
        ));
        let consent = Arc::new(ConsentService::new(
            auth_sessions.clone(),
            client_consents.clone(),
            clients.clone(),
            code_issuance.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // The WebAuthn RP ID and origin are derived from **the host of web's public base URL** (ADR-0019 decision 2;
        // Passkey ceremonies run on web's pages. When `PUBLIC_WEB_BASE_URL` is unset it follows the
        // issuer, so under single-origin it is the same as before). No per-tenant path is passed —
        // WebAuthn is per host by protocol and cannot include a path (ADR-0009 §6).
        // Tenant isolation is achieved by the app-level link "credential ⇔ user ⇔ home tenant".
        let webauthn = Arc::new(WebAuthnService::new(config.public_web_base_url()));
        // Passkey registration (used by both the user's settings screen and admin-issued setup links; ADR-0062).
        let passkey_registration = Arc::new(PasskeyRegistrationService::new(
            authenticators.clone(),
            webauthn_credentials.clone(),
            passkey_challenges.clone(),
            sso_sessions.clone(),
            webauthn.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // Account setup links issued by admins (ADR-0062). Used for create / reissue and by the linked screen.
        let account_setup_links = Arc::new(AccountSetupLinkIssuer::new(
            reset_tokens.clone(),
            tenant_settings.clone(),
            clock.clone(),
            config.public_web_base_url().to_string(),
        ));
        let account_setup = Arc::new(AccountSetupService::new(
            users.clone(),
            reset_tokens.clone(),
            passkey_registration.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // Passkey ceremonies (challenge issuance, assertion verification). Shared by the three paths: OIDC
        // authorization flow, admin console and portal (`application::passkey_assertion`).
        let passkey_assertion = Arc::new(PasskeyAssertionService::new(
            webauthn_credentials.clone(),
            authenticator_repository.clone(),
            passkey_challenges.clone(),
            users.clone(),
            tenant_memberships.clone(),
            webauthn.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // Admin console login (ADR-0006 §6). The IP rate limiter is shared with normal login.
        let admin_login = Arc::new(
            AdminLoginService::new(
                users.clone(),
                passkey_assertion.clone(),
                tenant_domains.clone(),
                sso_sessions.clone(),
                user_permissions.clone(),
                totp_secrets.clone(),
                policy_gate.clone(),
                hasher.clone(),
                password_policy.clone(),
                rate_limiter.clone(),
                audit.clone(),
                clock.clone(),
                tenant_settings.clone(),
            )
            .with_device_gate(device_gate.clone()),
        );
        // Direct login to the end-user portal. Same mechanism as admin_login (client-independent direct SSO issuance)
        // but it does not require admin permission and honours TOTP (MFA). The `mfa_ticket` signing key reuses the CSRF secret.
        let portal_login = Arc::new(
            PortalLoginService::new(
                authenticator_repository.clone(),
                users.clone(),
                passkey_assertion.clone(),
                tenant_domains.clone(),
                sso_sessions.clone(),
                totp_secrets.clone(),
                policy_gate.clone(),
                hasher.clone(),
                password_policy.clone(),
                rate_limiter.clone(),
                audit.clone(),
                clock.clone(),
                *config.key_encryption_key(),
                *config.csrf_secret(),
                tenant_settings.clone(),
            )
            .with_device_gate(device_gate.clone()),
        );
        // A person signing in correctly from an unregistered device verifies with a passkey and registers it (task #916).
        let device_enrollment = Arc::new(DeviceEnrollmentService::new(
            device_gate.clone(),
            user_devices.clone(),
            users.clone(),
            passkey_assertion.clone(),
            sign_in.clone(),
            security_alerts.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // Admin notes (ADR-0063 / ADR-0065). One table and one repository for people and service accounts.
        let account_note_repository: Arc<dyn AccountNoteRepository> =
            Arc::new(SqlxAccountNoteRepository::new(pool.clone(), ids.clone()));
        let clients_admin = Arc::new(ClientManagementService::new(
            clients.clone(),
            applications.clone(),
            account_note_repository.clone(),
            hasher.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // Client status list (A3): registered clients × last-used time from the audit log.
        let clients_status = Arc::new(ClientStatusService::new(
            clients.clone(),
            audit_logs.clone(),
        ));
        let audit_query = Arc::new(AuditQueryService::new(audit_logs));
        let application_logs = Arc::new(ApplicationLogService::new(
            Arc::new(SqlxApplicationLogSink::new(pool.clone())),
            Arc::new(SqlxApplicationLogQuery::new(pool.clone())),
            clock.clone(),
        ));
        // Client authentication shared by the three token paths (`/token`, `/introspect`, `/revoke`)
        // (ADR-0030). Keeps the per-method branching in one implementation injected into each service.
        let client_auth = Arc::new(ClientAuthenticator::new(
            hasher.clone(),
            Arc::new(SqlxClientAssertionReplayRepository::new(pool.clone())),
            clock.clone(),
            config.issuer().to_string(),
        ));
        // Admin API permissions held by system clients (ADR-0037). Looked up only when `client_credentials`
        // requests the admin API via `resource`.
        let client_permissions: Arc<dyn crate::domain::repositories::ClientPermissionRepository> =
            Arc::new(SqlxClientPermissionRepository::new(pool.clone()));
        // Audiences stamped into tokens and the clients allowed to request them (ADR-0042). Looked up only for
        // `client_credentials` whose `resource` names something other than assay itself.
        let resources: Arc<dyn crate::domain::repositories::ProtectedResourceRepository> =
            Arc::new(SqlxProtectedResourceRepository::new(pool.clone()));
        // DPoP proofs (ADR-0075). `/token` and `/userinfo` use the same one.
        let dpop = Arc::new(
            crate::application::dpop_proof_verification::DpopProofVerifier::new(
                Arc::new(SqlxDpopProofReplayRepository::new(pool.clone())),
                clock.clone(),
            ),
        );
        let token = Arc::new(TokenService::new(
            clients.clone(),
            users.clone(),
            tenants.clone(),
            codes.clone(),
            refresh_tokens.clone(),
            client_permissions.clone(),
            resources.clone(),
            applications.clone(),
            application_access.clone(),
            keys.clone(),
            client_auth.clone(),
            dpop.clone(),
            audit.clone(),
            sign_in_history_repository.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.access_token_ttl(),
            config.management_token_ttl(),
            config.id_token_ttl(),
            config.refresh_token_ttl(),
        ));
        // Access token verification (shared by /userinfo, /introspect, /revoke; `access_token_verification`).
        let access_tokens = Arc::new(AccessTokenVerifier::new(
            signing_keys.clone(),
            revoked_access_tokens.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.clock_skew(),
        ));
        let userinfo = Arc::new(UserInfoService::new(
            users.clone(),
            access_tokens.clone(),
            dpop.clone(),
            config.issuer().to_string(),
        ));
        let permissions_admin = Arc::new(PermissionManagementService::new(
            users.clone(),
            tenant_memberships.clone(),
            user_permissions.clone(),
            tenants.clone(),
            audit.clone(),
            clock.clone(),
        ));
        let admin_account_guard = Arc::new(AdminAccountGuard::new(
            users.clone(),
            user_permissions.clone(),
            clients.clone(),
            client_permissions.clone(),
            tenants.clone(),
            applications.clone(),
        ));
        // Auth policy management (CRUD). Shares the same implementation as the evaluation repositories (login / passkey_authentication).
        let authentication_policies_admin = Arc::new(AuthenticationPolicyManagementService::new(
            authentication_policies.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // User creation by an admin (ADR-0009 §5). The initial admin user created by the tenant creation flow
        // (tenants_admin) also goes through this service (single source of the creation logic).
        let users_admin = Arc::new(UserManagementService::new(
            users.clone(),
            tenant_memberships.clone(),
            hasher.clone(),
            account_setup_links.clone(),
            account_note_repository.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // G5: back-channel logout send queue. Logout handlers only enqueue notification requests, and the
        // actual HTTP sending is done with retries by the worker `assay_api::run` starts.
        let backchannel_logout = Arc::new(BackchannelLogoutDeliveryService::new(
            Arc::new(SqlxBackchannelLogoutDeliveryRepository::new(pool.clone())),
            Arc::new(KeyServiceLogoutTokenSigner::new(keys.clone())),
            Arc::new(ReqwestBackchannelLogoutSender::with_trust(
                config.outbound_trust(),
            )),
            ids.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.backchannel_logout_max_attempts() as i32,
            BACKCHANNEL_LOGOUT_BATCH_SIZE,
        ));

        // ADR-0049 I7: the outlet that tells RPs about revocations. ⚠ Deleting inside assay alone leaves the RP's
        // login state, so admin operations go through here to enqueue back-channel logout.
        let stop_announcement = Arc::new(StopAnnouncementService::new(
            clients.clone(),
            backchannel_logout.clone(),
        ));
        // User lifecycle operations by an admin (ADR-0009 §5, MT21). Password reissue, disable and MFA reset
        // revoke that user's sessions and tokens.
        let users_lifecycle = Arc::new(UserLifecycleService::new(
            authenticator_repository.clone(),
            users.clone(),
            sso_sessions.clone(),
            refresh_tokens.clone(),
            codes.clone(),
            totp_secrets.clone(),
            webauthn_credentials.clone(),
            hasher.clone(),
            password_policy.clone(),
            audit.clone(),
            stop_announcement.clone(),
            account_setup_links.clone(),
            clock.clone(),
        ));
        // Login identifier assignment by an admin (AP8; spec §4). An admin operation to let users sign in with
        // values the organization already hands out, like phone numbers or employee numbers.
        let login_identifiers_admin = Arc::new(LoginIdentifierManagementService::new(
            login_identifier_repository.clone(),
            users.clone(),
            tenant_domains.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // Tenant creation and management (ADR-0009 §4, §6). Registers the creator as the new tenant's bootstrap admin
        // (ACTIVE GUEST + idp.tenant.admin), persisting tenant, membership and permission grants in a
        // single transaction (unit of work; REF2). Grants bypass the check cache, but since the tenant ID is
        // newly generated, no such key can be in the cache.
        let tenants_admin = Arc::new(TenantManagementService::new(
            tenants.clone(),
            tenant_domains.clone(),
            Arc::new(SqlxTenantProvisioningRepository::new(pool.clone())),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // Guest invitations and memberships (ADR-0009 §3). Permissions share the same cached repository, so
        // permission revocation from membership removal is reflected in the check cache immediately. Invitation
        // mails (MT17) are sent best-effort via system SMTP (MT14); if unset or failing, the token is passed by hand.
        let invitations = Arc::new(InvitationService::new(
            users.clone(),
            tenant_memberships.clone(),
            user_permissions.clone(),
            // When a guest is suspended, revoke refresh tokens for that tenant (MT24).
            refresh_tokens.clone(),
            system_settings.clone(),
            Arc::new(LettreSmtpMailer::with_trust(config.outbound_trust())),
            audit.clone(),
            clock.clone(),
            tenant_settings.clone(),
            config.public_web_base_url().to_string(),
        ));
        // Member list lookup (MT22). A read-only path that filters and pages on the DB side, kept
        // separate from membership changes (InvitationService).
        let member_directory = Arc::new(MemberDirectoryService::new(Arc::new(
            SqlxTenantMemberQuery::new(pool.clone()),
        )));
        let account_notes = Arc::new(AccountNoteService::new(
            Arc::new(SqlxTenantMemberQuery::new(pool.clone())),
            clients.clone(),
            account_note_repository.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // Account list (people and service accounts; ADR-0065). Lists only readable kinds.
        let account_directory = Arc::new(AccountDirectoryService::new(Arc::new(
            SqlxAccountQuery::new(pool.clone()),
        )));
        let admin_access = Arc::new(AdminAccessService::new(
            sso_sessions.clone(),
            users.clone(),
            user_permissions,
            tenant_memberships.clone(),
            clock.clone(),
        ));
        // Admin API authorization (ADR-0037). Handles both the `RequirePerms` check and the admin console's
        // "SSO session → admin token" exchange.
        let management_tokens = Arc::new(ManagementTokenService::new(
            admin_access.clone(),
            keys.clone(),
            signing_keys.clone(),
            users.clone(),
            clients.clone(),
            revoked_access_tokens.clone(),
            clock.clone(),
            config.issuer().to_string(),
            config.management_token_ttl(),
            config.clock_skew(),
        ));
        let client_permissions_admin = Arc::new(ClientPermissionManagementService::new(
            clients.clone(),
            client_permissions,
            audit.clone(),
            clock.clone(),
        ));
        // App management (ADR-0054). Shares the repository implementation with the decider
        // (`ApplicationAccessService`), so adding / removing assignments takes effect from the next code issuance.
        let applications_admin = Arc::new(ApplicationManagementService::new(
            applications.clone(),
            clients.clone(),
            saml_service_provider_repo.clone(),
            resources.clone(),
            Arc::new(SqlxTenantMemberQuery::new(pool.clone())),
            audit.clone(),
            clock.clone(),
            ids.clone(),
        ));
        // App roster lookup (ADR-0057 / ADR-0059). The target app is determined by the calling service
        // account's identity binding (`find_by_binding_target`).
        let application_users = Arc::new(ApplicationUserDirectoryService::new(
            applications.clone(),
            Arc::new(SqlxApplicationUserQuery::new(pool.clone())),
        ));
        // Audience registration and lending to clients (ADR-0042). Shares the repository implementation with
        // the issuer (TokenService), so registration / revocation affects issuance immediately.
        let resources_admin = Arc::new(ResourceManagementService::new(
            resources,
            audit.clone(),
            clock.clone(),
            ids.clone(),
            config.issuer().to_string(),
        ));

        // F4: Logout (RP-initiated / front-channel / back-channel).
        let logout = Arc::new(LogoutService::new(
            sso_sessions.clone(),
            users.clone(),
            clients.clone(),
            codes,
            // Used to verify the `id_token_hint` signature (G12). Old ID Tokens signed with retired keys also
            // arrive as hints, so a kid-lookup repository is passed rather than the ACTIVE key.
            signing_keys.clone(),
            // Looked up to drop refresh tokens issued from the logged-out session (ADR-0044).
            refresh_tokens.clone(),
            audit.clone(),
            clock.clone(),
            config.issuer().to_string(),
        ));

        // AP10: external IdP login. External IdPs are the only path where "assay acts as a client", and
        // ID Token validation (signature, iss, aud, exp, nonce) is enclosed in the `ExternalOidcClient` implementation.
        let external_providers: Arc<
            dyn crate::domain::repositories::ExternalIdentityProviderRepository,
        > = Arc::new(SqlxExternalIdentityProviderRepository::new(pool.clone()));
        let external_login_requests: Arc<
            dyn crate::domain::repositories::ExternalLoginRequestRepository,
        > = Arc::new(SqlxExternalLoginRequestRepository::new(pool.clone()));
        // HTTP to external IdPs goes through one client (with timeouts, not following redirects).
        // Token exchange at login and discovery import before registration (task #77) follow the same rules.
        // Also checks the addresses a name resolves to (does not connect if internal; task #585).
        let external_oidc_client = Arc::new(ReqwestExternalOidcClient::with_trust(
            config.outbound_trust(),
        ));
        let external_login = Arc::new(ExternalLoginService::new(
            external_providers.clone(),
            Arc::new(SqlxExternalIdentityRepository::new(pool.clone())),
            external_login_requests.clone(),
            users.clone(),
            auth_sessions.clone(),
            sign_in.clone(),
            policy_gate.clone(),
            external_oidc_client.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
            *config.key_encryption_key(),
            config.public_web_base_url().to_string(),
        ));
        let external_idps = Arc::new(ExternalIdpManagementService::new(
            external_providers.clone(),
            audit.clone(),
            clock.clone(),
            ids.clone(),
            *config.key_encryption_key(),
        ));
        let external_idp_discovery =
            Arc::new(ExternalIdpDiscoveryService::new(external_oidc_client));

        // AP5: step-up authentication. Shares the IP rate limiter with login (with a separate budget,
        // an attacker locked out of login could keep trying through step-up).
        let step_up = Arc::new(StepUpService::new(
            sso_sessions.clone(),
            users.clone(),
            totp_secrets.clone(),
            // Passkey path for identity verification (AP5, T38). The ceremony shares the implementation with the three login paths.
            passkey_assertion.clone(),
            authenticator_repository.clone(),
            hasher.clone(),
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            *config.key_encryption_key(),
            tenant_settings.clone(),
        ));

        // G10: self-service security screen.
        let account_security = Arc::new(AccountSecurityService::new(
            sso_sessions.clone(),
            users.clone(),
            client_consents.clone(),
            clients.clone(),
            refresh_tokens.clone(),
            audit.clone(),
            clock.clone(),
        ));

        // task #872: the user's device list and notices of logins from unregistered devices.
        let device_registry = Arc::new(DeviceRegistryService::new(
            user_devices.clone(),
            sso_sessions.clone(),
            users.clone(),
            refresh_tokens.clone(),
            tenant_settings.clone(),
            security_alerts.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // task #885: SSH public keys registered by users (the notice sender is the same as for devices).
        let ssh_keys = Arc::new(SshKeyRegistryService::new(
            Arc::new(SqlxUserSshKeyRepository::new(pool.clone())),
            sso_sessions.clone(),
            users.clone(),
            tenant_settings.clone(),
            security_alerts.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // Binding the SSO session to the device key (DBSC; task #887, ADR-0074).
        let session_key_binding = Arc::new(SessionKeyBindingService::new(
            Arc::new(SqlxSessionKeyBindingRepository::new(pool.clone())),
            sso_sessions.clone(),
            user_devices.clone(),
            users.clone(),
            refresh_tokens.clone(),
            tenant_settings.clone(),
            security_alerts.clone(),
            audit.clone(),
            clock.clone(),
            *config.csrf_secret(),
        ));
        // Logins approved in the authenticator app ("Continue with the app"; task #892, ADR-0077).
        let app_approval = Arc::new(AppApprovalService::new(
            AppApprovalDependencies {
                keys: Arc::new(SqlxApproverKeyRepository::new(pool.clone())),
                enrollments: Arc::new(SqlxApproverEnrollmentRepository::new(pool.clone())),
                requests: Arc::new(SqlxApprovalRequestRepository::new(pool.clone())),
                users: users.clone(),
                memberships: tenant_memberships.clone(),
                sso_sessions: sso_sessions.clone(),
                refresh_tokens: refresh_tokens.clone(),
                auth_sessions: auth_sessions.clone(),
                clients: clients.clone(),
                policy_gate: policy_gate.clone(),
                sign_in: sign_in.clone(),
                settings: tenant_settings.clone(),
                audit: audit.clone(),
                alerts: security_alerts,
                rate_limiter: rate_limiter.clone(),
                clock: clock.clone(),
            },
            app_approver_policy(&config),
        ));

        // task #896: the "Status" the user sees (read-only).
        let security_status = Arc::new(SecurityStatusService::new(SecurityStatusDeps {
            query: Arc::new(SqlxSecurityStatusQuery::new(pool.clone())),
            sso_sessions: sso_sessions.clone(),
            users: users.clone(),
            authenticators: authenticator_repository.clone(),
            devices: user_devices.clone(),
            approver_keys: Arc::new(SqlxApproverKeyRepository::new(pool.clone())),
            ssh_keys: Arc::new(SqlxUserSshKeyRepository::new(pool.clone())),
            settings: tenant_settings.clone(),
            clock: clock.clone(),
        }));

        // task #879: sign-in history the user sees.
        let sign_in_history = Arc::new(SignInHistoryService::new(
            sign_in_history_repository.clone(),
            sso_sessions.clone(),
            users.clone(),
            clock.clone(),
        ));

        // F5: token management (revocation / introspection).
        let revocation = Arc::new(RevocationService::new(
            clients.clone(),
            refresh_tokens.clone(),
            revoked_access_tokens.clone(),
            access_tokens.clone(),
            client_auth.clone(),
            audit.clone(),
            clock.clone(),
        ));
        let introspection = Arc::new(IntrospectionService::new(
            clients.clone(),
            refresh_tokens,
            access_tokens.clone(),
            users.clone(),
            client_auth,
            clock.clone(),
            config.issuer().to_string(),
        ));

        let totp_registration = Arc::new(TotpRegistrationService::new(
            authenticators.clone(),
            totp_secrets.clone(),
            sso_sessions.clone(),
            users.clone(),
            *config.key_encryption_key(),
            config.issuer().to_string(),
            clock.clone(),
        ));
        let mfa_login = Arc::new(MfaLoginService::new(
            authenticator_repository.clone(),
            auth_sessions.clone(),
            totp_secrets,
            users.clone(),
            sign_in.clone(),
            // Shares the same limiter instance and lock policy as password authentication (SEC3).
            // With a separate budget one could try "up to the limit with password, then up to the limit with TOTP".
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
            *config.key_encryption_key(),
            tenant_settings.clone(),
            *config.csrf_secret(),
            policy_gate.clone(),
        ));

        let passkey_authentication = Arc::new(PasskeyAuthenticationService::new(
            passkey_assertion,
            auth_sessions.clone(),
            policy_gate.clone(),
            sign_in.clone(),
            // The rate limit shares its budget with the passkey paths of login and direct login (T39).
            rate_limiter.clone(),
            audit.clone(),
            clock.clone(),
        ));
        // Restart from the settings screen (ADR-0017). The signal itself goes to `run()`'s graceful shutdown and
        // the use case (audit → stop request) to the handler, so the same value is held on two paths.
        let restart = ServiceRestart::new();
        let service_restart = Arc::new(ServiceRestartService::new(
            Arc::new(restart.clone()),
            audit.clone(),
        ));

        // CORS allowed origins (G1). `/token` and `/userinfo` are hot paths, so the tenant → origin set is
        // cached with the same TTL as tenant resolution. Right after `redirect_uris` change in the admin screen
        // a set up to TTL old may be used, but the TTL is short by default and the only effect is "reads from a
        // new origin fail for a short while" (an old origin passing extra for the same duration also happens).
        let cors_policy = Arc::new(ApiCorsPolicy::new(
            clients.clone(),
            config.cors_allowed_origins(),
            Arc::new(InMemoryTtlCache::new(
                chrono_from_std(config.tenant_cache_ttl()),
                clock.clone(),
            )),
        ));

        // Bulk GC of expired records (G2). The target table list is defined once on the infrastructure side;
        // this only assembles it and passes it to the `run()` task.
        let expired_records = Arc::new(ExpiredRecordPurgeService::new(
            crate::infrastructure::repositories::expired_records::all_expiring_record_stores(
                pool.clone(),
            ),
            clock.clone(),
        ));

        // Load gate for the token endpoints (SEC10). Limits concurrent Argon2 verifications and
        // requests per source.
        let token_endpoint_load = Arc::new(
            crate::presentation::token_endpoint_load::TokenEndpointLoadGate::from_config(
                &config,
                clock.clone(),
            ),
        );

        Self {
            pool,
            config,
            started_at,
            clock: clock.clone(),
            metrics: crate::presentation::metrics::handle().map(Arc::new),
            token_endpoint_load,
            tenant_resolution,
            tenant_settings,
            register,
            email_verification,
            authorize,
            login,
            change_password,
            consent,
            token,
            userinfo,
            keys,
            admin_access,
            management_tokens,
            client_permissions_admin,
            resources_admin,
            applications_admin,
            application_users,
            admin_login,
            portal_login,
            clients_admin,
            clients_status,
            permissions_admin,
            admin_account_guard,
            authentication_policies_admin,
            users_admin,
            login_identifiers_admin,
            users_lifecycle,
            tenants_admin,
            system_settings,
            account_password,
            account_language,
            account_theme,
            account_profile,
            account_tenants,
            password_reset,
            invitations,
            member_directory,
            account_notes,
            account_directory,
            audit_query,
            audit,
            application_logs,
            logout,
            account_security,
            device_registry,
            device_gate,
            device_enrollment,
            sign_in_history,
            security_status,
            ssh_keys,
            session_key_binding,
            app_approval,
            step_up,
            authenticators,
            authenticator_repository,
            external_login,
            external_idps,
            external_idp_discovery,
            external_providers,
            external_login_requests,
            backchannel_logout,
            revocation,
            introspection,
            totp_registration,
            mfa_login,
            passkey_registration,
            account_setup,
            passkey_authentication,
            saml_service_providers,
            saml_sso,
            restart,
            service_restart,
            expired_records,
            cors_policy,
        }
    }
}

/// Converts a setting value (`std::time::Duration`) to a resolution cache TTL (`chrono::Duration`).
/// TTLs are second-precision, so rounding does not matter (saturates at the maximum on overflow).
fn chrono_from_std(d: std::time::Duration) -> chrono::Duration {
    chrono::Duration::from_std(d).unwrap_or(chrono::Duration::MAX)
}

impl FromRef<AppState> for Db {
    fn from_ref(state: &AppState) -> Db {
        state.pool.clone()
    }
}

impl FromRef<AppState> for Arc<RegisterService> {
    fn from_ref(state: &AppState) -> Arc<RegisterService> {
        state.register.clone()
    }
}

/// Notice sender for security notices (task #872). Does not send when there is no destination or the key cannot be read.
///
/// ⚠ Failing to read the key does not stop startup (logins are not stopped for the sake of notices). Instead
/// an error log is left, and the event can be traced in the audit log.
/// Rules for verifying authenticator app keys (env vars only; ADR-0077). Without a package name the endpoint is closed (`None`).
///
/// When the settings are broken (malformed fingerprint, unreadable root file), the endpoint is closed and startup
/// continues (login itself is not stopped; same treatment as the notice sender).
fn app_approver_policy(
    config: &Config,
) -> Option<crate::domain::key_attestation::AttestationPolicy> {
    use crate::domain::key_attestation::{root_keys_from_pem, AttestationPolicy, GOOGLE_ROOTS_PEM};
    let package = config.app_approver_package_name()?;
    let mut digests = Vec::new();
    for raw in config
        .app_approver_signing_cert_sha256()
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
    {
        let hex: String = raw.chars().filter(|c| *c != ':').collect();
        match hex::decode(&hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            Some(d) => digests.push(d),
            None => {
                tracing::error!("APP_APPROVER_SIGNING_CERT_SHA256 has a malformed fingerprint; the authenticator app is disabled");
                return None;
            }
        }
    }
    if digests.is_empty() {
        tracing::error!("APP_APPROVER_PACKAGE_NAME is set without APP_APPROVER_SIGNING_CERT_SHA256; the authenticator app is disabled");
        return None;
    }
    let mut roots = match root_keys_from_pem(GOOGLE_ROOTS_PEM) {
        Ok(roots) => roots,
        Err(e) => {
            tracing::error!(
                reason = e.as_str(),
                "the shipped Google attestation roots could not be read"
            );
            return None;
        }
    };
    if let Some(path) = config.app_approver_extra_attestation_roots_file() {
        match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|pem| root_keys_from_pem(&pem).map_err(|e| e.as_str().to_string()))
        {
            Ok(extra) if !extra.is_empty() => {
                tracing::warn!(
                    count = extra.len(),
                    "extra key attestation roots are trusted (staging only)"
                );
                roots.extend(extra);
            }
            Ok(_) | Err(_) => {
                tracing::error!("APP_APPROVER_EXTRA_ATTESTATION_ROOTS_FILE could not be read; the authenticator app is disabled");
                return None;
            }
        }
    }
    if config.app_approver_allow_software_attestation() {
        tracing::warn!("software key attestation is accepted (staging only)");
    }
    tracing::info!(package, "the authenticator app is enabled");
    Some(AttestationPolicy {
        trusted_root_keys: roots,
        package_name: package.to_string(),
        signing_cert_digests: digests,
        allow_software: config.app_approver_allow_software_attestation(),
    })
}

fn security_alert_sink(config: &Config) -> Arc<dyn SecurityAlertSink> {
    let Some(url) = config.security_alert_webhook_url() else {
        return Arc::new(DisabledSecurityAlertSink);
    };
    let token = match config.security_alert_webhook_token_file() {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(token) if !token.trim().is_empty() => token,
            Ok(_) => {
                tracing::error!(
                    "SECURITY_ALERT_WEBHOOK_TOKEN_FILE is empty; security alerts are disabled"
                );
                return Arc::new(DisabledSecurityAlertSink);
            }
            Err(e) => {
                tracing::error!(error = %e, "SECURITY_ALERT_WEBHOOK_TOKEN_FILE could not be read; security alerts are disabled");
                return Arc::new(DisabledSecurityAlertSink);
            }
        },
        None => {
            tracing::error!("SECURITY_ALERT_WEBHOOK_URL is set without SECURITY_ALERT_WEBHOOK_TOKEN_FILE; security alerts are disabled");
            return Arc::new(DisabledSecurityAlertSink);
        }
    };
    match WebhookSecurityAlertSink::new(url.to_string(), token) {
        Ok(sink) => {
            tracing::info!("security alerts are sent to the configured webhook");
            Arc::new(sink)
        }
        Err(e) => {
            tracing::error!(error = %e, "security alert webhook client could not be built; security alerts are disabled");
            Arc::new(DisabledSecurityAlertSink)
        }
    }
}
