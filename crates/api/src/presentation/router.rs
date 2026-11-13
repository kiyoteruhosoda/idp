//! Assembles the axum router. Merges each context's router with `.merge()` / `.nest()`.

use crate::presentation::correlation;
use crate::presentation::cors;
use crate::presentation::handlers::{
    account_setup, admin, admin_accounts, admin_application_logs, admin_applications, admin_audit,
    admin_authentication_policies, admin_client_permissions, admin_clients, admin_external_idps,
    admin_invitations, admin_login_identifiers, admin_members, admin_permissions, admin_resources,
    admin_restart, admin_saml_service_providers, admin_signing_keys, admin_ssh_keys,
    admin_system_settings, admin_tenant_settings, admin_tenant_smtp, admin_tenants, admin_users,
    app_approver, authorize, consent, discovery, health, internal_admin_token,
    internal_app_approval, internal_auth, internal_device_enrollment, internal_devices,
    internal_runtime_settings, internal_security_status, internal_session_keys,
    internal_sign_in_history, internal_ssh_keys, introspect, invitations, logout, mfa, passkey,
    register, revoke, saml_sso, token, userinfo,
};
use crate::presentation::openapi::ApiDoc;
use crate::presentation::security_headers::add_security_headers;
use crate::presentation::state::AppState;
use crate::presentation::tenant::resolve_tenant;
use axum::middleware;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn build(state: AppState) -> Router {
    let hsts_max_age = state.config.hsts_max_age();
    let api_docs_enabled = state.config.api_docs_enabled();
    // Internal auth API (ADR-0007 §3, §5). Service-to-service I/F from web (future) to api. Not public
    // (assumes the reverse proxy blocks /internal/*). As defence in depth, a route_layer requiring the
    // service auth token (X-Internal-Auth-Token) is attached to this sub-router only.
    let internal = Router::new()
        // Resumes the authorization flow (web handoff handle exchange + SSO check; ADR-0018 decision 2).
        .route(
            "/internal/authorize/resume",
            post(authorize::authorize_resume),
        )
        // Continues the authorization flow (on reopening the login screen, continue from an SSO set up in another tab).
        .route(
            "/internal/authorize/continue",
            post(authorize::authorize_continue),
        )
        // Login screen context (re-reading `login_hint` / `ui_locales`; G12).
        .route(
            "/internal/authorize/login-context",
            post(authorize::authorize_login_context),
        )
        // Resumes the SAML SSO flow (web handoff handle exchange + SSO check + response issuance).
        .route("/internal/saml/resume", post(saml_sso::saml_resume))
        // RP-initiated logout (end_session_endpoint is on web; api handles revocation, notifications, URL building).
        .route("/internal/logout/rp", post(logout::rp_logout))
        // Exchanges an admin console SSO session for an admin token (ADR-0037). The api `/admin/*` accepts
        // only Bearer, so web always goes through here before operating on data.
        .route(
            "/internal/admin/token",
            post(internal_admin_token::issue_management_token),
        )
        .route("/internal/authenticate", post(internal_auth::authenticate))
        .route(
            "/internal/authenticate/admin",
            post(internal_auth::authenticate_admin),
        )
        .route(
            "/internal/authenticate/admin/change-password",
            post(internal_auth::admin_change_password),
        )
        // Direct login to the end-user portal (client-independent; honours TOTP).
        .route(
            "/internal/authenticate/portal",
            post(internal_auth::authenticate_portal),
        )
        .route(
            "/internal/authenticate/portal/mfa",
            post(internal_auth::authenticate_portal_mfa),
        )
        // Forced password change in the portal (at first login; ADR-0009 §5).
        .route(
            "/internal/authenticate/portal/change-password",
            post(internal_auth::authenticate_portal_change_password),
        )
        .route(
            "/internal/change-password",
            post(internal_auth::change_password),
        )
        // Self-service password change (settings screen of a signed-in user; MT15).
        .route(
            "/internal/account/change-password",
            post(internal_auth::account_change_password),
        )
        // Self-service display language change (settings screen of a signed-in user; MT20).
        .route(
            "/internal/account/update-language",
            post(internal_auth::account_update_language),
        )
        // Self-service color scheme change (settings screen of a signed-in user).
        .route(
            "/internal/account/update-theme",
            post(internal_auth::account_update_theme),
        )
        // Self-service profile read and display name update (settings screen of a signed-in user).
        .route(
            "/internal/account/profile",
            post(internal_auth::account_profile),
        )
        .route(
            "/internal/account/update-name",
            post(internal_auth::account_update_name),
        )
        // External IdP login (AP10).
        .route(
            "/internal/external/providers",
            post(internal_auth::external_providers),
        )
        .route(
            "/internal/external/start",
            post(internal_auth::external_start),
        )
        .route(
            "/internal/external/callback",
            post(internal_auth::external_callback),
        )
        .route(
            "/internal/external/saml/acs",
            post(internal_auth::external_saml_acs),
        )
        // Unified authenticator management (list, state change, recovery codes, email OTP; AP9).
        .route(
            "/internal/account/authenticators",
            post(internal_auth::account_authenticators),
        )
        .route(
            "/internal/account/authenticators/status",
            post(internal_auth::account_authenticator_status),
        )
        .route(
            "/internal/account/recovery-codes",
            post(internal_auth::account_recovery_codes),
        )
        .route(
            "/internal/account/email-otp",
            post(internal_auth::account_email_otp),
        )
        // SMS OTP and phone number registration (AP13). Sending only for users awaiting MFA, registration via SSO session.
        .route(
            "/internal/account/sms-otp",
            post(internal_auth::account_sms_otp),
        )
        .route(
            "/internal/account/phone/register",
            post(internal_auth::account_phone_register),
        )
        .route(
            "/internal/account/phone/confirm",
            post(internal_auth::account_phone_confirm),
        )
        // Step-up authentication (re-verifying identity right before a sensitive operation; AP5).
        .route(
            "/internal/step-up/check",
            post(internal_auth::step_up_check),
        )
        .route(
            "/internal/step-up/verify",
            post(internal_auth::step_up_verify),
        )
        // Passkey path for identity verification (T38). Handles challenges with a different purpose from login begin/finish.
        .route(
            "/internal/step-up/passkey/begin",
            post(internal_auth::step_up_passkey_begin),
        )
        .route(
            "/internal/step-up/passkey/verify",
            post(internal_auth::step_up_passkey_verify),
        )
        // Self-service security screen (session list, revocation / unlinking apps; G10).
        .route(
            "/internal/account/security",
            post(internal_auth::account_security),
        )
        .route(
            "/internal/account/security/revoke-session",
            post(internal_auth::account_revoke_session),
        )
        .route(
            "/internal/account/security/revoke-consent",
            post(internal_auth::account_revoke_consent),
        )
        // Reissuing issued tokens (by the user; ADR-0047).
        .route(
            "/internal/account/security/reissue-tokens",
            post(internal_auth::account_reissue_tokens),
        )
        // The user's devices (task #872). Binding the signed-in device and the "Devices" section.
        .route("/internal/devices/observe", post(internal_devices::observe))
        // Registering the device on the spot when signing in correctly from an unregistered device (task #916).
        .route(
            "/internal/device-enrollment/describe",
            post(internal_device_enrollment::describe),
        )
        .route(
            "/internal/device-enrollment/passkey/begin",
            post(internal_device_enrollment::begin),
        )
        .route(
            "/internal/device-enrollment/passkey/complete",
            post(internal_device_enrollment::complete),
        )
        // "Continue with the app" and the authenticator app keys (task #892, ADR-0077).
        .route(
            "/internal/app-approval/start",
            post(internal_app_approval::start),
        )
        .route(
            "/internal/app-approval/complete",
            post(internal_app_approval::complete),
        )
        .route(
            "/internal/account/app-approver/enrollment",
            post(internal_app_approval::account_enrollment),
        )
        .route(
            "/internal/account/app-approver/confirm",
            post(internal_app_approval::account_confirm),
        )
        .route(
            "/internal/account/app-approver/keys",
            post(internal_app_approval::account_keys),
        )
        .route(
            "/internal/account/app-approver/keys/revoke",
            post(internal_app_approval::account_revoke_key),
        )
        // Binding the SSO session to the device key (DBSC; task #887).
        .route(
            "/internal/sso/key-binding",
            post(internal_session_keys::binding),
        )
        .route(
            "/internal/sso/key-binding/register",
            post(internal_session_keys::register),
        )
        .route(
            "/internal/sso/key-binding/refresh",
            post(internal_session_keys::refresh),
        )
        .route(
            "/internal/account/devices",
            post(internal_devices::account_devices),
        )
        .route(
            "/internal/account/devices/register",
            post(internal_devices::account_register_device),
        )
        .route(
            "/internal/account/devices/revoke",
            post(internal_devices::account_revoke_device),
        )
        // The "Status" the user sees (task #896).
        .route(
            "/internal/account/security/status",
            post(internal_security_status::account_security_status),
        )
        // The user's sign-in history (task #879).
        .route(
            "/internal/account/sign-in-history",
            post(internal_sign_in_history::account_sign_in_history),
        )
        // SSH public keys registered by the user (task #885).
        .route(
            "/internal/account/ssh-keys",
            post(internal_ssh_keys::account_ssh_keys),
        )
        .route(
            "/internal/account/ssh-keys/register",
            post(internal_ssh_keys::account_register_ssh_key),
        )
        .route(
            "/internal/account/ssh-keys/revoke",
            post(internal_ssh_keys::account_revoke_ssh_key),
        )
        // Lists the tenants of the signed-in user (tenant switcher UI).
        .route(
            "/internal/account/tenants",
            post(internal_auth::account_tenants),
        )
        .route("/internal/logout", post(internal_auth::logout))
        // Password reset (when forgotten; MT18). Unauthenticated path (web relays the form).
        .route(
            // Account setup link (ADR-0062). describe only reads and does not consume it.
            "/internal/account-setup/describe",
            post(account_setup::describe),
        )
        .route(
            "/internal/account-setup/passkey/begin",
            post(account_setup::passkey_begin),
        )
        .route(
            "/internal/account-setup/passkey/complete",
            post(account_setup::passkey_complete),
        )
        .route(
            "/internal/password-reset/request",
            post(internal_auth::password_reset_request),
        )
        .route(
            "/internal/password-reset/complete",
            post(internal_auth::password_reset_complete),
        )
        // Consent API (F3: Consent).
        .route("/internal/consent-info", get(consent::consent_info))
        .route("/internal/consent/approve", post(consent::consent_approve))
        .route("/internal/consent/deny", post(consent::consent_deny))
        // MFA (TOTP) self-registration and login verification API.
        .route("/internal/mfa/totp/setup", post(mfa::setup_totp))
        .route("/internal/mfa/totp/confirm", post(mfa::confirm_totp))
        .route("/internal/mfa/totp/delete", post(mfa::delete_totp))
        .route("/internal/mfa/totp/verify", post(mfa::verify_totp))
        // Passkey (WebAuthn) self-registration API.
        .route(
            "/internal/passkey/register/begin",
            post(passkey::register_begin),
        )
        .route(
            "/internal/passkey/register/complete",
            post(passkey::register_complete),
        )
        .route("/internal/passkey/delete", post(passkey::passkey_delete))
        .route("/internal/passkey/list", post(passkey::passkey_list))
        // Passkey login flow API.
        .route("/internal/passkey/login/begin", post(passkey::login_begin))
        .route(
            "/internal/passkey/login/complete",
            post(passkey::login_complete),
        )
        // Direct login outside the authorization flow (admin console, portal). Begin shares login/begin above,
        // and the challenge obtained without an `auth_session_id` is finished here.
        .route(
            "/internal/passkey/login/admin/complete",
            post(passkey::admin_login_complete),
        )
        .route(
            "/internal/passkey/login/portal/complete",
            post(passkey::portal_login_complete),
        )
        // Shared runtime settings web reads at startup (MT26 / ADR-0013). web has no DB, so this is the single
        // source of DB-managed values consumed by both api and web (COOKIE_SECURE etc.).
        .route(
            assay_contracts::runtime_settings::SHARED_RUNTIME_SETTINGS_PATH,
            get(internal_runtime_settings::shared_runtime_settings),
        )
        // Ingests web WARN / ERROR logs (CLAUDE.md "Logs"). web has no DB, so it sends its own
        // application logs here to have them written to the `log` table.
        .route(
            "/internal/logs",
            post(admin_application_logs::ingest_application_logs),
        )
        // Prometheus metrics (G6). Placed on the internal surface, not the public one (it aggregates who
        // failed when and how often; not something readable from outside). Proxy block + service token.
        .route(
            "/internal/metrics",
            get(crate::presentation::metrics::metrics_endpoint),
        )
        // Detailed health (ADR-0031). Returns version, uptime, server time and dependency check results.
        // The public surface (`/healthz`, `/readyz`) shows only the service name; details appear only here.
        .route("/internal/health", get(health::internal_health))
        // Build info and schema state (ADR-0034). Knowing the running commit lets outsiders tell which
        // known bugs are still open, so it is not exposed without auth. web calls it with the
        // service token, so the console's version screen keeps working.
        .route("/internal/version", get(health::version))
        .route("/internal/version/schema", get(health::schema_version))
        // The "trusted country" attached by web (task #895). Read only on requests that passed the service token check (outer).
        .route_layer(axum::middleware::from_fn(
            crate::presentation::client_country::capture_client_country,
        ))
        // The current browser's device mark attached by web (task #916). Likewise read only inside the service token check.
        .route_layer(axum::middleware::from_fn(
            crate::presentation::client_device::capture_client_device,
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            internal_auth::require_service_token,
        ));

    // Tenant-scoped routes (ADR-0009 §6). Paths do not contain `/{tenant_id}`; it is prefixed with `.nest()`.
    // `resolve_tenant` is attached via `route_layer`, and each handler receives `Extension<ResolvedTenant>`.
    let tenant_scoped = Router::new()
        .route("/auth/register", post(register::register))
        .route("/auth/verify-email", post(register::verify_email))
        .route("/authorize", get(authorize::authorize))
        // The three token endpoints (client auth = Argon2 verification) go through the load gate (SEC10).
        // When adding routes, put them on the same gate if they involve client authentication.
        .merge(
            Router::new()
                .route("/token", post(token::token))
                .route("/revoke", post(revoke::revoke))
                .route("/introspect", post(introspect::introspect))
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::presentation::token_endpoint_load::limit_token_endpoint_load,
                )),
        )
        .route("/userinfo", get(userinfo::userinfo))
        // `/logout` (end_session_endpoint) is served by web (ADR-0018 decision 2). api does not read browser
        // cookies, so it has no public logout route (handled by /internal/logout/rp).
        // Admin identity check (requires idp.tenant.admin; RequirePerms<IdpAdmin>). The web admin console uses it
        // to get auth state and identity with the admin token (ADR-0007 §4 / ADR-0037). HTML screens are in the web crate.
        .route("/admin/whoami", get(admin::whoami))
        // Tenant creation and management (ADR-0009 §5, §6). Requires idp.system.admin (effectively root only).
        .route(
            "/admin/tenants",
            get(admin_tenants::list_tenants).post(admin_tenants::create_tenant),
        )
        .route(
            "/admin/tenants/{child_id}",
            get(admin_tenants::get_tenant)
                .patch(admin_tenants::update_tenant)
                .delete(admin_tenants::delete_tenant),
        )
        // Reissues the password of a child tenant admin (requires idp.system.admin).
        .route(
            "/admin/tenants/{child_id}/admin-password-reset",
            post(admin_tenants::reset_tenant_admin_password),
        )
        // Assigns domains to tenants (ADR-0029; requires idp.system.admin). Targets are **the own tenant or
        // its direct children**, and root itself can be assigned too (root users enter tenants they created
        // as guests, so it is pointless unless they can enter with the domain qualifier). Domain uniqueness is
        // global, so only root's system admins may operate it, to avoid first-come-first-served.
        .route(
            "/admin/tenants/{target_id}/domains",
            get(admin_tenants::list_tenant_domains).post(admin_tenants::add_tenant_domain),
        )
        .route(
            "/admin/tenants/{target_id}/domains/{domain_id}",
            delete(admin_tenants::remove_tenant_domain),
        )
        // Tenant settings section of the settings screen (MT14). The own tenant's display name (idp.tenant-settings:read / :write).
        .route(
            "/admin/settings/tenant",
            get(admin_tenants::get_current_tenant).patch(admin_tenants::update_current_tenant),
        )
        // Tenant setting values (ADR-0058). Items derive from the key definitions; keys decided globally are not exposed.
        .route(
            "/admin/settings/tenant/keys",
            get(admin_tenant_settings::list_tenant_settings),
        )
        .route(
            "/admin/settings/tenant/keys/{key}",
            axum::routing::put(admin_tenant_settings::set_tenant_setting)
                .delete(admin_tenant_settings::clear_tenant_setting),
        )
        // System settings section of the settings screen (requires idp.system.admin = effectively root only). Not split
        // into fine-grained permissions — the only exception is the SMTP endpoint below (ADR-0051).
        .route(
            "/admin/system-settings",
            get(admin_system_settings::get_system_settings)
                .put(admin_system_settings::update_system_settings),
        )
        // The tenant's own mail route (ADR-0058 §8). Requires `idp.smtp:read` / `:write`; works in any tenant.
        .route(
            "/admin/settings/smtp",
            get(admin_tenant_smtp::get_tenant_smtp)
                .put(admin_tenant_smtp::update_tenant_smtp)
                .delete(admin_tenant_smtp::clear_tenant_smtp),
        )
        // The global-SMTP-only endpoint (ADR-0051). Guarded by `idp.smtp:read` / `:write`, a permission separate
        // from the system settings body (`/admin/system-settings`). ⚠ **Works only in the root tenant.**
        .route(
            "/admin/system-settings/smtp",
            get(admin_system_settings::get_smtp_settings)
                .put(admin_system_settings::update_smtp_settings),
        )
        // DB overrides of runtime settings (DB_MANAGED keys only; requires idp.system.admin).
        .route(
            "/admin/system-settings/runtime",
            axum::routing::put(admin_system_settings::update_runtime_setting),
        )
        // Restarts api to apply saved runtime settings (requires idp.system.admin; ADR-0017).
        .route("/admin/restart", post(admin_restart::restart_service))
        // Members and invitations (ADR-0009 §3, §6). Requires idp.members:read / idp.members:write.
        .route("/admin/members", get(admin_members::list_members))
        // Removing (DELETE) and suspending / resuming (PATCH) guest memberships (MT24).
        .route(
            "/admin/members/{user_id}",
            get(admin_members::get_member)
                .delete(admin_members::revoke_member)
                .patch(admin_members::update_member_status),
        )
        // Admin notes (ADR-0063) and the apps that person can use (the inverse of the app details).
        .route(
            "/admin/members/{user_id}/note",
            axum::routing::put(admin_members::update_member_note),
        )
        .route(
            "/admin/members/{user_id}/applications",
            get(admin_applications::list_member_applications),
        )
        // Accounts (people and service accounts; ADR-0065). The list shows only readable kinds
        // (people need idp.members:read, service accounts idp.clients:read). A single service account and
        // its admin notes and usable apps have the same shape as the people's `/admin/members/{user_id}/*`.
        .route("/admin/accounts", get(admin_accounts::list_accounts))
        .route(
            "/admin/service-accounts/{client_id}",
            get(admin_accounts::get_service_account),
        )
        .route(
            "/admin/service-accounts/{client_id}/note",
            axum::routing::put(admin_accounts::update_service_account_note),
        )
        .route(
            "/admin/service-accounts/{client_id}/applications",
            get(admin_applications::list_service_account_applications),
        )
        .route(
            "/admin/invitations",
            post(admin_invitations::create_invitation),
        )
        // Accepting an invitation (not an admin API; used by the signed-in user themselves; ADR-0009 §3).
        .route("/invitations/accept", post(invitations::accept_invitation))
        // Client (RP) registration and management API (A1, design spec §9.3). Requires idp.clients:read / idp.clients:write.
        .route(
            "/admin/clients",
            post(admin_clients::create_client).get(admin_clients::list_clients),
        )
        // Status list (static status takes precedence over dynamic {client_id}).
        .route(
            "/admin/clients/status",
            get(admin_clients::list_client_status),
        )
        .route(
            "/admin/clients/{client_id}",
            get(admin_clients::get_client)
                .patch(admin_clients::update_client)
                // Logical deletion (ADR-0035). Keeps the row and sets the state to DELETED.
                .delete(admin_clients::delete_client),
        )
        .route(
            "/admin/clients/{client_id}/secret",
            post(admin_clients::rotate_client_secret),
        )
        // Grants and revokes admin permissions for system clients (ADR-0037). The permission codes given here
        // become the `perms` of the admin token obtained via `client_credentials` (`resource={issuer}/admin`).
        // Requires idp.clients:read / idp.clients:write.
        .route(
            "/admin/clients/{client_id}/permissions",
            get(admin_client_permissions::list_client_permissions)
                .post(admin_client_permissions::grant_client_permission),
        )
        .route(
            "/admin/clients/{client_id}/permissions/{permission_code}",
            delete(admin_client_permissions::revoke_client_permission),
        )
        // Grantable permission codes (master) and user search / lookup (admin console support API).
        // Requires idp.permissions:read / idp.users:* (ADR-0037).
        .route(
            "/admin/permissions",
            get(admin_permissions::list_available_permissions),
        )
        .route(
            "/admin/users",
            post(admin_users::create_user).get(admin_users::search_user),
        )
        // User lookup, state change (enable / disable) and deletion. Requires idp.users:read / idp.users:write.
        .route(
            "/admin/users/{user_id}",
            get(admin_users::get_user)
                .patch(admin_users::update_user_status)
                .delete(admin_users::delete_user),
        )
        // Reissues a user's password (auto-generated with must_change_password). Requires idp.users:write.
        .route(
            "/admin/users/{user_id}/profile",
            patch(admin_users::update_user_profile),
        )
        .route(
            "/admin/users/{user_id}/password-reset",
            post(admin_users::reset_user_password),
        )
        // Resets a user's MFA (TOTP, Passkey) (recovery after losing a device; MT21). Requires idp.users:write.
        .route(
            "/admin/users/{user_id}/mfa-reset",
            post(admin_users::reset_user_mfa),
        )
        // Bulk revocation of issued refresh tokens (by an admin; ADR-0047). Requires idp.users:write.
        .route(
            "/admin/users/{user_id}/token-reissue",
            post(admin_users::reissue_user_tokens),
        )
        // Number of currently valid refresh tokens (shown before reissuing; task #83). Requires idp.users:read.
        .route(
            "/admin/users/{user_id}/active-tokens",
            get(admin_users::count_user_active_tokens),
        )
        // Immediate account unlock (AP6; spec §17.1, §24.6). Requires idp.users:write.
        .route(
            "/admin/users/{user_id}/unlock",
            post(admin_users::unlock_user),
        )
        // Login identifier assignment (AP8; spec §4). Requires idp.users:read / idp.users:write.
        .route(
            "/admin/users/{user_id}/login-identifiers",
            get(admin_login_identifiers::list_login_identifiers)
                .post(admin_login_identifiers::add_login_identifier),
        )
        .route(
            "/admin/users/{user_id}/login-identifiers/{identifier_id}",
            patch(admin_login_identifiers::update_login_identifier)
                .delete(admin_login_identifiers::delete_login_identifier),
        )
        // Promotes an alias email to the primary email (ADR-0052). It is a swap, not a field update.
        .route(
            "/admin/users/{user_id}/login-identifiers/{identifier_id}/primary-email",
            post(admin_login_identifiers::promote_primary_email),
        )
        // Grants, revokes and reads user permissions (A2, ADR-0006). Requires idp.permissions:read / :write.
        .route(
            "/admin/users/{user_id}/permissions",
            get(admin_permissions::list_permissions).post(admin_permissions::grant_permission),
        )
        .route(
            "/admin/users/{user_id}/permissions/{permission_code}",
            axum::routing::delete(admin_permissions::revoke_permission),
        )
        // Apps (ADR-0054 / ADR-0059). Identities (login, SAML, service account, audience) and
        // user assignments hang off this level.
        // Requires idp.applications:*.
        .route(
            "/admin/applications",
            get(admin_applications::list_applications).post(admin_applications::create_application),
        )
        .route(
            "/admin/applications/{application_id}",
            get(admin_applications::get_application)
                .put(admin_applications::update_application)
                .delete(admin_applications::delete_application),
        )
        .route(
            "/admin/applications/{application_id}/bindings",
            axum::routing::post(admin_applications::add_binding),
        )
        .route(
            "/admin/applications/{application_id}/bindings/{binding_id}",
            axum::routing::delete(admin_applications::remove_binding),
        )
        .route(
            "/admin/applications/{application_id}/assignments",
            axum::routing::post(admin_applications::assign_user),
        )
        // Assignments are of two kinds, people and service accounts (ADR-0059). Removal is addressed by a per-kind key.
        .route(
            "/admin/applications/{application_id}/assignments/users/{user_id}",
            axum::routing::delete(admin_applications::unassign_user),
        )
        .route(
            "/admin/applications/{application_id}/assignments/service-accounts/{client_id}",
            axum::routing::delete(admin_applications::unassign_service_account),
        )
        // Identity candidates (ADR-0067). Lets the admin pick the counterpart from a list rather than typing an ID.
        .route(
            "/admin/applications/{application_id}/binding-candidates",
            get(admin_applications::binding_candidates),
        )
        // List used to copy the people currently included before switching "Everyone" to "Individual".
        .route(
            "/admin/applications/{application_id}/current-users",
            get(admin_applications::current_users),
        )
        // The roster the RP's periodic reconciliation reads (ADR-0057 / ADR-0059). ⚠ **The RP does not name the target**
        // — returns the roster of the app the calling service account is bound to as an identity. No permission code
        // is required (`ManagementPrincipal`; 403 if there is no binding).
        .route(
            "/admin/applications/self/users",
            get(admin_applications::own_application_users),
        )
        // List of SSH keys read by the distributing machine (task #885). Requires idp.ssh-keys:read; machine clients only.
        .route("/admin/ssh-keys", get(admin_ssh_keys::list_ssh_keys))
        // Registers, suspends and deletes protected resources (audiences put in `aud`; ADR-0042). Requires idp.resources:*.
        .route(
            "/admin/resources",
            get(admin_resources::list_resources).post(admin_resources::register_resource),
        )
        .route(
            "/admin/resources/{resource_id}",
            patch(admin_resources::update_resource_status).delete(admin_resources::delete_resource),
        )
        // Authentication policy management (user authentication / auth policy spec §7). Requires idp.authentication-policies:*.
        .route(
            "/admin/authentication-policies",
            get(admin_authentication_policies::list_authentication_policies)
                .post(admin_authentication_policies::create_authentication_policy),
        )
        .route(
            "/admin/authentication-policies/{policy_id}",
            put(admin_authentication_policies::update_authentication_policy)
                .delete(admin_authentication_policies::delete_authentication_policy),
        )
        // External IdP settings (AP10). Requires idp.external-idps:read / :write. The client secret is write-only.
        .route(
            "/admin/external-idps",
            get(admin_external_idps::list_external_idps)
                .post(admin_external_idps::register_external_idp),
        )
        // External IdP metadata import (parse only, not persisted; AP12). Placed before `{id}` —
        // otherwise `import-metadata` would be parsed as an id and return 404.
        .route(
            "/admin/external-idps/import-metadata",
            post(admin_external_idps::import_external_idp_metadata),
        )
        // OIDC discovery document import (fetch and validate only, not persisted; task #77). Also before `{id}`.
        .route(
            "/admin/external-idps/import-discovery",
            post(admin_external_idps::import_external_idp_discovery),
        )
        .route(
            "/admin/external-idps/{id}",
            patch(admin_external_idps::update_external_idp)
                .delete(admin_external_idps::delete_external_idp),
        )
        // Audit log access (A3, design spec §7). Requires idp.audit:read.
        .route("/admin/audit-logs", get(admin_audit::list_audit_logs))
        // Error / warning log access (`log` table). Cross-tenant operational data, so requires idp.system.admin.
        .route(
            "/admin/logs",
            get(admin_application_logs::list_application_logs),
        )
        // SAML SP (client) registration. Requires idp.saml-service-providers:read / :write.
        .route(
            "/admin/saml-service-providers",
            get(admin_saml_service_providers::list).post(admin_saml_service_providers::register),
        )
        // SP metadata import (parse only, not persisted). Requires idp.saml-service-providers:write.
        .route(
            "/admin/saml-service-providers/import-metadata",
            post(admin_saml_service_providers::import_metadata),
        )
        // SP update and deletion. Requires idp.saml-service-providers:write.
        .route(
            "/admin/saml-service-providers/{id}",
            put(admin_saml_service_providers::update).delete(admin_saml_service_providers::delete),
        )
        // Signing key management API (K1). Requires idp.keys:read / idp.keys:write.
        .route(
            "/admin/signing-keys",
            get(admin_signing_keys::list_keys).post(admin_signing_keys::generate_key),
        )
        .route(
            "/admin/signing-keys/{kid}/retire",
            post(admin_signing_keys::retire_key),
        )
        .route(
            "/admin/signing-keys/{kid}",
            axum::routing::delete(admin_signing_keys::delete_key),
        )
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(discovery::jwks))
        // Endpoints called by the authenticator app (task #892, ADR-0077). The app holds no token and signs each operation with its key.
        .route(
            "/app-approver/enrollments",
            post(app_approver::start_enrollment),
        )
        .route(
            "/app-approver/enrollments/{id}/key",
            put(app_approver::submit_key),
        )
        .route(
            "/app-approver/enrollments/{id}/activate",
            post(app_approver::activate),
        )
        .route(
            "/app-approver/requests/{id}",
            get(app_approver::view_request),
        )
        .route(
            "/app-approver/requests/{id}/approve",
            post(app_approver::approve),
        )
        .route("/app-approver/requests/{id}/deny", post(app_approver::deny))
        .route("/app-approver/keys/{key_id}", get(app_approver::key_state))
        .route(
            "/app-approver/keys/{key_id}/revoke",
            post(app_approver::revoke),
        )
        // SAML IdP metadata output (public; the metadata an SP imports to trust assay).
        .route("/saml/metadata", get(discovery::saml_idp_metadata))
        // SAML SSO endpoint (the SingleSignOnService the metadata advertises; supports both Redirect and POST).
        .route(
            "/saml/sso",
            get(saml_sso::sso_redirect).post(saml_sso::sso_post),
        )
        // Attaches tenant resolution (UUID validation, existence / ACTIVE check) to all tenant routes (ADR-0009 §7).
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            resolve_tenant,
        ));

    // Paths outside tenants (no prefix; ADR-0009 §6): health checks, internal API, API docs.
    Router::new()
        .route("/healthz", get(health::liveness))
        // App Link for the authenticator app (task #892). assetlinks.json and the guide shown when opened in a browser.
        .route(
            "/.well-known/assetlinks.json",
            get(app_approver::asset_links),
        )
        .route("/app/approve", get(app_approver::app_link_fallback))
        .route("/app/enrolled", get(app_approver::app_link_fallback))
        .route("/readyz", get(health::readiness))
        .nest("/{tenant_id}", tenant_scoped)
        .merge(internal)
        // Swagger UI and OpenAPI document (SEC12). The api surface is public, so they are not served by default
        // (the spec of every endpoint, admin API included, would be readable without auth). Enable them in
        // dev / test environments with `API_DOCS_ENABLED=true`.
        .merge(if api_docs_enabled {
            SwaggerUi::new("/api/docs")
                .url("/api/openapi.json", ApiDoc::openapi())
                .into()
        } else {
            Router::new()
        })
        // CORS (G1). Attached with `layer`, not `route_layer`, because a preflight (OPTIONS) matches
        // no route and would be 405 — it is caught here and returned with CORS headers.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            cors::apply_cors,
        ))
        .layer(axum::middleware::from_fn(correlation::propagate))
        // Per-endpoint duration (G6). Placed outside `correlation::propagate` to measure
        // "entry to exit" including the correlation ID assignment.
        .layer(axum::middleware::from_fn(
            crate::presentation::metrics::track_http_metrics,
        ))
        // The access span records only the path (so `code` and `code_challenge` in the query string
        // never reach the logs; SEC9). The builder is shared with web.
        .layer(TraceLayer::new_for_http().make_span_with(assay_contracts::http_trace::request_span))
        .layer(middleware::from_fn(move |req, next| {
            add_security_headers(req, next, hsts_max_age)
        }))
        .with_state(state)
}
