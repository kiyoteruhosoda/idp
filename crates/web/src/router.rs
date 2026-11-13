//! Assembly of web's axum router (ADR-0009 §6, §10, MT13).
//!
//! Except for non-tenant paths (`/healthz`, `/readyz`), every screen URL is uniformly placed under
//! `/{tenant_id}/...` (no special branch even for root; same scheme as the api's router.rs).

use crate::client_ip::resolve_client_ip;
use crate::correlation;
use crate::display_preferences::resolve_display_preferences;
use crate::error_pages;
use crate::handlers::{
    account_setup, admin_accounts_console, admin_applications_console,
    admin_authentication_policies_console, admin_clients_console, admin_console,
    admin_external_idps_console, admin_invitations_console, admin_login_identifiers_console,
    admin_members_console, admin_resources_console, admin_restart_console,
    admin_saml_clients_console, admin_settings, admin_signing_keys_console, admin_status_console,
    admin_tenants_console, admin_users_console, app_approval, authenticators, consent,
    console_script, device_enrollment, external_login, health, invitation_accept, locale, login,
    mfa_totp, page_scripts, passkey, password_change, password_reset, portal, react_assets,
    rp_logout, saml_sso, step_up, stylesheet, submit_feedback_script, user_security, user_settings,
    vendor_assets, verify_email, web_app_manifest,
};
use crate::i18n::Messages;
use crate::login_context::load_rp_login_context;
use crate::security_headers::add_security_headers;
use crate::state::WebState;
use crate::templates::{render, MessagePage};
use crate::tenant::capture_tenant;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

pub fn build(state: WebState) -> Router {
    let hsts_max_age = state.config.hsts_max_age();
    let trust_forwarded = state.config.trust_forwarded_headers();
    let cookie_policy = state.config.cookie_policy().clone();
    let tenant_scoped = Router::new()
        .route("/login", get(login::login_page).post(login::login))
        // End-user portal TOTP input (the second step of the `/login` direct login path).
        .route("/login/mfa", get(portal::mfa_page).post(portal::mfa_submit))
        // "Continue in the app" (task #892, ADR-0077).
        // On-the-spot device registration when signing in correctly from an unregistered device (task #916).
        .route("/device-enrollment", get(device_enrollment::page))
        .route(
            "/device-enrollment/begin",
            post(device_enrollment::begin_api),
        )
        .route(
            "/device-enrollment/complete",
            post(device_enrollment::complete_api),
        )
        .route("/login/app/start", post(app_approval::start))
        .route("/login/app/complete", get(app_approval::complete))
        .route(
            "/settings/app-approver/confirm",
            get(app_approval::confirm_page).post(app_approval::confirm),
        )
        .route(
            "/settings/security/revoke-approver-key",
            post(app_approval::revoke_key),
        )
        // End-user portal forced password change (at first login. ADR-0009 §5. Reuses the same shared screen as the
        // admin console).
        .route(
            "/login/password-change",
            get(portal::password_change_page).post(portal::password_change),
        )
        // GET: OIDC RP-initiated Logout (end_session_endpoint. Moved from the api under ADR-0018 decision 2).
        // POST: end-user logout (from the account screen. Revokes SSO).
        .route("/logout", get(rp_logout::logout).post(portal::logout))
        // Endpoint pressed from the confirmation screen of sign-out requests without `id_token_hint` (task #588).
        .route("/logout/confirm", post(rp_logout::confirm))
        // SAML SSO continuation (receiving the hand-off from the api's /saml/sso and returning to the flow after login).
        .route("/saml/continue", get(saml_sso::continue_sso))
        // Forced password change (ADR-0009 §5, MT12). Used in the pending state after password authentication, before SSO issuance.
        .route(
            "/password-change",
            get(password_change::page).post(password_change::submit),
        )
        // Password reset (forgotten. MT18). Unauthenticated path (opened from the email link).
        .route(
            "/forgot-password",
            get(password_reset::forgot_page).post(password_reset::forgot_submit),
        )
        .route(
            // Landing point of the account setup link (ADR-0062). Unauthenticated path.
            "/account-setup",
            get(account_setup::setup_page).post(account_setup::set_password),
        )
        .route("/account-setup/done", get(account_setup::done_page))
        .route(
            "/account-setup/passkey/begin",
            post(account_setup::passkey_begin),
        )
        .route(
            "/account-setup/passkey/complete",
            post(account_setup::passkey_complete),
        )
        .route(
            "/password-reset",
            get(password_reset::reset_page).post(password_reset::reset_submit),
        )
        // Email verification screen (SEC6b). Opened from the self-registration confirmation email link. Unauthenticated (no SSO).
        .route(
            "/verify-email",
            get(verify_email::page).post(verify_email::submit),
        )
        // User self-service settings screen (MT15). Password change, language, MFA entry points. Requires SSO authentication.
        .route("/settings", get(user_settings::page))
        .route("/settings/password", post(user_settings::change_password))
        .route("/settings/name", post(user_settings::change_name))
        // The only path saving display settings (language, color scheme) to user settings (task #79. POST with CSRF).
        .route(
            "/settings/display",
            post(user_settings::save_display_preferences),
        )
        // External IdP login (AP10). Start is a 302; the callback is where the external IdP returns.
        .route("/external/{provider}/start", get(external_login::start))
        .route(
            "/external/{provider}/callback",
            get(external_login::callback),
        )
        // SAML ACS. The external IdP makes the browser POST, so GET is not accepted.
        .route(
            "/external/{provider}/saml/acs",
            post(external_login::saml_acs),
        )
        // "Send a code by email" from the MFA input screen (AP9).
        .route("/mfa/totp/email-code", post(mfa_totp::send_email_code))
        // SMS OTP send request (AP13). Same role as email OTP.
        .route("/mfa/totp/sms-code", post(mfa_totp::send_sms_code))
        // Authenticator management (list, suspend, revoke, issue recovery codes. AP9).
        .route("/settings/authenticators", get(authenticators::page))
        .route(
            "/settings/authenticators/phone",
            post(authenticators::start_phone_registration),
        )
        .route(
            "/settings/authenticators/phone/confirm",
            post(authenticators::confirm_phone_registration),
        )
        .route(
            "/settings/authenticators/status",
            post(authenticators::set_status),
        )
        .route(
            "/settings/recovery-codes",
            post(authenticators::issue_recovery_codes),
        )
        // Step-up re-verification screen (right before sensitive operations. AP5). Password (+TOTP) POST and
        // the two-step passkey JSON exchange (T38; goes through the browser's WebAuthn API, so it cannot be a form).
        .route("/settings/verify", get(step_up::page))
        .route("/settings/verify", post(step_up::verify))
        .route(
            "/settings/verify/passkey/begin",
            post(step_up::passkey_begin),
        )
        .route(
            "/settings/verify/passkey/complete",
            post(step_up::passkey_complete),
        )
        // Self-service security screen (session list/revocation, unlinking apps. G10).
        .route("/settings/security", get(user_security::page))
        // Registering/revoking devices (task #872).
        .route(
            "/settings/security/register-device",
            post(user_security::register_device),
        )
        .route(
            "/settings/security/revoke-device",
            post(user_security::revoke_device),
        )
        // Registering/revoking SSH public keys (task #885).
        .route(
            "/settings/security/register-ssh-key",
            post(user_security::register_ssh_key),
        )
        .route(
            "/settings/security/revoke-ssh-key",
            post(user_security::revoke_ssh_key),
        )
        .route(
            "/settings/security/revoke-session",
            post(user_security::revoke_session),
        )
        .route(
            "/settings/security/revoke-consent",
            post(user_security::revoke_consent),
        )
        .route(
            "/settings/security/reissue-tokens",
            post(user_security::reissue_tokens),
        )
        // Invitation acceptance screen (ADR-0009 §3, MT17). Opened from the invitation email link. Requires SSO authentication.
        .route(
            "/invitations/accept",
            get(invitation_accept::page).post(invitation_accept::submit),
        )
        // Consent screen (F3: Consent).
        .route(
            "/consent",
            get(consent::consent_page).post(consent::consent),
        )
        // MFA: login flow TOTP input (after password authentication).
        .route(
            "/mfa/totp",
            get(mfa_totp::verify_page).post(mfa_totp::verify),
        )
        // MFA: user self-enrollment (TOTP setup/deletion). Requires SSO authentication.
        .route(
            "/account/mfa/totp/setup",
            get(mfa_totp::setup_page).post(mfa_totp::setup_confirm),
        )
        .route("/account/mfa/totp/delete", post(mfa_totp::setup_delete))
        // Passkey (WebAuthn) self-registration. Requires SSO authentication.
        .route("/account/passkey", get(passkey::list_page))
        .route("/account/passkey/register", get(passkey::register_page))
        .route("/account/passkey/delete", post(passkey::delete))
        // Passkey registration JSON API (called from browser JS).
        .route("/passkey/register/begin", post(passkey::register_begin_api))
        .route(
            "/passkey/register/complete",
            post(passkey::register_complete_api),
        )
        // Passkey authentication JSON API (called from the JS of the 3 login screens). Two begin endpoints split by
        // "whether the authorization flow cookie is read", and 3 complete endpoints, one per screen, since issued cookies and destinations differ.
        .route("/passkey/login/begin", post(passkey::login_begin_api))
        .route("/passkey/login/complete", post(passkey::login_complete_api))
        .route(
            "/passkey/login/direct/begin",
            post(passkey::direct_login_begin_api),
        )
        .route(
            "/passkey/login/admin/complete",
            post(passkey::admin_login_complete_api),
        )
        .route(
            "/passkey/login/portal/complete",
            post(passkey::portal_login_complete_api),
        )
        // Admin console (ADR-0006 §6, ADR-0007 §4, ADR-0009 §10). Login needs no client.
        .route(
            "/admin/login",
            get(admin_console::login_page).post(admin_console::login),
        )
        .route(
            "/admin/password-change",
            get(admin_console::password_change_page).post(admin_console::password_change),
        )
        .route("/admin/logout", post(admin_console::logout))
        .route("/admin", get(admin_console::home))
        // Manifest for adding to the home screen (per tenant). ⚠ Placed outside authentication
        // (browsers fetch it without cookies. `handlers::web_app_manifest`).
        .route(
            "/admin/manifest.webmanifest",
            get(web_app_manifest::manifest),
        )
        // Tenant switching (move to a member tenant's admin console. ADR-0009 §8).
        .route("/admin/switch-tenant", get(admin_console::switch_tenant))
        // Settings screen (MT14). Tenant settings (idp.tenant.admin) + root-only system settings section (SMTP).
        .route("/admin/settings", get(admin_settings::page))
        // Authentication policies (AP1). List, create, edit, delete. HTML forms cannot send PUT/DELETE, so
        // updates and deletes go through dedicated POST paths converted to the api's PUT/DELETE.
        .route(
            "/admin/authentication-policies",
            get(admin_authentication_policies_console::list)
                .post(admin_authentication_policies_console::create),
        )
        .route(
            "/admin/authentication-policies/{policy_id}/update",
            post(admin_authentication_policies_console::update),
        )
        .route(
            "/admin/authentication-policies/{policy_id}/delete",
            post(admin_authentication_policies_console::delete),
        )
        // External IdP settings (AP16; the API is AP10). HTML forms cannot send PATCH/DELETE, so
        // updates and deletes go through dedicated POST paths converted to the api's PATCH/DELETE.
        .route(
            "/admin/external-idps",
            get(admin_external_idps_console::list).post(admin_external_idps_console::create),
        )
        // Registration starts by choosing the protocol. Putting OIDC and SAML fields on one form mixes
        // fields to fill with fields not needed, which is unreadable.
        .route(
            "/admin/external-idps/new",
            get(admin_external_idps_console::choose_protocol),
        )
        // A separate path per protocol. The routes express "these two can be registered", so misspelled
        // URLs become 404 (instead of silently falling back to the default protocol).
        .route(
            "/admin/external-idps/new/oidc",
            get(admin_external_idps_console::new_oidc_form),
        )
        .route(
            "/admin/external-idps/new/saml",
            get(admin_external_idps_console::new_saml_form),
        )
        .route(
            "/admin/external-idps/{id}/edit",
            get(admin_external_idps_console::edit_form),
        )
        // Importing external IdP metadata (AP12). A static path that does not collide with `{id}/update`.
        .route(
            "/admin/external-idps/import",
            post(admin_external_idps_console::import_metadata),
        )
        // Importing an OIDC discovery document (task #77). Likewise a static path.
        .route(
            "/admin/external-idps/import-discovery",
            post(admin_external_idps_console::import_discovery),
        )
        .route(
            "/admin/external-idps/{id}/update",
            post(admin_external_idps_console::update),
        )
        .route(
            "/admin/external-idps/{id}/delete",
            post(admin_external_idps_console::delete),
        )
        // Login identifiers (AP16; the API is AP8). Likewise updates and deletes go through dedicated POST paths.
        .route(
            "/admin/users/{user_id}/login-identifiers",
            get(admin_login_identifiers_console::list).post(admin_login_identifiers_console::add),
        )
        .route(
            "/admin/users/{user_id}/login-identifiers/{identifier_id}/active",
            post(admin_login_identifiers_console::set_active),
        )
        .route(
            "/admin/users/{user_id}/login-identifiers/{identifier_id}/delete",
            post(admin_login_identifiers_console::delete),
        )
        .route(
            "/admin/users/{user_id}/login-identifiers/{identifier_id}/primary-email",
            post(admin_login_identifiers_console::promote_primary_email),
        )
        .route(
            "/admin/settings/tenant",
            post(admin_settings::update_tenant),
        )
        // Tenant setting values (ADR-0058).
        .route(
            "/admin/settings/tenant/keys",
            post(admin_settings::update_tenant_setting),
        )
        .route(
            "/admin/settings/tenant/keys/clear",
            post(admin_settings::clear_tenant_setting),
        )
        // The tenant's own mail route (ADR-0058 §8).
        .route(
            "/admin/settings/smtp",
            post(admin_settings::update_tenant_smtp),
        )
        .route(
            "/admin/settings/smtp/clear",
            post(admin_settings::clear_tenant_smtp),
        )
        .route(
            "/admin/system-settings",
            post(admin_settings::update_system),
        )
        // DB overrides of runtime settings (root only. A restart is needed to apply).
        .route(
            "/admin/system-settings/runtime",
            post(admin_settings::update_runtime),
        )
        // api → web restart to apply saved runtime settings (root only. ADR-0017).
        .route("/admin/restart", post(admin_restart_console::restart))
        .route(
            "/admin/tenants",
            get(admin_tenants_console::list).post(admin_tenants_console::create),
        )
        // Child tenant editing (display name, status. MT23), deletion, admin password reissue (root only).
        .route(
            "/admin/tenants/{child_id}/update",
            post(admin_tenants_console::update),
        )
        .route(
            "/admin/tenants/{child_id}/delete",
            post(admin_tenants_console::delete),
        )
        .route(
            "/admin/tenants/{child_id}/reset-admin-password",
            post(admin_tenants_console::reset_admin_password),
        )
        // Client (RP) management screens. The static segment (new) takes priority over the dynamic {client_id}.
        .route("/admin/clients", get(admin_clients_console::list))
        // Service account (machine principal) registration (ADR-0038). The list and single-item screen are on the account side
        // (ADR-0065; `/admin/accounts` below). Edit, secret, permissions and delete share
        // `/admin/clients/{client_id}/*`.
        .route(
            "/admin/service-accounts/new",
            get(admin_clients_console::new_service_account_form)
                .post(admin_clients_console::create),
        )
        .route(
            "/admin/clients/new",
            get(admin_clients_console::new_form).post(admin_clients_console::create),
        )
        .route(
            "/admin/clients/{client_id}",
            get(admin_clients_console::detail),
        )
        .route(
            "/admin/clients/{client_id}/edit",
            get(admin_clients_console::edit_form).post(admin_clients_console::update),
        )
        // Granting/revoking admin permissions (ADR-0037). The section is on the details screen; this only receives execution
        // (returns to the details via Post/Redirect/Get).
        .route(
            "/admin/clients/{client_id}/permissions/grant",
            post(admin_clients_console::grant_permission),
        )
        .route(
            "/admin/clients/{client_id}/permissions/revoke",
            post(admin_clients_console::revoke_permission),
        )
        .route(
            "/admin/clients/{client_id}/rotate-secret",
            post(admin_clients_console::rotate_secret),
        )
        .route(
            "/admin/clients/{client_id}/delete",
            // Logical deletion (ADR-0035). POST from browsers (HTML forms cannot send DELETE).
            post(admin_clients_console::delete),
        )
        // SAML SP (client) list and add screens.
        .route(
            "/admin/saml-clients",
            get(admin_saml_clients_console::list).post(admin_saml_clients_console::create),
        )
        // SP metadata import (prefills the registration form).
        .route(
            "/admin/saml-clients/import",
            post(admin_saml_clients_console::import_metadata),
        )
        // Download IdP metadata from the web origin (do not expose a direct link to the api).
        .route(
            "/admin/saml-clients/idp-metadata",
            get(admin_saml_clients_console::download_idp_metadata),
        )
        // SP update/delete (dedicated paths since HTML forms only POST).
        .route(
            "/admin/saml-clients/{id}/update",
            post(admin_saml_clients_console::update),
        )
        .route(
            "/admin/saml-clients/{id}/delete",
            post(admin_saml_clients_console::delete),
        )
        // User creation and permission grant/revoke screens (listing and search start from the members screen, /admin/members).
        .route(
            "/admin/users/new",
            get(admin_users_console::new_form).post(admin_users_console::create),
        )
        .route(
            "/admin/users/{user_id}/permissions",
            get(admin_users_console::view),
        )
        // Profile (email, login identifier, display name) editing (MT25).
        .route(
            "/admin/users/{user_id}/profile",
            post(admin_users_console::update_profile),
        )
        .route(
            "/admin/users/{user_id}/permissions/grant",
            post(admin_users_console::grant),
        )
        .route(
            "/admin/users/{user_id}/permissions/revoke",
            post(admin_users_console::revoke),
        )
        // Member (HOME/GUEST) list and guest removal (ADR-0009 §3), and for users whose home (HOME) is this tenant,
        // disable, enable, password reissue and deletion (ADR-0009 §5).
        // Accounts (people and service accounts. ADR-0065). The two legacy lists redirect to this list filtered by kind.
        .route("/admin/accounts", get(admin_accounts_console::list))
        .route("/admin/members", get(admin_accounts_console::members_list))
        .route(
            "/admin/service-accounts",
            get(admin_accounts_console::service_accounts_list),
        )
        // Single service account screen (same skeleton as the person `/admin/members/{user_id}`), and its
        // admin note and adding/removing available apps.
        .route(
            "/admin/service-accounts/{client_id}",
            get(admin_accounts_console::service_account_detail),
        )
        .route(
            "/admin/service-accounts/{client_id}/note",
            post(admin_accounts_console::update_service_account_note),
        )
        .route(
            "/admin/service-accounts/{client_id}/applications/{application_id}/assign",
            post(admin_accounts_console::assign_service_account_application),
        )
        .route(
            "/admin/service-accounts/{client_id}/applications/{application_id}/unassign",
            post(admin_accounts_console::unassign_service_account_application),
        )
        // Single member screen (operations are gathered here; the list is the place to find).
        .route(
            "/admin/members/{user_id}",
            get(admin_members_console::detail),
        )
        .route(
            "/admin/members/{user_id}/revoke",
            post(admin_members_console::revoke),
        )
        .route(
            "/admin/members/{user_id}/status",
            post(admin_members_console::set_status),
        )
        .route(
            "/admin/members/{user_id}/reset-password",
            post(admin_members_console::reset_password),
        )
        .route(
            "/admin/members/{user_id}/reset-mfa",
            post(admin_members_console::reset_mfa),
        )
        .route(
            "/admin/members/{user_id}/unlock",
            post(admin_members_console::unlock),
        )
        // Reissuing issued tokens (the admin specifies the target. ADR-0047).
        .route(
            "/admin/members/{user_id}/reissue-tokens",
            post(admin_members_console::reissue_tokens),
        )
        // Suspending/resuming guest memberships (MT24). Unlike removal (deletion), it can be undone.
        .route(
            "/admin/members/{user_id}/suspend",
            post(admin_members_console::suspend),
        )
        .route(
            "/admin/members/{user_id}/resume",
            post(admin_members_console::resume),
        )
        .route(
            "/admin/members/{user_id}/delete",
            post(admin_members_console::delete),
        )
        // Admin note (ADR-0063) and the person's app assignments (calls the same API as the app details).
        .route(
            "/admin/members/{user_id}/note",
            post(admin_members_console::update_note),
        )
        .route(
            "/admin/members/{user_id}/applications/{application_id}/assign",
            post(admin_members_console::assign_application),
        )
        .route(
            "/admin/members/{user_id}/applications/{application_id}/unassign",
            post(admin_members_console::unassign_application),
        )
        // Creating guest invitations (ADR-0009 §3).
        .route(
            "/admin/invitations",
            get(admin_invitations_console::new_form).post(admin_invitations_console::create),
        )
        // Status screens (audit log, client status). Read-only.
        .route("/admin/audit-logs", get(admin_status_console::audit_logs))
        // Error/warning logs (`log` table). The api requires idp.system.admin.
        .route("/admin/logs", get(admin_status_console::application_logs))
        .route("/admin/status", get(admin_status_console::client_status))
        // The running build and applied schema (ADR-0034). Not exposed on an unauthenticated surface.
        .route("/admin/version", get(admin_status_console::version))
        // Only the running build's label (endpoint for open screens to notice a new version).
        .route(
            "/admin/version/current",
            get(admin_status_console::current_build),
        )
        // Apps (ADR-0054). Authentication methods (OIDC / SAML) and user assignments hang off this level.
        // ⚠ **This is the recovery path for lockouts** (step 4 of decision 4). List → item → assignment, and done.
        .route("/admin/applications", get(admin_applications_console::list))
        .route(
            "/admin/applications/create",
            post(admin_applications_console::create),
        )
        .route(
            "/admin/applications/{application_id}",
            get(admin_applications_console::detail),
        )
        .route(
            "/admin/applications/{application_id}/update",
            post(admin_applications_console::update),
        )
        .route(
            "/admin/applications/{application_id}/bind",
            post(admin_applications_console::bind),
        )
        .route(
            "/admin/applications/{application_id}/unbind",
            post(admin_applications_console::unbind),
        )
        .route(
            "/admin/applications/{application_id}/delete",
            post(admin_applications_console::delete),
        )
        .route(
            "/admin/applications/{application_id}/assign",
            post(admin_applications_console::assign),
        )
        .route(
            "/admin/applications/{application_id}/unassign",
            post(admin_applications_console::unassign),
        )
        // Protected resources (names that go into `aud`. ADR-0042). Lending is in the client details.
        .route("/admin/resources", get(admin_resources_console::list))
        .route(
            "/admin/resources/register",
            post(admin_resources_console::register),
        )
        .route(
            "/admin/resources/status",
            post(admin_resources_console::set_status),
        )
        .route(
            "/admin/resources/delete",
            post(admin_resources_console::delete),
        )
        // Signing key management screen (K1).
        .route("/admin/signing-keys", get(admin_signing_keys_console::list))
        .route(
            "/admin/signing-keys/generate",
            post(admin_signing_keys_console::generate),
        )
        .route(
            "/admin/signing-keys/retire",
            post(admin_signing_keys_console::retire),
        )
        .route(
            "/admin/signing-keys/delete",
            post(admin_signing_keys_console::delete),
        )
        // Deciding the display language (MT20) happens inside tenant resolution. The priority of `?lang=` / user setting / cookie /
        // `ui_locales` / browser language is unified here, and each handler just calls
        // `handlers::locale`.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            resolve_display_preferences,
        ))
        // Re-fetching the context an authorization request brings (`login_hint` / `ui_locales`. G12). The language decision
        // reads `ui_locales`, so it sits outside (= runs before) `resolve_display_preferences`.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            load_rp_login_context,
        ))
        .route_layer(axum::middleware::from_fn(capture_tenant));

    Router::new()
        .route("/", get(root_entrypoint))
        .route("/healthz", get(health::liveness))
        .route("/readyz", get(health::readiness))
        // Detailed health (ADR-0031). Returns version, uptime, server time and reachability of the api.
        // The public surface (`/healthz`, `/readyz`) goes only as far as the service name; details are behind the service token.
        .merge(
            Router::new()
                .route("/internal/health", get(health::internal_health))
                .route_layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    crate::internal_auth::require_service_token,
                )),
        )
        .route("/assets/app.css", get(stylesheet::app_css))
        .route("/assets/assay.svg", get(stylesheet::assay_svg))
        .route(
            "/assets/icons/assay-192.png",
            get(stylesheet::assay_192_png),
        )
        .route(
            "/assets/icons/assay-512.png",
            get(stylesheet::assay_512_png),
        )
        .route(
            "/assets/icons/assay-maskable-512.png",
            get(stylesheet::assay_maskable_512_png),
        )
        .route("/assets/console.js", get(console_script::console_js))
        .route(
            "/assets/button-pending.js",
            get(submit_feedback_script::button_pending_js),
        )
        .route("/assets/theme.js", get(submit_feedback_script::theme_js))
        .route(
            "/assets/submit-feedback.js",
            get(submit_feedback_script::submit_feedback_js),
        )
        // Screen-specific scripts (former inline scripts. SEC12).
        .route(
            "/assets/passkey-login.js",
            get(page_scripts::passkey_login_js),
        )
        .route(
            "/assets/app-approval-login.js",
            get(page_scripts::app_approval_login_js),
        )
        .route(
            "/assets/passkey-register.js",
            get(page_scripts::passkey_register_js),
        )
        .route(
            "/assets/account-setup.js",
            get(page_scripts::account_setup_js),
        )
        .route("/assets/share-link.js", get(page_scripts::share_link_js))
        .route(
            "/assets/password-visibility.js",
            get(page_scripts::password_visibility_js),
        )
        .route("/assets/rp-logout.js", get(page_scripts::rp_logout_js))
        .route("/assets/auto-submit.js", get(page_scripts::auto_submit_js))
        .route("/assets/client-form.js", get(page_scripts::client_form_js))
        .route("/assets/local-time.js", get(page_scripts::local_time_js))
        .route("/assets/list-filter.js", get(page_scripts::list_filter_js))
        .route("/assets/live-search.js", get(page_scripts::live_search_js))
        .route(
            "/assets/vendor/bootstrap.min.css",
            get(vendor_assets::bootstrap_css),
        )
        .route(
            "/assets/vendor/bootstrap.bundle.min.js",
            get(vendor_assets::bootstrap_js),
        )
        .route(
            "/assets/vendor/fontawesome/css/all.min.css",
            get(vendor_assets::fontawesome_css),
        )
        .route(
            "/assets/vendor/fontawesome/webfonts/fa-solid-900.woff2",
            get(vendor_assets::fa_solid_woff2),
        )
        .route(
            "/assets/vendor/fontawesome/webfonts/fa-regular-400.woff2",
            get(vendor_assets::fa_regular_woff2),
        )
        .route(
            "/assets/vendor/fontawesome/webfonts/fa-brands-400.woff2",
            get(vendor_assets::fa_brands_woff2),
        )
        .route(
            "/assets/vendor/fontawesome/webfonts/fa-v4compatibility.woff2",
            get(vendor_assets::fa_v4compatibility_woff2),
        )
        .route("/assets/react/app.js", get(react_assets::app_js))
        // Binding SSO sessions to the device key (Chrome's DBSC. task #887, ADR-0074). Not tenant-scoped
        // (there is one SSO session cookie per origin).
        .route("/dbsc/register", post(crate::session_key::register))
        .route("/dbsc/refresh", post(crate::session_key::refresh))
        // Routes under this nest with `{user_id}` etc. have two path parameters together with the
        // nesting `{tenant_id}`. Handlers must receive them as a `Path<(String, String)>` tuple
        // (`Path<String>` gives a runtime 500 "Wrong number of path arguments").
        .nest("/{tenant_id}", tenant_scoped)
        // Requests matching no route get the 404 error page (avoids axum's default empty response).
        .fallback(error_pages::fallback)
        // Tell the api which device signed in (task #872). Whatever the login path, only whether the response set the SSO
        // session cookie is looked at. Placed inside the tracking key (correlation) and client IP.
        // For SSO sessions bound to the device key, the long cookie is removed without a matching short cookie (task #887).
        // Placed inside the cookie name mapping (looks at mapped names) and inside the tracking key.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::session_key::enforce,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::device_observation::observe_sign_ins,
        ))
        // Keep the current request's trustworthy country only for the request so it can be attached to internal api calls (task #895).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::client_country::scope_client_country,
        ))
        .layer(axum::middleware::from_fn(correlation::propagate))
        // Mapping session cookie names (over HTTPS only `__Host-` prefixed ones are read. task #583).
        // Placed outside the routes so it runs before any handler or route_layer.
        .layer(axum::middleware::from_fn(move |req, next| {
            crate::cookies::bind_session_cookie_names(cookie_policy.clone(), req, next)
        }))
        // Deciding the client IP (SEC1). Whether to trust `X-Forwarded-For` is gated by the same setting key as the api;
        // when untrusted it falls back to the TCP peer. Handlers receive only the result via `Extension<ClientIp>`.
        .layer(axum::middleware::from_fn(move |req, next| {
            resolve_client_ip(trust_forwarded, req, next)
        }))
        // Make the bodies of all error responses (4xx / 5xx) the shared error page. Responses returned by handlers without a body,
        // extractor rejections and method mismatches (405) are also turned into HTML here (see the `error_pages` module
        // documentation). Placing it outside routing covers unmatched and rejected paths too.
        .layer(axum::middleware::from_fn(error_pages::render_error_pages))
        // The access span records only the path (do not drop single-use handles like `?auth_session=` in the query string
        // into logs. SEC9). The building is shared with the api.
        .layer(TraceLayer::new_for_http().make_span_with(assay_contracts::http_trace::request_span))
        .layer(axum::middleware::from_fn(move |req, next| {
            add_security_headers(req, next, hsts_max_age)
        }))
        .with_state(state)
}

/// Landing for the root (no tenant specified).
///
/// It used to redirect to `/{root_tenant_id}/admin/login`, which exposed the root tenant's UUID and the admin login
/// screen just by accessing the bare domain, a possible starting point for attacks on root.
/// To avoid revealing tenants, the redirect was removed and a generic guidance page not touching any specific tenant is
/// rendered (legitimate users access via the `/{tenant_id}/...` URL given by their admin).
async fn root_entrypoint(headers: HeaderMap) -> impl IntoResponse {
    let messages = Messages::new(locale(&headers));
    (
        StatusCode::NOT_FOUND,
        Html(render(&MessagePage {
            lang: messages.lang(),
            title: messages.get("root-landing-title"),
            message: messages.get("root-landing-message"),
        })),
    )
}

/// Collects the paths `build` declared in `route`, with parameter names collapsed (`/admin/users/{}`).
///
/// It reads its own source because axum's `Router` does not expose registered paths. This keeps checks needing the route
/// list (template link targets, reverse proxy routing) from diverging from a separate list updated by hand
/// whenever routes are added.
#[cfg(test)]
pub(crate) fn declared_route_paths() -> std::collections::HashSet<String> {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/router.rs"))
        .expect("read router.rs");
    // Below this function (test-only code) there are path strings that are not routes, so cut them off.
    // Comment lines are also dropped (so example `route`s written as explanations are not counted as real routes).
    let source: String = source
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut paths = std::collections::HashSet::new();
    for after in source.split(".route(").skip(1) {
        let Some(open) = after.find('"') else {
            continue;
        };
        let Some(len) = after[open + 1..].find('"') else {
            continue;
        };
        paths.insert(collapse_params(&after[open + 1..open + 1 + len]));
    }
    paths
}

/// Collapses parameters like `{{ expr }}` (Askama) and `{param}` (axum routes) into `{}`.
/// Discards everything up to the closing symbol at once so consecutive opening symbols `{{` count as one parameter.
#[cfg(test)]
pub(crate) fn collapse_params(raw: &str) -> String {
    let mut out = String::new();
    let mut rest = raw;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        out.push_str("{}");
        // Skip consecutive closing symbols like `}}`.
        rest = rest[start + end..].trim_start_matches('}');
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    /// The reverse proxy in the single-origin setup (`PUBLISH_TOPOLOGY=single-origin`) routes to web or the api
    /// by path. If a web screen path is not listed in `docker/nginx.conf`, it flows to the api via the catch-all
    /// and becomes 404 (the route exists in web but is never reached; the same mix-up of path and service as
    /// web-origin-relative links not reaching api paths in the domain-split setup).
    ///
    /// Regular expressions are not evaluated. It only checks that **the screen's first segment appears in the config**,
    /// detecting regressions where a route was added but its routing forgotten.
    #[test]
    fn single_origin_proxy_routes_every_web_page_to_web() {
        let conf = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docker/nginx.conf"
        ))
        .expect("read docker/nginx.conf");
        // Only `location` block declaration lines are considered (merely mentioning it in a comment does not route).
        let locations: String = conf
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("location"))
            .collect::<Vec<_>>()
            .join("\n");
        // Non-tenant paths are excluded. `/` and `/assets/...` have dedicated locations in the proxy, and
        // `/healthz` and `/readyz` also exist as api routes, so the api may answer via the catch-all.
        // `/internal/health` correctly **must not be reachable from outside** (blocked by `location /internal/ { return 404; }`;
        // ADR-0031 decision 2). Not flowing to web is as expected, so it is excluded.
        let non_tenant = ["/", "/healthz", "/readyz", "/internal/health"];
        let mut checked = 0;
        for route in declared_route_paths() {
            if non_tenant.contains(&route.as_str()) || route.starts_with("/assets/") {
                continue;
            }
            let Some(segment) = route.trim_start_matches('/').split('/').next() else {
                continue;
            };
            checked += 1;
            assert!(
                locations.contains(segment),
                "route `{route}` is served by web but `{segment}` does not appear in any \
                 location of docker/nginx.conf; in the single-origin setup it flows to the api and becomes 404"
            );
        }
        assert!(checked > 0, "expected routes to check");
    }

    /// ADR-0031 decision 1: with only a 200, "which service answered" could not be told.
    #[tokio::test]
    async fn liveness_names_the_service_that_answered() {
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["service"], "web");
    }

    /// ADR-0031 decision 2: details are exposed only behind the internal token.
    #[tokio::test]
    async fn the_detailed_health_is_not_readable_without_the_service_token() {
        for header in [None, Some("wrong-token")] {
            let mut request = Request::builder().uri("/internal/health");
            if let Some(token) = header {
                request =
                    request.header(assay_contracts::internal_auth::SERVICE_TOKEN_HEADER, token);
            }
            let response = build(test_state())
                .oneshot(request.body(Body::empty()).expect("request"))
                .await
                .expect("response");
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "detailed health must not be readable with token={header:?}"
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            assert!(
                !String::from_utf8_lossy(&body).contains("git_version"),
                "the rejection response must not carry build info"
            );
        }
    }

    /// With the token, version, uptime, server time and dependency check results are returned.
    #[tokio::test]
    async fn the_detailed_health_reports_the_service_state() {
        let state = test_state();
        let token = state.config.internal_service_token().to_string();
        let response = build(state)
            .oneshot(
                Request::builder()
                    .uri("/internal/health")
                    .header(assay_contracts::internal_auth::SERVICE_TOKEN_HEADER, token)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["service"], "web");
        assert!(json["version"]["git_version"].is_string());
        assert!(json["started_at"].is_string());
        assert!(json["server_time"].is_string());
        assert!(json["uptime_seconds"].is_number());
        // The only dependency web checks is the api (there is no api in tests, so it is a fail).
        assert_eq!(json["checks"][0]["name"], "api");
        assert_eq!(json["status"], json["checks"][0]["status"]);
    }

    fn test_state() -> WebState {
        WebState::build(Arc::new(
            crate::config::Config::from_env().expect("config with dev defaults"),
        ))
    }

    /// Regression test that the root `/` does not redirect but returns a guidance page (404) and the response never contains
    /// the root tenant's UUID (bare domain access must not expose root).
    #[tokio::test]
    async fn root_does_not_redirect_or_leak_tenant() {
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // No redirect (no Location header).
        assert!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .is_none(),
            "root must not redirect"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        // Do not embed a UUID (`/{tenant_id}/...`) in the body.
        assert!(
            !text.contains("/admin/login"),
            "root page must not expose an admin login link"
        );
        let uuid_re_hits = text
            .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
            .any(|tok| uuid::Uuid::parse_str(tok).is_ok());
        assert!(!uuid_re_hits, "root page must not embed any tenant UUID");
    }

    /// Regression test that a URL matching no route returns the 404 error page (with an HTML body) (not axum's
    /// default empty response).
    #[tokio::test]
    async fn unmatched_route_returns_404_error_page() {
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri("/no/such/path")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        // An error page containing the status code and description is rendered.
        assert!(text.contains("404"), "error page must show the status code");
        assert!(
            text.contains("<!DOCTYPE html>"),
            "fallback must render the full error page, not an empty body"
        );
    }

    /// Regression test that the error page middleware works on the real router too (405 for a method mismatch, and
    /// no exposure of extractor rejection internal messages). Turning error responses into HTML is centralized in
    /// `error_pages`, so this only checks it is wired up.
    #[tokio::test]
    async fn error_responses_are_rendered_as_pages_by_the_router() {
        // POST to a GET-only route (405).
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("405"), "error page must show the status code");
        assert!(text.contains("<!DOCTYPE html>"));

        // Form extraction rejections must not expose axum's default plain text (internal details).
        let tenant = "019f6514-08ea-7138-ad71-838a7bdd3575";
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{tenant}/login"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(response.status().is_client_error());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("Failed to deserialize"),
            "internal rejection message must not leak: {text}"
        );
        assert!(text.contains("<!DOCTYPE html>"));
    }

    /// MT20: the middleware decides the display language, and `?lang=` works on **every screen**.
    ///
    /// Verified on the signed-out login screen (a screen renderable without calling the api). A request with `?lang=`
    /// (1) is rendered in the given language and (2) saves the `lang` cookie (a temporary switch;
    /// not written to user settings — task #79).
    /// Previously screens differed in whether they interpreted `?lang=` (only the settings screen did).
    #[tokio::test]
    async fn language_query_applies_to_every_page_and_is_kept_in_the_cookie() {
        let tenant = "019f6514-08ea-7138-ad71-838a7bdd3575";
        let english = Messages::new(crate::i18n::Locale::En).get("login-title");
        let japanese = Messages::new(crate::i18n::Locale::Ja).get("login-title");

        for (uri, expected, expect_cookie) in [
            // `?lang=` has top priority (stronger than Accept-Language).
            (format!("/{tenant}/admin/login?lang=en"), &english, true),
            (format!("/{tenant}/login?lang=en"), &english, true),
            // Unsupported values are ignored and fall to the next priority (here no Accept-Language, so the default ja).
            (format!("/{tenant}/admin/login?lang=fr"), &japanese, false),
            // Without `?lang=`, the default ja. The cookie is not rewritten either.
            (format!("/{tenant}/admin/login"), &japanese, false),
        ] {
            let response = build(test_state())
                .oneshot(
                    Request::builder()
                        .uri(&uri)
                        .header("accept-language", "ja")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let cookies: Vec<String> = response
                .headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(str::to_string)
                .collect();
            let saved = cookies.iter().any(|c| c.starts_with("lang="));
            assert_eq!(saved, expect_cookie, "uri={uri} cookies={cookies:?}");

            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let text = String::from_utf8_lossy(&body);
            assert!(text.contains(expected.as_str()), "uri={uri}: {text}");
        }
    }

    /// Without `?lang=` the `lang` cookie applies, and without it, it falls back to the browser language.
    #[tokio::test]
    async fn language_falls_back_to_the_cookie_then_the_browser() {
        let tenant = "019f6514-08ea-7138-ad71-838a7bdd3575";
        let english = Messages::new(crate::i18n::Locale::En).get("login-title");
        let uri = format!("/{tenant}/admin/login");

        // The cookie takes priority over the browser language.
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header(axum::http::header::COOKIE, "lang=en")
                    .header("accept-language", "ja")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(String::from_utf8_lossy(&body).contains(english.as_str()));

        // Without the cookie, the browser language.
        let response = build(test_state())
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("accept-language", "en-US,en;q=0.9")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(String::from_utf8_lossy(&body).contains(english.as_str()));
    }

    /// Regression test that `Path` extraction works for two-parameter routes under the nest, `{tenant_id}` + `{user_id}` etc.
    /// A mismatched extraction makes axum return 500 ("Wrong number of path arguments").
    /// Here a body-less POST is expected to stop at the `Form` extraction failure (4xx), and
    /// reaching the API is unnecessary (no network dependency).
    #[tokio::test]
    async fn nested_two_param_routes_extract_path_without_error() {
        let tenant = "019f6514-08ea-7138-ad71-838a7bdd3575";
        let id = "019f7576-b5b8-73f2-a496-0df7a83c667f";
        let post_uris = [
            format!("/{tenant}/admin/members/{id}/revoke"),
            format!("/{tenant}/admin/members/{id}/status"),
            format!("/{tenant}/admin/members/{id}/reset-password"),
            format!("/{tenant}/admin/members/{id}/reset-mfa"),
            format!("/{tenant}/admin/members/{id}/reissue-tokens"),
            format!("/{tenant}/admin/members/{id}/suspend"),
            format!("/{tenant}/admin/members/{id}/resume"),
            format!("/{tenant}/admin/members/{id}/delete"),
            format!("/{tenant}/admin/users/{id}/profile"),
            format!("/{tenant}/admin/users/{id}/permissions/grant"),
            format!("/{tenant}/admin/users/{id}/permissions/revoke"),
            format!("/{tenant}/admin/clients/{id}/edit"),
            format!("/{tenant}/admin/clients/{id}/rotate-secret"),
            format!("/{tenant}/admin/tenants/{id}/update"),
            format!("/{tenant}/admin/tenants/{id}/delete"),
            format!("/{tenant}/admin/tenants/{id}/reset-admin-password"),
            format!("/{tenant}/admin/saml-clients/{id}/update"),
            format!("/{tenant}/admin/saml-clients/{id}/delete"),
        ];
        for uri in post_uris {
            let response = build(test_state())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(&uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_ne!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "path extraction failed for {uri}"
            );
            assert!(
                response.status().is_client_error(),
                "unexpected status for {uri}"
            );
        }
    }
}
