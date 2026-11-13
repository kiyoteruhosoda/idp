//! Form DTOs received by web.

use serde::Deserialize;

/// Login form (`POST /login`). The login identifier is the username (`preferred_username`. ADR-0009 §8).
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

/// Query of the SAML SSO continuation screen (`GET /saml/continue`).
#[derive(Debug, Deserialize)]
pub struct SamlContinueQuery {
    /// Single-use, short-lived handle the api's `/saml/sso` put in the hand-off URL. web immediately
    /// exchanges it via `/internal/saml/resume` (same scheme as ADR-0018 decision 2).
    #[serde(default)]
    pub handle: Option<String>,
}

/// Query of the login screen (`GET /login`).
#[derive(Debug, Deserialize)]
pub struct LoginPageQuery {
    /// Single-use, short-lived handle the api's `/authorize` put in the hand-off URL (ADR-0018 decision 2).
    /// web immediately exchanges it via `/internal/authorize/resume` and removes it from the URL with a 303.
    #[serde(default)]
    pub auth_session: Option<String>,
    /// Error kind when returning via PRG from a failed POST (CSRF mismatch etc.) (`csrf` only).
    /// Shows an error banner on the form re-rendered with a new token.
    #[serde(default)]
    pub error: Option<String>,
}

/// PRG return query shared by form pages (`?error=csrf`). Used to show an error banner on the form re-rendered with a new
/// token when a POST with a CSRF mismatch is sent back to GET with 303.
#[derive(Debug, Default, Deserialize)]
pub struct FormPageQuery {
    #[serde(default)]
    pub error: Option<String>,
}

/// Query of RP-initiated Logout (`GET /logout`, OIDC RP-Initiated Logout 1.0. ADR-0018 decision 2).
#[derive(Debug, Deserialize)]
pub struct RpLogoutQuery {
    /// CSRF synchronizer token carried by the POST from the confirmation screen (requests without `id_token_hint`. task #588).
    #[serde(default)]
    pub csrf_token: Option<String>,
    /// ID Token indicating whom to log out (optional. G12). The api verifies signature/issuer and uses it
    /// to match `post_logout_redirect_uri` and to confirm "whose logout it is".
    #[serde(default)]
    pub id_token_hint: Option<String>,
    /// Redirect destination after logout (the api allows only registered ones).
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
    /// Random value received by the RP (passed through onto the redirect_uri).
    #[serde(default)]
    pub state: Option<String>,
    /// Used to validate post_logout_redirect_uri (optional).
    #[serde(default)]
    pub client_id: Option<String>,
}

/// TOTP confirmation form (`POST /account/mfa/totp/setup`).
#[derive(Debug, Deserialize)]
pub struct TotpConfirmForm {
    /// 6-digit code entered from the authenticator app.
    pub code: String,
    /// CSRF synchronizer token (`console_csrf_token`. task #118). If missing it is not a 422 but treated as empty
    /// in verification (nothing saved, same as a mismatch).
    #[serde(default)]
    pub csrf_token: String,
}

/// TOTP deletion form (`POST /account/mfa/totp/delete`).
#[derive(Debug, Deserialize)]
pub struct TotpDeleteForm {
    /// CSRF synchronizer token (`console_csrf_token`. task #118). If missing it is not a 422 but treated as empty
    /// in verification (nothing saved, same as a mismatch).
    #[serde(default)]
    pub csrf_token: String,
}

/// Logout form (account settings' `POST /{tenant_id}/logout` and the admin console's
/// `POST /{tenant_id}/admin/logout`). Logout from an RP (`GET /logout`) does not use this.
#[derive(Debug, Default, Deserialize)]
pub struct LogoutForm {
    /// CSRF synchronizer token (`console_csrf_token`. task #143). If missing it is not a 422 but treated as empty
    /// in verification (no logout, same as a mismatch).
    #[serde(default)]
    pub csrf_token: String,
    /// Whether account settings were opened from the admin console (`admin`). When returning to the settings screen due to
    /// a token mismatch, the back link context is kept (same as other settings forms).
    #[serde(default)]
    pub from: Option<String>,
}

/// Portal TOTP input form (`POST /{tenant_id}/login/mfa`).
#[derive(Debug, Deserialize)]
pub struct PortalTotpForm {
    pub totp_code: String,
    pub csrf_token: String,
}

/// Consent form (`POST /consent`, F3).
#[derive(Debug, Deserialize)]
pub struct ConsentForm {
    pub auth_session_id: String,
    pub csrf_token: String,
    /// `approve` or `deny`.
    pub action: String,
}

/// Forced password change form (`POST /password-change`, ADR-0009 §5). Assumes the login flow's
/// `auth_session_id` (password verified, SSO not yet issued).
#[derive(Debug, Deserialize)]
pub struct PasswordChangeForm {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
    pub csrf_token: String,
}

/// Forced password change form (at first login. ADR-0009 §5). Shared by the admin console login
/// (`POST /admin/password-change`) and the portal (general) login (`POST /login/password-change`).
/// Neither has temporary state like `auth_session_id`, so everything including `username` (login identifier)
/// is resent in full and the api re-verifies including the current password.
#[derive(Debug, Deserialize)]
pub struct ForcedPasswordChangeForm {
    pub username: String,
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
    pub csrf_token: String,
}

/// Tenant display name form on the settings screen (`POST /{tenant_id}/admin/settings/tenant`. MT14).
#[derive(Debug, Deserialize)]
pub struct AdminTenantSettingsForm {
    pub name: String,
    /// Self-registration toggle (SEC6). A checkbox is sent only when checked (`Some(_)` = enabled).
    #[serde(default)]
    pub self_registration_enabled: Option<String>,
    /// Toggle for login by email (ADR-0050). Likewise sent only when checked.
    #[serde(default)]
    pub email_login_enabled: Option<String>,
    pub csrf_token: String,
}

/// System settings (SMTP) form on the settings screen (`POST /{tenant_id}/admin/system-settings`. MT14).
/// `smtp_port` is received as a string; `smtp_use_tls` is a checkbox (sent only when checked).
/// If `smtp_password` is an empty string the current password is kept (not changed).
#[derive(Debug, Deserialize)]
pub struct AdminSystemSettingsForm {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: String,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: Option<String>,
    /// SMS gateway (AP13). If `sms_auth_token` is an empty string the current token is kept.
    #[serde(default)]
    pub sms_gateway_url: String,
    #[serde(default)]
    pub sms_auth_header: String,
    #[serde(default)]
    pub sms_auth_token: String,
    #[serde(default)]
    pub sms_sender_id: String,
    pub csrf_token: String,
}

/// Self-service password change form (`POST /{tenant_id}/settings/password`. MT15).
/// `from` carries over the context of having opened it from the admin console (`admin` keeps the back path after PRG).
#[derive(Debug, Deserialize)]
pub struct AccountPasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
    #[serde(default)]
    pub from: Option<String>,
    /// CSRF synchronizer token (`console_csrf_token`. task #118). If missing it is not a 422 but treated as empty
    /// in verification (nothing saved, same as a mismatch; reported with a banner on the settings screen).
    #[serde(default)]
    pub csrf_token: String,
}

/// Self-service display name change form (`POST /{tenant_id}/settings/name`).
/// `from` carries over the context of having opened it from the admin console (keeps the back path after PRG).
#[derive(Debug, Deserialize)]
pub struct AccountNameForm {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    /// CSRF synchronizer token (`console_csrf_token`. task #118). If missing it is not a 422 but treated as empty
    /// in verification (nothing saved, same as a mismatch; reported with a banner on the settings screen).
    #[serde(default)]
    pub csrf_token: String,
}

/// Form saving display settings (language, color scheme) (`POST /{tenant_id}/settings/display`. task #79).
///
/// Sent by the settings screen's language/color scheme choices and the admin console header's language dropdown. GET
/// `?lang=` / `?theme=` are temporary switches; only this POST writes to user settings (DB).
/// Either `lang` or `theme` alone is fine (only what is sent is saved).
#[derive(Debug, Deserialize)]
pub struct DisplayPreferencesForm {
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub theme: Option<String>,
    /// Screen to return to after saving (only paths under this tenant are accepted; otherwise the settings screen).
    #[serde(default)]
    pub return_to: Option<String>,
    /// Context of the settings screen opened from the admin console (kept when returning to the settings screen on a CSRF mismatch etc.).
    #[serde(default)]
    pub from: Option<String>,
    /// CSRF synchronizer token (`console_csrf_token`. task #118). If missing it is not a 422 but treated as empty
    /// in verification (nothing saved, same as a mismatch; reported with a banner on the settings screen).
    #[serde(default)]
    pub csrf_token: String,
}

/// GET query of the settings screen (temporary language/color scheme switches, saved/error banners, carrying over the origin).
#[derive(Debug, Default, Deserialize)]
pub struct SettingsQuery {
    #[serde(default)]
    pub lang: Option<String>,
    /// Temporary color scheme switch (`?theme=`). **This screen also reads it itself to render the selector's selection**
    /// (the cookie is rewritten in the response, so only the old value is at hand in this request.
    /// Without reading it, the screen is dark while the selector points to the saved value). Not saved (task #79).
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub saved: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// Origin of navigation (`admin` = admin console; shows a back link in the top left).
    #[serde(default)]
    pub from: Option<String>,
    /// Settings filter: text (key, display name, description).
    #[serde(default)]
    pub q: Option<String>,
    /// Settings filter: only what this tenant decided (enabled if any value is present).
    #[serde(default)]
    pub mine: Option<String>,
    /// Settings filter: kind of global runtime setting (`tenant` / `action` / `pending`).
    #[serde(default)]
    pub runtime: Option<String>,
}

/// Tenant registration form (`POST /{tenant_id}/admin/tenants`. root / `idp.system.admin` only).
/// The creator becomes the new tenant's bootstrap admin, so no initial admin email is taken (ADR-0009 §4).
#[derive(Debug, Deserialize)]
pub struct AdminTenantCreateForm {
    pub name: String,
    pub csrf_token: String,
}

/// GET query of the tenant management screen.
#[derive(Debug, Default, Deserialize)]
pub struct TenantsQuery {
    #[serde(default)]
    pub error: Option<String>,
    /// Update completion notice (shows a success banner when returning via Post/Redirect/Get).
    #[serde(default)]
    pub saved: Option<String>,
    /// Number of items the pager skips. Unspecified is 0 (G7).
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Child tenant edit form (`POST /{tenant_id}/admin/tenants/{child_id}/update`. MT23).
/// Changes the display name and status (`ACTIVE` / `DISABLED`). Delegated to the api's `PATCH /admin/tenants/{child_id}`.
#[derive(Debug, Deserialize)]
pub struct AdminTenantUpdateForm {
    pub name: String,
    pub status: String,
    pub csrf_token: String,
}

/// Form for CSRF-only actions on the tenant management screen (deletion etc.).
#[derive(Debug, Deserialize)]
pub struct AdminTenantActionForm {
    pub csrf_token: String,
}

/// Password reissue form by an admin (the target is specified by email address).
#[derive(Debug, Deserialize)]
pub struct AdminPasswordResetForm {
    #[serde(default)]
    pub email: String,
    pub csrf_token: String,
}

/// Form changing a user's status in the member list (`ACTIVE` / `DISABLED`).
#[derive(Debug, Deserialize)]
pub struct MemberStatusForm {
    pub status: String,
    pub csrf_token: String,
}

/// Form for CSRF-only actions in the member list (deletion, password reissue etc.).
/// `email` is for display on the result screen (optional; not used for authorization or target resolution).
#[derive(Debug, Deserialize)]
pub struct MemberActionForm {
    #[serde(default)]
    pub email: String,
    pub csrf_token: String,
}

/// Admin note form (ADR-0063). Sending it empty deletes the note.
#[derive(Debug, Deserialize)]
pub struct MemberNoteForm {
    #[serde(default)]
    pub note: String,
    pub csrf_token: String,
}

/// Runtime setting (DB override) form on the settings screen
/// (`POST /{tenant_id}/admin/system-settings/runtime`). Empty `value` = remove the override.
#[derive(Debug, Deserialize)]
pub struct AdminRuntimeSettingForm {
    pub key: String,
    #[serde(default)]
    pub value: String,
    pub csrf_token: String,
}

/// Form setting a tenant setting value (`POST /{tenant_id}/admin/settings/tenant/keys`. ADR-0058).
///
/// `confirmed` is attached only when resent from the confirmation screen (when changing to a value that could lock people out).
#[derive(Debug, Deserialize)]
pub struct AdminTenantSettingForm {
    pub key: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub confirmed: Option<String>,
    pub csrf_token: String,
}

/// Form removing a tenant override (back to global) (`POST /{tenant_id}/admin/settings/tenant/keys/clear`).
#[derive(Debug, Deserialize)]
pub struct AdminTenantSettingClearForm {
    pub key: String,
    pub csrf_token: String,
}

/// Form for the tenant's own mail route (`POST /{tenant_id}/admin/settings/smtp`. ADR-0058 §8).
///
/// If `smtp_password` is empty the current password is kept (same rule as the global screen). To delete it,
/// attach `smtp_password_clear` — reading an empty field as "delete" would delete the password when only other fields
/// were fixed without re-entering it.
#[derive(Debug, Deserialize)]
pub struct AdminTenantSmtpForm {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: String,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub smtp_password_clear: Option<String>,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: Option<String>,
    pub csrf_token: String,
}

/// Form removing the tenant's mail route and falling back to the global route (`POST /{tenant_id}/admin/settings/smtp/clear`).
#[derive(Debug, Deserialize)]
pub struct AdminTenantSmtpClearForm {
    pub csrf_token: String,
}

/// Form restarting the api and web (`POST /{tenant_id}/admin/restart`. ADR-0017).
#[derive(Debug, Deserialize)]
pub struct AdminRestartForm {
    pub csrf_token: String,
}

/// SAML SP (client) registration form (`POST /{tenant_id}/admin/saml-clients`).
#[derive(Debug, Deserialize)]
pub struct AdminSamlServiceProviderForm {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    #[serde(default)]
    pub name_id_format: String,
    #[serde(default)]
    pub x509_certificate: String,
    #[serde(default)]
    pub enabled: Option<String>,
    pub csrf_token: String,
}

/// SAML SP (client) deletion form (`POST /{tenant_id}/admin/saml-clients/{id}/delete`).
#[derive(Debug, Deserialize)]
pub struct AdminSamlServiceProviderDeleteForm {
    pub csrf_token: String,
}

/// Authentication policy create/edit form (`POST /{tenant_id}/admin/authentication-policies`, AP1).
///
/// Conditions with a variable count (target clients, users, CIDRs, `acr_values`, time windows) cannot map one-to-one
/// onto HTML input fields, so they are received as text areas. Formatting and round-tripping are collected in
/// [`crate::authentication_policy_form`].
#[derive(Debug, Deserialize)]
pub struct AdminAuthenticationPolicyForm {
    pub policy_code: String,
    pub policy_name: String,
    pub priority: String,
    /// Unchecked checkboxes are not submitted, so it is received as `Option`.
    #[serde(default)]
    pub enabled: Option<String>,
    pub effect: String,
    /// Authentication methods allowed by `require_specific_method` (a group of checkboxes).
    ///
    /// Repeated keys (`methods=a&methods=b`) are not received as a `Vec` because `serde_urlencoded`, used to decode
    /// forms, does not support sequences. The methods are a closed vocabulary
    /// ([`assay_contracts::admin::AUTHENTICATION_METHOD_CODES`]), so each method is received as an independent
    /// checkbox.
    #[serde(default)]
    pub method_password: Option<String>,
    #[serde(default)]
    pub method_totp: Option<String>,
    #[serde(default)]
    pub method_webauthn: Option<String>,
    #[serde(default)]
    pub method_recovery_code: Option<String>,
    #[serde(default)]
    pub method_email_otp: Option<String>,
    #[serde(default)]
    pub method_sms_otp: Option<String>,
    #[serde(default)]
    pub method_external_idp: Option<String>,
    #[serde(default)]
    pub user_verification: Option<String>,
    /// Internal IDs of target apps (newline-separated. Empty = all apps. Decision 5 of ADR-0054).
    #[serde(default)]
    pub application_ids: String,
    #[serde(default)]
    pub user_ids: String,
    #[serde(default)]
    pub ip_cidrs: String,
    #[serde(default)]
    pub time_windows: String,
    #[serde(default)]
    pub requested_acr: String,
    pub csrf_token: String,
}

/// Authentication policy deletion form (`POST /{tenant_id}/admin/authentication-policies/{id}/delete`).
#[derive(Debug, Deserialize)]
pub struct AdminAuthenticationPolicyDeleteForm {
    pub csrf_token: String,
}
