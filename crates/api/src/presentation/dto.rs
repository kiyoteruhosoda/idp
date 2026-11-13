//! Common DTOs used across presentation (`XxxRequest` / `XxxResponse`).
//! The OpenAPI schema is generated from `utoipa::ToSchema` (not hand-written).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    pub sub: String,
    pub status: String,
    /// Whether a verification email was sent (SEC6b). If `true`, sign-in is not possible until the link is followed.
    /// `false` when SMTP is not configured (the account exists but verification comes later).
    pub email_verification_required: bool,
}

/// Consumes an email verification link (SEC6b). Receives the plaintext token and sets `email_verified`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyEmailRequest {
    pub token: String,
}

/// Query parameters of `GET /authorize` (design spec §4.2).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// `prompt` parameter (OIDC Core §3.1.2.1): `none` / `login` / `consent` / `select_account`.
    pub prompt: Option<String>,
    /// `max_age` parameter (OIDC Core §3.1.2.1): max seconds elapsed since the SSO session's auth_time.
    pub max_age: Option<u64>,
    /// `acr_values` parameter (OIDC Core §3.1.2.1): authentication context classes requested by the RP
    /// (space-separated, G12). **A request is not a guarantee** -- it is only referenced by authentication policies'
    /// `requested_acr` condition (AP3), and unsatisfiable requests are not an error (voluntary per §3.1.2.1).
    pub acr_values: Option<String>,
    /// `login_hint` parameter (OIDC Core §3.1.2.1): identifier prefilled on the login screen (G12).
    pub login_hint: Option<String>,
    /// `ui_locales` parameter (OIDC Core §3.1.2.1): display languages requested by the RP (space-separated
    /// BCP47 tags, G12).
    pub ui_locales: Option<String>,
    /// `response_mode` parameter (OAuth 2.0 Multiple Response Type Encoding Practices):
    /// `query` (default) or `form_post` (G12). Unknown values are `invalid_request`.
    pub response_mode: Option<String>,
}

/// Form parameters of `POST /login` (design spec §4.3).
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub csrf_token: String,
}

// DTOs of the internal auth API (`/internal/authenticate*`) are shared by the api server and the web client, so they are
// defined in the `assay-contracts` crate (ADR-0007 §6). Handlers use `assay_contracts::auth::*`.

/// Form parameters of `POST /token` (design spec §4.4, §9.1).
#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
    /// Client secret for `client_secret_post` (RFC 6749 §2.3.1, G3). Combining it with `Authorization: Basic`
    /// is `invalid_request`.
    pub client_secret: Option<String>,
    /// For the `refresh_token` grant only.
    pub refresh_token: Option<String>,
    /// Scopes requested with the `client_credentials` grant (space-separated, G4).
    pub scope: Option<String>,
    /// Requested resource indicator (RFC 8707 `resource`, ADR-0037). System clients calling assay's own
    /// admin API specify `{issuer}/admin` to receive an admin token.
    pub resource: Option<String>,
    /// Signed `private_key_jwt` assertion (RFC 7523 §2.2, ADR-0030).
    pub client_assertion: Option<String>,
    /// Type of `client_assertion`. Only `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
    pub client_assertion_type: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    /// Returned only for grants that authenticated a user (omitted for `client_credentials`, which has no user, G4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub scope: String,
    /// Returned only when the `offline_access` scope was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// OAuth 2.0 error response (RFC 6749 §5.2).
#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Client (RP) registration request (admin API, design spec §9.3).
/// `client_id` is auto-assigned; `client_secret` is issued for confidential clients (not included in the request).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ClientRegisterRequest {
    pub app_name: String,
    /// `public` or `confidential`.
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    /// Whether to allow the `client_credentials` grant for server-to-server (M2M) integration (G4; default false).
    /// Effective only for confidential clients.
    #[serde(default)]
    pub allow_client_credentials: Option<bool>,
    /// Client authentication method (G3): `private_key_jwt` (default, ADR-0030 / ADR-0036),
    /// `client_secret_basic`, `client_secret_post`. Only confidential clients can specify it.
    /// When omitted it is treated as `private_key_jwt`, so `jwks` is required.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// Redirect targets for RP-initiated logout (only registered ones are allowed).
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Front-channel logout URI (OIDC Front-Channel Logout 1.0).
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    /// Back-channel logout URI (OIDC Back-Channel Logout 1.0).
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// Verification keys for `private_key_jwt` (a JWK Set JSON string, ADR-0030). Required for that method,
    /// not allowed for other methods. Key rotation is done by listing old and new in this set.
    #[serde(default)]
    pub jwks: Option<String>,
    /// Admin note (optional, up to 2000 characters, ADR-0065). ⚠ Writable only for **service accounts**
    /// (clients with `allow_client_credentials` and no redirect_uri). Sending it for a connected app gives 400.
    #[serde(default)]
    pub note: Option<String>,
}

/// Partial client update request. Only the given fields are updated.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ClientUpdateRequest {
    #[serde(default)]
    pub app_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Allowing the `client_credentials` grant (G4). Effective only for confidential clients.
    #[serde(default)]
    pub allow_client_credentials: Option<bool>,
    /// Client authentication method (G3): `client_secret_basic`, `client_secret_post`,
    /// `private_key_jwt` (ADR-0030). Only confidential clients can change it.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// Replaces the `private_key_jwt` verification keys (a JWK Set JSON string, ADR-0030).
    /// Key rotation is done without downtime by listing old and new in this set and removing the old key after switching.
    #[serde(default)]
    pub jwks: Option<String>,
    /// `ACTIVE` or `DISABLED`.
    #[serde(default)]
    pub client_status: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
}

/// Query parameters for audit log search (admin API, A3, design spec §7).
/// `from` / `to` are RFC3339 (e.g. `2026-07-06T00:00:00Z`). Unspecified fields don't filter.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AuditLogQueryParams {
    #[serde(default)]
    pub event_type: Option<String>,
    /// `success` or `failure`.
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Response for one audit log row (the log fields of design spec §7).
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditLogEntryResponse {
    pub id: i64,
    pub event_type: String,
    pub occurred_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub correlation_id: String,
}

/// Query parameters for error/warning log search (admin API, `log` table).
/// `from` / `to` are RFC3339 (e.g. `2026-07-06T00:00:00Z`). Unspecified fields don't filter.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ApplicationLogQueryString {
    /// `ERROR` or `WARN`.
    #[serde(default)]
    pub level: Option<String>,
    /// `api` or `web`.
    #[serde(default)]
    pub service: Option<String>,
    /// Prefix match on the emitting module path (e.g. `assay_api::presentation`).
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Request to grant an admin permission to a client (`POST /admin/clients/{client_id}/permissions`, ADR-0037).
#[derive(Debug, Deserialize, ToSchema)]
pub struct GrantClientPermissionRequest {
    /// Permission code to grant (fine-grained codes only; `idp.tenant.admin` / `idp.system.admin` not allowed).
    pub permission_code: String,
}

/// Request to grant a permission to a user (admin API, A2, ADR-0006).
#[derive(Debug, Deserialize, ToSchema)]
pub struct GrantPermissionRequest {
    /// Permission code to grant (e.g. `idp.tenant.admin`). Must exist in the `permissions` master.
    pub permission_code: String,
}

/// Response listing the permission codes a user holds (A2, ADR-0006).
#[derive(Debug, Serialize, ToSchema)]
pub struct UserPermissionsResponse {
    /// Internal ID (UUID) of the target user.
    pub user_id: String,
    /// Held permission codes (order unspecified).
    pub permission_codes: Vec<String>,
}

/// Public representation of a client (`client_secret_hash` is not returned).
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientResponse {
    pub id: String,
    pub client_id: String,
    pub client_type: String,
    pub client_status: String,
    pub app_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth_method: String,
    /// Verification keys for `private_key_jwt` (a JWK Set JSON string, ADR-0030). Only public keys are stored, so they are
    /// returned as is -- admins need to check "which key is active now" during rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Registration response. `client_secret` is returned in plaintext only for confidential clients, **only in this response**.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientCreatedResponse {
    #[serde(flatten)]
    pub client: ClientResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// Secret reissue response. The plaintext is returned only in this response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientSecretResponse {
    pub client_id: String,
    pub client_secret: String,
}

/// Response of `GET /userinfo` (claims vary by scope, design spec §4.7).
#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Public representation of a signing key (no private or encryption keys).
#[derive(Debug, Serialize, ToSchema)]
pub struct SigningKeyResponse {
    pub kid: String,
    /// `RS256` or `ES256`.
    pub algorithm: String,
    /// `ACTIVE` or `RETIRED`.
    pub status: String,
    /// RFC3339 string.
    pub not_before: String,
    /// RFC3339 string.
    pub not_after: String,
    /// RFC3339 string.
    pub created_at: String,
    /// **Whether this key is currently used for signing.** `status` alone doesn't tell -- when there are several ACTIVE keys
    /// only one signs, and `not_before` decides which.
    pub is_current_signer: bool,
    /// **Whether the key is published but not yet used for signing** (`not_before` in the future). Rotation passes
    /// through this state. It is in JWKS, so RPs can import it in advance.
    pub is_pending: bool,
}

/// Request to generate a new signing key (`POST /admin/signing-keys`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct GenerateSigningKeyRequest {
    /// `RS256` or `ES256`.
    pub algorithm: String,
    /// **Whether to start signing with it right away.** With the default `false`, the key is only published to JWKS and
    /// starts signing after `KEY_ROTATION_PUBLISH_LEAD_HOURS` (grace for RPs caching JWKS to pick up
    /// the new kid). `true` is for when there is no room for a grace period, such as key compromise; verification at
    /// RPs with a cache may fail temporarily.
    #[serde(default)]
    pub activate_immediately: bool,
}

// --- Tenant management (ADR-0009 §5, §6; requires `idp.system.admin`) ---------------------------------

/// Child tenant creation request (`POST /{tenant_id}/admin/tenants`). The `id` (UUID) is auto-assigned by the system.
/// The creator becomes the new tenant's bootstrap admin (ACTIVE GUEST + `idp.tenant.admin`), so
/// no initial admin email is accepted (ADR-0009 §4).
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    /// Tenant display name. No uniqueness constraint; not used in URLs.
    pub name: String,
}

/// Partial child tenant update request (`PATCH /{tenant_id}/admin/tenants/{child_id}`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTenantRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// `ACTIVE` or `DISABLED`.
    #[serde(default)]
    pub status: Option<String>,
}

/// Public representation of a tenant.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantResponse {
    pub id: String,
    /// The creating tenant. `None` only for root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_tenant_id: Option<String>,
    pub name: String,
    /// `ACTIVE` or `DISABLED`.
    pub status: String,
    /// Whether self-registration (`/auth/register`) is allowed (SEC6; disabled by default).
    pub self_registration_enabled: bool,
    /// Whether sign-in by email address is allowed (ADR-0050; disabled by default).
    pub email_login_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Domains assigned to a tenant (`/{tenant_id}/admin/tenants/{target_id}/domains`, ADR-0029).
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantDomainResponse {
    pub id: String,
    pub tenant_id: String,
    /// Normalized domain (lowercase, no trailing dot).
    pub domain: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Domain assignment request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddTenantDomainRequest {
    /// The domain to assign. Normalization (lowercasing, removing a trailing dot) is done server-side.
    pub domain: String,
}

/// Request to update the own tenant's display name from the settings screen (`PATCH /{tenant_id}/admin/settings/tenant`, MT14).
/// An admin holding `idp.tenant-settings:write` changes only the own tenant's display name (`status` and `parent_tenant_id` stay).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTenantSettingsRequest {
    pub name: String,
    /// Self-registration toggle (SEC6). Unchanged when omitted.
    #[serde(default)]
    pub self_registration_enabled: Option<bool>,
    /// Toggle for sign-in by email address (ADR-0050). Unchanged when omitted.
    #[serde(default)]
    pub email_login_enabled: Option<bool>,
}

// --- System settings (SMTP, etc.; root/idp.system.admin only, MT14) -------------------------------

/// Runtime setting resolution result. Besides source and safety attributes, non-secret keys return for display the
/// **effective value resolved at startup** (`value`), the built-in default (`default_value`) and the DB override (`db_value`).
/// For secret keys all of these are `None` (plaintext is never exposed).
#[derive(Debug, Serialize, ToSchema)]
pub struct RuntimeSettingResponse {
    pub key: String,
    pub owner: String,
    pub source: String,
    pub secret: bool,
    pub restart_required: bool,
    pub default_risk: String,
    /// `SAFE` or `NEEDS_ACTION`. Contains no secret plaintext or fingerprint.
    pub status: String,
    /// Reason for the verdict. Contains no secret plaintext or fingerprint.
    pub reason: String,
    /// Description of what this setting is used for (for operators).
    pub description: String,
    /// Effective value resolved at startup (non-secret only). Doesn't change after a DB update until restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Built-in default (non-secret only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// Override value currently stored in the DB (non-secret only; `None` when unset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_value: Option<String>,
    /// Whether it can be overridden from this screen (DB) (`owner == DB_MANAGED` and non-secret).
    pub editable: bool,
    /// **Saved but not yet applied to the running api** (MT27). Means the value saved in the DB differs from the effective
    /// value the api resolved at startup. Also `true` when **clearing** an override is not yet applied.
    pub pending_restart: bool,
    /// Whether web also consumes the key (ADR-0013). Keys with `true` need restarting **both api and web** to apply.
    pub shared_with_web: bool,
    /// Whether tenants can override the key (ADR-0058 §3).
    pub tenant_overridable: bool,
    /// Number of tenants following the global value (tenant-overridable keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenants_following: Option<u64>,
    /// Tenants deviating from the default (tenant-overridable keys only; not interfered with, but not hidden either).
    pub tenants_overriding: Vec<TenantOverrideResponse>,
}

/// Public representation of system settings (`GET/PUT /{tenant_id}/admin/system-settings`). The SMTP password is
/// never returned in plaintext; only whether it is set (`smtp_password_set`).
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemSettingsResponse {
    pub smtp_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_port: Option<u16>,
    pub smtp_username: String,
    /// Whether the SMTP password is set (plaintext is not returned).
    pub smtp_password_set: bool,
    pub smtp_from_address: String,
    pub smtp_use_tls: bool,
    /// SMS gateway (AP13). URL to which send requests are POSTed. Empty = SMS sending disabled.
    #[serde(default)]
    pub sms_gateway_url: String,
    #[serde(default)]
    pub sms_auth_header: String,
    /// Whether the SMS gateway auth token is set (plaintext is not returned).
    #[serde(default)]
    pub sms_auth_token_set: bool,
    #[serde(default)]
    pub sms_sender_id: String,
    #[serde(default)]
    pub runtime_settings: Vec<RuntimeSettingResponse>,
}

/// System settings update request (`PUT /{tenant_id}/admin/system-settings`). `smtp_password`:
/// `None` (unspecified) = keep current, `Some("")` = clear, `Some(x)` = set (stored encrypted).
/// Representation of SMTP settings only (`GET/PUT /{tenant_id}/admin/system-settings/smtp`, ADR-0051).
///
/// **A different type** from the whole system settings ([`SystemSettingsResponse`]), to express with the type
/// the range opened to machines. Reusing a type carrying SMS and runtime settings would let fields that "are not supposed
/// to be returned" go out along with it the moment they are added to that type in the future.
#[derive(Debug, Serialize, ToSchema)]
pub struct SmtpSettingsResponse {
    pub smtp_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_port: Option<u16>,
    pub smtp_username: String,
    /// Whether the SMTP password is set (**plaintext is not returned**).
    pub smtp_password_set: bool,
    pub smtp_from_address: String,
    pub smtp_use_tls: bool,
}

/// Representation of a tenant's SMTP settings (`GET/PUT/DELETE /{tenant_id}/admin/settings/smtp`, ADR-0058 §8).
///
/// The same fields as global SMTP ([`SmtpSettingsResponse`]) plus `inherited`. ⚠ **When the tenant has no route,
/// the global values are not returned** (fields are empty). There is no reason to show tenant admins the global route's host or
/// username.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantSmtpSettingsResponse {
    /// `true` = this tenant has no route and sends mail via the global route.
    pub inherited: bool,
    pub smtp_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp_port: Option<u16>,
    pub smtp_username: String,
    /// Whether the SMTP password is set (**plaintext is not returned**).
    pub smtp_password_set: bool,
    pub smtp_from_address: String,
    pub smtp_use_tls: bool,
}

/// SMTP settings update request.
///
/// `smtp_password` is three-valued (same rule as the system settings screen):
/// `None` = keep current / `Some("")` = clear / `Some(x)` = set.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSmtpSettingsRequest {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: Option<String>,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSystemSettingsRequest {
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: Option<String>,
    #[serde(default)]
    pub smtp_from_address: String,
    #[serde(default)]
    pub smtp_use_tls: bool,
    /// SMS gateway (AP13). `sms_auth_token` follows the same rule as the SMTP password
    /// (`None` = keep current, `Some("")` = clear, `Some(x)` = set).
    #[serde(default)]
    pub sms_gateway_url: String,
    #[serde(default)]
    pub sms_auth_header: String,
    #[serde(default)]
    pub sms_auth_token: Option<String>,
    #[serde(default)]
    pub sms_sender_id: String,
}

/// Runtime setting DB override update request (`PUT /{tenant_id}/admin/system-settings/runtime`).
/// When `value` is `None` or an empty string the override is cleared (falls back to the default / environment variable).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRuntimeSettingRequest {
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
}

// --- Tenant setting values (ADR-0058; `idp.tenant-settings:read` / `:write`) --------------------------

/// List of settings the tenant can override (`GET /{tenant_id}/admin/settings/tenant/keys`).
///
/// Fields are derived from the key definitions (`scope = TenantOverridable`). ⚠ **Don't add fields to this type
/// for every new key** -- the screen picks the input from `kind` and `choices`.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantSettingsListResponse {
    pub settings: Vec<TenantSettingResponse>,
}

/// One tenant setting.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantSettingResponse {
    pub key: String,
    /// What the setting is used for (one sentence for operators, in the ops language).
    pub description: String,
    /// Value type: `UNSIGNED_INTEGER` / `BOOLEAN` / `TEXT` / `PUBLIC_BASE_URL` / `CHOICE`.
    pub kind: String,
    /// Choices when `kind = CHOICE` (empty otherwise).
    pub choices: Vec<SettingChoiceResponse>,
    /// The value in effect for this tenant.
    pub value: String,
    /// Source of the value: `TENANT_OVERRIDE` (set by this tenant) / `INHERITED` (follows the global value).
    pub origin: String,
    /// The global value. Clearing the override reverts to it (returned even for overridden fields).
    pub whole_idp_value: String,
}

/// One choice.
#[derive(Debug, Serialize, ToSchema)]
pub struct SettingChoiceResponse {
    pub value: String,
    /// Whether this value could lock users out. Changing to a `true` value needs `confirmed: true`.
    pub locks_out: bool,
}

/// Updates a tenant setting value (`PUT /{tenant_id}/admin/settings/tenant/keys/{key}`).
///
/// Reverting to the global value is done with `DELETE` (empty values are not accepted).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateTenantSettingRequest {
    pub value: String,
    /// Whether changing to a value that could lock people out (a choice's `locks_out`) is confirmed. Without it, 409.
    #[serde(default)]
    pub confirmed: bool,
}

/// One "tenant deviating from the default" shown on the global settings screen (ADR-0058 §6).
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantOverrideResponse {
    pub tenant_id: String,
    pub tenant_name: String,
    pub value: String,
}

/// Acceptance response for a restart request (`POST /{tenant_id}/admin/restart`, ADR-0017).
///
/// It stops **after** returning the response, so this means "accepted", not "restart finished".
#[derive(Debug, Serialize, ToSchema)]
pub struct RestartServiceResponse {
    /// Name of the service stopping (currently always `api`).
    pub service: String,
    pub restarting: bool,
}

// --- Admin console support APIs (identity, client status, permission master, user search; task #146) -------
//
// web (the admin console) receives these with the same-named types in `assay_contracts::admin`. `assay_contracts`
// has no `utoipa` (ADR-0007), so types of **the same shape** are placed here to appear in OpenAPI.
// If they diverge, web can't decode the response and the screen won't open, so matching shapes are
// pinned by `console_support_contract_tests` via JSON round trips.

/// Response of `GET /{tenant_id}/admin/whoami` (same shape as `assay_contracts::admin::WhoamiResponse`).
#[derive(Debug, Serialize, ToSchema)]
pub struct WhoamiResponse {
    /// Internal ID (UUID) of the admin token's principal (user).
    pub user_id: String,
    /// Display name (null if unset).
    pub name: Option<String>,
    /// Login identifier (null if unset).
    pub preferred_username: Option<String>,
    /// Display name of the route's tenant (`/{tenant_id}/...`).
    pub tenant_name: Option<String>,
    /// Permission codes the caller **can actually exercise** in this tenant (implications expanded).
    pub permissions: Vec<String>,
}

/// Element of `GET /{tenant_id}/admin/clients/status` (same shape as
/// `assay_contracts::admin::ClientStatusResponse`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientStatusResponse {
    pub client_id: String,
    pub app_name: String,
    /// `ACTIVE` / `DISABLED`.
    pub status: String,
    pub scopes: Vec<String>,
    /// Last used time (RFC3339; latest successful token / code issuance; null if never used).
    pub last_used_at: Option<String>,
}

/// Response of `GET /{tenant_id}/admin/permissions` (same shape as
/// `assay_contracts::admin::AvailablePermissionsResponse`).
#[derive(Debug, Serialize, ToSchema)]
pub struct AvailablePermissionsResponse {
    /// Permission codes grantable in the requesting tenant (from the `permissions` master).
    pub codes: Vec<String>,
}

/// User summary (response of `GET /{tenant_id}/admin/users?q=`, `GET …/users/{user_id}` and status/profile
/// updates; same shape as `assay_contracts::admin::UserSummaryResponse`). Sensitive information such as password hashes
/// is not included.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserSummaryResponse {
    /// Internal ID (UUID).
    pub id: String,
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
    /// `ACTIVE` / `DISABLED`, etc.
    pub status: String,
}

// --- User creation (ADR-0009 §5, §6; requires `idp.users:write`) -------------------------------------

/// User creation request by an admin (`POST /{tenant_id}/admin/users`). The password is auto-generated.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// Admin note (optional, up to 2000 characters, ADR-0063). Attached to the created user's HOME membership.
    /// Empty (whitespace only) is treated as "no note".
    #[serde(default)]
    pub note: Option<String>,
}

/// User creation response. `setup_url` is returned **only in this response** (never in logs or audits, ADR-0062).
#[derive(Debug, Serialize, ToSchema)]
pub struct UserCreatedResponse {
    pub user_id: String,
    pub sub: String,
    /// Account setup link to hand to the user (absolute URL, single use). There they register a passkey or
    /// set a password. ⚠ **Admins don't hold the user's credentials** -- the hash stored at creation is
    /// a value nobody knows, and the generated password is no longer returned.
    pub setup_url: String,
    /// Expiry time of the link (RFC3339). Defaults to 24 hours later (`ACCOUNT_SETUP_TTL_SECS`).
    pub setup_expires_at: String,
}

/// App registration request (`POST /{tenant_id}/admin/applications`, ADR-0054).
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationRequest {
    /// Name shown on screens and in rejection messages.
    pub display_name: String,
    /// `EVERYONE` (any user of the tenant) or `INDIVIDUAL` (only assigned users).
    /// ⚠ **`INDIVIDUAL` when omitted.** Prevents an app someone forgot to restrict from staying open to all.
    #[serde(default)]
    pub assignment_mode: Option<String>,
    /// Whether to assign the creator at the same time. ⚠ **The screen checks it by default**
    /// -- right after creating an "individual" app nobody can get in, so don't lock the creator out.
    /// Default `true` (when a machine creates it there is nobody to assign, so nothing happens).
    #[serde(default = "default_enabled")]
    pub assign_creator: bool,
}

/// App update request (`PUT /{tenant_id}/admin/applications/{application_id}`).
///
/// **Not a partial update.** All three values decide "who can get in", so if omission meant "unchanged",
/// a request sent from a stale screen would unintentionally rewrite only one of them.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateApplicationRequest {
    pub display_name: String,
    /// `ACTIVE` or `DISABLED`.
    pub status: String,
    /// `EVERYONE` or `INDIVIDUAL`.
    pub assignment_mode: String,
}

/// Request to add a binding to an app (`POST /{tenant_id}/admin/applications/{application_id}/bindings`,
/// ADR-0059).
///
/// `kind` decides the kind, and the target is given in the one field fixed per kind:
///
/// | `kind` | Field naming the target | Target condition |
/// |---|---|---|
/// | `oidc` | `client_id` | A sign-in (`authorization_code`) client |
/// | `saml` | `service_provider_id` | Internal ID of a SAML SP |
/// | `service_account` | `client_id` | A service account (a `client_credentials`-only client) |
/// | `resource` | `resource_uri` | A registered audience (`aud`) |
///
/// ⚠ A target belongs to only one app. If it is another app's binding, 409 (returning that app's name).
/// To **move** it from that app, put the current owner app's ID in `move_from_application_id`
/// (unbind + bind in one go, ADR-0067). Still 409 if it differs from the current owner.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationBindingRequest {
    /// `oidc` / `saml` / `service_account` / `resource`. ⚠ Omission is 400 (no default kind).
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub service_provider_id: Option<String>,
    #[serde(default)]
    pub resource_uri: Option<String>,
    /// If the target is another app's binding, move it from that app (ADR-0067). The value is **the current owner app's ID**.
    /// ⚠ It is named explicitly so that if the owner changed between checking and sending, we don't silently take it
    /// from an app nobody checked. If the target belongs nowhere, it is simply bound.
    #[serde(default)]
    pub move_from_application_id: Option<String>,
}

/// Request to assign a principal that uses the app
/// (`POST /{tenant_id}/admin/applications/{application_id}/assignments`, ADR-0059 decision 5).
///
/// | `kind` | Field naming the target | Meaning of the assignment |
/// |---|---|---|
/// | `user` | `user_id` (user's internal ID; a member of the requesting tenant) | May sign in |
/// | `service_account` | `client_id` (a `client_credentials`-only client) | May get tokens for this app's audience |
///
/// ⚠ **No roles are carried** (ADR-0054 decision 1). Only the single bit "may use" is carried.
/// ⚠ "Everyone" (`EVERYONE`) includes only people; service accounts are always assigned individually.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationAssignmentRequest {
    /// `user` / `service_account`. ⚠ Omission is 400 (no default kind).
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Public representation of an app.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationResponse {
    pub id: String,
    pub display_name: String,
    pub status: String,
    pub assignment_mode: String,
    /// This app's bindings (sign-in clients, SAML SPs, service accounts, audiences).
    pub bindings: Vec<ApplicationBindingResponse>,
    /// Number of people assigned (service accounts not counted). 0 for `EVERYONE`, which has no rows.
    pub assigned_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Public representation of one binding.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationBindingResponse {
    pub id: String,
    /// `oidc` / `saml` / `service_account` / `resource`.
    pub kind: String,
    /// `client_id` for sign-in and service accounts, `entity_id` for SAML, `resource_uri` for
    /// audiences. `null` if the target is gone.
    pub identifier: Option<String>,
    /// The target's registered name.
    pub display_name: Option<String>,
}

/// Binding candidates
/// (`GET /{tenant_id}/admin/applications/{application_id}/binding-candidates`, ADR-0067).
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationBindingCandidateListResponse {
    /// Ordered by kind (`oidc`, `saml`, `service_account`, `resource`), then by display name ascending.
    /// Those already bound to this app are not listed.
    pub candidates: Vec<ApplicationBindingCandidateResponse>,
}

/// One binding candidate.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationBindingCandidateResponse {
    /// `oidc` / `saml` / `service_account` / `resource`.
    pub kind: String,
    /// The value to send when binding (put as is in the target field of `POST …/bindings`).
    /// `client_id` for `oidc` and `service_account`, the SP's internal ID for `saml`, the audience URI for `resource`.
    pub reference: String,
    /// The value people use to tell them apart (`client_id`, `entity_id`, audience URI).
    pub identifier: String,
    /// The target's registered name.
    pub display_name: String,
    /// The app that currently has this target as a binding (`null` if it belongs nowhere).
    pub application_id: Option<String>,
    /// That app's display name.
    pub application_name: Option<String>,
}

/// App list (`GET /{tenant_id}/admin/applications`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationListResponse {
    pub applications: Vec<ApplicationResponse>,
    /// How far the decision currently goes in rejecting (`record_only` / `enforce`).
    /// ⚠ The screen reads it to show that assignments are not yet in effect while "only recording".
    pub enforcement: String,
}

/// App detail (`GET /{tenant_id}/admin/applications/{application_id}`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationDetailResponse {
    #[serde(flatten)]
    pub application: ApplicationResponse,
    /// Assigned people.
    pub assigned: Vec<ApplicationAssignmentResponse>,
    /// Assigned service accounts (may get tokens for this app's audience, ADR-0059).
    pub assigned_service_accounts: Vec<ApplicationServiceAccountAssignmentResponse>,
    /// How far the decision currently goes in rejecting (`record_only` / `enforce`).
    /// The same value as the list is attached so that **the screen does not re-fetch the list
    /// just to show "not in effect"**.
    pub enforcement: String,
}

/// One assigned user row.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationAssignmentResponse {
    pub user_id: String,
    /// The token's subject identifier. The key for matching against the RP-side roster.
    pub sub: String,
    pub email: String,
    pub name: Option<String>,
    /// Status of the user account itself (`ACTIVE` / `DISABLED` / `LOCKED`).
    pub status: String,
    pub assigned_at: String,
}

/// One assigned service account row.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationServiceAccountAssignmentResponse {
    pub client_id: String,
    /// The client's registered name.
    pub app_name: String,
    /// The client's status (`ACTIVE` / `DISABLED` / `DELETED`).
    pub status: String,
    pub assigned_at: String,
}

/// "The people who can get in now"
/// (`GET /{tenant_id}/admin/applications/{application_id}/current-users`).
///
/// A list for copying straight into the roster before switching from "everyone" to "individual".
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationCurrentUsersResponse {
    pub users: Vec<ApplicationCurrentUserResponse>,
    /// Total number of people (before truncating at the limit).
    pub total: i64,
    /// Whether it was truncated at the limit. ⚠ **If true, the screen must say "not everyone could be listed".**
    pub truncated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationCurrentUserResponse {
    pub user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

/// Roster query (`GET /{tenant_id}/admin/applications/self/users`, ADR-0057 / ADR-0059).
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct ApplicationUserQueryParams {
    /// Entries per page. 50 if unspecified, max 200 (larger values are clamped to the max).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Number of entries to skip. 0 if unspecified.
    #[serde(default)]
    pub offset: Option<i64>,
    /// `sub`s to ask about (comma-separated; ⚠ up to 100 at a time).
    ///
    /// ⚠ **`unknown` (= gone) is returned only when this is given** -- people who are gone,
    /// being absent, don't appear in the candidate list. If unspecified, one page of this app's candidates is returned.
    #[serde(default)]
    pub subs: Option<String>,
}

/// One roster row (ADR-0057).
///
/// ⚠ **Only `sub` and status are carried.** Copies of attributes are handed over at every sign-in, so this is
/// an inventory endpoint, not one that distributes attributes.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationUserResponse {
    /// The token's subject identifier. The key for matching against the RP's roster (`federated_identities`).
    pub sub: String,
    /// `allowed` = may use now / `blocked` = exists in assay but cannot use (⚠ **keep the link**) /
    /// `unknown` = not a user of this tenant (= gone; the link may be dropped too).
    pub state: String,
}

/// Roster query result (`GET /{tenant_id}/admin/applications/self/users`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplicationUserListResponse {
    pub users: Vec<ApplicationUserResponse>,
    /// Total matches ignoring `limit` / `offset`.
    pub total: i64,
    /// The values actually applied (after clamping).
    pub limit: i64,
    pub offset: i64,
}

/// Registration request for a protected resource (audience name put in `aud`) (`POST /{tenant_id}/admin/resources`, ADR-0042).
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterResourceRequest {
    /// The value put in `aud`. Absolute URI, no fragment. **An audience name, not an address to call**, so it needn't resolve
    /// (forms like `api://blobshare` can be registered too).
    pub resource_uri: String,
    /// Name shown on screens.
    pub display_name: String,
}

/// Status update request for a protected resource (`PATCH /{tenant_id}/admin/resources/{resource_id}`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateResourceStatusRequest {
    /// `ACTIVE` or `DISABLED`.
    pub status: String,
}

/// Public representation of a protected resource.
#[derive(Debug, Serialize, ToSchema)]
pub struct ResourceResponse {
    pub id: String,
    pub resource_uri: String,
    pub display_name: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

/// List of protected resources (`GET /{tenant_id}/admin/resources`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ResourceListResponse {
    pub resources: Vec<ResourceResponse>,
}

/// One SSH key row handed to the distributing machine (`GET /{tenant_id}/admin/ssh-keys`, task #885).
#[derive(Debug, Serialize, ToSchema)]
pub struct SshKeyResponse {
    /// assay username (preferred_username). The distributor maps it to the device's user.
    pub username: String,
    /// Key name given by the user.
    pub name: String,
    /// "type body" of an authorized_keys line (no comment or options).
    pub public_key: String,
    /// `SHA256:…` (same as `ssh-keygen -l`).
    pub fingerprint: String,
    /// Registration time (RFC 3339, UTC).
    pub created_at: String,
}

/// List of the organization's active SSH keys (`GET /{tenant_id}/admin/ssh-keys`).
#[derive(Debug, Serialize, ToSchema)]
pub struct SshKeyListResponse {
    pub keys: Vec<SshKeyResponse>,
}

/// User status update request (`PATCH /{tenant_id}/admin/users/{user_id}`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserStatusRequest {
    /// `ACTIVE` or `DISABLED` (`LOCKED` cannot be set by admin operations).
    pub status: String,
}

/// User profile update request by an admin (`PATCH /{tenant_id}/admin/users/{user_id}/profile`,
/// MT25). Omitted fields are unchanged (partial update). `preferred_username` is the login identifier;
/// changing it changes that user's login name (clearing with an empty string is 400). Passing an empty string for `name`
/// clears the display name.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserProfileRequest {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Password reissue response by an admin. Everything is returned **only in this response** (never in logs or audits).
#[derive(Debug, Serialize, ToSchema)]
pub struct UserPasswordResetResponse {
    pub user_id: String,
    /// Account setup link to hand to the user (absolute URL, single use, ADR-0062).
    pub setup_url: String,
    /// Expiry time of the link (RFC3339).
    pub setup_expires_at: String,
}

/// Guest membership status update request (`PATCH /{tenant_id}/admin/members/{user_id}`, MT24).
/// Only `SUSPENDED` (suspend) and `ACTIVE` (resume) are accepted. `INVITED` is a state managed by the invitation flow,
/// so it can't be set from here.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMemberStatusRequest {
    /// `SUSPENDED` = suspend / `ACTIVE` = resume.
    pub status: String,
}

/// Account unlock response by an admin (AP6).
///
/// `was_locked` is "whether it was locked before unlocking". The operation is idempotent, so it succeeds even if it
/// wasn't locked to begin with. The screen uses this value to choose between
/// "Unlocked" and "It wasn't locked".
#[derive(Debug, Serialize, ToSchema)]
pub struct UserUnlockResponse {
    pub user_id: String,
    pub was_locked: bool,
}

/// MFA reset response by an admin (MT21). Returns only what was removed, not the contents of secrets or
/// credentials. Succeeds even when nothing is configured (all `false` / `0`).
#[derive(Debug, Serialize, ToSchema)]
pub struct UserMfaResetResponse {
    pub user_id: String,
    /// Whether a TOTP configuration existed and was deleted.
    pub totp_removed: bool,
    /// Number of passkeys (WebAuthn credentials) deleted.
    pub passkeys_removed: u64,
}

/// Token reissue response by an admin (ADR-0047). Returns only the number dropped, neither token values nor
/// hashes. Succeeds even with no live tokens (`revoked = 0`), and the screen uses this to show
/// "there was nothing to revoke".
#[derive(Debug, Serialize, ToSchema)]
pub struct UserTokenReissueResponse {
    pub user_id: String,
    /// Number of refresh tokens revoked.
    pub revoked: u64,
}

/// Number of the user's currently active tokens (`GET /{tenant_id}/admin/users/{user_id}/active-tokens`,
/// task #83). A read to show whether there is anything to target before pressing reissue (ADR-0047).
///
/// ⚠ **Only refresh tokens are counted.** Access tokens are self-contained JWTs with no DB rows,
/// so they can't be counted (they stay valid until expiry). The field name includes the kind to prevent mix-ups.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserActiveTokensResponse {
    pub user_id: String,
    /// Number of unrevoked, unexpired refresh tokens. Counted across tenants (same range as what reissue drops).
    pub active_refresh_tokens: u64,
}

/// Password reissue request for a child tenant admin
/// (`POST /{tenant_id}/admin/tenants/{child_id}/admin-password-reset`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct TenantAdminPasswordResetRequest {
    /// Email address of the target user (belonging to the child tenant).
    pub email: String,
}

// --- Members and invitations (ADR-0009 §3, §6) --------------------------------------------------------

/// One entry of the member list (`GET /{tenant_id}/admin/members`). Both HOME and GUEST.
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberResponse {
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Primary login identifier (username). Omitted for accounts created without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `HOME` or `GUEST`.
    pub membership_type: String,
    /// `INVITED` or `ACTIVE`.
    pub status: String,
    /// Status of the user account itself (`ACTIVE` / `DISABLED` / `LOCKED`). `None` for nonexistent users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_status: Option<String>,
    /// Whether a lock from failed sign-ins is in effect **now** (AP6). Separate from `user_status`
    /// (the lock is represented by `locked_until`, and whether it expired is decided at read time).
    pub locked: bool,
    /// Whether provisionally registered (ADR-0064). The user has not yet set credentials via the setup link and can't sign in.
    pub pending_setup: bool,
    /// For provisionally registered people, the current setup link's expiry (RFC 3339, UTC). Omitted if not provisional or no link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_link_expires_at: Option<String>,
    /// Whether provisionally registered with no usable setup link (expired or never issued). Decided at read time.
    /// If set, nobody can get in until an admin issues a new one.
    pub setup_link_expired: bool,
    /// Admin note (ADR-0063). Omitted if nothing is written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<AccountNoteResponse>,
}

/// Admin note for an account (person or service account) (ADR-0063 / ADR-0065). Free text for recording
/// background; never used for decisions.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountNoteResponse {
    pub text: String,
    /// When it was last written (RFC 3339, UTC).
    pub updated_at: String,
}

/// Writing an admin note (`PUT /{tenant_id}/admin/members/{user_id}/note`,
/// `PUT /{tenant_id}/admin/service-accounts/{client_id}/note`, ADR-0063 / ADR-0065).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAccountNoteRequest {
    /// Note body (up to 2000 characters). Empty (whitespace only) deletes the note.
    pub note: String,
}

/// List of apps one account can use (ADR-0063 / ADR-0065).
///
/// - People (`GET /{tenant_id}/admin/members/{user_id}/applications`): only apps with sign-in bindings (OIDC / SAML)
///   are listed
/// - Service accounts (`GET /{tenant_id}/admin/service-accounts/{client_id}/applications`): only apps with audience
///   (`resource`) bindings are listed
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountApplicationListResponse {
    pub applications: Vec<AccountApplicationResponse>,
    /// How far the decision for people currently goes in rejecting (`record_only` / `enforce`). Service account
    /// token issuance rejects regardless of this setting.
    pub enforcement: String,
}

/// One app as seen from an account.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountApplicationResponse {
    pub application_id: String,
    pub display_name: String,
    /// The app's status (`ACTIVE` / `DISABLED`).
    pub status: String,
    /// `EVERYONE` / `INDIVIDUAL`.
    pub assignment_mode: String,
    /// Whether this account can use it now (`allowed` / `not_assigned` / `application_disabled`).
    /// Decided by the same rule as the decision (sign-in for people, token issuance for service accounts).
    pub access: String,
    /// Time of the individual assignment (RFC 3339, UTC). Omitted if there is no assignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_at: Option<String>,
}

/// Paging query for lists (`GET /{tenant_id}/admin/tenants` and others, G7).
///
/// Shared by lists without filter conditions. Lists with filters (clients, members) have their own types.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct PageQueryParams {
    /// Entries per page. 50 if unspecified, max 200 (larger values are clamped to the max).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Number of entries to skip. 0 if unspecified.
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Client list query (`GET /{tenant_id}/admin/clients`). Layers filters on top of paging.
///
/// `grant_type` is for splitting the admin console list into "connected apps" and "service accounts"
/// (ADR-0038). **The purpose itself is not accepted** -- purpose is not in the api's model; it is vocabulary web
/// translates into whether `redirect_uris` exist and whether `client_credentials` is allowed (ADR-0032).
/// `authorization_code` and `client_credentials` never coexist in one client
/// (ADR-0032 Revised), so a single grant splits them exclusively.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct ClientListQueryParams {
    /// Entries per page. 50 if unspecified, max 200 (larger values are clamped to the max).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Number of entries to skip. 0 if unspecified.
    #[serde(default)]
    pub offset: Option<i64>,
    /// Grant to filter by (`authorization_code` / `client_credentials`). No filtering if unspecified.
    #[serde(default)]
    pub grant_type: Option<String>,
}

/// Client list response (`GET /{tenant_id}/admin/clients`, G7).
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientListResponse {
    pub clients: Vec<ClientResponse>,
    /// Total matches ignoring `limit` / `offset`. Lets the screen settle "N in total" and whether a next page exists.
    pub total: i64,
    /// The values actually applied (after clamping). The requested values are not echoed so that callers can use
    /// the clamped result as is when computing paging.
    pub limit: i64,
    pub offset: i64,
}

/// Child tenant list response (`GET /{tenant_id}/admin/tenants`, G7).
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantListResponse {
    pub tenants: Vec<TenantResponse>,
    /// Total matches ignoring `limit` / `offset`.
    pub total: i64,
    /// The values actually applied (after clamping).
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters of the member list (`GET /{tenant_id}/admin/members`, MT22).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct MemberListQueryParams {
    /// Filter term. **Partial match** on email address and name (case-insensitive). Unspecified or empty doesn't filter.
    #[serde(default)]
    pub q: Option<String>,
    /// Entries per page. 50 if unspecified, max 200 (larger values are clamped to the max).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Number of entries to skip. 0 if unspecified.
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Member list response (`GET /{tenant_id}/admin/members`, MT22).
#[derive(Debug, Serialize, ToSchema)]
pub struct MemberListResponse {
    pub members: Vec<MemberResponse>,
    /// Total matches ignoring `limit` / `offset`. Lets the screen settle "N in total" and whether a next page exists.
    pub total: i64,
    /// The values actually applied (after clamping). The requested values are not echoed so that callers can use
    /// the clamped result as is when computing paging.
    pub limit: i64,
    pub offset: i64,
}

// --- Accounts (people and service accounts, ADR-0065) -------------------------------------------

/// Account list query (`GET /{tenant_id}/admin/accounts`).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AccountListQueryParams {
    /// Kind to list (`user` / `service_account`). Unspecified means "everything readable".
    /// ⚠ Specifying an unreadable kind gives 403 (not a silent empty list).
    #[serde(default)]
    pub kind: Option<String>,
    /// **Partial match** of the filter term (case-insensitive). For people: email, name, username, note;
    /// for service accounts: registered name, `client_id`, note. Unspecified or empty doesn't filter.
    #[serde(default)]
    pub q: Option<String>,
    /// Entries per page. 50 if unspecified, max 200 (larger values are clamped to the max).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Number of entries to skip. 0 if unspecified.
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Account list response (`GET /{tenant_id}/admin/accounts`).
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountListResponse {
    /// Ascending by heading (people: email -> username; service accounts: registered name). Kinds are mixed together.
    pub accounts: Vec<AccountResponse>,
    /// Kinds actually listed.
    pub kinds: Vec<String>,
    /// Kinds the calling principal can read (so the screen can offer filter choices).
    pub readable_kinds: Vec<String>,
    /// Total matches ignoring `limit` / `offset`.
    pub total: i64,
    /// The values actually applied (after clamping).
    pub limit: i64,
    pub offset: i64,
}

/// One account list row. Depending on `kind`, exactly one of `user` or `service_account` is present.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountResponse {
    /// `user` / `service_account`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<MemberResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account: Option<ServiceAccountResponse>,
}

/// One service account (`GET /{tenant_id}/admin/service-accounts/{client_id}`, also one list row,
/// ADR-0065). Connection settings (auth method, scopes, keys) are at `GET /admin/clients/{client_id}`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceAccountResponse {
    pub client_id: String,
    /// Registered name.
    pub app_name: String,
    /// `ACTIVE` / `DISABLED`.
    pub status: String,
    /// Registration time (RFC 3339, UTC).
    pub created_at: String,
    /// The app that has this service account as a binding. Omitted if none.
    /// ⚠ A different relation from "usable apps" (assignments).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_of: Option<IdentityApplicationResponse>,
    /// Admin note. Omitted if nothing is written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<AccountNoteResponse>,
}

/// The app that has a service account as a binding.
#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityApplicationResponse {
    pub application_id: String,
    pub display_name: String,
}

/// Guest invitation creation request (`POST /{tenant_id}/admin/invitations`). The invitee is an existing user whose
/// home is another tenant, specified by internal ID.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInvitationRequest {
    /// The person to invite. **Email address or internal ID (UUID)** (ADR-0061).
    ///
    /// Also accepted under the old name `user_id` (from when only internal IDs were accepted). ⚠ **Keep it a single field;
    /// don't add another** -- "point by email" and "point by ID" are one and the same decision, and splitting it into two inputs
    /// creates an unrepresentable state of "which wins if both are written" (ADR-0032).
    #[serde(alias = "user_id")]
    pub invitee: String,
}

/// Invitation creation response. `token` is the plaintext invitation token, returned **only in this response** (if mail fails,
/// the admin notifies the invitee separately; never in logs or audits, ADR-0009 §3).
#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationCreatedResponse {
    pub token: String,
    /// Invitation expiry time (RFC3339).
    pub expires_at: String,
    /// Whether the invitation mail (acceptance link) could be sent to the invitee (MT17). false when SMTP is unset or sending failed
    /// (the invitation is still valid; the admin conveys the token manually).
    pub email_sent: bool,
    /// The invitee's email address (for confirming the recipient). Present **only when invited by email address**
    /// (omitted when invited by internal ID, so an ID can't be used to pull out another tenant's user's address, task #591).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee_email: Option<String>,
}

/// Invitation acceptance request (`POST /{tenant_id}/invitations/accept`). A signed-in user presents the token.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AcceptInvitationRequest {
    pub token: String,
}

/// One authentication policy (user authentication / authentication policy spec §7).
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthenticationPolicyResponse {
    pub id: String,
    pub policy_code: String,
    pub policy_name: String,
    /// Evaluation order (ascending = smaller takes priority).
    pub priority: i32,
    pub enabled: bool,
    /// `allow` / `deny` / `require_mfa` / `require_specific_method`.
    pub effect: String,
    /// What `require_specific_method` requires (`null` for other effects, AP3).
    pub effect_params: Option<RequiredMethodsDto>,
    /// Internal IDs of target apps (empty = all apps, ADR-0054 decision 5).
    pub application_ids: Vec<String>,
    /// Internal IDs of target users (empty = all users).
    pub user_ids: Vec<String>,
    /// Target network zones (CIDR notation; empty = all networks, AP3).
    pub ip_cidrs: Vec<String>,
    /// Time windows when it applies (empty = always, AP3).
    pub time_windows: Vec<TimeWindowDto>,
    /// `acr_values` condition of the authorization request (empty = regardless of what is requested, AP3).
    pub requested_acr: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// What `require_specific_method` requires (AP3, spec §12.2).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RequiredMethodsDto {
    /// Allowed authentication methods (`password` / `totp` / `webauthn` / `recovery_code` / `email_otp` /
    /// `sms_otp` / `external_idp`). Satisfied if **any one** of them was used.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Whether WebAuthn User Verification (biometrics, PIN) is required.
    #[serde(default)]
    pub user_verification: bool,
}

/// Time window when it applies (AP3). The time zone is a fixed UTC offset (minutes).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TimeWindowDto {
    /// Target weekdays (0 = Sunday … 6 = Saturday; empty = every day).
    #[serde(default)]
    pub days: Vec<u8>,
    /// Start time (minutes from midnight, 0-1439).
    pub start_minute: u16,
    /// End time (same; if smaller than the start, the window crosses midnight).
    pub end_minute: u16,
    /// UTC offset (minutes; e.g. JST = 540).
    #[serde(default)]
    pub utc_offset_minutes: i16,
}

/// Authentication policy list (priority ascending).
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthenticationPoliciesResponse {
    pub policies: Vec<AuthenticationPolicyResponse>,
    /// Default behaviour when no policy matches (`allow` / `deny`). **This tenant's value**
    /// (ADR-0058 §4). The meaning of the policies is only settled together with this value, so it is in the same response as the list.
    pub default_effect: String,
}

/// Authentication policy create/update (replace all fields) request.
///
/// **Unknown keys are rejected.** Silently dropping them would let a request with a typo in a condition name or an unsupported
/// condition (such as `country`) return 200 and **save a policy without that restriction**,
/// while the sender believes they narrowed it. For the same reason ADR-0020 put `deny_unknown_fields` on `PolicyConditions`,
/// it is needed on the entry DTO too -- here the conditions are laid out flat, so the check on the stored form
/// never reaches the request (ADR-0028).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationPolicyUpsertRequest {
    /// Identifier code unique within the tenant (alphanumerics and `-` `_` `.`, 1-100 characters).
    pub policy_code: String,
    pub policy_name: String,
    /// Evaluation order (ascending = smaller takes priority).
    pub priority: i32,
    /// Enabled (`true`) when omitted.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// `allow` / `deny` / `require_mfa` / `require_specific_method`.
    pub effect: String,
    /// What `require_specific_method` requires (an error if given with other effects, AP3).
    #[serde(default)]
    pub effect_params: Option<RequiredMethodsDto>,
    /// Internal IDs of target apps (UUID; omitted/empty = all apps, ADR-0054 decision 5).
    #[serde(default)]
    pub application_ids: Vec<String>,
    /// Internal IDs of target users (UUID; omitted/empty = all users).
    #[serde(default)]
    pub user_ids: Vec<String>,
    /// Target network zones (CIDR notation; omitted/empty = all networks, AP3).
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    /// Time windows when it applies (omitted/empty = always, AP3).
    #[serde(default)]
    pub time_windows: Vec<TimeWindowDto>,
    /// `acr_values` condition of the authorization request (omitted/empty = regardless of what is requested, AP3).
    #[serde(default)]
    pub requested_acr: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod authentication_policy_contract_tests {
    use super::*;

    /// The `assay_contracts::admin` DTO used by the admin console (web) and the one here (the api-side DTO that
    /// appears in OpenAPI) **must be the same JSON**. If they diverge, saving from the admin screen breaks
    /// (the api can't decode what web sent). Both are round-tripped through JSON to pin the shapes together.
    #[test]
    fn authentication_policy_contract_matches_the_api_dto() {
        let shared = assay_contracts::admin::AuthenticationPolicyUpsertRequest {
            policy_code: "office-hours".to_string(),
            policy_name: "Office hours".to_string(),
            priority: 10,
            enabled: true,
            effect: "require_specific_method".to_string(),
            effect_params: Some(assay_contracts::admin::RequiredMethodsPayload {
                methods: vec!["webauthn".to_string()],
                user_verification: true,
            }),
            application_ids: vec!["01990000-0000-7000-8000-000000000001".to_string()],
            user_ids: vec!["019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string()],
            ip_cidrs: vec!["10.0.0.0/8".to_string()],
            time_windows: vec![assay_contracts::admin::TimeWindowPayload {
                days: vec![1, 2, 3, 4, 5],
                start_minute: 540,
                end_minute: 1080,
                utc_offset_minutes: 540,
            }],
            requested_acr: vec!["urn:example:high".to_string()],
        };
        let json = serde_json::to_value(&shared).expect("serialize the shared contract");
        let api: AuthenticationPolicyUpsertRequest =
            serde_json::from_value(json).expect("the api must accept what web sends");

        assert_eq!(api.policy_code, shared.policy_code);
        assert_eq!(api.priority, shared.priority);
        assert_eq!(api.enabled, shared.enabled);
        assert_eq!(api.effect, shared.effect);
        let params = api.effect_params.expect("effect_params must survive");
        assert_eq!(params.methods, vec!["webauthn".to_string()]);
        assert!(params.user_verification);
        assert_eq!(api.application_ids, shared.application_ids);
        assert_eq!(api.user_ids, shared.user_ids);
        assert_eq!(api.ip_cidrs, shared.ip_cidrs);
        assert_eq!(api.requested_acr, shared.requested_acr);
        assert_eq!(api.time_windows.len(), 1);
        assert_eq!(api.time_windows[0].days, vec![1, 2, 3, 4, 5]);
        assert_eq!(api.time_windows[0].start_minute, 540);
        assert_eq!(api.time_windows[0].end_minute, 1080);
        assert_eq!(api.time_windows[0].utc_offset_minutes, 540);
    }

    /// The method checkboxes the admin console draws must be **exactly the stored values** of the api's
    /// `AuthenticationMethod` (so a chosen method is never rejected by the api).
    #[test]
    fn authentication_method_codes_match_the_contract() {
        use crate::domain::values::AuthenticationMethod;

        let expected = [
            AuthenticationMethod::Password,
            AuthenticationMethod::Totp,
            AuthenticationMethod::WebAuthn,
            AuthenticationMethod::RecoveryCode,
            AuthenticationMethod::EmailOtp,
            AuthenticationMethod::SmsOtp,
            AuthenticationMethod::ExternalIdp,
        ]
        .map(|m| m.as_str())
        .to_vec();
        assert_eq!(
            assay_contracts::admin::AUTHENTICATION_METHOD_CODES.to_vec(),
            expected
        );
        // Each code listed can actually be parsed (detects misspellings).
        for code in assay_contracts::admin::AUTHENTICATION_METHOD_CODES {
            assert!(
                AuthenticationMethod::parse(code).is_ok(),
                "unknown method code in the contract: {code}"
            );
        }
    }

    /// The login identifier type dropdown the admin console draws must be **exactly the stored values** of the api's
    /// `LoginIdentifierType` (AP16; so a chosen type is never rejected by the api).
    #[test]
    fn login_identifier_type_codes_match_the_contract() {
        use crate::domain::login_identifier::LoginIdentifierType;

        let expected = [
            LoginIdentifierType::Username,
            LoginIdentifierType::Email,
            LoginIdentifierType::PhoneNumber,
            LoginIdentifierType::EmployeeNumber,
        ]
        .map(|t| t.as_str())
        .to_vec();
        assert_eq!(
            assay_contracts::admin::LOGIN_IDENTIFIER_TYPE_CODES.to_vec(),
            expected
        );
        for code in assay_contracts::admin::LOGIN_IDENTIFIER_TYPE_CODES {
            assert!(
                LoginIdentifierType::parse(code).is_ok(),
                "unknown login identifier type code in the contract: {code}"
            );
        }
    }
}

#[cfg(test)]
mod console_support_contract_tests {
    use super::*;

    /// The JSON the api returns and the JSON web builds from the `assay_contracts` types are **identical down to the keys**.
    /// If a field is added on only one side, web's decoding fails or OpenAPI shows a shape different from reality.
    fn assert_same_json(api: &impl Serialize, shared: &impl Serialize) {
        assert_eq!(
            serde_json::to_value(api).expect("serialize the api dto"),
            serde_json::to_value(shared).expect("serialize the shared contract"),
        );
    }

    #[test]
    fn whoami_contract_matches_the_api_dto() {
        assert_same_json(
            &WhoamiResponse {
                user_id: "019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string(),
                name: Some("Admin".to_string()),
                preferred_username: None,
                tenant_name: Some("Corp".to_string()),
                permissions: vec!["idp.tenant.admin".to_string()],
            },
            &assay_contracts::admin::WhoamiResponse {
                user_id: "019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string(),
                name: Some("Admin".to_string()),
                preferred_username: None,
                tenant_name: Some("Corp".to_string()),
                permissions: vec!["idp.tenant.admin".to_string()],
            },
        );
    }

    #[test]
    fn client_status_contract_matches_the_api_dto() {
        assert_same_json(
            &ClientStatusResponse {
                client_id: "cid".to_string(),
                app_name: "App".to_string(),
                status: "ACTIVE".to_string(),
                scopes: vec!["openid".to_string()],
                last_used_at: None,
            },
            &assay_contracts::admin::ClientStatusResponse {
                client_id: "cid".to_string(),
                app_name: "App".to_string(),
                status: "ACTIVE".to_string(),
                scopes: vec!["openid".to_string()],
                last_used_at: None,
            },
        );
    }

    #[test]
    fn available_permissions_contract_matches_the_api_dto() {
        assert_same_json(
            &AvailablePermissionsResponse {
                codes: vec!["idp.users:read".to_string()],
            },
            &assay_contracts::admin::AvailablePermissionsResponse {
                codes: vec!["idp.users:read".to_string()],
            },
        );
    }

    #[test]
    fn user_summary_contract_matches_the_api_dto() {
        assert_same_json(
            &UserSummaryResponse {
                id: "019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string(),
                sub: "sub-1".to_string(),
                email: "a@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("alice".to_string()),
                name: None,
                status: "ACTIVE".to_string(),
            },
            &assay_contracts::admin::UserSummaryResponse {
                id: "019f8ea8-f5dd-7fc7-ac15-a7d4337e4610".to_string(),
                sub: "sub-1".to_string(),
                email: "a@example.com".to_string(),
                email_verified: true,
                preferred_username: Some("alice".to_string()),
                name: None,
                status: "ACTIVE".to_string(),
            },
        );
    }
}
