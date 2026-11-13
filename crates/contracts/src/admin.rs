//! DTO contracts shared when the admin console (web) calls api's JSON admin API (`/admin/*`).
//!
//! These are inputs and outputs of the admin API protected by api's `RequirePerms<…>`, and web calls them with an
//! admin token (`Authorization: Bearer`) exchanged from the SSO session (ADR-0007 §4 / ADR-0037). This crate
//! has no `utoipa`, so routes exposed in OpenAPI have a same-shaped DTO with `utoipa` on the api side, and
//! shape mismatches are caught by api tests (`…_contract_matches_the_api_dto` etc.).

use serde::{Deserialize, Serialize};

/// Response of `GET /admin/whoami`. Being able to access it at all means "a valid admin token + holding `idp.tenant.admin`".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResponse {
    /// Internal ID of the authorized admin user (UUID string).
    pub user_id: String,
    /// Display name (`None` if unset). Shown in the admin console header.
    #[serde(default)]
    pub name: Option<String>,
    /// Login identifier (`None` if unset). Used in the header in place of a missing display name.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Display name of the route's tenant (`/{tenant_id}/...`). Returned so every admin console screen header
    /// can show "which tenant you are operating on now".
    ///
    /// `#[serde(default)]` so decoding does not fail during a rolling deploy mixing web with an old api
    /// (one that does not return this field) (when missing, only the name in the header is omitted).
    #[serde(default)]
    pub tenant_name: Option<String>,
    /// Permission codes the caller can **actually exercise** in this tenant (implications expanded).
    ///
    /// Used by the admin console to "not show links to screens it cannot enter". Implications are expanded on the
    /// api side, so web needs only a simple containment check (keeping a single source of the decision in core;
    /// the same reason as the filtering in `handlers::admin_permissions`).
    ///
    /// `#[serde(default)]` so decoding does not fail during a rolling deploy mixed with an old api (one not
    /// returning this field). **When missing it is empty**, so consumers must treat it as "cannot filter",
    /// not "empty = no permissions", and not hide too much of the menu.
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// User summary (response of `GET /admin/users?q=` search and `GET /admin/users/{id}`). Used by the admin console's
/// permission screen to identify and show the target user. No sensitive data such as password hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummaryResponse {
    pub id: String,
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// `ACTIVE` / `DISABLED` etc.
    pub status: String,
}

/// Client status (`GET /admin/clients/status`). Status, scopes, last used time.
/// The last used time comes from the audit log (latest successful token/code issuance). `None` if never used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientStatusResponse {
    pub client_id: String,
    pub app_name: String,
    /// `ACTIVE` / `DISABLED`.
    pub status: String,
    pub scopes: Vec<String>,
    /// RFC3339 string. `None` if never used.
    #[serde(default)]
    pub last_used_at: Option<String>,
}

/// Grantable permission codes (`GET /admin/permissions`; from the `permissions` master).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailablePermissionsResponse {
    pub codes: Vec<String>,
}

/// A user's held permission codes (`GET/POST /admin/users/{id}/permissions` and the revoke response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPermissionsResponse {
    pub user_id: String,
    pub permission_codes: Vec<String>,
}

/// Public representation of a signing key (response element of `GET /admin/signing-keys`, `POST /admin/signing-keys` etc.).
/// No private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Request to generate a new signing key (`POST /admin/signing-keys`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSigningKeyRequest {
    /// `RS256` or `ES256`.
    pub algorithm: String,
}

/// SAML metadata import request (paste metadata XML to get candidate registration values).
/// Used for both SP (client) side and external IdP side imports (the input shape is the same `EntityDescriptor`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlMetadataImportRequest {
    /// SAML metadata XML (`EntityDescriptor`).
    pub metadata_xml: String,
}

/// SAML SP (client) registration request (`POST /admin/saml-service-providers`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProviderRegisterRequest {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    /// NameID format (empty means the default persistent).
    #[serde(default)]
    pub name_id_format: String,
    /// Signing/encryption certificate (optional).
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// SAML SP (client) update request (`PUT /admin/saml-service-providers/{id}`).
/// Takes the same fields as registration and replaces the given SP's content (the tenant is not changed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProviderUpdateRequest {
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    /// NameID format (empty means the default persistent).
    #[serde(default)]
    pub name_id_format: String,
    /// Signing/encryption certificate (optional).
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
}

/// Admin API representation of a SAML SP (client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlServiceProviderResponse {
    pub id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    pub name_id_format: String,
    /// Signing/encryption certificate (optional; `None` if not set). Used as the edit form's initial value.
    #[serde(default)]
    pub x509_certificate: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Response of SAML SP metadata import (initial values of the registration form).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSpMetadataImportResponse {
    #[serde(default)]
    pub display_name: String,
    pub entity_id: String,
    pub acs_url: String,
    #[serde(default)]
    pub name_id_format: String,
    #[serde(default)]
    pub x509_certificate: String,
}

/// Response of external SAML IdP metadata import (initial values of the external IdP registration form; AP12).
///
/// `entity_id` becomes the `issuer` at registration (the value matched exactly against the assertion's `<Issuer>`).
///
/// The api side has same-shaped DTOs (`SamlIdpMetadataImportRequest` / `SamlIdpMetadataImportResponse`)
/// with `utoipa` (task #124). Mismatches are caught by an api test (`saml_metadata_import_contract_matches_the_api_dto`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlIdpMetadataImportResponse {
    #[serde(default)]
    pub display_name: String,
    pub entity_id: String,
    pub sso_url: String,
    /// Certificates for signature verification. **Several may be returned** (during certificate rollover, old and new are both valid).
    #[serde(default)]
    pub certificates: Vec<String>,
    #[serde(default)]
    pub name_id_format: String,
}

/// Request to import an external OIDC IdP's discovery (`POST /admin/external-idps/import-discovery`; task #77).
///
/// The api side has same-shaped DTOs (`OidcDiscoveryImportRequest` / `OidcDiscoveryImportResponse`)
/// with `utoipa`. Mismatches are caught by an api test (`discovery_import_contract_matches_the_api_dto`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryImportRequest {
    pub issuer: String,
}

/// Response of importing an external OIDC IdP's discovery (initial values of the external IdP registration form; not registered).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryImportResponse {
    /// The document's `issuer` (the one that matched the input exactly).
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

// ── Authentication policies (AP1; contract for the admin console calling `/admin/authentication-policies`) ──
//
// The api side has same-shaped DTOs in `presentation::dto` (those carry `utoipa` to appear in OpenAPI).
// **If the two diverge, saving from the admin screen breaks**, so an api test
// (`authentication_policy_contract_matches_the_api_dto`) round-trips JSON to pin the shapes together.

/// Admin API representation of an authentication policy (element of `GET /admin/authentication-policies`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPolicyResponse {
    pub id: String,
    pub policy_code: String,
    pub policy_name: String,
    /// Evaluation order (ascending = smaller has priority).
    pub priority: i32,
    pub enabled: bool,
    /// `allow` / `deny` / `require_mfa` / `require_specific_method`.
    pub effect: String,
    /// Requirement of `require_specific_method` (`None` for other effects).
    #[serde(default)]
    pub effect_params: Option<RequiredMethodsPayload>,
    /// Internal IDs of target apps (empty = all apps; decision 5 of ADR-0054).
    #[serde(default)]
    pub application_ids: Vec<String>,
    /// Internal IDs of target users (empty = all users).
    #[serde(default)]
    pub user_ids: Vec<String>,
    /// Target network zones (CIDR notation; empty = all networks).
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    /// Applicable time windows (empty = always).
    #[serde(default)]
    pub time_windows: Vec<TimeWindowPayload>,
    /// `acr_values` condition of the authorization request (empty = regardless of the request).
    #[serde(default)]
    pub requested_acr: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Authentication policy list (ascending priority).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPoliciesResponse {
    pub policies: Vec<AuthenticationPolicyResponse>,
    /// Default effect when no policy matches (`allow` / `deny`). **This tenant's value**
    /// (ADR-0058 §4). Policies mean something only combined with this value, so it is in the same response as the list:
    /// web only renders it and holds no value itself (ADR-0058 §10).
    pub default_effect: String,
}

/// Request to create or update (full replacement) an authentication policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPolicyUpsertRequest {
    pub policy_code: String,
    pub policy_name: String,
    pub priority: i32,
    pub enabled: bool,
    pub effect: String,
    #[serde(default)]
    pub effect_params: Option<RequiredMethodsPayload>,
    /// Internal IDs of target apps (empty = all apps; decision 5 of ADR-0054).
    #[serde(default)]
    pub application_ids: Vec<String>,
    #[serde(default)]
    pub user_ids: Vec<String>,
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    #[serde(default)]
    pub time_windows: Vec<TimeWindowPayload>,
    #[serde(default)]
    pub requested_acr: Vec<String>,
}

/// Authentication method codes selectable for `require_specific_method` (display order).
///
/// The real thing is api's `AuthenticationMethod` (stored string values); this is **a copy of that vocabulary**.
/// web touches neither the DB nor core, so it needs this list to render the options. If they diverge, a method chosen
/// on the admin screen is rejected by api, so an api test (`authentication_method_codes_match_the_contract`)
/// pins it to the enum.
pub const AUTHENTICATION_METHOD_CODES: &[&str] = &[
    "password",
    "totp",
    "webauthn",
    "recovery_code",
    "email_otp",
    "sms_otp",
    "external_idp",
];

/// Login identifier type codes (display order; AP8 / AP16).
///
/// The real thing is api's `LoginIdentifierType` (stored string values); this is **a copy of that vocabulary**.
/// web touches neither the DB nor core, so it needs this list to render the type dropdown on the admin screen.
/// If they diverge, a type chosen on screen is rejected by api, so an api test
/// (`login_identifier_type_codes_match_the_contract`) pins it to the enum.
pub const LOGIN_IDENTIFIER_TYPE_CODES: &[&str] =
    &["username", "email", "phone_number", "employee_number"];

/// Requirement of `require_specific_method`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredMethodsPayload {
    /// Allowed authentication methods. Satisfied by using **any one** of them.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Whether WebAuthn User Verification (biometric, PIN) is required.
    #[serde(default)]
    pub user_verification: bool,
}

/// Applicable time window. The time zone is a fixed UTC offset (minutes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindowPayload {
    /// Target weekdays (0 = Sunday … 6 = Saturday; empty = every day).
    #[serde(default)]
    pub days: Vec<u8>,
    /// Start time (minutes from 0:00; 0..1439).
    pub start_minute: u16,
    /// End time (same; if smaller than the start, the window crosses midnight).
    pub end_minute: u16,
    /// UTC offset (minutes; e.g. JST = 540).
    #[serde(default)]
    pub utc_offset_minutes: i16,
}

/// Admin token exchange request (`POST /internal/admin/token`; ADR-0037).
///
/// The admin console (web) passes the SSO session cookie value here and receives an access token for calling
/// api's admin API. **There is no route forwarding the cookie itself to api's admin API.**
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementTokenRequest {
    /// Target tenant (`/internal/*` has no tenant in the path, so it is passed in the DTO).
    pub tenant_id: String,
    /// Plain value of the SSO session cookie.
    pub sso_session_id: String,
}

/// Admin token exchange response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    /// Permission codes the principal held at issuance. The console uses them to tailor screens and operations.
    pub permission_codes: Vec<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
}

/// A client's held permission codes (`GET/POST/DELETE /admin/clients/{client_id}/permissions`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPermissionsResponse {
    pub client_id: String,
    pub permission_codes: Vec<String>,
}

/// Maximum length (characters) of the admin note on an account (person or service account; ADR-0063 / ADR-0065).
///
/// api's validation (`domain::account_note`) and web's input field (`maxlength`) read the same value. Changing only
/// one side means it can be typed on screen but is refused on save.
pub const ACCOUNT_NOTE_MAX_LEN: usize = 2000;
