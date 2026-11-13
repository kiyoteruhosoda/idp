//! HTTP client to the api (ADR-0007).
//!
//! web has no DB; all data retrieval and manipulation goes through the api's HTTP endpoints. This module is
//! the only gateway for that. Internal authentication (`/internal/authenticate*`) is called with the service auth token
//! (`X-Internal-Auth-Token`). DTOs are shared with the api in `assay-contracts`, guaranteeing contract consistency at compile time.
//!
//! `/admin/*` (JSON admin API) is called via the tenant route (`/{tenant_id}/admin/*`; ADR-0009 §6).
//! The tenant id is passed explicitly by callers from web's route (`crate::tenant::WebTenant`) (MT13).

use crate::admin_dto::{
    AccountListView, ApiErrorBody, AuditLogView, ClientCreatedView, ClientListView,
    ClientSecretView, ClientView, InvitationCreatedView, MemberView, ServiceAccountView,
    UserCreatedView,
};
use assay_contracts::admin::{
    AuthenticationPoliciesResponse, AuthenticationPolicyResponse,
    AuthenticationPolicyUpsertRequest, AvailablePermissionsResponse, ClientPermissionsResponse,
    ClientStatusResponse, ManagementTokenRequest, ManagementTokenResponse,
    OidcDiscoveryImportRequest, OidcDiscoveryImportResponse, SamlIdpMetadataImportResponse,
    SamlServiceProviderRegisterRequest, SamlServiceProviderResponse,
    SamlServiceProviderUpdateRequest, SamlSpMetadataImportResponse, UserPermissionsResponse,
    UserSummaryResponse, WhoamiResponse,
};
use assay_contracts::application_log::{
    ApplicationLogEntryResponse, ApplicationLogIngestRequest, ApplicationLogIngestResponse,
    ApplicationLogPayload,
};
use assay_contracts::auth::{
    InternalAccountSetupDescribeRequest, InternalAccountSetupDescribeResponse,
    InternalAccountSetupPasskeyBeginRequest, InternalAccountSetupPasskeyBeginResponse,
    InternalAccountSetupPasskeyCompleteRequest, InternalAccountSetupPasskeyCompleteResponse,
    InternalAdminAuthenticateRequest, InternalAdminAuthenticateResponse,
    InternalAdminChangePasswordRequest, InternalAdminChangePasswordResponse,
    InternalAdminPasskeyLoginCompleteRequest, InternalAdminPasskeyLoginCompleteResponse,
    InternalAuthenticateRequest, InternalAuthenticateResponse, InternalAuthorizeContinueRequest,
    InternalAuthorizeLoginContextRequest, InternalAuthorizeLoginContextResponse,
    InternalAuthorizeResumeRequest, InternalAuthorizeResumeResponse, InternalChangePasswordRequest,
    InternalChangePasswordResponse, InternalConsentApproveRequest, InternalConsentApproveResponse,
    InternalConsentDenyRequest, InternalConsentDenyResponse, InternalConsentInfoResponse,
    InternalLogoutRequest, InternalPasskeyDeleteRequest, InternalPasskeyDeleteResponse,
    InternalPasskeyListRequest, InternalPasskeyListResponse, InternalPasskeyLoginBeginRequest,
    InternalPasskeyLoginBeginResponse, InternalPasskeyLoginCompleteRequest,
    InternalPasskeyLoginCompleteResponse, InternalPasskeyRegisterBeginRequest,
    InternalPasskeyRegisterBeginResponse, InternalPasskeyRegisterCompleteRequest,
    InternalPasskeyRegisterCompleteResponse, InternalPasswordResetCompleteRequest,
    InternalPasswordResetCompleteResponse, InternalPasswordResetRequestRequest,
    InternalPasswordResetRequestResponse, InternalPortalAuthenticateRequest,
    InternalPortalAuthenticateResponse, InternalPortalChangePasswordRequest,
    InternalPortalChangePasswordResponse, InternalPortalMfaRequest, InternalPortalMfaResponse,
    InternalPortalPasskeyLoginCompleteRequest, InternalPortalPasskeyLoginCompleteResponse,
    InternalRpLogoutRequest, InternalRpLogoutResponse, InternalSamlResumeRequest,
    InternalSamlResumeResponse, InternalTotpConfirmRequest, InternalTotpConfirmResponse,
    InternalTotpDeleteRequest, InternalTotpDeleteResponse, InternalTotpSetupRequest,
    InternalTotpSetupResponse, InternalVerifyTotpRequest, InternalVerifyTotpResponse,
    UNKNOWN_TENANT_ERROR_CODE,
};
use assay_contracts::runtime_settings::{
    SharedRuntimeSettingsResponse, SHARED_RUNTIME_SETTINGS_PATH,
};
use assay_contracts::version::SchemaVersionInfo;
use reqwest::Method;
use std::collections::HashMap;

/// Header name of the service auth token (must match the api's `require_service_token`).
use assay_contracts::internal_auth::SERVICE_TOKEN_HEADER;
/// Header name for propagating correlation_id (requestId) (must match the api's correlation middleware).
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Result of consuming an email verification link (SEC6b).
pub enum VerifyEmailResult {
    /// `email_verified` was set.
    Verified,
    /// The token is invalid, expired, used, or for another tenant.
    InvalidOrExpired,
}

/// Failure of an `/internal/*` call (MT28).
///
/// `/internal/*` has no tenant prefix, so it doesn't pass through the api's `TenantResolver` middleware;
/// the api judges the tenant's existence and status from the body's `tenant_id` (ADR-0009 §8).
/// **Only that rejection is distinguished from other failures.** Otherwise, requests whose URL merely has a wrong tenant ID
/// would become 502 as "a web implementation/configuration error", inconsistent with other tenant-route responses (404).
pub enum InternalCallError {
    /// The api could not resolve the tenant (nonexistent or `DISABLED`). Callers fall back to the 404 screen.
    UnknownTenant,
    /// Anything else -- the api is unreachable, the response can't be decoded, an unexpected status.
    /// It can't be caused by user input (a web implementation/configuration error or an api failure), so it becomes 502.
    Failed(String),
}

impl InternalCallError {
    fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }
}

/// Representation for operational logs (operational language = English; `CLAUDE.md` "Scope of internationalization").
impl std::fmt::Display for InternalCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTenant => write!(f, "unknown or disabled tenant"),
            Self::Failed(m) => write!(f, "{m}"),
        }
    }
}

impl std::fmt::Debug for InternalCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for InternalCallError {}

/// Whether the api's error body means "could not resolve the tenant" (MT28).
///
/// Decided by matching [`UNKNOWN_TENANT_ERROR_CODE`], defined once in `contracts`. The human-readable
/// description is not used because it would silently break the moment the wording is edited. When the body can't be read
/// as JSON, it falls back to "other failure" (fail-safe; doesn't show the 404 screen by mistake).
fn is_unknown_tenant_error(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error")?.as_str().map(str::to_string))
        .is_some_and(|code| code == UNKNOWN_TENANT_ERROR_CODE)
}

/// Error for mapping failures of `/admin/*` calls to web screen behavior (ADR-0007 §4).
pub enum AdminApiError {
    /// Unauthenticated or SSO expired (401) -> redirect to the login screen.
    Unauthorized,
    /// Insufficient permission (403) -> 403 screen.
    Forbidden,
    /// Not found (404).
    NotFound,
    /// Validation error (400). The message is shown.
    Validation(String),
    /// Conflict (409). The message is shown.
    Conflict(String),
    /// Network/decode error or unexpected status.
    Transport(String),
}

/// Representation for operational logs (operational language = English; `CLAUDE.md` "Scope of internationalization").
///
/// Wording shown on screen is resolved by each handler from translation keys. What this returns is **the reason for logs**,
/// placed on the type so each handler doesn't rewrite the same `match`.
impl std::fmt::Display for AdminApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Forbidden => write!(f, "forbidden"),
            Self::NotFound => write!(f, "not_found"),
            Self::Validation(m) => write!(f, "validation: {m}"),
            Self::Conflict(m) => write!(f, "conflict: {m}"),
            Self::Transport(m) => write!(f, "transport: {m}"),
        }
    }
}

/// Result of forwarding an admin's SSO cookie to the api's `/admin/*` (`RequirePerms<IdpAdmin>`) (ADR-0007 §4).
pub enum AdminSession {
    /// Valid SSO + holds tenant admin permission (`idp.tenant.admin` / `idp.system.admin`).
    /// Returns the context shown in the admin console header (the admin's display label and the current tenant's display name).
    Authenticated(AdminIdentity),
    /// Unauthenticated or SSO expired (redirect to the login screen).
    Unauthenticated,
    /// Authenticated but without tenant admin permission (403 screen).
    Forbidden,
    /// The api could not resolve the tenant (404). The route's `{tenant_id}` is unknown, `DISABLED`, or an invalid UUID
    /// (the api's `resolve_tenant` maps all of these to 404). web only validates the UUID format, so
    /// admin console URLs of nonexistent tenants land here.
    NotFound,
    /// api call failure (configuration/outage).
    Error,
}

/// Maps non-200 whoami responses to the session state. 200 (which involves decoding the body) is handled by the caller.
///
/// The point is not including 404 in `Error` (= not falling back to 502). A URL of a nonexistent tenant is not a gateway
/// failure but "that page doesn't exist", and the screen must show 404 too.
fn admin_session_for_status(status: reqwest::StatusCode) -> AdminSession {
    match status {
        reqwest::StatusCode::UNAUTHORIZED => AdminSession::Unauthenticated,
        reqwest::StatusCode::FORBIDDEN => AdminSession::Forbidden,
        reqwest::StatusCode::NOT_FOUND => AdminSession::NotFound,
        _ => AdminSession::Error,
    }
}

/// Identity of the authenticated admin (used for display in the admin console's common header).
#[derive(Debug, Clone)]
pub struct AdminIdentity {
    /// The admin's display label (display name -> login identifier -> internal ID).
    pub label: String,
    /// Display name of the current tenant. `None` only if the api didn't return it.
    pub tenant_name: Option<String>,
    /// Permission codes this admin can exercise in this tenant (implications already expanded by the api).
    /// Used to show/hide menu items. **Not authorization** (the api decides what is actually allowed every time).
    permissions: Vec<String>,
}

impl AdminIdentity {
    /// Borrow for passing to the common layout. The decision itself is held by
    /// [`crate::templates::ConsoleAdmin::can`] as the single source.
    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }

    #[cfg(test)]
    pub(crate) fn for_test(label: &str, tenant_name: Option<&str>) -> Self {
        Self {
            label: label.to_string(),
            tenant_name: tenant_name.map(str::to_string),
            permissions: Vec::new(),
        }
    }
}

/// Maps the whoami response to the header display context.
fn admin_identity(mut w: WhoamiResponse) -> AdminIdentity {
    let tenant_name = non_empty(w.tenant_name.take());
    let permissions = std::mem::take(&mut w.permissions);
    AdminIdentity {
        label: admin_display_label(w),
        tenant_name,
        permissions,
    }
}

/// Decides the display label shown in the admin console header. Takes the first non-empty value in the order display name (`name`)
/// -> login identifier (`preferred_username`) -> internal ID (`user_id`).
fn admin_display_label(w: WhoamiResponse) -> String {
    non_empty(w.name)
        .or_else(|| non_empty(w.preferred_username))
        .unwrap_or(w.user_id)
}

/// Treats whitespace-only values as "unset".
fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// HTTP client to the api. `reqwest::Client` contains a connection pool, so cloning is cheap.
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
    service_token: String,
    /// Display language passed to the api (`Accept-Language`). If `None`, nothing is sent and the api uses the default `ja`.
    ///
    /// web decides the display language, and the api only looks at `Accept-Language` (`CLAUDE.md` "Internationalization").
    /// Sending the language web decided makes the screen and the api's error messages the same language.
    /// **Cookies and the `lang` query are not sent to the api** (the boundary ensuring the api doesn't look at them).
    accept_language: Option<&'static str>,
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>, service_token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            service_token: service_token.into(),
            accept_language: None,
        }
    }

    /// Returns a client carrying the display language (MT20). Subsequent api calls get `Accept-Language`,
    /// and the api's error messages arrive in the same language as the screen. `reqwest::Client` wraps an Arc,
    /// so cloning is cheap and it may be created per request.
    pub fn for_locale(&self, locale: crate::i18n::Locale) -> Self {
        Self {
            accept_language: Some(locale.as_tag()),
            ..self.clone()
        }
    }

    /// Attaches `Accept-Language` (if decided), plus the current request's trusted country (task #895) and the device mark
    /// (task #916).
    fn with_language(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let request = match self.accept_language {
            Some(tag) => request.header(reqwest::header::ACCEPT_LANGUAGE, tag),
            None => request,
        };
        let request = match crate::client_country::current() {
            Some(country) => request.header(assay_contracts::auth::CLIENT_COUNTRY_HEADER, country),
            None => request,
        };
        // The current browser's device mark (task #916). The api decides "is it a registered device" right at login.
        match crate::device_observation::current_device_token() {
            Some(token) => request.header(assay_contracts::auth::CLIENT_DEVICE_HEADER, token),
            None => request,
        }
    }

    /// Fetches SAML IdP metadata from the api.
    ///
    /// Rather than sending the browser directly to the api origin, it is used from the download use case web provides.
    /// Communication with the api is concentrated in this client, so HTTP details don't leak
    /// into the presentation layer.
    pub async fn fetch_saml_idp_metadata(
        &self,
        correlation_id: &str,
        tenant_id: &str,
    ) -> anyhow::Result<String> {
        self.http
            .get(format!("{}/{tenant_id}/saml/metadata", self.base_url))
            .header(REQUEST_ID_HEADER, correlation_id)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
            .map_err(Into::into)
    }

    /// Resumes the authorization flow (`POST /internal/authorize/resume`, ADR-0018 decision 2). Passes the single-use handle received
    /// in the handoff from `/authorize` and our domain's SSO cookie value, delegating the SSO decision and code issuance
    /// to the api.
    pub async fn authorize_resume(
        &self,
        correlation_id: &str,
        req: &InternalAuthorizeResumeRequest,
    ) -> Result<InternalAuthorizeResumeResponse, InternalCallError> {
        self.post_internal("/internal/authorize/resume", correlation_id, req)
            .await
    }

    /// Continues the authorization flow (`POST /internal/authorize/continue`). When the login screen is reopened,
    /// passes the local `auth_session_id` and SSO cookie value to continue from an SSO established in another tab.
    pub async fn authorize_continue(
        &self,
        correlation_id: &str,
        req: &InternalAuthorizeContinueRequest,
    ) -> Result<InternalAuthorizeResumeResponse, InternalCallError> {
        self.post_internal("/internal/authorize/continue", correlation_id, req)
            .await
    }

    /// Login screen context (`POST /internal/authorize/login-context`; G12). Looks up the `login_hint` / `ui_locales`
    /// brought in by the in-progress authorization request from `auth_session_id`.
    pub async fn authorize_login_context(
        &self,
        correlation_id: &str,
        req: &InternalAuthorizeLoginContextRequest,
    ) -> Result<InternalAuthorizeLoginContextResponse, InternalCallError> {
        self.post_internal("/internal/authorize/login-context", correlation_id, req)
            .await
    }

    /// Resumes the SAML SSO flow (`POST /internal/saml/resume`). Passes the single-use handle received in the handoff from `/saml/sso`
    /// (or `saml_request_id` after login) and our domain's SSO cookie value,
    /// delegating the SSO decision and issuance of the signed SAML Response to the api.
    pub async fn saml_resume(
        &self,
        correlation_id: &str,
        req: &InternalSamlResumeRequest,
    ) -> Result<InternalSamlResumeResponse, InternalCallError> {
        self.post_internal("/internal/saml/resume", correlation_id, req)
            .await
    }

    /// RP-initiated logout (`POST /internal/logout/rp`, ADR-0018 decision 2). Delegates SSO revocation, back-channel
    /// notification and building the post-logout redirect URL to the api (web discards the cookies).
    pub async fn rp_logout(
        &self,
        correlation_id: &str,
        req: &InternalRpLogoutRequest,
    ) -> Result<InternalRpLogoutResponse, InternalCallError> {
        self.post_internal("/internal/logout/rp", correlation_id, req)
            .await
    }

    /// OIDC login authentication (`POST /internal/authenticate`).
    pub async fn authenticate(
        &self,
        correlation_id: &str,
        req: &InternalAuthenticateRequest,
    ) -> Result<InternalAuthenticateResponse, InternalCallError> {
        self.post_internal("/internal/authenticate", correlation_id, req)
            .await
    }

    /// Forced password change (`POST /internal/change-password`, ADR-0009 §5).
    pub async fn change_password(
        &self,
        correlation_id: &str,
        req: &InternalChangePasswordRequest,
    ) -> Result<InternalChangePasswordResponse, InternalCallError> {
        self.post_internal("/internal/change-password", correlation_id, req)
            .await
    }

    /// Admin console authentication (`POST /internal/authenticate/admin`).
    pub async fn authenticate_admin(
        &self,
        correlation_id: &str,
        req: &InternalAdminAuthenticateRequest,
    ) -> Result<InternalAdminAuthenticateResponse, InternalCallError> {
        self.post_internal("/internal/authenticate/admin", correlation_id, req)
            .await
    }

    /// End-user portal authentication (`POST /internal/authenticate/portal`).
    pub async fn authenticate_portal(
        &self,
        correlation_id: &str,
        req: &InternalPortalAuthenticateRequest,
    ) -> Result<InternalPortalAuthenticateResponse, InternalCallError> {
        self.post_internal("/internal/authenticate/portal", correlation_id, req)
            .await
    }

    /// Portal TOTP verification (`POST /internal/authenticate/portal/mfa`).
    pub async fn authenticate_portal_mfa(
        &self,
        correlation_id: &str,
        req: &InternalPortalMfaRequest,
    ) -> Result<InternalPortalMfaResponse, InternalCallError> {
        self.post_internal("/internal/authenticate/portal/mfa", correlation_id, req)
            .await
    }

    /// Portal forced password change (`POST /internal/authenticate/portal/change-password`, ADR-0009 §5).
    pub async fn authenticate_portal_change_password(
        &self,
        correlation_id: &str,
        req: &InternalPortalChangePasswordRequest,
    ) -> Result<InternalPortalChangePasswordResponse, InternalCallError> {
        self.post_internal(
            "/internal/authenticate/portal/change-password",
            correlation_id,
            req,
        )
        .await
    }

    /// Admin console forced password change (`POST /internal/authenticate/admin/change-password`).
    pub async fn admin_change_password(
        &self,
        correlation_id: &str,
        req: &InternalAdminChangePasswordRequest,
    ) -> Result<InternalAdminChangePasswordResponse, InternalCallError> {
        self.post_internal(
            "/internal/authenticate/admin/change-password",
            correlation_id,
            req,
        )
        .await
    }

    /// Password reset request (`POST /internal/password-reset/request`; MT18).
    pub async fn password_reset_request(
        &self,
        correlation_id: &str,
        req: &InternalPasswordResetRequestRequest,
    ) -> Result<InternalPasswordResetRequestResponse, InternalCallError> {
        self.post_internal("/internal/password-reset/request", correlation_id, req)
            .await
    }

    /// Password reset execution (`POST /internal/password-reset/complete`; MT18).
    pub async fn password_reset_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasswordResetCompleteRequest,
    ) -> Result<InternalPasswordResetCompleteResponse, InternalCallError> {
        self.post_internal("/internal/password-reset/complete", correlation_id, req)
            .await
    }

    /// Reads the contents of an account setup link (`POST /internal/account-setup/describe`; ADR-0062).
    /// ⚠ **Only reads; does not consume.**
    pub async fn account_setup_describe(
        &self,
        correlation_id: &str,
        req: &InternalAccountSetupDescribeRequest,
    ) -> Result<InternalAccountSetupDescribeResponse, InternalCallError> {
        self.post_internal("/internal/account-setup/describe", correlation_id, req)
            .await
    }

    /// Begins passkey registration from a setup link (`POST /internal/account-setup/passkey/begin`).
    pub async fn account_setup_passkey_begin(
        &self,
        correlation_id: &str,
        req: &InternalAccountSetupPasskeyBeginRequest,
    ) -> Result<InternalAccountSetupPasskeyBeginResponse, InternalCallError> {
        self.post_internal("/internal/account-setup/passkey/begin", correlation_id, req)
            .await
    }

    /// Completes passkey registration from a setup link (`POST /internal/account-setup/passkey/complete`).
    pub async fn account_setup_passkey_complete(
        &self,
        correlation_id: &str,
        req: &InternalAccountSetupPasskeyCompleteRequest,
    ) -> Result<InternalAccountSetupPasskeyCompleteResponse, InternalCallError> {
        self.post_internal(
            "/internal/account-setup/passkey/complete",
            correlation_id,
            req,
        )
        .await
    }

    /// Consumes an email verification link (`POST /{tenant_id}/auth/verify-email`; SEC6b). A public endpoint,
    /// so no service token or SSO is needed (the plaintext token itself is the capability).
    pub async fn verify_email(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        token: &str,
    ) -> anyhow::Result<VerifyEmailResult> {
        let response = self
            .http
            .post(format!("{}/{}/auth/verify-email", self.base_url, tenant_id))
            .header(REQUEST_ID_HEADER, correlation_id)
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request to api /auth/verify-email failed: {e}"))?;
        match response.status() {
            s if s.is_success() => Ok(VerifyEmailResult::Verified),
            reqwest::StatusCode::BAD_REQUEST => Ok(VerifyEmailResult::InvalidOrExpired),
            other => anyhow::bail!("api /auth/verify-email returned status {other}"),
        }
    }

    /// Logout (`POST /internal/logout`). The api revokes the SSO session (web expires the cookies).
    pub async fn logout(
        &self,
        correlation_id: &str,
        req: &InternalLogoutRequest,
    ) -> anyhow::Result<()> {
        let response = self
            .http
            .post(format!("{}/internal/logout", self.base_url))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .header(REQUEST_ID_HEADER, correlation_id)
            .json(req)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request to api /internal/logout failed: {e}"))?;
        if !response.status().is_success() {
            anyhow::bail!("api /internal/logout returned status {}", response.status());
        }
        Ok(())
    }

    /// Fetches consent screen info (`GET /internal/consent-info`). `tenant_id` is the flow's tenant (required;
    /// the api rejects missing or invalid values with 400).
    pub async fn consent_info(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        auth_session_id: &str,
    ) -> Result<InternalConsentInfoResponse, InternalCallError> {
        let response = self
            .http
            .get(format!("{}/internal/consent-info", self.base_url))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .header(REQUEST_ID_HEADER, correlation_id)
            .query(&[
                ("tenant_id", tenant_id),
                ("auth_session_id", auth_session_id),
            ])
            .send()
            .await
            .map_err(|e| {
                InternalCallError::failed(format!(
                    "request to api /internal/consent-info failed: {e}"
                ))
            })?;
        // The only GET under `/internal/*`. Like the POST side (`post_internal`), tenant resolution failures are
        // distinguished (otherwise only this screen would stay at 502 for nonexistent tenants).
        let status = response.status();
        if !status.is_success() {
            if status == reqwest::StatusCode::BAD_REQUEST
                && is_unknown_tenant_error(&response.text().await.unwrap_or_default())
            {
                return Err(InternalCallError::UnknownTenant);
            }
            return Err(InternalCallError::failed(format!(
                "api /internal/consent-info returned unexpected status {status}"
            )));
        }
        response
            .json::<InternalConsentInfoResponse>()
            .await
            .map_err(|e| {
                InternalCallError::failed(format!("failed to decode consent-info response: {e}"))
            })
    }

    /// Consent approval (`POST /internal/consent/approve`).
    pub async fn consent_approve(
        &self,
        correlation_id: &str,
        req: &InternalConsentApproveRequest,
    ) -> Result<InternalConsentApproveResponse, InternalCallError> {
        self.post_internal("/internal/consent/approve", correlation_id, req)
            .await
    }

    /// Consent denial (`POST /internal/consent/deny`).
    pub async fn consent_deny(
        &self,
        correlation_id: &str,
        req: &InternalConsentDenyRequest,
    ) -> Result<InternalConsentDenyResponse, InternalCallError> {
        self.post_internal("/internal/consent/deny", correlation_id, req)
            .await
    }

    /// Begins TOTP setup (`POST /internal/mfa/totp/setup`). Returns the QR URI and the raw secret.
    pub async fn totp_setup(
        &self,
        correlation_id: &str,
        req: &InternalTotpSetupRequest,
    ) -> Result<InternalTotpSetupResponse, InternalCallError> {
        self.post_internal("/internal/mfa/totp/setup", correlation_id, req)
            .await
    }

    /// TOTP confirmation (`POST /internal/mfa/totp/confirm`). Activates with a 6-digit code.
    pub async fn totp_confirm(
        &self,
        correlation_id: &str,
        req: &InternalTotpConfirmRequest,
    ) -> Result<InternalTotpConfirmResponse, InternalCallError> {
        self.post_internal("/internal/mfa/totp/confirm", correlation_id, req)
            .await
    }

    /// TOTP deletion (`POST /internal/mfa/totp/delete`). Disables MFA.
    pub async fn totp_delete(
        &self,
        correlation_id: &str,
        req: &InternalTotpDeleteRequest,
    ) -> Result<InternalTotpDeleteResponse, InternalCallError> {
        self.post_internal("/internal/mfa/totp/delete", correlation_id, req)
            .await
    }

    /// TOTP verification in the login flow (`POST /internal/mfa/totp/verify`).
    pub async fn verify_totp(
        &self,
        correlation_id: &str,
        req: &InternalVerifyTotpRequest,
    ) -> Result<InternalVerifyTotpResponse, InternalCallError> {
        self.post_internal("/internal/mfa/totp/verify", correlation_id, req)
            .await
    }

    // ─── Passkey (WebAuthn) API ───────────────────────────────────────────

    /// Begins passkey registration (`POST /internal/passkey/register/begin`).
    pub async fn passkey_register_begin(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyRegisterBeginRequest,
    ) -> Result<InternalPasskeyRegisterBeginResponse, InternalCallError> {
        self.post_internal("/internal/passkey/register/begin", correlation_id, req)
            .await
    }

    /// Completes passkey registration (`POST /internal/passkey/register/complete`).
    pub async fn passkey_register_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyRegisterCompleteRequest,
    ) -> Result<InternalPasskeyRegisterCompleteResponse, InternalCallError> {
        self.post_internal("/internal/passkey/register/complete", correlation_id, req)
            .await
    }

    /// Deletes a passkey (`POST /internal/passkey/delete`).
    pub async fn passkey_delete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyDeleteRequest,
    ) -> Result<InternalPasskeyDeleteResponse, InternalCallError> {
        self.post_internal("/internal/passkey/delete", correlation_id, req)
            .await
    }

    /// List of registered passkeys (`POST /internal/passkey/list`).
    pub async fn passkey_list(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyListRequest,
    ) -> Result<InternalPasskeyListResponse, InternalCallError> {
        self.post_internal("/internal/passkey/list", correlation_id, req)
            .await
    }

    /// Begins passkey authentication (`POST /internal/passkey/login/begin`).
    pub async fn passkey_login_begin(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyLoginBeginRequest,
    ) -> Result<InternalPasskeyLoginBeginResponse, InternalCallError> {
        self.post_internal("/internal/passkey/login/begin", correlation_id, req)
            .await
    }

    /// Completes passkey authentication (`POST /internal/passkey/login/complete`).
    pub async fn passkey_login_complete(
        &self,
        correlation_id: &str,
        req: &InternalPasskeyLoginCompleteRequest,
    ) -> Result<InternalPasskeyLoginCompleteResponse, InternalCallError> {
        self.post_internal("/internal/passkey/login/complete", correlation_id, req)
            .await
    }

    /// Completes passkey login for the admin console (`POST /internal/passkey/login/admin/complete`).
    /// Begin calls the shared `passkey_login_begin` without `auth_session_id`.
    pub async fn passkey_login_admin_complete(
        &self,
        correlation_id: &str,
        req: &InternalAdminPasskeyLoginCompleteRequest,
    ) -> Result<InternalAdminPasskeyLoginCompleteResponse, InternalCallError> {
        self.post_internal(
            "/internal/passkey/login/admin/complete",
            correlation_id,
            req,
        )
        .await
    }

    /// Completes passkey login for the portal (`POST /internal/passkey/login/portal/complete`).
    /// Begin calls the shared `passkey_login_begin` without `auth_session_id`.
    pub async fn passkey_login_portal_complete(
        &self,
        correlation_id: &str,
        req: &InternalPortalPasskeyLoginCompleteRequest,
    ) -> Result<InternalPortalPasskeyLoginCompleteResponse, InternalCallError> {
        self.post_internal(
            "/internal/passkey/login/portal/complete",
            correlation_id,
            req,
        )
        .await
    }

    /// Exchanges the admin's SSO session for an admin token and gets the authentication state and identity via the api's
    /// `GET /{tenant_id}/admin/whoami` (ADR-0007 §4, ADR-0009 §6, ADR-0037).
    ///
    /// A 401 on exchange means not logged in (`Unauthenticated`). If the exchange passes but whoami returns 403, it is
    /// "logged in but not an admin"; being able to separate these two is also why the token exchange
    /// is done per request.
    pub async fn admin_whoami(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
    ) -> AdminSession {
        let token = match self
            .management_token(correlation_id, tenant_id, sso_session_id)
            .await
        {
            Ok(token) => token.access_token,
            Err(AdminApiError::Unauthorized) => return AdminSession::Unauthenticated,
            Err(e) => {
                tracing::error!(error = %e, "management token exchange for whoami failed");
                return AdminSession::Error;
            }
        };
        let response = match self
            .http
            .get(format!("{}/{}/admin/whoami", self.base_url, tenant_id))
            .header(REQUEST_ID_HEADER, correlation_id)
            .bearer_auth(token)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "admin whoami call to api failed");
                return AdminSession::Error;
            }
        };
        match response.status() {
            reqwest::StatusCode::OK => match response.json::<WhoamiResponse>().await {
                Ok(w) => AdminSession::Authenticated(admin_identity(w)),
                Err(e) => {
                    tracing::error!(error = %e, "failed to decode whoami response");
                    AdminSession::Error
                }
            },
            other => {
                let session = admin_session_for_status(other);
                if matches!(session, AdminSession::Error) {
                    tracing::error!(status = %other, "unexpected whoami status from api");
                }
                session
            }
        }
    }

    // ── Admin console -> JSON admin API (`/{tenant_id}/admin/*`, admin token; ADR-0037) ─────────
    //
    // The `sso` each method receives is the SSO session cookie value, but what is forwarded to the api is a token,
    // not the cookie. The `admin_send` family exchanges it with `management_token` and then sends it as Bearer.

    /// One page of the client list (`GET /admin/clients`; G7). Paging is done by the api (DB).
    pub async fn list_clients(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<ClientListView, AdminApiError> {
        self.admin_get_with_query(tenant_id, "/admin/clients", correlation_id, sso, query)
            .await
    }

    /// A single client (`GET /admin/clients/{id}`).
    pub async fn get_client(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<ClientView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/clients/{client_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Creates a client (`POST /admin/clients`).
    pub async fn create_client(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<ClientCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/clients",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Partially updates a client (`PATCH /admin/clients/{id}`).
    pub async fn update_client(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
        body: serde_json::Value,
    ) -> Result<ClientView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/clients/{client_id}"),
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Reissues the secret (`POST /admin/clients/{id}/secret`).
    pub async fn rotate_client_secret(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<ClientSecretView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/clients/{client_id}/secret"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// List of permission codes **grantable** to clients (`GET /admin/permissions?grantable_to=client`).
    ///
    /// Filtering is done by the api with `domain::permission::is_grantable_to_client`. web doesn't hold the same check
    /// to avoid only one side going stale when the master grows (ADR-0037).
    pub async fn client_grantable_permissions(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<AvailablePermissionsResponse, AdminApiError> {
        self.admin_get_with_query(
            tenant_id,
            "/admin/permissions",
            correlation_id,
            sso,
            &[("grantable_to", "client".to_string())],
        )
        .await
    }

    /// List of a client's held admin permissions (`GET /admin/clients/{id}/permissions`; ADR-0037).
    pub async fn list_client_permissions(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<ClientPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/clients/{client_id}/permissions"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Grants an admin permission to a client (`POST /admin/clients/{id}/permissions`).
    pub async fn grant_client_permission(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
        code: &str,
    ) -> Result<ClientPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/clients/{client_id}/permissions"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "permission_code": code })),
        )
        .await
    }

    /// Revokes an admin permission from a client (`DELETE /admin/clients/{id}/permissions/{code}`).
    pub async fn revoke_client_permission(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
        code: &str,
    ) -> Result<ClientPermissionsResponse, AdminApiError> {
        // The `:` in permission codes can go into a path segment as is (pchar of RFC 3986).
        self.admin_send(
            Method::DELETE,
            tenant_id,
            &format!("/admin/clients/{client_id}/permissions/{code}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── Users and permissions (admin console permission screens) ─────────────────────────────────

    /// Gets a user (`GET /admin/users/{id}`).
    pub async fn get_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/users/{user_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Creates a user (`POST /admin/users`). Returns the setup link to hand to the user only once (ADR-0062).
    pub async fn create_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<UserCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/users",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Grantable permission codes (`GET /admin/permissions`).
    pub async fn available_permissions(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<AvailablePermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/permissions",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// List of held permissions (`GET /admin/users/{id}/permissions`).
    pub async fn list_user_permissions(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/users/{user_id}/permissions"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Grants a permission (`POST /admin/users/{id}/permissions`).
    pub async fn grant_permission(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        code: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/permissions"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "permission_code": code })),
        )
        .await
    }

    /// Revokes a permission (`DELETE /admin/users/{id}/permissions/{code}`).
    pub async fn revoke_permission(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        code: &str,
    ) -> Result<UserPermissionsResponse, AdminApiError> {
        self.admin_send(
            Method::DELETE,
            tenant_id,
            &format!("/admin/users/{user_id}/permissions/{code}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Changes a user's status (`PATCH /admin/users/{user_id}`; ACTIVE / DISABLED).
    pub async fn update_user_status(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        status: &str,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/users/{user_id}"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "status": status })),
        )
        .await
    }

    /// Updates a user's profile (email, login identifier, display name)
    /// (`PATCH /admin/users/{user_id}/profile`; MT25). `profile` is
    /// `{ email, preferred_username, name }` (an empty `name` means unset).
    pub async fn update_user_profile(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        profile: serde_json::Value,
    ) -> Result<UserSummaryResponse, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/users/{user_id}/profile"),
            correlation_id,
            sso,
            Some(profile),
        )
        .await
    }

    /// Deletes a user (`DELETE /admin/users/{user_id}`; only users whose owning tenant is this tenant).
    pub async fn delete_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/users/{user_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Reissues a user's password (`POST /admin/users/{user_id}/password-reset`).
    /// Returns the setup link to hand to the user only once (ADR-0062).
    pub async fn reset_user_password(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::UserPasswordResetView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/password-reset"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Resets a user's MFA (`POST /admin/users/{user_id}/mfa-reset`; MT21).
    /// Removes TOTP and passkeys together and returns a breakdown of what was removed.
    pub async fn reset_user_mfa(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::UserMfaResetView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/mfa-reset"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Bulk-revokes refresh tokens issued to a user (`POST /admin/users/{user_id}/token-reissue`;
    /// ADR-0047). Returns the number dropped (0 is also success).
    pub async fn reissue_user_tokens(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::UserTokenReissueView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/token-reissue"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Number of a user's currently valid refresh tokens (`GET /admin/users/{user_id}/active-tokens`;
    /// task #83). Read to show whether there is anything to target before reissue is pressed.
    pub async fn count_user_active_tokens(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::UserActiveTokensView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/users/{user_id}/active-tokens"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Immediately unlocks an account (`POST /admin/users/{user_id}/unlock`; AP6).
    /// The api clears the lock expiry and resets the failure count at the same time.
    pub async fn unlock_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::UserUnlockView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/unlock"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── External IdP settings and login identifiers (AP16; APIs are AP10 / AP8) ────────────────

    /// List of external IdP settings (`GET /admin/external-idps`).
    pub async fn list_external_idps(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<crate::admin_dto::ExternalIdpView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/external-idps",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Creates an external IdP setting (`POST /admin/external-idps`).
    pub async fn create_external_idp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::ExternalIdpView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/external-idps",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Partially updates an external IdP setting (`PATCH /admin/external-idps/{id}`).
    pub async fn update_external_idp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        id: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::ExternalIdpView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/external-idps/{id}"),
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Imports external IdP metadata (`POST /admin/external-idps/import-metadata`). AP12.
    /// Only parses and returns candidate values for registration (nothing is persisted).
    pub async fn import_external_idp_metadata(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        metadata_xml: &str,
    ) -> Result<SamlIdpMetadataImportResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/external-idps/import-metadata",
            correlation_id,
            sso,
            Some(serde_json::json!({ "metadata_xml": metadata_xml })),
        )
        .await
    }

    /// Imports an external OIDC IdP's discovery (`POST /admin/external-idps/import-discovery`; task #77).
    /// The api reads and validates the issuer's discovery document and returns candidate values for registration (nothing is persisted).
    pub async fn import_external_idp_discovery(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        issuer: &str,
    ) -> Result<OidcDiscoveryImportResponse, AdminApiError> {
        let body = OidcDiscoveryImportRequest {
            issuer: issuer.to_string(),
        };
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/external-idps/import-discovery",
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// Deletes an external IdP setting (`DELETE /admin/external-idps/{id}`).
    pub async fn delete_external_idp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/external-idps/{id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// List of a user's login identifiers (`GET /admin/users/{user_id}/login-identifiers`).
    pub async fn list_login_identifiers(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<Vec<crate::admin_dto::LoginIdentifierView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Adds a login identifier (`POST /admin/users/{user_id}/login-identifiers`).
    pub async fn add_login_identifier(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::LoginIdentifierView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers"),
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Enables/disables a login identifier (`PATCH .../login-identifiers/{id}`).
    pub async fn set_login_identifier_active(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        identifier_id: &str,
        is_active: bool,
    ) -> Result<crate::admin_dto::LoginIdentifierView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers/{identifier_id}"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "is_active": is_active })),
        )
        .await
    }

    /// Promotes an alias email to the primary email (`POST .../login-identifiers/{id}/primary-email`; ADR-0052).
    pub async fn promote_primary_email(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        identifier_id: &str,
    ) -> Result<crate::admin_dto::LoginIdentifierView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers/{identifier_id}/primary-email"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Deletes a login identifier (`DELETE .../login-identifiers/{id}`).
    pub async fn delete_login_identifier(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        identifier_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/users/{user_id}/login-identifiers/{identifier_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── Members and invitations (ADR-0009 §3) ─────────────────────────────────────────

    /// Account list (`GET /admin/accounts`; people and service accounts; ADR-0065). Kind, filter and
    /// paging conditions are passed as `(key, value)` pairs (filtering is done on the api side = DB).
    pub async fn list_accounts(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<AccountListView, AdminApiError> {
        self.admin_get_with_query(tenant_id, "/admin/accounts", correlation_id, sso, query)
            .await
    }

    /// One service account (`GET /admin/service-accounts/{client_id}`; ADR-0065).
    pub async fn get_service_account(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<ServiceAccountView, AdminApiError> {
        self.admin_get_with_query(
            tenant_id,
            &format!("/admin/service-accounts/{client_id}"),
            correlation_id,
            sso,
            &[],
        )
        .await
    }

    /// Writes the admin note of a service account (`PUT /admin/service-accounts/{client_id}/note`).
    /// Empty deletes it.
    pub async fn update_service_account_note(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
        note: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::PUT,
            tenant_id,
            &format!("/admin/service-accounts/{client_id}/note"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "note": note })),
        )
        .await
    }

    /// Apps a service account can use (`GET /admin/service-accounts/{client_id}/applications`).
    pub async fn list_service_account_applications(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<crate::admin_dto::AccountApplicationListView, AdminApiError> {
        self.admin_get_with_query(
            tenant_id,
            &format!("/admin/service-accounts/{client_id}/applications"),
            correlation_id,
            sso,
            &[],
        )
        .await
    }

    /// One member (`GET /admin/members/{user_id}`). Looked up for the detail screen.
    ///
    /// ⚠ **Don't search the list.** The list is paged, so we can't know which page
    /// the person we want is on.
    pub async fn get_member(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<MemberView, AdminApiError> {
        let response = self
            .with_language(
                self.http
                    .get(format!(
                        "{}/{}/admin/members/{}",
                        self.base_url, tenant_id, user_id
                    ))
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .bearer_auth(
                        self.management_token(correlation_id, tenant_id, sso)
                            .await?
                            .access_token,
                    ),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/members/{user_id}").await
    }

    /// Suspends/resumes a guest membership (`PATCH /admin/members/{user_id}`; MT24).
    /// `status` is `SUSPENDED` (suspend) or `ACTIVE` (resume).
    pub async fn update_member_status(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        status: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::PATCH,
            tenant_id,
            &format!("/admin/members/{user_id}"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "status": status })),
        )
        .await
    }

    /// Writes an admin note (`PUT /admin/members/{user_id}/note`; ADR-0063). Empty deletes it.
    pub async fn update_member_note(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
        note: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::PUT,
            tenant_id,
            &format!("/admin/members/{user_id}/note"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "note": note })),
        )
        .await
    }

    /// Apps one member can use (`GET /admin/members/{user_id}/applications`; ADR-0063).
    pub async fn list_member_applications(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<crate::admin_dto::AccountApplicationListView, AdminApiError> {
        self.admin_get_with_query(
            tenant_id,
            &format!("/admin/members/{user_id}/applications"),
            correlation_id,
            sso,
            &[],
        )
        .await
    }

    /// Removes a guest membership (`DELETE /admin/members/{user_id}`; HOME is not allowed).
    pub async fn revoke_member(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        user_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/members/{user_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Creates a guest invitation (`POST /admin/invitations`). Returns the invitation token only once.
    pub async fn create_invitation(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        invitee: &str,
    ) -> Result<InvitationCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/invitations",
            correlation_id,
            sso,
            // The invitee may be an email address or an internal ID (the api tells them apart; ADR-0061).
            Some(serde_json::json!({ "invitee": invitee })),
        )
        .await
    }

    /// Accepts an invitation (`POST /{tenant_id}/invitations/accept`). **Forwards the invitee's own SSO cookie
    /// as is**.
    ///
    /// ⚠ **Don't use the admin API's common path (`admin_send_*`).** It calls after **exchanging the SSO session for an admin token
    /// of that tenant** via `POST /internal/admin/token`.
    /// ⚠ **The invitee is not yet a member of that tenant, so the exchange always fails** (401).
    /// Accepting is the operation of becoming a member, so it can't presuppose membership.
    ///
    /// The api endpoint accepts the cookie as the credential (`AuthenticatedUser`; no permission required;
    /// ADR-0009 §3). Success is 204.
    pub async fn accept_invitation(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        token: &str,
    ) -> Result<(), AdminApiError> {
        let response = self
            .with_language(
                self.http
                    .post(format!(
                        "{}/{}/invitations/accept",
                        self.base_url, tenant_id
                    ))
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .header(
                        reqwest::header::COOKIE,
                        format!("{}={}", assay_contracts::cookies::SSO_SESSION_COOKIE, sso),
                    ),
            )
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let message = response
            .json::<ApiErrorBody>()
            .await
            .map(|b| b.message)
            .unwrap_or_default();
        Err(match status {
            reqwest::StatusCode::UNAUTHORIZED => AdminApiError::Unauthorized,
            reqwest::StatusCode::FORBIDDEN => AdminApiError::Forbidden,
            reqwest::StatusCode::NOT_FOUND => AdminApiError::NotFound,
            reqwest::StatusCode::BAD_REQUEST => AdminApiError::Validation(message),
            reqwest::StatusCode::CONFLICT => AdminApiError::Conflict(message),
            other => AdminApiError::Transport(format!("unexpected status {other}")),
        })
    }

    // ── Status checks (audit log, client status) ─────────────────────────────────

    /// Audit log search (`GET /admin/audit-logs`). Filters are passed as `(key, value)` pairs.
    pub async fn search_audit_logs(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<Vec<AuditLogView>, AdminApiError> {
        let response = self
            .with_language(
                self.http
                    .get(format!("{}/{}/admin/audit-logs", self.base_url, tenant_id))
                    .query(query)
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .bearer_auth(
                        self.management_token(correlation_id, tenant_id, sso)
                            .await?
                            .access_token,
                    ),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/audit-logs").await
    }

    /// Error/warning log search (`GET /admin/logs`). Filters are passed as `(key, value)` pairs.
    /// Read permission is enforced by the api as `idp.system.admin` (cross-tenant operational information).
    pub async fn search_application_logs(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<Vec<ApplicationLogEntryResponse>, AdminApiError> {
        let response = self
            .with_language(
                self.http
                    .get(format!("{}/{}/admin/logs", self.base_url, tenant_id))
                    .query(query)
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .bearer_auth(
                        self.management_token(correlation_id, tenant_id, sso)
                            .await?
                            .access_token,
                    ),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, "/admin/logs").await
    }

    /// Sends our own WARN / ERROR to the api to have them written to the `log` table (`POST /internal/logs`).
    /// web has no DB, so this is the only path for keeping application logs (CLAUDE.md "Logging").
    ///
    /// **Callers must not log on failure** (a log about a send failure would trigger another send).
    /// Returns the number accepted.
    pub async fn push_application_logs(
        &self,
        records: Vec<ApplicationLogPayload>,
    ) -> anyhow::Result<usize> {
        let response = self
            .http
            .post(format!("{}/internal/logs", self.base_url))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .json(&ApplicationLogIngestRequest { records })
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("api /internal/logs returned status {}", response.status());
        }
        Ok(response
            .json::<ApplicationLogIngestResponse>()
            .await?
            .accepted)
    }

    /// Client status list (`GET /admin/clients/status`).
    pub async fn list_client_status(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<ClientStatusResponse>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/clients/status",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// SAML SP (client) list (`GET /admin/saml-service-providers`).
    pub async fn list_saml_service_providers(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<crate::admin_dto::SamlServiceProviderView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/saml-service-providers",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    // ── Authentication policies (AP1; `/admin/authentication-policies`) ────────────────────────

    /// Authentication policy list (`GET /admin/authentication-policies`; ascending priority, including disabled ones).
    pub async fn list_authentication_policies(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<AuthenticationPoliciesResponse, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/authentication-policies",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Creates an authentication policy (`POST /admin/authentication-policies`).
    pub async fn create_authentication_policy(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: AuthenticationPolicyUpsertRequest,
    ) -> Result<AuthenticationPolicyResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/authentication-policies",
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// Updates an authentication policy (`PUT /admin/authentication-policies/{id}`; full replacement).
    pub async fn update_authentication_policy(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        policy_id: &str,
        body: AuthenticationPolicyUpsertRequest,
    ) -> Result<AuthenticationPolicyResponse, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            &format!("/admin/authentication-policies/{policy_id}"),
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// Deletes an authentication policy (`DELETE /admin/authentication-policies/{id}`).
    pub async fn delete_authentication_policy(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        policy_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/authentication-policies/{policy_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Registers a SAML SP (client) (`POST /admin/saml-service-providers`).
    pub async fn register_saml_service_provider(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: SamlServiceProviderRegisterRequest,
    ) -> Result<SamlServiceProviderResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/saml-service-providers",
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// Updates a SAML SP (client) (`PUT /admin/saml-service-providers/{id}`).
    pub async fn update_saml_service_provider(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        id: &str,
        body: SamlServiceProviderUpdateRequest,
    ) -> Result<SamlServiceProviderResponse, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            &format!("/admin/saml-service-providers/{id}"),
            correlation_id,
            sso,
            Some(serde_json::to_value(body).map_err(|e| AdminApiError::Transport(e.to_string()))?),
        )
        .await
    }

    /// Logically deletes a client (ADR-0035). The entity remains and its status becomes DELETED.
    pub async fn delete_client(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        client_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/clients/{client_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Deletes a SAML SP (client) (`DELETE /admin/saml-service-providers/{id}`).
    pub async fn delete_saml_service_provider(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/saml-service-providers/{id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Imports SP metadata (`POST /admin/saml-service-providers/import-metadata`).
    pub async fn import_saml_sp_metadata(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        metadata_xml: &str,
    ) -> Result<SamlSpMetadataImportResponse, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/saml-service-providers/import-metadata",
            correlation_id,
            sso,
            Some(serde_json::json!({ "metadata_xml": metadata_xml })),
        )
        .await
    }

    // ── Signing key management (K1) ─────────────────────────────────────────────────────

    /// Signing key list (`GET /admin/signing-keys`).
    pub async fn list_signing_keys(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<Vec<crate::admin_dto::SigningKeyView>, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/signing-keys",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Generates a new signing key (`POST /admin/signing-keys`). `algorithm` is `RS256` or `ES256`.
    pub async fn generate_signing_key(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        algorithm: &str,
        activate_immediately: bool,
    ) -> Result<crate::admin_dto::SigningKeyView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/signing-keys",
            correlation_id,
            sso,
            Some(serde_json::json!({
                "algorithm": algorithm,
                "activate_immediately": activate_immediately,
            })),
        )
        .await
    }

    /// Retires a signing key (`POST /admin/signing-keys/{kid}/retire`).
    pub async fn retire_signing_key(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        kid: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::POST,
            tenant_id,
            &format!("/admin/signing-keys/{kid}/retire"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Deletes a signing key (`DELETE /admin/signing-keys/{kid}`). Only RETIRED keys.
    pub async fn delete_signing_key(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        kid: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/signing-keys/{kid}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Lists registered audiences (`GET /admin/resources`; ADR-0042).
    pub async fn list_resources(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::ResourceListView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/resources",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Lists apps (`GET /admin/applications`; ADR-0054).
    pub async fn list_applications(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::ApplicationListView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/applications",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Gets the details of one app (`GET /admin/applications/{id}`).
    pub async fn get_application(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
    ) -> Result<crate::admin_dto::ApplicationDetailView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/applications/{application_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Registers an app (`POST /admin/applications`).
    ///
    /// `assign_creator` means "assign myself". ⚠ **Right after creating it as "individual" nobody can get in**, so
    /// the screen has it checked from the start.
    pub async fn create_application(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        display_name: &str,
        assignment_mode: &str,
        assign_creator: bool,
    ) -> Result<crate::admin_dto::ApplicationView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/applications",
            correlation_id,
            sso,
            Some(serde_json::json!({
                "display_name": display_name,
                "assignment_mode": assignment_mode,
                "assign_creator": assign_creator,
            })),
        )
        .await
    }

    /// Updates an app (`PUT /admin/applications/{id}`). The 3 values are always sent together.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_application(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
        display_name: &str,
        status: &str,
        assignment_mode: &str,
    ) -> Result<crate::admin_dto::ApplicationView, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            &format!("/admin/applications/{application_id}"),
            correlation_id,
            sso,
            Some(serde_json::json!({
                "display_name": display_name,
                "status": status,
                "assignment_mode": assignment_mode,
            })),
        )
        .await
    }

    /// Deletes an app (`DELETE /admin/applications/{id}`). The RP registrations are not deleted.
    pub async fn delete_application(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/applications/{application_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Adds a binding (`POST /admin/applications/{id}/bindings`; ADR-0059).
    ///
    /// The counterpart is sent in the field fixed per kind (`client_id` for `oidc` / `service_account`, `service_provider_id`
    /// for `saml`, `resource_uri` for `resource`). Unknown kinds are refused by the api with 400.
    ///
    /// `move_from` is the app ID of the current owner when "the counterpart is another app's binding, so move it from that app"
    /// (ADR-0067). If it differs from the current owner, the api refuses with 409.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_application_binding(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
        kind: &str,
        target: &str,
        move_from: Option<&str>,
    ) -> Result<crate::admin_dto::ApplicationView, AdminApiError> {
        let field = match kind {
            "saml" => "service_provider_id",
            "resource" => "resource_uri",
            _ => "client_id",
        };
        let mut body = serde_json::json!({ "kind": kind });
        body[field] = serde_json::Value::String(target.to_string());
        if let Some(from) = move_from {
            body["move_from_application_id"] = serde_json::Value::String(from.to_string());
        }
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/applications/{application_id}/bindings"),
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Looks up binding candidates (`GET /admin/applications/{id}/binding-candidates`; ADR-0067).
    pub async fn application_binding_candidates(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
    ) -> Result<crate::admin_dto::ApplicationBindingCandidateListView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/applications/{application_id}/binding-candidates"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Removes a binding (`DELETE /admin/applications/{id}/bindings/{binding_id}`).
    pub async fn remove_application_binding(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
        binding_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/applications/{application_id}/bindings/{binding_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Assigns a principal (`POST /admin/applications/{id}/assignments`; idempotent; ADR-0059).
    ///
    /// `kind` is `user` (counterpart `user_id`) or `service_account` (counterpart `client_id`). Unknown kinds are
    /// refused by the api with 400.
    pub async fn assign_application_principal(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
        kind: &str,
        target: &str,
    ) -> Result<crate::admin_dto::ApplicationDetailView, AdminApiError> {
        let field = if kind == "service_account" {
            "client_id"
        } else {
            "user_id"
        };
        let mut body = serde_json::json!({ "kind": kind });
        body[field] = serde_json::Value::String(target.to_string());
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/applications/{application_id}/assignments"),
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Removes a person's assignment (`DELETE /admin/applications/{id}/assignments/users/{user_id}`).
    pub async fn unassign_application_user(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
        user_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/applications/{application_id}/assignments/users/{user_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Removes a service account's assignment
    /// (`DELETE /admin/applications/{id}/assignments/service-accounts/{client_id}`).
    pub async fn unassign_application_service_account(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
        client_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!(
                "/admin/applications/{application_id}/assignments/service-accounts/{client_id}"
            ),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Looks up "people who can get in now" (`GET /admin/applications/{id}/current-users`).
    ///
    /// The copy source before switching from "everyone" to "individual". ⚠ **Never let it switch without showing this.**
    pub async fn application_current_users(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        application_id: &str,
    ) -> Result<crate::admin_dto::ApplicationCurrentUsersView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            &format!("/admin/applications/{application_id}/current-users"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Registers an audience (`POST /admin/resources`).
    pub async fn register_resource(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        resource_uri: &str,
        display_name: &str,
    ) -> Result<crate::admin_dto::ResourceView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/resources",
            correlation_id,
            sso,
            Some(serde_json::json!({
                "resource_uri": resource_uri,
                "display_name": display_name,
            })),
        )
        .await
    }

    /// Changes an audience's status (`PATCH /admin/resources/{id}`). `status` is `ACTIVE` / `DISABLED`.
    pub async fn update_resource_status(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        resource_id: &str,
        status: &str,
    ) -> Result<crate::admin_dto::ResourceView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/resources/{resource_id}"),
            correlation_id,
            sso,
            Some(serde_json::json!({ "status": status })),
        )
        .await
    }

    /// Deletes an audience (`DELETE /admin/resources/{id}`). The app bindings are deleted with it.
    pub async fn delete_resource(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        resource_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/resources/{resource_id}"),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Exchanges the SSO session for an api admin token (`POST /internal/admin/token`; ADR-0037).
    ///
    /// **Exchanged every time before calling the admin API.** It is not cached so that session revocation, permission revocation
    /// and guest suspension are not delayed by the token's lifetime. Admin console traffic is low, and
    /// at the cost of one extra round trip the window of "disabled but still able to operate" disappears.
    async fn management_token(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<ManagementTokenResponse, AdminApiError> {
        let response = self
            .with_language(
                self.http
                    .post(format!("{}/internal/admin/token", self.base_url))
                    .header(SERVICE_TOKEN_HEADER, &self.service_token)
                    .header(REQUEST_ID_HEADER, correlation_id),
            )
            .json(&ManagementTokenRequest {
                tenant_id: tenant_id.to_string(),
                sso_session_id: sso.to_string(),
            })
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        match response.status() {
            reqwest::StatusCode::OK => response
                .json::<ManagementTokenResponse>()
                .await
                .map_err(|e| AdminApiError::Transport(e.to_string())),
            // Invalid session = not logged in. The caller falls back to the login screen.
            reqwest::StatusCode::UNAUTHORIZED => Err(AdminApiError::Unauthorized),
            other => Err(AdminApiError::Transport(format!(
                "management token exchange returned {other}"
            ))),
        }
    }

    /// Common call to `/{tenant_id}/admin/*` (`RequirePerms`). Exchanges the received SSO session
    /// for an admin token via [`Self::management_token`] and calls with Bearer and correlation_id
    /// (cookies are not forwarded; ADR-0037). The api's status is mapped to web's [`AdminApiError`],
    /// and on success the body is decoded into `T`.
    async fn admin_send<T>(
        &self,
        method: Method,
        tenant_id: &str,
        path: &str,
        correlation_id: &str,
        sso: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, AdminApiError>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut req = self.with_language(
            self.http
                .request(method, format!("{}/{}{}", self.base_url, tenant_id, path))
                .header(REQUEST_ID_HEADER, correlation_id)
                .bearer_auth(
                    self.management_token(correlation_id, tenant_id, sso)
                        .await?
                        .access_token,
                ),
        );
        if let Some(json) = body {
            req = req.json(&json);
        }
        let response = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, path).await
    }

    /// Variant of `admin_send` that GETs with a query string (list paging; G7).
    /// reqwest builds it instead of string-concatenating onto the path so percent-encoding of values
    /// isn't written per caller.
    async fn admin_get_with_query<T>(
        &self,
        tenant_id: &str,
        path: &str,
        correlation_id: &str,
        sso: &str,
        query: &[(&str, String)],
    ) -> Result<T, AdminApiError>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .with_language(
                self.http
                    .get(format!("{}/{}{}", self.base_url, tenant_id, path))
                    .query(query)
                    .header(REQUEST_ID_HEADER, correlation_id)
                    .bearer_auth(
                        self.management_token(correlation_id, tenant_id, sso)
                            .await?
                            .access_token,
                    ),
            )
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        Self::handle_admin_response(response, path).await
    }

    /// Variant of `admin_send` expecting a success response without a body (204 etc.).
    async fn admin_send_no_content(
        &self,
        method: Method,
        tenant_id: &str,
        path: &str,
        correlation_id: &str,
        sso: &str,
        body: Option<serde_json::Value>,
    ) -> Result<(), AdminApiError> {
        let mut req = self.with_language(
            self.http
                .request(method, format!("{}/{}{}", self.base_url, tenant_id, path))
                .header(REQUEST_ID_HEADER, correlation_id)
                .bearer_auth(
                    self.management_token(correlation_id, tenant_id, sso)
                        .await?
                        .access_token,
                ),
        );
        if let Some(json) = body {
            req = req.json(&json);
        }
        let response = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let message = response
            .json::<ApiErrorBody>()
            .await
            .map(|b| b.message)
            .unwrap_or_default();
        Err(match status {
            reqwest::StatusCode::UNAUTHORIZED => AdminApiError::Unauthorized,
            reqwest::StatusCode::FORBIDDEN => AdminApiError::Forbidden,
            reqwest::StatusCode::NOT_FOUND => AdminApiError::NotFound,
            reqwest::StatusCode::BAD_REQUEST => AdminApiError::Validation(message),
            reqwest::StatusCode::CONFLICT => AdminApiError::Conflict(message),
            other => AdminApiError::Transport(format!("unexpected status {other}")),
        })
    }

    /// Common handling mapping the api's `/admin/*` responses to `T` or an error.
    async fn handle_admin_response<T>(
        response: reqwest::Response,
        path: &str,
    ) -> Result<T, AdminApiError>
    where
        T: serde::de::DeserializeOwned,
    {
        let status = response.status();
        if status.is_success() {
            return response
                .json::<T>()
                .await
                .map_err(|e| AdminApiError::Transport(format!("decode {path}: {e}")));
        }
        // On failure, extract the message from the error body (for displaying 400/409).
        let message = response
            .json::<ApiErrorBody>()
            .await
            .map(|b| b.message)
            .unwrap_or_default();
        Err(match status {
            reqwest::StatusCode::UNAUTHORIZED => AdminApiError::Unauthorized,
            reqwest::StatusCode::FORBIDDEN => AdminApiError::Forbidden,
            reqwest::StatusCode::NOT_FOUND => AdminApiError::NotFound,
            reqwest::StatusCode::BAD_REQUEST => AdminApiError::Validation(message),
            reqwest::StatusCode::CONFLICT => AdminApiError::Conflict(message),
            other => AdminApiError::Transport(format!("unexpected status {other}")),
        })
    }

    // ── Settings screens (MT14) ─────────────────────────────────────────────────────

    /// One page of the child tenant list (`GET /admin/tenants`; idp.system.admin required; G7).
    pub async fn list_tenants(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        query: &[(&str, String)],
    ) -> Result<crate::admin_dto::TenantListView, AdminApiError> {
        self.admin_get_with_query(
            tenant_id,
            "/admin/tenants",
            correlation_id,
            sso_session_id,
            query,
        )
        .await
    }

    /// Creates a child tenant (`POST /admin/tenants`; idp.system.admin required). The creator becomes the new tenant's
    /// bootstrap admin (ADR-0009 §4). The response is the created tenant.
    pub async fn create_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        name: &str,
    ) -> Result<crate::admin_dto::TenantCreatedView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            "/admin/tenants",
            correlation_id,
            sso_session_id,
            Some(serde_json::json!({ "name": name })),
        )
        .await
    }

    /// Partially updates a child tenant's display name and status (`PATCH /admin/tenants/{child_id}`;
    /// idp.system.admin required; MT23). `status` is `ACTIVE` / `DISABLED`.
    pub async fn update_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        child_id: &str,
        name: &str,
        status: &str,
    ) -> Result<crate::admin_dto::TenantView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            &format!("/admin/tenants/{child_id}"),
            correlation_id,
            sso_session_id,
            Some(serde_json::json!({ "name": name, "status": status })),
        )
        .await
    }

    /// Deletes a child tenant (`DELETE /admin/tenants/{child_id}`; idp.system.admin required;
    /// 409 if child tenants, users or clients remain under it).
    pub async fn delete_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        child_id: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::DELETE,
            tenant_id,
            &format!("/admin/tenants/{child_id}"),
            correlation_id,
            sso_session_id,
            None,
        )
        .await
    }

    /// Reissues a child tenant admin's password
    /// (`POST /admin/tenants/{child_id}/admin-password-reset`; idp.system.admin required).
    /// Returns the setup link to hand to the user only once (ADR-0062).
    pub async fn reset_tenant_admin_password(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso_session_id: &str,
        child_id: &str,
        email: &str,
    ) -> Result<crate::admin_dto::UserPasswordResetView, AdminApiError> {
        self.admin_send(
            Method::POST,
            tenant_id,
            &format!("/admin/tenants/{child_id}/admin-password-reset"),
            correlation_id,
            sso_session_id,
            Some(serde_json::json!({ "email": email })),
        )
        .await
    }

    /// Gets our own tenant (`GET /admin/settings/tenant`; idp.tenant-settings:read).
    pub async fn get_current_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::TenantView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/settings/tenant",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Updates our own tenant's display name (`PATCH /admin/settings/tenant`; idp.tenant-settings:write).
    pub async fn update_current_tenant(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        name: &str,
        self_registration_enabled: bool,
        email_login_enabled: bool,
    ) -> Result<crate::admin_dto::TenantView, AdminApiError> {
        self.admin_send(
            Method::PATCH,
            tenant_id,
            "/admin/settings/tenant",
            correlation_id,
            sso,
            Some(serde_json::json!({
                "name": name,
                "self_registration_enabled": self_registration_enabled,
                "email_login_enabled": email_login_enabled,
            })),
        )
        .await
    }

    /// List of the tenant's setting values (`GET /admin/settings/tenant/keys`; idp.tenant-settings:read; ADR-0058).
    pub async fn list_tenant_settings(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::TenantSettingsListView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/settings/tenant/keys",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Decides a tenant value (`PUT /admin/settings/tenant/keys/{key}`; idp.tenant-settings:write).
    ///
    /// For values that could lock people out, `Conflict` (409) is returned without `confirmed`.
    pub async fn set_tenant_setting(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        key: &str,
        value: &str,
        confirmed: bool,
    ) -> Result<crate::admin_dto::TenantSettingsListView, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            &tenant_setting_path(key),
            correlation_id,
            sso,
            Some(serde_json::json!({ "value": value, "confirmed": confirmed })),
        )
        .await
    }

    /// Removes the tenant's override (`DELETE /admin/settings/tenant/keys/{key}`; idp.tenant-settings:write).
    pub async fn clear_tenant_setting(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        key: &str,
    ) -> Result<crate::admin_dto::TenantSettingsListView, AdminApiError> {
        self.admin_send(
            Method::DELETE,
            tenant_id,
            &tenant_setting_path(key),
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// The tenant's own mail route (`GET /admin/settings/smtp`; idp.smtp:read; ADR-0058 §8).
    /// Without permission, `Forbidden` (web hides that section).
    pub async fn get_tenant_smtp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::TenantSmtpView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/settings/smtp",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Saves the tenant's own mail route (`PUT /admin/settings/smtp`; idp.smtp:write).
    pub async fn update_tenant_smtp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::TenantSmtpView, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            "/admin/settings/smtp",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Removes the tenant's mail route, reverting to the global route (`DELETE /admin/settings/smtp`; idp.smtp:write).
    pub async fn clear_tenant_smtp(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::TenantSmtpView, AdminApiError> {
        self.admin_send(
            Method::DELETE,
            tenant_id,
            "/admin/settings/smtp",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Gets system settings (`GET /admin/system-settings`; idp.system.admin required = effectively root only).
    /// Returns `Forbidden` unless root (web hides that section).
    pub async fn get_system_settings(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<crate::admin_dto::SystemSettingsView, AdminApiError> {
        self.admin_send(
            Method::GET,
            tenant_id,
            "/admin/system-settings",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Updates system settings (`PUT /admin/system-settings`; idp.system.admin required).
    pub async fn update_system_settings(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        body: serde_json::Value,
    ) -> Result<crate::admin_dto::SystemSettingsView, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            "/admin/system-settings",
            correlation_id,
            sso,
            Some(body),
        )
        .await
    }

    /// Updates a runtime setting's DB override (`PUT /admin/system-settings/runtime`; idp.system.admin required).
    /// When `value` is `None` or empty, the override is removed.
    pub async fn update_runtime_setting(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
        key: &str,
        value: Option<&str>,
    ) -> Result<crate::admin_dto::SystemSettingsView, AdminApiError> {
        self.admin_send(
            Method::PUT,
            tenant_id,
            "/admin/system-settings/runtime",
            correlation_id,
            sso,
            Some(serde_json::json!({ "key": key, "value": value })),
        )
        .await
    }

    /// Requests an api restart (`POST /{tenant_id}/admin/restart`; ADR-0017).
    ///
    /// The api returns accepted (202) and then stops, so **success of this call means "accepted",
    /// not "stopped"**. web stops itself only after confirming this success (if web went down first,
    /// the request wouldn't reach the api, and web would start first and grab the old shared settings).
    pub async fn request_restart(
        &self,
        correlation_id: &str,
        tenant_id: &str,
        sso: &str,
    ) -> Result<(), AdminApiError> {
        self.admin_send_no_content(
            Method::POST,
            tenant_id,
            "/admin/restart",
            correlation_id,
            sso,
            None,
        )
        .await
    }

    /// Self-service password change (`POST /internal/account/change-password`; MT15).
    pub async fn account_change_password(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountChangePasswordRequest,
    ) -> Result<assay_contracts::auth::InternalAccountChangePasswordResponse, InternalCallError>
    {
        self.post_internal("/internal/account/change-password", correlation_id, req)
            .await
    }

    /// Persists a logged-in user's display language to the DB (MT20).
    pub async fn account_update_language(
        &self,
        req: &assay_contracts::auth::InternalAccountUpdateLanguageRequest,
    ) -> Result<assay_contracts::auth::InternalAccountUpdateLanguageResponse, InternalCallError>
    {
        // correlation_id isn't needed (not audited), so an empty string is passed.
        self.post_internal("/internal/account/update-language", "", req)
            .await
    }

    /// Updates a logged-in user's color scheme setting (`users.theme`).
    pub async fn account_update_theme(
        &self,
        req: &assay_contracts::auth::InternalAccountUpdateThemeRequest,
    ) -> Result<assay_contracts::auth::InternalAccountUpdateThemeResponse, InternalCallError> {
        // correlation_id isn't needed (not audited), so an empty string is passed.
        self.post_internal("/internal/account/update-theme", "", req)
            .await
    }

    /// Gets the self-service profile (display name etc.) (for prefilling the settings screen).
    pub async fn account_profile(
        &self,
        req: &assay_contracts::auth::InternalAccountProfileRequest,
    ) -> Result<assay_contracts::auth::InternalAccountProfileResponse, InternalCallError> {
        self.post_internal("/internal/account/profile", "", req)
            .await
    }

    /// Updates a logged-in user's display name (`users.name`).
    pub async fn account_update_name(
        &self,
        req: &assay_contracts::auth::InternalAccountUpdateNameRequest,
    ) -> Result<assay_contracts::auth::InternalAccountUpdateNameResponse, InternalCallError> {
        self.post_internal("/internal/account/update-name", "", req)
            .await
    }

    /// Lists active external IdPs (for login screen buttons; AP10).
    pub async fn external_providers(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalExternalProvidersRequest,
    ) -> Result<assay_contracts::auth::InternalExternalProvidersResponse, InternalCallError> {
        self.post_internal("/internal/external/providers", correlation_id, req)
            .await
    }

    /// Starts an external IdP login and gets the authorization endpoint URL (AP10).
    pub async fn external_start(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalExternalStartRequest,
    ) -> Result<assay_contracts::auth::InternalExternalStartResponse, InternalCallError> {
        self.post_internal("/internal/external/start", correlation_id, req)
            .await
    }

    /// Has the callback from the external IdP verified (AP10).
    pub async fn external_callback(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalExternalCallbackRequest,
    ) -> Result<assay_contracts::auth::InternalExternalCallbackResponse, InternalCallError> {
        self.post_internal("/internal/external/callback", correlation_id, req)
            .await
    }

    /// Passes an external SAML IdP's assertion to the api for verification (AP12).
    pub async fn external_saml_acs(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalExternalSamlAcsRequest,
    ) -> Result<assay_contracts::auth::InternalExternalCallbackResponse, InternalCallError> {
        self.post_internal("/internal/external/saml/acs", correlation_id, req)
            .await
    }

    /// Gets the list of registered authenticators and the number of remaining recovery codes (AP9).
    pub async fn account_authenticators(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAuthenticatorsRequest,
    ) -> Result<assay_contracts::auth::InternalAuthenticatorsResponse, InternalCallError> {
        self.post_internal("/internal/account/authenticators", correlation_id, req)
            .await
    }

    /// Changes an authenticator's state (suspend, resume, revoke; AP9).
    pub async fn account_authenticator_status(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAuthenticatorStatusRequest,
    ) -> Result<assay_contracts::auth::InternalAuthenticatorStatusResponse, InternalCallError> {
        self.post_internal(
            "/internal/account/authenticators/status",
            correlation_id,
            req,
        )
        .await
    }

    /// (Re)issues recovery codes (AP9). The plaintext is available only in this response.
    pub async fn account_recovery_codes(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalRecoveryCodesRequest,
    ) -> Result<assay_contracts::auth::InternalRecoveryCodesResponse, InternalCallError> {
        self.post_internal("/internal/account/recovery-codes", correlation_id, req)
            .await
    }

    /// Sends an email OTP to a user awaiting MFA (AP9).
    pub async fn account_email_otp(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalEmailOtpRequest,
    ) -> Result<assay_contracts::auth::InternalEmailOtpResponse, InternalCallError> {
        self.post_internal("/internal/account/email-otp", correlation_id, req)
            .await
    }

    /// Sends an SMS OTP to a user awaiting MFA (AP13).
    pub async fn account_sms_otp(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalSmsOtpRequest,
    ) -> Result<assay_contracts::auth::InternalSmsOtpResponse, InternalCallError> {
        self.post_internal("/internal/account/sms-otp", correlation_id, req)
            .await
    }

    /// Starts phone number registration (sends the confirmation code; AP13).
    pub async fn account_phone_register(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalPhoneRegistrationRequest,
    ) -> Result<assay_contracts::auth::InternalPhoneRegistrationResponse, InternalCallError> {
        self.post_internal("/internal/account/phone/register", correlation_id, req)
            .await
    }

    /// Confirms phone number registration (AP13).
    pub async fn account_phone_confirm(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalPhoneConfirmationRequest,
    ) -> Result<assay_contracts::auth::InternalPhoneConfirmationResponse, InternalCallError> {
        self.post_internal("/internal/account/phone/confirm", correlation_id, req)
            .await
    }

    /// Determines whether step-up is needed right before a sensitive operation (AP5).
    pub async fn step_up_check(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalStepUpCheckRequest,
    ) -> Result<assay_contracts::auth::InternalStepUpCheckResponse, InternalCallError> {
        self.post_internal("/internal/step-up/check", correlation_id, req)
            .await
    }

    /// Verifies step-up identity verification (AP5).
    pub async fn step_up_verify(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalStepUpVerifyRequest,
    ) -> Result<assay_contracts::auth::InternalStepUpVerifyResponse, InternalCallError> {
        self.post_internal("/internal/step-up/verify", correlation_id, req)
            .await
    }

    /// Starts identity verification with a passkey (AP5, T38). The challenge has a different purpose from login's.
    pub async fn step_up_passkey_begin(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalStepUpPasskeyBeginRequest,
    ) -> Result<assay_contracts::auth::InternalStepUpPasskeyBeginResponse, InternalCallError> {
        self.post_internal("/internal/step-up/passkey/begin", correlation_id, req)
            .await
    }

    /// Verifies identity verification with a passkey (AP5, T38).
    pub async fn step_up_passkey_verify(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalStepUpPasskeyVerifyRequest,
    ) -> Result<assay_contracts::auth::InternalStepUpPasskeyVerifyResponse, InternalCallError> {
        self.post_internal("/internal/step-up/passkey/verify", correlation_id, req)
            .await
    }

    /// Gets the contents of the self-service security screen (session list, linked apps) (G10).
    pub async fn account_security(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountSecurityRequest,
    ) -> Result<assay_contracts::auth::InternalAccountSecurityResponse, InternalCallError> {
        self.post_internal("/internal/account/security", correlation_id, req)
            .await
    }

    /// Revokes a logged-in session (G10).
    pub async fn account_revoke_session(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountRevokeSessionRequest,
    ) -> Result<assay_contracts::auth::InternalAccountRevokeSessionResponse, InternalCallError>
    {
        self.post_internal(
            "/internal/account/security/revoke-session",
            correlation_id,
            req,
        )
        .await
    }

    /// Revokes consent for a linked app (G10).
    pub async fn account_revoke_consent(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountRevokeConsentRequest,
    ) -> Result<assay_contracts::auth::InternalAccountRevokeConsentResponse, InternalCallError>
    {
        self.post_internal(
            "/internal/account/security/revoke-consent",
            correlation_id,
            req,
        )
        .await
    }

    /// Has issued tokens reissued (by the user; ADR-0047).
    pub async fn account_reissue_tokens(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountReissueTokensRequest,
    ) -> Result<assay_contracts::auth::InternalAccountReissueTokensResponse, InternalCallError>
    {
        self.post_internal(
            "/internal/account/security/reissue-tokens",
            correlation_id,
            req,
        )
        .await
    }

    /// Starts a "Continue with the app" request (task #892).
    pub async fn app_approval_start(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAppApprovalStartRequest,
    ) -> Result<assay_contracts::auth::InternalAppApprovalStartResponse, InternalCallError> {
        self.post_internal("/internal/app-approval/start", correlation_id, req)
            .await
    }

    /// Completes "Continue with the app" in the browser opened by the authenticator app (task #892).
    pub async fn app_approval_complete(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAppApprovalCompleteRequest,
    ) -> Result<assay_contracts::auth::InternalAppApprovalCompleteResponse, InternalCallError> {
        self.post_internal("/internal/app-approval/complete", correlation_id, req)
            .await
    }

    /// Contents of the authenticator app registration confirmation screen (task #892).
    pub async fn account_approver_enrollment(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountApproverEnrollmentRequest,
    ) -> Result<assay_contracts::auth::InternalAccountApproverEnrollmentResponse, InternalCallError>
    {
        self.post_internal(
            "/internal/account/app-approver/enrollment",
            correlation_id,
            req,
        )
        .await
    }

    /// Confirms the authenticator app registration (task #892).
    pub async fn account_approver_confirm(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountApproverEnrollmentRequest,
    ) -> Result<assay_contracts::auth::InternalAccountApproverConfirmResponse, InternalCallError>
    {
        self.post_internal(
            "/internal/account/app-approver/confirm",
            correlation_id,
            req,
        )
        .await
    }

    /// List of "authenticator apps" (task #892).
    pub async fn account_approver_keys(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountApproverKeysRequest,
    ) -> Result<assay_contracts::auth::InternalAccountApproverKeysResponse, InternalCallError> {
        self.post_internal("/internal/account/app-approver/keys", correlation_id, req)
            .await
    }

    /// Revokes an authenticator app's key (task #892).
    pub async fn account_revoke_approver_key(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountRevokeApproverKeyRequest,
    ) -> Result<assay_contracts::auth::InternalAccountRevokeApproverKeyResponse, InternalCallError>
    {
        self.post_internal(
            "/internal/account/app-approver/keys/revoke",
            correlation_id,
            req,
        )
        .await
    }

    /// Binds the device to a freshly logged-in SSO session (task #872).
    pub async fn device_observe(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalDeviceObserveRequest,
    ) -> Result<assay_contracts::auth::InternalDeviceObserveResponse, InternalCallError> {
        self.post_internal("/internal/devices/observe", correlation_id, req)
            .await
    }

    /// Contents of the device registration card (task #916).
    pub async fn device_enrollment_describe(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalDeviceEnrollmentDescribeRequest,
    ) -> Result<assay_contracts::auth::InternalDeviceEnrollmentDescribeResponse, InternalCallError>
    {
        self.post_internal("/internal/device-enrollment/describe", correlation_id, req)
            .await
    }

    /// Starts the passkey verification for device registration (task #916).
    pub async fn device_enrollment_begin(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalDeviceEnrollmentBeginRequest,
    ) -> Result<assay_contracts::auth::InternalDeviceEnrollmentBeginResponse, InternalCallError>
    {
        self.post_internal(
            "/internal/device-enrollment/passkey/begin",
            correlation_id,
            req,
        )
        .await
    }

    /// Verifies with a passkey, registers the device and logs in (task #916).
    pub async fn device_enrollment_complete(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalDeviceEnrollmentCompleteRequest,
    ) -> Result<assay_contracts::auth::InternalDeviceEnrollmentCompleteResponse, InternalCallError>
    {
        self.post_internal(
            "/internal/device-enrollment/passkey/complete",
            correlation_id,
            req,
        )
        .await
    }

    /// Binds the SSO session to a device key (DBSC registration; task #887).
    pub async fn session_key_register(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalSessionKeyRegisterRequest,
    ) -> Result<assay_contracts::auth::InternalSessionKeyResponse, InternalCallError> {
        self.post_internal("/internal/sso/key-binding/register", correlation_id, req)
            .await
    }

    /// Refreshes the binding (DBSC; task #887).
    pub async fn session_key_refresh(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalSessionKeyRefreshRequest,
    ) -> Result<assay_contracts::auth::InternalSessionKeyResponse, InternalCallError> {
        self.post_internal("/internal/sso/key-binding/refresh", correlation_id, req)
            .await
    }

    /// Whether the SSO session is bound to a device key (task #887).
    pub async fn session_key_binding(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalSessionKeyBindingRequest,
    ) -> Result<assay_contracts::auth::InternalSessionKeyBindingResponse, InternalCallError> {
        self.post_internal("/internal/sso/key-binding", correlation_id, req)
            .await
    }

    /// The "Devices" section (task #872).
    pub async fn account_devices(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountDevicesRequest,
    ) -> Result<assay_contracts::auth::InternalAccountDevicesResponse, InternalCallError> {
        self.post_internal("/internal/account/devices", correlation_id, req)
            .await
    }

    /// The "Status" section (task #896).
    pub async fn account_security_status(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountSecurityStatusRequest,
    ) -> Result<assay_contracts::auth::InternalAccountSecurityStatusResponse, InternalCallError>
    {
        self.post_internal("/internal/account/security/status", correlation_id, req)
            .await
    }

    /// The user's own login history (task #879).
    pub async fn account_sign_in_history(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountSignInHistoryRequest,
    ) -> Result<assay_contracts::auth::InternalAccountSignInHistoryResponse, InternalCallError>
    {
        self.post_internal("/internal/account/sign-in-history", correlation_id, req)
            .await
    }

    /// Registers the current browser as a device (task #872).
    pub async fn account_register_device(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountRegisterDeviceRequest,
    ) -> Result<assay_contracts::auth::InternalAccountRegisterDeviceResponse, InternalCallError>
    {
        self.post_internal("/internal/account/devices/register", correlation_id, req)
            .await
    }

    /// Revokes a device registration (task #872).
    pub async fn account_revoke_device(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountRevokeDeviceRequest,
    ) -> Result<assay_contracts::auth::InternalAccountRevokeDeviceResponse, InternalCallError> {
        self.post_internal("/internal/account/devices/revoke", correlation_id, req)
            .await
    }

    /// The "SSH keys" section (task #885).
    pub async fn account_ssh_keys(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountSshKeysRequest,
    ) -> Result<assay_contracts::auth::InternalAccountSshKeysResponse, InternalCallError> {
        self.post_internal("/internal/account/ssh-keys", correlation_id, req)
            .await
    }

    /// Registers an SSH public key (task #885).
    pub async fn account_register_ssh_key(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountRegisterSshKeyRequest,
    ) -> Result<assay_contracts::auth::InternalAccountRegisterSshKeyResponse, InternalCallError>
    {
        self.post_internal("/internal/account/ssh-keys/register", correlation_id, req)
            .await
    }

    /// Revokes an SSH public key (task #885).
    pub async fn account_revoke_ssh_key(
        &self,
        correlation_id: &str,
        req: &assay_contracts::auth::InternalAccountRevokeSshKeyRequest,
    ) -> Result<assay_contracts::auth::InternalAccountRevokeSshKeyResponse, InternalCallError> {
        self.post_internal("/internal/account/ssh-keys/revoke", correlation_id, req)
            .await
    }

    /// Enumerates the logged-in user's tenants (`ACTIVE`) (for the tenant switcher UI).
    pub async fn account_tenants(
        &self,
        req: &assay_contracts::auth::InternalAccountTenantsRequest,
    ) -> Result<assay_contracts::auth::InternalAccountTenantsResponse, InternalCallError> {
        self.post_internal("/internal/account/tenants", "", req)
            .await
    }

    /// Gets the DB overrides of the runtime settings shared with the api (MT26 / ADR-0013).
    ///
    /// web has no DB, so it receives from the api the DB overrides of settings like `COOKIE_SECURE`, `HSTS_MAX_AGE` and
    /// `AUTH_SESSION_TTL_SECS` that "break if they diverge from the api". Called only once at startup
    /// (applying changes requires restarting web; MT27).
    ///
    /// Only DB overrides are returned, not the api's effective values. Keys not here are resolved by web's own
    /// ENV -> default.
    pub async fn fetch_shared_runtime_settings(&self) -> anyhow::Result<HashMap<String, String>> {
        let path = SHARED_RUNTIME_SETTINGS_PATH;
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("request to api {path} failed: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            // 401 is a service token mismatch (`INTERNAL_SERVICE_TOKEN` differs between api and web).
            anyhow::bail!("api {path} returned unexpected status {status}");
        }
        let body = response
            .json::<SharedRuntimeSettingsResponse>()
            .await
            .map_err(|e| anyhow::anyhow!("failed to decode api {path} response: {e}"))?;
        Ok(body.settings.into_iter().collect())
    }

    /// Checks reachability of the api (`GET /healthz`). Used by web's readiness.
    pub async fn is_api_reachable(&self) -> bool {
        match self
            .http
            .get(format!("{}/healthz", self.base_url))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Gets the applied state of the DB schema (migrations) from the api's `GET /internal/version/schema`.
    /// For display on the version info screen. Unreachable api and decode failures both give `None` (fail-soft; the screen
    /// shows "unavailable"). **It is an internal endpoint, so the service token is attached** (moved from the public
    /// endpoints in ADR-0034).
    pub async fn fetch_schema_version(&self) -> Option<SchemaVersionInfo> {
        self.http
            .get(format!("{}/internal/version/schema", self.base_url))
            .header(SERVICE_TOKEN_HEADER, &self.service_token)
            .send()
            .await
            .ok()?
            .json::<SchemaVersionInfo>()
            .await
            .ok()
    }

    /// Common POST handling to `/internal/*` (attaches the service token + correlation_id and exchanges JSON).
    async fn post_internal<B, R>(
        &self,
        path: &str,
        correlation_id: &str,
        body: &B,
    ) -> Result<R, InternalCallError>
    where
        B: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self
            .with_language(
                self.http
                    .post(format!("{}{}", self.base_url, path))
                    .header(SERVICE_TOKEN_HEADER, &self.service_token)
                    .header(REQUEST_ID_HEADER, correlation_id),
            )
            .json(body)
            .send()
            .await
            .map_err(|e| InternalCallError::failed(format!("request to api {path} failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            // Distinguish only the 400 for an unresolvable tenant so callers can fall back to the 404 screen
            // (MT28). The body is read only for this branch, so if reading fails it falls back to a plain failure.
            if status == reqwest::StatusCode::BAD_REQUEST
                && is_unknown_tenant_error(&response.text().await.unwrap_or_default())
            {
                return Err(InternalCallError::UnknownTenant);
            }
            // Business results of internal authentication (invalid/locked etc.) come back as 200 + result. Reaching here means
            // a web implementation/configuration error such as a token mismatch (401) or a server failure.
            return Err(InternalCallError::failed(format!(
                "api {path} returned unexpected status {status}"
            )));
        }
        response.json::<R>().await.map_err(|e| {
            InternalCallError::failed(format!("failed to decode api {path} response: {e}"))
        })
    }
}

/// Characters encoded as one path segment (other than alphanumerics and `-` `.` `_` `~`). `_` in setting keys
/// is left as is (as `%5F` the key would be unreadable in logs and recorded request paths).
const PATH_SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Path of one tenant setting item. The key comes from a form, so it is encoded so it can't inject path separators.
fn tenant_setting_path(key: &str) -> String {
    format!(
        "/admin/settings/tenant/keys/{}",
        percent_encoding::utf8_percent_encode(key, PATH_SEGMENT)
    )
}

#[cfg(test)]
mod tests {
    use super::{admin_display_label, admin_identity, admin_session_for_status, AdminSession};
    use assay_contracts::admin::WhoamiResponse;

    /// Distinguishes only the api's "can't resolve the tenant" 400 (MT28). Decided by the code, not dependent on the
    /// human-readable description.
    #[test]
    fn only_the_unknown_tenant_code_is_recognized() {
        assert!(super::is_unknown_tenant_error(
            r#"{"error":"unknown_tenant","error_description":"unknown or disabled tenant"}"#
        ));
        // Other 400s (invalid body etc.) remain "other failure" = 502.
        assert!(!super::is_unknown_tenant_error(
            r#"{"error":"invalid_request","error_description":"missing or invalid tenant_id"}"#
        ));
        // A match on the description alone doesn't trigger it (editing the wording doesn't break it / isn't broken by it).
        assert!(!super::is_unknown_tenant_error(
            r#"{"error":"invalid_request","error_description":"unknown or disabled tenant"}"#
        ));
        // When the body can't be read, fail-safe (doesn't show the 404 screen by mistake).
        for body in ["", "not json", "[]", "{}", r#"{"error":123}"#] {
            assert!(!super::is_unknown_tenant_error(body), "{body:?}");
        }
    }

    /// Failure kinds map to the screen's status (MT28).
    #[test]
    fn internal_call_failures_map_to_the_intended_status() {
        use crate::handlers::internal_call_status;
        assert_eq!(
            internal_call_status(&super::InternalCallError::UnknownTenant),
            axum::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            internal_call_status(&super::InternalCallError::Failed("boom".to_string())),
            axum::http::StatusCode::BAD_GATEWAY
        );
    }

    /// Mapping of non-200 whoami responses. Regression test that 404 (api can't resolve the tenant) is not included in `Error`
    /// = the screen doesn't fall back to 502.
    #[test]
    fn whoami_statuses_map_to_sessions() {
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::UNAUTHORIZED),
            AdminSession::Unauthenticated
        ));
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::FORBIDDEN),
            AdminSession::Forbidden
        ));
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::NOT_FOUND),
            AdminSession::NotFound
        ));
        // Unexpected cases such as a transient tenant resolution failure (503) are treated as gateway failures.
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::SERVICE_UNAVAILABLE),
            AdminSession::Error
        ));
        assert!(matches!(
            admin_session_for_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            AdminSession::Error
        ));
    }

    fn whoami(name: Option<&str>, preferred_username: Option<&str>) -> WhoamiResponse {
        WhoamiResponse {
            user_id: "019f8ea9-0879-7f75-85ab-68b0571b6e7d".to_string(),
            name: name.map(str::to_string),
            preferred_username: preferred_username.map(str::to_string),
            tenant_name: Some("Acme".to_string()),
            permissions: Vec::new(),
        }
    }

    #[test]
    fn display_label_prefers_name_then_username_then_id() {
        // The display name if present.
        assert_eq!(
            admin_display_label(whoami(Some("Alice"), Some("alice"))),
            "Alice"
        );
        // Without a display name, the login identifier.
        assert_eq!(admin_display_label(whoami(None, Some("alice"))), "alice");
        // Without either, the internal ID.
        assert_eq!(
            admin_display_label(whoami(None, None)),
            "019f8ea9-0879-7f75-85ab-68b0571b6e7d"
        );
    }

    /// The tenant name in the header comes from the api's whoami. When it isn't returned or is whitespace-only, it is omitted
    /// (even in mixed deployments with an old api, nothing but the header breaks).
    #[test]
    fn identity_carries_tenant_name_when_present() {
        let mut w = whoami(Some("Alice"), Some("alice"));
        assert_eq!(
            admin_identity(w.clone()).tenant_name.as_deref(),
            Some("Acme")
        );

        w.tenant_name = None;
        assert_eq!(admin_identity(w.clone()).tenant_name, None);

        w.tenant_name = Some("   ".to_string());
        assert_eq!(admin_identity(w).tenant_name, None);
    }

    #[test]
    fn display_label_treats_blank_values_as_absent() {
        // Whitespace-only is treated as unset and falls back to the next candidate.
        assert_eq!(
            admin_display_label(whoami(Some("   "), Some("alice"))),
            "alice"
        );
        assert_eq!(
            admin_display_label(whoami(Some(""), Some(""))),
            "019f8ea9-0879-7f75-85ab-68b0571b6e7d"
        );
    }
}
